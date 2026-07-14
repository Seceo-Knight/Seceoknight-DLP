"""
Tests for the ML classification + context analysis wiring in
app.services.classification_engine.ClassificationEngine.

app.services.ml_classification (spaCy NER + TF-IDF/SGD classifier) and
app.services.context_analyzer (false-positive/true-positive phrase scoring)
were fully built but had no caller — classification_engine_ml_patch.py was
a set of "how to integrate" instructions that was never actually applied.
This wires _apply_ml_classification / _apply_context_analysis /
_combine_scores into classify_content() (Step 6b), gated behind
settings.FEATURE_ML_CLASSIFICATION so the rule-only path is byte-for-byte
unchanged when the flag is off or the ML pass fails/times out.
"""
import uuid

import pytest

from app.services.classification_engine import ClassificationEngine
from app.models.rule import Rule


def _make_rule(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        name=f"rule-{uuid.uuid4().hex[:8]}",
        description="test rule",
        enabled=True,
        type="regex",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        threshold=1,
        weight=0.9,
        priority=100,
        classification_labels=["SSN"],
        severity="critical",
        category="PII",
        created_by=uuid.uuid4(),
    )
    defaults.update(overrides)
    return Rule(**defaults)


class TestCombineScores:
    """Pure-function tests for the weighting arithmetic — no I/O."""

    def test_weighted_combination(self, db_session):
        engine = ClassificationEngine(db_session)
        combined = engine._combine_scores(
            rule_confidence=0.8, ml_confidence=0.6, context_adjustment=0.5,
            is_false_positive=False,
        )
        # 0.8*0.5 + 0.6*0.3 + 0.5*0.2 = 0.4 + 0.18 + 0.1 = 0.68
        assert combined == pytest.approx(0.68, abs=1e-6)

    def test_false_positive_hard_cap(self, db_session):
        engine = ClassificationEngine(db_session)
        combined = engine._combine_scores(
            rule_confidence=0.9, ml_confidence=0.9, context_adjustment=0.9,
            is_false_positive=True,
        )
        # min(0.25, 0.9*0.3) = min(0.25, 0.27) = 0.25
        assert combined == 0.25

    def test_false_positive_scales_with_low_rule_confidence(self, db_session):
        engine = ClassificationEngine(db_session)
        combined = engine._combine_scores(
            rule_confidence=0.2, ml_confidence=0.9, context_adjustment=0.9,
            is_false_positive=True,
        )
        # min(0.25, 0.2*0.3) = min(0.25, 0.06) = 0.06
        assert combined == pytest.approx(0.06, abs=1e-6)

    def test_output_clamped_to_unit_interval(self, db_session):
        engine = ClassificationEngine(db_session)
        combined = engine._combine_scores(
            rule_confidence=1.0, ml_confidence=1.0, context_adjustment=1.0,
            is_false_positive=False,
        )
        assert 0.0 <= combined <= 1.0


class TestApplyMlClassificationGracefulDegradation:
    """_apply_ml_classification must never raise — always falls back cleanly."""

    @pytest.mark.asyncio
    async def test_ml_service_exception_falls_back_to_public(self, db_session, monkeypatch):
        engine = ClassificationEngine(db_session)

        class _BoomService:
            async def classify(self, **kwargs):
                raise RuntimeError("model not loaded")

        monkeypatch.setattr(
            "app.services.classification_engine.get_ml_service",
            lambda: _BoomService(),
        )

        result = await engine._apply_ml_classification("some content")
        assert result["ml_confidence"] == 0.0
        assert result["ml_label"] == "public"
        assert "ML error" in result["explanation"]

    @pytest.mark.asyncio
    async def test_ml_service_timeout_falls_back_to_public(self, db_session, monkeypatch):
        import asyncio

        engine = ClassificationEngine(db_session)

        class _SlowService:
            async def classify(self, **kwargs):
                await asyncio.sleep(5)  # far beyond _ML_TIMEOUT_SECONDS

        monkeypatch.setattr(
            "app.services.classification_engine.get_ml_service",
            lambda: _SlowService(),
        )

        result = await engine._apply_ml_classification("some content")
        assert result["ml_confidence"] == 0.0
        assert "timeout" in result["explanation"].lower()

    @pytest.mark.asyncio
    async def test_ml_service_success_path(self, db_session, monkeypatch):
        engine = ClassificationEngine(db_session)

        class _FakeResult:
            ml_confidence = 0.77
            predicted_label = "restricted"
            entities_detected = [{"type": "SSN", "text": "123-45-6789"}]
            explanation = "fake explanation"
            processing_time_ms = 12.3

        class _FakeService:
            async def classify(self, **kwargs):
                return _FakeResult()

        monkeypatch.setattr(
            "app.services.classification_engine.get_ml_service",
            lambda: _FakeService(),
        )

        result = await engine._apply_ml_classification("My SSN is 123-45-6789")
        assert result["ml_confidence"] == 0.77
        assert result["ml_label"] == "restricted"
        assert result["entities"][0]["type"] == "SSN"


class TestClassifyContentMlGate:
    """End-to-end classify_content() behavior with the feature flag."""

    @pytest.mark.asyncio
    async def test_ml_disabled_matches_legacy_rule_only_behavior(self, db_session, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "FEATURE_ML_CLASSIFICATION", False)

        rule = _make_rule()
        db_session.add(rule)
        await db_session.commit()

        engine = ClassificationEngine(db_session)
        result = await engine.classify_content("My SSN is 123-45-6789, please keep it safe")

        assert result.ml_analysis is None
        assert result.context_analysis is None
        assert result.details["method"] == "multi_technique_correlated"
        assert result.total_matches >= 1

    @pytest.mark.asyncio
    async def test_ml_enabled_populates_analysis_fields(self, db_session, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "FEATURE_ML_CLASSIFICATION", True)

        # Force a deterministic, fast ML result instead of depending on
        # spaCy/sklearn actually being installed in the test environment.
        class _FakeResult:
            ml_confidence = 0.5
            predicted_label = "confidential"
            entities_detected = []
            explanation = "fake"
            processing_time_ms = 1.0

        class _FakeService:
            async def classify(self, **kwargs):
                return _FakeResult()

        monkeypatch.setattr(
            "app.services.classification_engine.get_ml_service",
            lambda: _FakeService(),
        )

        rule = _make_rule()
        db_session.add(rule)
        await db_session.commit()

        engine = ClassificationEngine(db_session)
        result = await engine.classify_content("My SSN is 123-45-6789, please keep it safe")

        assert result.ml_analysis is not None
        assert result.ml_analysis["ml_confidence"] == 0.5
        assert result.context_analysis is not None
        assert result.details["method"] == "multi_technique_correlated_ml"

    @pytest.mark.asyncio
    async def test_ml_pass_exception_does_not_break_classification(self, db_session, monkeypatch):
        """If the whole ML/context pass blows up unexpectedly, classify_content
        must still return a valid rule-only result rather than raising."""
        from app.core.config import settings

        monkeypatch.setattr(settings, "FEATURE_ML_CLASSIFICATION", True)

        def _boom():
            raise RuntimeError("totally broken")

        monkeypatch.setattr("app.services.classification_engine.get_ml_service", _boom)

        rule = _make_rule()
        db_session.add(rule)
        await db_session.commit()

        engine = ClassificationEngine(db_session)
        result = await engine.classify_content("My SSN is 123-45-6789, please keep it safe")

        # Falls back to rule-only scoring, no exception propagates.
        assert result.ml_analysis is None
        assert result.context_analysis is None
        assert result.total_matches >= 1
