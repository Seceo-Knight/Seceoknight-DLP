"""
Integration Patch for ClassificationEngine
============================================
Add these methods to your existing classification_engine.py
to integrate ML classification alongside regex/keyword rules.

How to integrate:
1. Import at the top of classification_engine.py:
   from app.services.ml_classification import get_ml_service
   from app.services.context_analyzer import get_context_analyzer

2. Add the methods below to your ClassificationEngine class.

3. In your main classify() method, call _apply_ml_classification()
   after the existing rule evaluation, then call _apply_context_analysis()
   to adjust for false positives.
"""

# ===========================================================
# ADD THESE IMPORTS to the top of classification_engine.py
# ===========================================================
# from app.services.ml_classification import get_ml_service, MLClassificationResult
# from app.services.context_analyzer import get_context_analyzer, ContextAnalysisResult


# ===========================================================
# ADD THESE METHODS to your ClassificationEngine class
# ===========================================================

async def _apply_ml_classification(
    self,
    content: str,
    metadata: dict = None,
) -> dict:
    """
    Run ML classification on content and return ML signals.
    Called after rule-based evaluation.

    Returns:
        dict with keys: ml_confidence, ml_label, entities, explanation
    """
    ml_service = get_ml_service()

    try:
        result = await ml_service.classify(
            content=content,
            content_type=metadata.get("content_type", "text") if metadata else "text",
            metadata=metadata,
        )
        return {
            "ml_confidence": result.ml_confidence,
            "ml_label": result.predicted_label,
            "entities": result.entities_detected,
            "explanation": result.explanation,
            "processing_time_ms": result.processing_time_ms,
        }
    except asyncio.TimeoutError:
        # ML took too long (>200ms), fall back to rule-only
        return {
            "ml_confidence": 0.0,
            "ml_label": "public",
            "entities": [],
            "explanation": "ML timeout, using rules only",
            "processing_time_ms": 200.0,
        }
    except Exception as e:
        logger.warning("ML classification failed, using rules only", error=str(e))
        return {
            "ml_confidence": 0.0,
            "ml_label": "public",
            "entities": [],
            "explanation": f"ML error: {str(e)}",
            "processing_time_ms": 0.0,
        }


def _apply_context_analysis(
    self,
    content: str,
    matched_values: list,
    rule_confidence: float,
    metadata: dict = None,
) -> dict:
    """
    Run context analysis to detect false positives and adjust confidence.

    Args:
        content: The full scanned content.
        matched_values: Values detected by regex rules (e.g. SSN strings).
        rule_confidence: The confidence score from rule-based detection.
        metadata: Optional file/event metadata.

    Returns:
        dict with keys: adjusted_confidence, is_false_positive, reason
    """
    analyzer = get_context_analyzer()

    result = analyzer.analyze(
        content=content,
        matched_values=matched_values,
        metadata=metadata,
    )

    adjusted = max(0.0, min(1.0, rule_confidence + result.confidence_adjustment))

    return {
        "adjusted_confidence": adjusted,
        "is_false_positive": result.is_false_positive,
        "reason": result.reason,
        "fp_indicators": result.fp_indicators_found,
        "tp_indicators": result.tp_indicators_found,
    }


def _combine_scores(
    self,
    rule_confidence: float,
    ml_confidence: float,
    context_adjustment: float,
    is_false_positive: bool,
) -> float:
    """
    Combine rule-based, ML, and context scores into final confidence.

    Weighting:
    - Rule-based: 50% (proven, deterministic)
    - ML: 30% (contextual, probabilistic)
    - Context adjustment: 20% (false positive reduction)

    If context says false positive, hard-cap at 0.25 (still logged but
    classified as Public/Internal, not blocked).
    """
    if is_false_positive:
        # Don't completely zero it out (audit trail), but prevent blocking
        return min(0.25, rule_confidence * 0.3)

    # Weighted combination
    combined = (
        rule_confidence * 0.50 +
        ml_confidence * 0.30 +
        context_adjustment * 0.20
    )

    return max(0.0, min(1.0, combined))


# ===========================================================
# MODIFY YOUR EXISTING classify() METHOD
# ===========================================================
# Here's how your updated classify() should look (pseudocode):
#
# async def classify(self, content: str, metadata: dict = None) -> ClassificationResult:
#     # Step 1: Existing rule-based evaluation (keep as-is)
#     rule_result = self._evaluate_rules(content)
#     rule_confidence = rule_result.confidence
#     matched_values = [m.matched_text for m in rule_result.matches]
#
#     # Step 2: ML classification (NEW)
#     ml_result = await self._apply_ml_classification(content, metadata)
#
#     # Step 3: Context analysis (NEW)
#     context_result = self._apply_context_analysis(
#         content, matched_values, rule_confidence, metadata
#     )
#
#     # Step 4: Combine scores (NEW)
#     final_confidence = self._combine_scores(
#         rule_confidence=rule_confidence,
#         ml_confidence=ml_result["ml_confidence"],
#         context_adjustment=context_result["adjusted_confidence"],
#         is_false_positive=context_result["is_false_positive"],
#     )
#
#     # Step 5: Determine classification level (same thresholds as before)
#     if final_confidence >= 0.8:
#         classification = "Restricted"
#     elif final_confidence >= 0.6:
#         classification = "Confidential"
#     elif final_confidence >= 0.3:
#         classification = "Internal"
#     else:
#         classification = "Public"
#
#     # Step 6: Return enriched result
#     return ClassificationResult(
#         classification=classification,
#         confidence_score=final_confidence,
#         matched_rules=rule_result.matched_rules,
#         ml_analysis=ml_result,
#         context_analysis=context_result,
#         is_false_positive=context_result["is_false_positive"],
#     )
