"""
Tests for app.services.compliance_report_service.ComplianceReportService —
the GDPR Article 30 / HIPAA Breach Notification / PCI DSS Scope report data
fetchers wired into the reports API (report_type: gdpr_art30, hipaa_breach,
pci_scope) alongside the existing summary/trends/violators report types.

These reports assemble real platform data (policies, events, incidents,
agents, retention config, classification labels) but deliberately do NOT
fabricate values the schema has no way to know (controller identity,
recipients, cross-border transfers, legal risk-of-harm conclusions). The
tests below cover both halves: that real data is surfaced correctly, and
that the fields the platform genuinely can't answer come back explicitly
flagged rather than silently blank or guessed.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.services.compliance_report_service import ComplianceReportService
from app.models.policy import Policy
from app.models.data_label import DataLabel
from app.models.event import Event
from app.models.incident import Incident
from app.models.agent import Agent
from app.models.policy_agent import PolicyAgent
from app.models.classified_file import ClassifiedFile
from app.models.retention_config import RetentionConfig, MIN_RETENTION_DAYS


def _window():
    now = datetime.now(timezone.utc)
    return now - timedelta(days=1), now + timedelta(days=1)


def _make_policy(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        name=f"policy-{uuid.uuid4().hex[:8]}",
        description="test policy",
        status="active",
        conditions={"match": "all", "rules": []},
        actions={"alert": {"severity": "high"}},
        created_by=uuid.uuid4(),
    )
    defaults.update(overrides)
    return Policy(**defaults)


def _make_agent(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        agent_id=f"agent-{uuid.uuid4().hex[:8]}",
        name="Test Endpoint",
        hostname="test-host",
        os="Windows",
        ip_address="10.0.0.5",
    )
    defaults.update(overrides)
    return Agent(**defaults)


def _make_event(**overrides):
    now = datetime.now(timezone.utc)
    defaults = dict(
        id=uuid.uuid4(),
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        event_type="file",
        source_type="agent",
        description="test event",
        severity="high",
        action="logged",
        department="ENGINEERING",
        timestamp=now,
    )
    defaults.update(overrides)
    return Event(**defaults)


def _make_incident(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        severity=3,
        status="open",
        title="Test incident",
    )
    defaults.update(overrides)
    return Incident(**defaults)


# ── GDPR Article 30 ──────────────────────────────────────────────────────────

class TestGdprArticle30:
    @pytest.mark.asyncio
    async def test_empty_state_flags_manual_fields_not_fabricated(self, db_session):
        service = ComplianceReportService(db_session)
        start, end = _window()

        result = await service.get_gdpr_article_30_data(start, end)

        assert result["processing_activities"] == []
        assert result["data_categories"] == []
        # The platform has no controller/recipient/transfer data model —
        # these must come back None and explicitly flagged, never guessed.
        manual = result["manual_fields"]
        assert manual["manual_review_required"] is True
        assert manual["controller_name"] is None
        assert manual["controller_contact"] is None
        assert manual["categories_of_recipients"] is None
        assert manual["third_country_transfers"] is None
        assert "DPO" in manual["note"] or "Protection Officer" in manual["note"]
        # No retention_config row → configured False, not a fabricated number
        assert result["retention"]["configured"] is False

    @pytest.mark.asyncio
    async def test_real_data_is_surfaced_correctly(self, db_session):
        policy = _make_policy(name="GDPR PII Policy", compliance_tags=["gdpr", "pii"])
        label = DataLabel(id=uuid.uuid4(), name="EMAIL_ADDRESS", severity="medium", description="Email PII")
        event = _make_event(department="SALES")
        retention = RetentionConfig(id=1, event_retention_days=365, opensearch_retention_days=180)

        db_session.add_all([policy, label, event, retention])
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_gdpr_article_30_data(start, end)

        assert any(a["activity_name"] == "GDPR PII Policy" for a in result["processing_activities"])
        assert any(a["activity_name"] == "GDPR PII Policy" for a in result["gdpr_tagged_activities"])
        assert any(c["name"] == "EMAIL_ADDRESS" for c in result["data_categories"])
        assert any(s["department"] == "SALES" for s in result["data_subject_categories"])
        assert result["retention"]["event_retention_days"] == 365
        assert result["retention"]["opensearch_retention_days"] == 180
        assert result["retention"]["compliance_floor_days"] == MIN_RETENTION_DAYS
        # Real security-control description, not a marketing claim —
        # the known plaintext-PII gap must be listed, not hidden.
        assert any("plaintext" in g.lower() for g in result["security_measures"]["known_gaps"])

    @pytest.mark.asyncio
    async def test_non_gdpr_policy_excluded_from_tagged_list(self, db_session):
        policy = _make_policy(name="Unrelated Policy", compliance_tags=["internal-only"])
        db_session.add(policy)
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_gdpr_article_30_data(start, end)

        assert any(a["activity_name"] == "Unrelated Policy" for a in result["processing_activities"])
        assert not any(a["activity_name"] == "Unrelated Policy" for a in result["gdpr_tagged_activities"])


# ── HIPAA Breach Notification ────────────────────────────────────────────────

class TestHipaaBreachNotification:
    @pytest.mark.asyncio
    async def test_empty_state_flags_manual_fields_not_fabricated(self, db_session):
        service = ComplianceReportService(db_session)
        start, end = _window()

        result = await service.get_hipaa_breach_notification_data(start, end)

        assert result["candidates"] == []
        assert result["summary_counts"]["total_candidates"] == 0
        notif = result["notification_fields"]
        assert notif["manual_review_required"] is True
        assert notif["risk_of_harm_assessment_conclusion"] is None
        assert notif["hhs_notified_date"] is None
        assert "164.402" in notif["note"]

    @pytest.mark.asyncio
    async def test_phi_labeled_incident_surfaces_as_candidate(self, db_session):
        label = DataLabel(id=uuid.uuid4(), name="PHI_MEDICAL_RECORD", severity="critical")
        event = _make_event(action="allowed", classification_label=label.id, department="CLINICAL")
        incident = _make_incident(event_id=event.id, severity=4)

        db_session.add_all([label, event, incident])
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_hipaa_breach_notification_data(start, end)

        assert result["summary_counts"]["total_candidates"] == 1
        candidate = result["candidates"][0]
        assert candidate["matched_keyword"] == "phi"
        # action="allowed" → the data actually went through, not blocked
        assert candidate["exposure_likely"] is True
        assert result["summary_counts"]["likely_exposure"] == 1
        assert result["summary_counts"]["prevented_by_policy"] == 0

    @pytest.mark.asyncio
    async def test_blocked_action_marks_prevented_not_exposed(self, db_session):
        label = DataLabel(id=uuid.uuid4(), name="PATIENT_DIAGNOSIS", severity="critical")
        event = _make_event(action="blocked", classification_label=label.id)
        incident = _make_incident(event_id=event.id)

        db_session.add_all([label, event, incident])
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_hipaa_breach_notification_data(start, end)

        candidate = result["candidates"][0]
        assert candidate["exposure_likely"] is False
        assert result["summary_counts"]["prevented_by_policy"] == 1
        assert result["summary_counts"]["likely_exposure"] == 0

    @pytest.mark.asyncio
    async def test_non_phi_incident_excluded(self, db_session):
        label = DataLabel(id=uuid.uuid4(), name="INTERNAL_MEMO", severity="low")
        event = _make_event(action="allowed", classification_label=label.id)
        incident = _make_incident(event_id=event.id)

        db_session.add_all([label, event, incident])
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_hipaa_breach_notification_data(start, end)

        assert result["candidates"] == []


# ── PCI DSS Scope ─────────────────────────────────────────────────────────────

class TestPciDssScope:
    @pytest.mark.asyncio
    async def test_empty_state_includes_caveat_and_zero_counts(self, db_session):
        service = ComplianceReportService(db_session)
        start, end = _window()

        result = await service.get_pci_dss_scope_data(start, end)

        assert result["pci_policies"] == []
        assert result["in_scope_agents"] == []
        assert result["counts"]["pci_policies"] == 0
        # The scope caveat is mandatory — this report is not a certified
        # CDE determination and must say so every time.
        assert "not a certified" in result["scope_caveat"].lower()
        assert "QSA" in result["scope_caveat"]

    @pytest.mark.asyncio
    async def test_pci_tagged_policy_and_linked_agent_are_in_scope(self, db_session):
        policy = _make_policy(name="Cardholder Data Policy", compliance_tags=["pci-dss"])
        agent = _make_agent(name="POS-Terminal-01")

        db_session.add_all([policy, agent])
        await db_session.commit()

        link = PolicyAgent(id=uuid.uuid4(), policy_id=policy.id, agent_id=agent.agent_id)
        db_session.add(link)
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_pci_dss_scope_data(start, end)

        assert any(p["policy_name"] == "Cardholder Data Policy" for p in result["pci_policies"])
        assert any(a["name"] == "POS-Terminal-01" for a in result["in_scope_agents"])
        assert result["counts"]["in_scope_agents"] == 1

    @pytest.mark.asyncio
    async def test_credit_card_event_detected_in_period(self, db_session):
        label = DataLabel(id=uuid.uuid4(), name="CREDIT_CARD_NUMBER", severity="critical")
        event = _make_event(action="blocked", classification_label=label.id, file_name="statement.csv")

        db_session.add_all([label, event])
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_pci_dss_scope_data(start, end)

        assert result["counts"]["pci_events_in_period"] == 1
        assert result["pci_events"][0]["detected_label"] == "CREDIT_CARD_NUMBER"

    @pytest.mark.asyncio
    async def test_classified_file_with_pci_tag_is_flagged(self, db_session):
        cf = ClassifiedFile(
            id=uuid.uuid4(),
            file_id=f"file-{uuid.uuid4().hex[:8]}",
            file_name="cardholders.xlsx",
            file_path="/data/finance/cardholders.xlsx",
            file_size=2048,
            file_hash="a" * 64,
            source_type="agent",
            classification="restricted",
            classification_labels=["PCI-DSS", "CREDIT_CARD"],
        )
        db_session.add(cf)
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_pci_dss_scope_data(start, end)

        assert result["counts"]["flagged_files"] == 1
        assert result["flagged_files"][0]["file_name"] == "cardholders.xlsx"

    @pytest.mark.asyncio
    async def test_non_pci_policy_and_file_excluded(self, db_session):
        policy = _make_policy(name="HR Onboarding Policy", compliance_tags=["internal"])
        cf = ClassifiedFile(
            id=uuid.uuid4(),
            file_id=f"file-{uuid.uuid4().hex[:8]}",
            file_name="handbook.pdf",
            file_path="/hr/handbook.pdf",
            file_size=1024,
            file_hash="b" * 64,
            source_type="agent",
            classification="internal",
            classification_labels=["HR", "GENERAL"],
        )
        db_session.add_all([policy, cf])
        await db_session.commit()

        service = ComplianceReportService(db_session)
        start, end = _window()
        result = await service.get_pci_dss_scope_data(start, end)

        assert result["pci_policies"] == []
        assert result["flagged_files"] == []
