"""
Compliance Report Data Service

Builds the data payloads for three regulator-facing report types:
  - GDPR Article 30  — Records of Processing Activities (ROPA)
  - HIPAA Breach Notification — candidate-breach summary (45 CFR 164.400-414)
  - PCI DSS Scope — DLP-visible Cardholder Data Environment scope

Honesty note (read before extending this file): these reports assemble
everything the platform actually KNOWS from its own data (policies,
events, incidents, agents, retention config, classification labels).
They deliberately do NOT fabricate values the schema has no way to know
— data controller identity, cross-border transfer mechanisms, legal
risk-of-harm conclusions, formal CDE network boundaries. Those fields
are returned with "manual_review_required": True and a null/placeholder
value, and the PDF renders them in a visually distinct "requires manual
completion" block rather than presenting invented facts as fact. A
compliance report that guesses is worse than no report at all.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime

from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Policy, DataLabel, Event, Incident, Agent, PolicyAgent, ClassifiedFile
from app.models.retention_config import RetentionConfig, MIN_RETENTION_DAYS
from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)

# Best-effort keyword filters used to spot regulated-category signal in
# free-text/JSON fields (DataLabel.name, Event.classification_level,
# ClassifiedFile.classification_labels, Policy.compliance_tags). The
# platform has no first-class "this is PHI" / "this is cardholder data"
# flag, so this is a keyword match, not a certified legal determination
# — every report section built from these lists says so explicitly.
_HIPAA_KEYWORDS = ["hipaa", "phi", "health", "medical", "patient", "diagnosis", "prescription", "mrn"]
_PCI_KEYWORDS = ["pci", "credit_card", "credit card", "card_number", "cardholder", "cvv", "pan", "creditcard"]
_GDPR_TAG_KEYWORDS = ["gdpr"]


def _severity_label(sev: int) -> str:
    return {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(sev, "unknown")


def _matches_any(value: Optional[str], keywords: List[str]) -> Optional[str]:
    """Return the first keyword found in value (case-insensitive), else None."""
    if not value:
        return None
    low = str(value).lower()
    for kw in keywords:
        if kw in low:
            return kw
    return None


def _tags_match_any(tags: Optional[list], keywords: List[str]) -> Optional[str]:
    if not tags:
        return None
    for tag in tags:
        hit = _matches_any(str(tag), keywords)
        if hit:
            return hit
    return None


class ComplianceReportService:
    """Assembles data for the GDPR / HIPAA / PCI compliance report types."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ── GDPR Article 30 — Records of Processing Activities ─────────────────

    async def get_gdpr_article_30_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Art. 30(1) requires, per processing activity: controller identity,
        purposes, categories of data subjects/personal data, recipients,
        third-country transfers, retention periods, and a general
        description of technical/organisational security measures.

        We can genuinely derive: processing activities (active policies),
        categories of personal data (DataLabel table), retention periods
        (RetentionConfig), and an accurate description of the platform's
        real security controls. We CANNOT derive controller identity,
        recipients, or third-country transfers from this schema — those
        come back flagged for manual completion.
        """
        try:
            # Active/draft policies stand in for "processing activities" —
            # each policy defines a purpose (its description/type) and the
            # data categories it acts on.
            policy_result = await self.db.execute(
                select(Policy).where(Policy.deleted_at.is_(None)).order_by(Policy.name)
            )
            policies = policy_result.scalars().all()

            processing_activities = [
                {
                    "activity_name": p.name,
                    "purpose": p.description or f"{(p.type or 'general').replace('_', ' ').title()} policy",
                    "policy_type": p.type,
                    "status": p.status,
                    "severity": p.severity,
                    "compliance_tags": p.compliance_tags or [],
                    "created_at": p.created_at.isoformat() if p.created_at else None,
                }
                for p in policies
            ]

            gdpr_tagged = [
                p for p in processing_activities
                if _tags_match_any(p["compliance_tags"], _GDPR_TAG_KEYWORDS)
            ]

            # Categories of personal data processed
            label_result = await self.db.execute(select(DataLabel).order_by(DataLabel.name))
            data_categories = [
                {"name": l.name, "severity": l.severity, "description": l.description}
                for l in label_result.scalars().all()
            ]

            # Categories of data subjects — best-effort via distinct
            # departments seen on events in the period (a real, queryable
            # signal; not a substitute for a formal data-subject register).
            dept_result = await self.db.execute(
                select(Event.department, func.count(Event.id))
                .where(and_(Event.timestamp >= start_date, Event.timestamp <= end_date))
                .group_by(Event.department)
                .order_by(func.count(Event.id).desc())
            )
            data_subject_categories = [
                {"department": row[0] or "UNKNOWN", "event_count": row[1]}
                for row in dept_result.all()
            ]

            # Retention — the one Art. 30(1)(f) field we have real data for
            retention_result = await self.db.execute(select(RetentionConfig).where(RetentionConfig.id == 1))
            retention_row = retention_result.scalar_one_or_none()
            retention = {
                "event_retention_days": retention_row.event_retention_days if retention_row else None,
                "opensearch_retention_days": retention_row.opensearch_retention_days if retention_row else None,
                "compliance_floor_days": MIN_RETENTION_DAYS,
                "configured": retention_row is not None,
            }

            # Security measures — an accurate description of what's real,
            # including the known gap (plaintext PII at the app level per
            # the platform's own enterprise audit). Overstating controls
            # in a GDPR Art. 32 description is a compliance liability, not
            # a feature — so the gap is listed alongside the real controls.
            security_measures = {
                "implemented": [
                    "TLS in transit for all portal/API/agent traffic (Nginx-terminated, Let's Encrypt)",
                    "Role-based access control (RBAC) with domain-scoped admin roles",
                    "Attribute-based access control (ABAC) on department + clearance level",
                    "Multi-factor authentication (TOTP) available for all user accounts",
                    "bcrypt password hashing; JWT access/refresh tokens with Redis-backed revocation",
                    "IP allowlisting for portal access",
                    "Structured audit logging of authentication and privilege-sensitive actions",
                    "SHA-256 file fingerprinting for known-sensitive-document detection",
                ],
                "known_gaps": [
                    "No database-level encryption at rest — PII in PostgreSQL and event content in "
                    "MongoDB is stored in plaintext at the application level.",
                    "No enterprise SSO/SAML/LDAP identity federation — users are local-database-only.",
                    "JWT signing uses HS256 (shared secret) rather than RS256 (asymmetric).",
                ],
                "source": "Derived from ENTERPRISE_AUDIT.md as of the report generation date — "
                           "re-verify against the current audit before submitting this report.",
            }

            # Fields the schema genuinely cannot answer
            manual_fields = {
                "controller_name": None,
                "controller_contact": None,
                "dpo_name": None,
                "dpo_contact": None,
                "categories_of_recipients": None,
                "third_country_transfers": None,
                "manual_review_required": True,
                "note": (
                    "The platform has no data model for controller identity, third-party "
                    "recipients, or cross-border transfer mechanisms (SCCs, adequacy "
                    "decisions, BCRs). These sections must be completed by the Data "
                    "Protection Officer before this document is submitted or filed."
                ),
            }

            return {
                "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
                "processing_activities": processing_activities,
                "gdpr_tagged_activities": gdpr_tagged,
                "data_categories": data_categories,
                "data_subject_categories": data_subject_categories,
                "retention": retention,
                "security_measures": security_measures,
                "manual_fields": manual_fields,
                "counts": {
                    "total_processing_activities": len(processing_activities),
                    "gdpr_tagged_activities": len(gdpr_tagged),
                    "data_categories": len(data_categories),
                },
                "generated_at": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.log_error(e, {"operation": "get_gdpr_article_30_data"})
            raise

    # ── HIPAA Breach Notification ───────────────────────────────────────────

    async def get_hipaa_breach_notification_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        45 CFR 164.404(c) requires a notification describing what happened,
        the types of unsecured PHI involved, mitigation steps taken, and
        contact information. This report surfaces CANDIDATE breach-relevant
        incidents (keyword-matched against PHI-indicating classification
        labels) for a privacy officer to review — it does not itself decide
        whether an event meets the legal definition of a reportable breach
        under 164.402, which requires a risk-of-harm assessment this system
        has no basis to perform.
        """
        try:
            query = (
                select(Incident, Event, DataLabel)
                .join(Event, Incident.event_id == Event.id, isouter=True)
                .join(DataLabel, Event.classification_label == DataLabel.id, isouter=True)
                .where(
                    and_(
                        Incident.created_at >= start_date,
                        Incident.created_at <= end_date,
                        Incident.deleted_at.is_(None),
                    )
                )
                .order_by(Incident.created_at.desc())
            )
            result = await self.db.execute(query)
            rows = result.all()

            candidates = []
            for incident, event, label in rows:
                hit = (
                    _matches_any(label.name if label else None, _HIPAA_KEYWORDS)
                    or _matches_any(event.classification_level if event else None, _HIPAA_KEYWORDS)
                    or _matches_any(incident.title, _HIPAA_KEYWORDS)
                    or _matches_any(incident.description, _HIPAA_KEYWORDS)
                )
                if not hit:
                    continue

                action = (event.action if event else None) or "unknown"
                # blocked/quarantined means the DLP prevented the data from
                # leaving — genuinely lower exposure risk than
                # allowed/logged, which means it went through.
                exposure_likely = action in ("allowed", "logged")

                candidates.append({
                    "incident_id": str(incident.id),
                    "incident_created_at": incident.created_at.isoformat() if incident.created_at else None,
                    "severity": _severity_label(incident.severity),
                    "status": incident.status,
                    "title": incident.title,
                    "matched_keyword": hit,
                    "action_taken": action,
                    "exposure_likely": exposure_likely,
                    "event_timestamp": event.timestamp.isoformat() if event and event.timestamp else None,
                    "file_name": event.file_name if event else None,
                    "file_path": event.file_path if event else None,
                    "department": event.department if event else None,
                    "user_email": event.user_email if event else None,
                    "username": event.username if event else None,
                    "agent_id": event.agent_id if event else None,
                    "classification_level": event.classification_level if event else None,
                    "detected_label": label.name if label else None,
                    "confidence_score": round(float(event.confidence_score) * 100, 1)
                        if event and event.confidence_score is not None else None,
                })

            likely_exposure = sum(1 for c in candidates if c["exposure_likely"])
            prevented = len(candidates) - likely_exposure

            notification_fields = {
                "risk_of_harm_assessment_conclusion": None,
                "individuals_notified_date": None,
                "hhs_notified_date": None,
                "media_notice_issued": None,  # required if breach affects 500+ residents of a state/jurisdiction
                "credit_monitoring_offered": None,
                "manual_review_required": True,
                "note": (
                    "This system flags candidate PHI-related events by keyword-matching "
                    "classification labels — it does NOT perform the risk-of-harm "
                    "assessment required by 45 CFR 164.402 to determine whether an event "
                    "legally qualifies as a reportable breach. A privacy/compliance "
                    "officer must review every candidate below before any notification "
                    "obligation is triggered or notice is issued."
                ),
            }

            return {
                "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
                "candidates": candidates,
                "summary_counts": {
                    "total_candidates": len(candidates),
                    "likely_exposure": likely_exposure,
                    "prevented_by_policy": prevented,
                },
                "notification_fields": notification_fields,
                "generated_at": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.log_error(e, {"operation": "get_hipaa_breach_notification_data"})
            raise

    # ── PCI DSS Scope ────────────────────────────────────────────────────

    async def get_pci_dss_scope_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Builds a DLP-visibility view of the Cardholder Data Environment:
        policies tagged for PCI-DSS, the endpoints those policies are
        applied to, and actual cardholder-data-pattern detections in the
        period. This is NOT a certified PCI DSS scope determination —
        network segmentation and any payment infrastructure without an
        installed agent are invisible to this system, and only a QSA /
        internal security team can validate the true CDE boundary.
        """
        try:
            policy_result = await self.db.execute(
                select(Policy).where(Policy.deleted_at.is_(None)).order_by(Policy.name)
            )
            all_policies = policy_result.scalars().all()

            pci_policies = [
                p for p in all_policies
                if _tags_match_any(p.compliance_tags, _PCI_KEYWORDS)
                or _matches_any(p.name, _PCI_KEYWORDS)
                or _matches_any(p.description, _PCI_KEYWORDS)
            ]
            pci_policy_ids = [p.id for p in pci_policies]

            pci_policies_out = [
                {
                    "policy_name": p.name,
                    "status": p.status,
                    "severity": p.severity,
                    "compliance_tags": p.compliance_tags or [],
                    "description": p.description,
                }
                for p in pci_policies
            ]

            # Agents those PCI policies are actually applied to
            in_scope_agent_ids: set = set()
            if pci_policy_ids:
                pa_result = await self.db.execute(
                    select(PolicyAgent.agent_id).where(PolicyAgent.policy_id.in_(pci_policy_ids))
                )
                in_scope_agent_ids = {row[0] for row in pa_result.all()}

            in_scope_agents = []
            if in_scope_agent_ids:
                agent_result = await self.db.execute(
                    select(Agent).where(Agent.agent_id.in_(in_scope_agent_ids))
                )
                for a in agent_result.scalars().all():
                    in_scope_agents.append({
                        "agent_id": a.agent_id,
                        "agent_code": a.agent_code,
                        "name": a.name,
                        "hostname": a.hostname,
                        "os": a.os,
                        "os_version": a.os_version,
                        "ip_address": str(a.ip_address) if a.ip_address else None,
                        "status": a.status,
                        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                    })

            # Real cardholder-data-pattern detections in the period
            event_query = (
                select(Event, DataLabel)
                .join(DataLabel, Event.classification_label == DataLabel.id, isouter=True)
                .where(and_(Event.timestamp >= start_date, Event.timestamp <= end_date))
                .order_by(Event.timestamp.desc())
            )
            event_result = await self.db.execute(event_query)
            pci_events = []
            for event, label in event_result.all():
                hit = (
                    _matches_any(label.name if label else None, _PCI_KEYWORDS)
                    or _matches_any(event.classification_level, _PCI_KEYWORDS)
                )
                if not hit:
                    continue
                pci_events.append({
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "agent_id": event.agent_id,
                    "file_name": event.file_name,
                    "classification_level": event.classification_level,
                    "detected_label": label.name if label else None,
                    "action": event.action,
                    "confidence_score": round(float(event.confidence_score) * 100, 1)
                        if event.confidence_score is not None else None,
                })
            truncated = len(pci_events) > 200
            pci_events = pci_events[:200]

            # Classified files flagged with a PCI-like label (any period —
            # file classification isn't timestamped to the report window
            # the way events are, so this is a current-state inventory)
            cf_result = await self.db.execute(
                select(ClassifiedFile).order_by(ClassifiedFile.created_at.desc()).limit(500)
            )
            flagged_files = []
            for f in cf_result.scalars().all():
                hit = _tags_match_any(f.classification_labels, _PCI_KEYWORDS)
                if not hit:
                    continue
                flagged_files.append({
                    "file_name": f.file_name,
                    "file_path": f.file_path,
                    "classification": f.classification,
                    "classification_labels": f.classification_labels,
                    "sensitive_data_count": f.sensitive_data_count,
                    "owner_email": f.owner_email,
                    "agent_id": f.agent_id,
                })

            scope_caveat = (
                "This report lists endpoints where a PCI-DSS-tagged DLP policy is "
                "actively enforced and/or where the classification engine detected "
                "cardholder-data patterns during the period. It is a DLP-visibility "
                "view of the CDE, not a certified formal PCI DSS scope determination "
                "— network segmentation, payment-processing infrastructure without an "
                "installed agent, and third-party service providers are outside what "
                "this report can see. A PCI QSA or internal security team must "
                "validate the full CDE boundary separately (PCI DSS Requirement 1 / "
                "scoping guidance)."
            )

            return {
                "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
                "pci_policies": pci_policies_out,
                "in_scope_agents": in_scope_agents,
                "pci_events": pci_events,
                "pci_events_truncated": truncated,
                "flagged_files": flagged_files,
                "scope_caveat": scope_caveat,
                "counts": {
                    "pci_policies": len(pci_policies_out),
                    "in_scope_agents": len(in_scope_agents),
                    "pci_events_in_period": len(pci_events),
                    "flagged_files": len(flagged_files),
                },
                "generated_at": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.log_error(e, {"operation": "get_pci_dss_scope_data"})
            raise
