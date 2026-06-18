"""
Incident Database Model (PostgreSQL)
Represents security incidents escalated from DLP events
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Index, CheckConstraint, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # FK now points to the UUID primary key of events (was incorrectly referencing events.event_id)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True)
    # 0=info, 1=low, 2=medium, 3=high, 4=critical — matches IncidentCreate pydantic.
    severity = Column(Integer, nullable=False, default=1, server_default="1")

    # ABAC columns (Phase 3 prep). Nullable today — the effective ABAC rule
    # still joins to ``events.department``. When Phase 3 starts populating
    # these at incident creation, non-admin visibility can become per-row
    # without the join. DO NOT reference these in ABAC filters yet.
    department = Column(String(255), nullable=True, index=True)
    required_clearance = Column(Integer, nullable=True)
    status = Column(String(30), nullable=False, default="open", index=True)  # open, investigating, resolved
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    title = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True, index=True)

    # Soft delete
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    event = relationship("Event", backref="incidents", foreign_keys=[event_id])
    assignee = relationship("User", backref="assigned_incidents", foreign_keys=[assigned_to])
    policy = relationship("Policy", backref="incidents", foreign_keys=[policy_id])

    __table_args__ = (
        CheckConstraint("severity BETWEEN 0 AND 4", name="ck_incident_severity"),
        Index("idx_incidents_severity_status", "severity", "status"),
    )

    def __repr__(self):
        return f"<Incident {self.id} - {self.severity}/{self.status}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "event_id": str(self.event_id) if self.event_id else None,
            "severity": self.severity,
            "status": self.status,
            "assigned_to": str(self.assigned_to) if self.assigned_to else None,
            "title": self.title,
            "description": self.description,
            "policy_id": str(self.policy_id) if self.policy_id else None,
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
