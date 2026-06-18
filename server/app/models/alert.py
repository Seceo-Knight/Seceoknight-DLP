"""
Alert Database Model (PostgreSQL)
Represents system alerts generated from events or conditions
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Text, JSON, Integer, Index, CheckConstraint, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)

    # Alert classification
    alert_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    priority = Column(Integer, nullable=False, default=100)

    # Alert content
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    message = Column(Text, nullable=True)

    # Source information
    source = Column(String(100), nullable=False)
    source_id = Column(String(64), nullable=True)

    # Related entities
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True)
    agent_id = Column(String(64), nullable=True, index=True)
    user_email = Column(String(255), nullable=True, index=True)
    policy_id = Column(UUID(as_uuid=True), nullable=True)

    # Relationships
    event = relationship("Event", backref="alerts", foreign_keys=[event_id])

    # Alert details
    details = Column(JSON, nullable=True)
    alert_metadata = Column("metadata", JSON, nullable=True)
    tags = Column(JSON, nullable=True)

    # Status and workflow
    status = Column(String(20), nullable=False, default="new", index=True)
    assigned_to = Column(UUID(as_uuid=True), nullable=True)
    assigned_at = Column(DateTime(timezone=True), nullable=True)

    # Resolution
    resolved = Column(Boolean, default=False, nullable=False)
    resolved_by = Column(UUID(as_uuid=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # Notification tracking
    notifications_sent = Column(JSON, nullable=True)
    notification_history = Column(JSON, nullable=True)

    # Escalation
    escalated = Column(Boolean, default=False, nullable=False)
    escalated_at = Column(DateTime(timezone=True), nullable=True)
    escalation_level = Column(Integer, default=0, nullable=False)

    # Timestamps
    triggered_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Indexes for common queries
    __table_args__ = (
        CheckConstraint("severity IN ('low', 'medium', 'high', 'critical', 'info')", name="ck_alert_severity"),
        Index('idx_alert_severity_status', 'severity', 'status'),
        Index('idx_alert_type_triggered', 'alert_type', 'triggered_at'),
        Index('idx_alert_user_triggered', 'user_email', 'triggered_at'),
        Index('idx_alert_resolved_triggered', 'resolved', 'triggered_at'),
    )

    def __repr__(self):
        return f"<Alert {self.alert_id} - {self.title}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "priority": self.priority,
            "title": self.title,
            "description": self.description,
            "message": self.message,
            "source": self.source,
            "source_id": self.source_id,
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "user_email": self.user_email,
            "policy_id": str(self.policy_id) if self.policy_id else None,
            "details": self.details,
            "metadata": self.alert_metadata,
            "tags": self.tags,
            "status": self.status,
            "assigned_to": str(self.assigned_to) if self.assigned_to else None,
            "assigned_at": format_iso(self.assigned_at),
            "resolved": self.resolved,
            "resolved_by": str(self.resolved_by) if self.resolved_by else None,
            "resolved_at": format_iso(self.resolved_at),
            "resolution_notes": self.resolution_notes,
            "notifications_sent": self.notifications_sent,
            "notification_history": self.notification_history,
            "escalated": self.escalated,
            "escalated_at": format_iso(self.escalated_at),
            "escalation_level": self.escalation_level,
            "triggered_at": format_iso(self.triggered_at),
            "acknowledged_at": format_iso(self.acknowledged_at),
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
