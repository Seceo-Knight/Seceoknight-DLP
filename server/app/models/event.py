"""
Event Database Model (PostgreSQL)
Represents DLP events detected by agents or collectors
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Integer, Float, Text, JSON, Index, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(String(64), unique=True, nullable=False, index=True)

    # Event classification
    event_type = Column(String(50), nullable=False, index=True)  # file, clipboard, usb, network, cloud
    event_subtype = Column(String(50), nullable=True)  # file_copy, file_delete, clipboard_copy, etc.

    # Source information
    agent_id = Column(String(64), nullable=True, index=True)
    endpoint_id = Column(UUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    source_type = Column(String(50), nullable=False)  # agent, collector, connector
    source_id = Column(String(64), nullable=True)

    # User information
    user_email = Column(String(255), nullable=True, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    username = Column(String(255), nullable=True)

    # Event details
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    action = Column(String(50), nullable=False)  # allowed, blocked, alerted, quarantined, logged

    # File/data information
    file_path = Column(Text, nullable=True)
    file_name = Column(Text, nullable=True)
    file_size = Column(Integer, nullable=True)
    file_hash = Column(String(64), nullable=True)

    # Classification results
    classification = Column(JSON, nullable=True)
    classification_label = Column(UUID(as_uuid=True), ForeignKey("data_labels.id", ondelete="SET NULL"), nullable=True, index=True)
    # Denormalized tier for filter-driven dashboards (Public/Internal/
    # Confidential/Restricted). Populated at ingest time; retained even if
    # the source event's classification payload changes later.
    classification_level = Column(String(50), nullable=True, index=True)
    confidence_score = Column(Float, nullable=True)

    # Policy information
    policy_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    policy_name = Column(Text, nullable=True)
    policy_violated = Column(Text, nullable=True)

    # Channel and decision
    channel = Column(String(50), nullable=True)
    decision = Column(String(30), nullable=True)

    # Destination information
    destination = Column(Text, nullable=True)
    destination_details = Column(JSON, nullable=True)

    # Relationships
    endpoint = relationship("Endpoint", backref="events", foreign_keys=[endpoint_id])
    label = relationship("DataLabel", backref="events", foreign_keys=[classification_label])

    # Network information (for network events)
    source_ip = Column(INET, nullable=True)
    destination_ip = Column(INET, nullable=True)
    protocol = Column(String(20), nullable=True)

    # Additional metadata
    details = Column(JSON, nullable=True)
    tags = Column(JSON, nullable=True)

    # ABAC attributes (Phase 2). Frozen at ingest time — see abac_service.
    # `department` mirrors the user's department at the moment the event
    # was recorded. `required_clearance` defaults to 0 (non-sensitive) and
    # can be lifted by policy enrichment later.
    department = Column(
        String(255), nullable=False, default="DEFAULT", server_default="DEFAULT", index=True
    )
    required_clearance = Column(
        Integer, nullable=False, default=0, server_default="0"
    )

    # Status and processing
    status = Column(String(20), nullable=False, default="new")
    reviewed = Column(String(20), nullable=False, default="no")
    reviewed_by = Column(UUID(as_uuid=True), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    timestamp = Column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Indexes for common queries
    __table_args__ = (
        CheckConstraint("severity IN ('low', 'medium', 'high', 'critical', 'info')", name="ck_event_severity"),
        Index('idx_event_severity_timestamp', 'severity', 'timestamp'),
        Index('idx_event_user_timestamp', 'user_email', 'timestamp'),
        Index('idx_event_type_timestamp', 'event_type', 'timestamp'),
        Index('idx_event_agent_timestamp', 'agent_id', 'timestamp'),
        Index('idx_event_status_timestamp', 'status', 'timestamp'),
    )

    def __repr__(self):
        return f"<Event {self.event_id} - {self.event_type}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "event_id": self.event_id,
            "event_type": self.event_type,
            "event_subtype": self.event_subtype,
            "agent_id": self.agent_id,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "user_email": self.user_email,
            "user_id": str(self.user_id) if self.user_id else None,
            "username": self.username,
            "description": self.description,
            "severity": self.severity,
            "action": self.action,
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "classification": self.classification,
            "classification_level": self.classification_level,
            "confidence_score": self.confidence_score,
            "policy_id": str(self.policy_id) if self.policy_id else None,
            "policy_name": self.policy_name,
            "policy_violated": self.policy_violated,
            "destination": self.destination,
            "destination_details": self.destination_details,
            "source_ip": str(self.source_ip) if self.source_ip else None,
            "destination_ip": str(self.destination_ip) if self.destination_ip else None,
            "protocol": self.protocol,
            "details": self.details,
            "tags": self.tags,
            "department": self.department,
            "required_clearance": self.required_clearance,
            "status": self.status,
            "reviewed": self.reviewed,
            "reviewed_by": str(self.reviewed_by) if self.reviewed_by else None,
            "reviewed_at": format_iso(self.reviewed_at),
            "timestamp": format_iso(self.timestamp),
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
