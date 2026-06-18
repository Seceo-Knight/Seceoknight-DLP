"""
Agent Database Model (PostgreSQL)
Represents DLP agents deployed on endpoints
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID, INET
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String(64), unique=True, nullable=False, index=True)
    # Short, human-readable numeric ID. Sequence-assigned by the DB
    # (see migration 018); never set by application code. The UI zero-pads
    # this for display ("001", "012"); we keep it as a plain INTEGER so
    # it sorts naturally and width is a presentation concern.
    agent_code = Column(Integer, unique=True, nullable=True, index=True)
    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    os = Column(String(50), nullable=False)
    os_version = Column(String(100), nullable=True)
    ip_address = Column(INET, nullable=False)
    version = Column(String(50), nullable=False, default="1.0.0")
    status = Column(String(20), nullable=False, default="offline")

    # Agent configuration
    config = Column(JSON, nullable=True)

    # Monitoring capabilities
    capabilities = Column(JSON, nullable=True)

    # Statistics
    total_events = Column(Integer, default=0, nullable=False)
    total_violations = Column(Integer, default=0, nullable=False)

    # Heartbeat and health
    last_seen = Column(DateTime(timezone=True), nullable=True)
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)
    health_status = Column(JSON, nullable=True)

    # Soft delete
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    # Metadata
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    registered_by = Column(UUID(as_uuid=True), nullable=True)

    def __repr__(self):
        return f"<Agent {self.agent_id} - {self.name}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "agent_id": self.agent_id,
            "agent_code": self.agent_code,
            "name": self.name,
            "hostname": self.hostname,
            "os": self.os,
            "os_version": self.os_version,
            "ip_address": str(self.ip_address),
            "version": self.version,
            "status": self.status,
            "config": self.config,
            "capabilities": self.capabilities,
            "total_events": self.total_events,
            "total_violations": self.total_violations,
            "last_seen": format_iso(self.last_seen),
            "last_heartbeat": format_iso(self.last_heartbeat),
            "health_status": self.health_status,
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
