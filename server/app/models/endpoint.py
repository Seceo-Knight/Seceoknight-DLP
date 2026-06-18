"""
Endpoint Database Model (PostgreSQL)
Consolidates physical/virtual device + DLP agent into a single entity
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(INET, nullable=True)
    os = Column(String(100), nullable=False)
    agent_version = Column(String(50), nullable=True)
    status = Column(String(20), nullable=False, default="offline")
    last_seen = Column(DateTime(timezone=True), nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    user = relationship("User", backref="endpoints", foreign_keys=[user_id])

    __table_args__ = (
        Index("idx_endpoints_status_last_seen", "status", "last_seen"),
    )

    def __repr__(self):
        return f"<Endpoint {self.hostname}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "hostname": self.hostname,
            "ip_address": str(self.ip_address) if self.ip_address else None,
            "os": self.os,
            "agent_version": self.agent_version,
            "status": self.status,
            "last_seen": format_iso(self.last_seen),
            "user_id": str(self.user_id) if self.user_id else None,
            "created_at": format_iso(self.created_at),
        }
