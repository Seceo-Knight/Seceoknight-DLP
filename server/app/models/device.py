"""
Device Database Model (PostgreSQL)
Represents physical/virtual devices monitored by DLP agents
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Device(Base):
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    os = Column(String(100), nullable=False)
    agent_version = Column(String(50), nullable=True)
    status = Column(String(30), nullable=False, default="inactive")

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    user = relationship("User", backref="devices", foreign_keys=[user_id])

    def __repr__(self):
        return f"<Device {self.hostname}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "hostname": self.hostname,
            "user_id": str(self.user_id) if self.user_id else None,
            "os": self.os,
            "agent_version": self.agent_version,
            "status": self.status,
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
