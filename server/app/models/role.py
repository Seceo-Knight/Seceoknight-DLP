"""
Role Database Model (PostgreSQL)
RBAC roles with JSONB permissions
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Role(Base):
    __tablename__ = "roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(50), unique=True, nullable=False, index=True)
    permissions = Column(JSONB, nullable=True)  # {"events.read": true, "policies.write": true, ...}

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    def __repr__(self):
        return f"<Role {self.name}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "name": self.name,
            "permissions": self.permissions,
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
