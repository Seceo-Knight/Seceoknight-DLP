"""
Permission & RolePermission models (normalized RBAC).

Phase 1 of the RBAC/ABAC rework. The existing `roles` table retains its
`permissions` JSONB column for now; these new tables are the authoritative
source going forward, and the JSONB column is kept only until the migration
path has been validated in production.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<Permission {self.name}>"


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id = Column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id = Column(
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )

    role = relationship("Role", backref="role_permissions")
    permission = relationship("Permission", backref="role_permissions")


class UserPermission(Base):
    """Direct permission grant for a single user.

    Unioned with the user's role permissions at resolution time. Rows here
    represent *extra* permissions the admin explicitly granted on top of
    the role — they do not subtract anything the role already confers.
    """

    __tablename__ = "user_permissions"

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id = Column(
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )
