"""
User Database Models (PostgreSQL)
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
import enum

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    MANAGER = "MANAGER"
    VIEWER = "VIEWER"
    AGENT = "AGENT"
    # Domain-scoped admins (granular RBAC). Each is scoped to one policy
    # domain; see app.core.domains.
    THREAT_ADMIN = "THREAT_ADMIN"
    DATA_PROTECTION_ADMIN = "DATA_PROTECTION_ADMIN"
    ACCESS_CONTROL_ADMIN = "ACCESS_CONTROL_ADMIN"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(150), unique=True, nullable=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True, index=True)
    department = Column(String(255), nullable=True)
    clearance_level = Column(Integer, nullable=False, default=1, server_default="1")
    organization = Column(String(255), nullable=False)

    # Relationships
    role_ref = relationship("Role", backref="users", foreign_keys=[role_id])
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    must_change_password = Column(Boolean, default=False, nullable=False, server_default="false")

    # MFA / TOTP
    mfa_enabled = Column(Boolean, default=False, nullable=False, server_default="false")
    mfa_secret = Column(String(255), nullable=True)  # Fernet-encrypted TOTP secret

    # Soft delete
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    last_login = Column(DateTime(timezone=True), nullable=True)

    # ── SSO/SIEM provenance (app/core/sso_roles.py) ──────────────────────
    # Ported from CyberSentinel-DLP, gap-scan of August 26 2026.
    # sso_managed marks an account as owned by the SIEM sync: role,
    # department and clearance are re-applied from the exchange token on
    # every login (SSO_SYNC_ON_LOGIN). An admin editing such a user's role
    # by hand through the normal admin UI detaches it (sso_managed=false)
    # rather than having the edit silently revert at the user's next login.
    # sso_source_role records the last SIEM role:access pair seen (e.g.
    # "L3:ro"), purely for tracing — an unexpected DLP role can be traced
    # back to what the SIEM actually sent.
    sso_managed = Column(Boolean, default=False, nullable=False, server_default="false")
    sso_source_role = Column(String(64), nullable=True)
    # siem_sub is the SIEM's own immutable user id (the exchange token's
    # `sub` claim), and is the key an SSO login is matched on in preference
    # to email. Email is a display attribute that people change: keyed on
    # email alone, a rename orphans the account and the next login silently
    # provisions a SECOND one, leaving the original's history attached to
    # nobody. Nullable because locally-created accounts have no SIEM
    # identity, and backfilled on the first login that presents a sub.
    siem_sub = Column(String(255), unique=True, nullable=True, index=True)

    def __repr__(self):
        return f"<User {self.email}>"
