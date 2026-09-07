"""
Policy Database Models (PostgreSQL)
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, JSON, Text, CheckConstraint, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.hybrid import hybrid_property
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Policy(Base):
    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # NOTE: uniqueness on `name` is enforced at the DB level by a partial
    # unique index (ix_policies_name_active, WHERE deleted_at IS NULL --
    # see alembic 043_policy_name_unique_active_only) rather than a plain
    # column-level UNIQUE constraint. Policies are soft-deleted (see
    # `deleted_at` below); a table-wide unique constraint would otherwise
    # permanently reserve a deleted policy's name and block anyone from
    # ever creating a new policy with that name again.
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="active")  # active, inactive, draft
    priority = Column(Integer, default=100, nullable=False)
    type = Column(String(50), nullable=True)
    # Domain-scoped RBAC: which admin domain owns this policy. Derived from
    # ``type`` at create time (see app.core.domains). Super admin sees all;
    # domain admins are scoped to their own domain.
    domain = Column(
        String(30), nullable=False, default="general", server_default="general", index=True
    )
    severity = Column(String(20), nullable=True)  # low, medium, high, critical
    config = Column(JSON, nullable=True)
    conditions = Column(JSON, nullable=False)
    actions = Column(JSON, nullable=False)
    compliance_tags = Column(JSON, nullable=True)
    agent_ids = Column(JSON, nullable=True)
    created_by = Column(UUID(as_uuid=True), nullable=False)

    # Soft delete
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        CheckConstraint("status IN ('active', 'inactive', 'draft')", name="ck_policy_status"),
        CheckConstraint("severity IS NULL OR severity IN ('low', 'medium', 'high', 'critical', 'info')", name="ck_policy_severity"),
        # Partial unique index instead of a column-level unique=True -- see
        # the NOTE on `name` above and alembic/043_policy_name_unique_active_only.
        # `sqlite_where` mirrors `postgresql_where` so the same constraint is
        # exercised by the in-memory SQLite DB used in tests (conftest.py
        # builds the schema from this metadata via Base.metadata.create_all,
        # not from Alembic migrations).
        Index(
            "ix_policies_name_active",
            "name",
            unique=True,
            postgresql_where=Column("deleted_at").is_(None),
            sqlite_where=Column("deleted_at").is_(None),
        ),
    )

    @hybrid_property
    def enabled(self) -> bool:
        """Derived from status — no separate column needed."""
        return self.status == "active"

    def __repr__(self):
        return f"<Policy {self.name}>"
