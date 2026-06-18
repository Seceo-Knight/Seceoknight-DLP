"""
Policy Database Models (PostgreSQL)
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, JSON, Text, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.hybrid import hybrid_property
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Policy(Base):
    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="active")  # active, inactive, draft
    priority = Column(Integer, default=100, nullable=False)
    type = Column(String(50), nullable=True)
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
    )

    @hybrid_property
    def enabled(self) -> bool:
        """Derived from status — no separate column needed."""
        return self.status == "active"

    def __repr__(self):
        return f"<Policy {self.name}>"
