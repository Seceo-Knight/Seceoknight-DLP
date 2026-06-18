"""
Policy Condition Database Model (PostgreSQL)

DEPRECATED: This table is NOT used for policy evaluation.
The source of truth for policy conditions is the JSON ``conditions``
column on the ``policies`` table.  This table is retained only for
potential future migration to fully normalised conditions.  Do NOT
write evaluation logic that reads from this table.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class PolicyCondition(Base):
    __tablename__ = "policy_conditions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True)
    condition_type = Column(String(50), nullable=False)
    operator = Column(String(20), nullable=True)
    value = Column(String(500), nullable=False)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Relationships
    policy = relationship("Policy", backref="policy_conditions_rel", foreign_keys=[policy_id])

    def __repr__(self):
        return f"<PolicyCondition {self.condition_type} {self.operator} {self.value}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "policy_id": str(self.policy_id),
            "condition_type": self.condition_type,
            "operator": self.operator,
            "value": self.value,
            "created_at": format_iso(self.created_at),
        }
