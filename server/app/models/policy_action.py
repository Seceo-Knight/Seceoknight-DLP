"""
Policy Action Database Model (PostgreSQL)

DEPRECATED: This table is NOT used for action execution.
The source of truth for policy actions is the JSON ``actions``
column on the ``policies`` table.  Do NOT write execution logic
that reads from this table.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class PolicyAction(Base):
    __tablename__ = "policy_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False)
    parameters = Column(JSONB, nullable=True)
    value = Column(String(500), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Relationships
    policy = relationship("Policy", backref="policy_actions_rel", foreign_keys=[policy_id])

    def __repr__(self):
        return f"<PolicyAction {self.action_type}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "policy_id": str(self.policy_id),
            "action_type": self.action_type,
            "parameters": self.parameters,
            "value": self.value,
            "created_at": format_iso(self.created_at),
        }
