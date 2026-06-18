"""
Policy-Agent Junction Table (PostgreSQL)
Maps which agents should enforce which policies.
Replaces the JSON agent_ids column on Policy.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class PolicyAgent(Base):
    __tablename__ = "policy_agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Relationships
    policy = relationship("Policy", backref="agent_assignments")

    __table_args__ = (
        UniqueConstraint("policy_id", "agent_id", name="uq_policy_agent"),
    )

    def __repr__(self):
        return f"<PolicyAgent policy={self.policy_id} agent={self.agent_id}>"
