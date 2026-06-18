"""
Incident Comment Database Model (PostgreSQL)
Discussion thread on security incidents
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class IncidentComment(Base):
    __tablename__ = "incident_comments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    comment = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Relationships
    incident = relationship("Incident", backref="comments", foreign_keys=[incident_id])
    user = relationship("User", backref="incident_comments", foreign_keys=[user_id])

    def __repr__(self):
        return f"<IncidentComment {self.id} on {self.incident_id}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "incident_id": str(self.incident_id),
            "user_id": str(self.user_id) if self.user_id else None,
            "comment": self.comment,
            "created_at": format_iso(self.created_at),
        }
