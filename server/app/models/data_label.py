"""
Data Label Database Model (PostgreSQL)
Classification labels used to tag sensitive data
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class DataLabel(Base):
    __tablename__ = "data_labels"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="low")  # low, medium, high, critical
    description = Column(Text, nullable=True)
    color = Column(String(20), nullable=True)  # hex color code e.g. #FF0000

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        CheckConstraint("severity IN ('low', 'medium', 'high', 'critical', 'info')", name="ck_datalabel_severity"),
    )

    def __repr__(self):
        return f"<DataLabel {self.name}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "color": self.color,
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
