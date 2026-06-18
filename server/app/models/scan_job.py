"""
Scan Job Database Model (PostgreSQL)
Data discovery scan jobs
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Index
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="pending", index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        Index("idx_scan_jobs_status_created", "status", "created_at"),
    )

    def __repr__(self):
        return f"<ScanJob {self.id} target={self.target} status={self.status}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "target": self.target,
            "status": self.status,
            "started_at": format_iso(self.started_at),
            "completed_at": format_iso(self.completed_at),
            "created_at": format_iso(self.created_at),
        }
