"""
Scan Result Database Model (PostgreSQL)
Individual findings from data discovery scans
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    file_path = Column(Text, nullable=False)
    label_id = Column(UUID(as_uuid=True), ForeignKey("data_labels.id", ondelete="SET NULL"), nullable=True, index=True)
    matched_rule = Column(UUID(as_uuid=True), ForeignKey("rules.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Relationships
    job = relationship("ScanJob", backref="results", foreign_keys=[job_id])
    label = relationship("DataLabel", backref="scan_results", foreign_keys=[label_id])
    rule = relationship("Rule", backref="scan_results", foreign_keys=[matched_rule])

    __table_args__ = (
        Index("idx_scan_results_label_created", "label_id", "created_at"),
    )

    def __repr__(self):
        return f"<ScanResult {self.file_path}>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "job_id": str(self.job_id),
            "file_path": self.file_path,
            "label_id": str(self.label_id) if self.label_id else None,
            "matched_rule": str(self.matched_rule) if self.matched_rule else None,
            "created_at": format_iso(self.created_at),
        }
