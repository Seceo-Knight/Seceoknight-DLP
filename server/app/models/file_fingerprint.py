"""
File Fingerprint Database Model (PostgreSQL)
Known file hashes mapped to classification labels
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class FileFingerprint(Base):
    __tablename__ = "file_fingerprints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hash = Column(String(128), nullable=False, unique=True, index=True)
    file_name = Column(String(500), nullable=True)
    label_id = Column(UUID(as_uuid=True), ForeignKey("data_labels.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    label = relationship("DataLabel", backref="fingerprints", foreign_keys=[label_id])

    def __repr__(self):
        return f"<FileFingerprint {self.hash[:16]}...>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "hash": self.hash,
            "file_name": self.file_name,
            "label_id": str(self.label_id) if self.label_id else None,
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
