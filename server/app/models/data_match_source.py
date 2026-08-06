"""
Data-match source: a stored EDM dataset or fingerprinted document.

Holds ONLY the keyed one-way index produced by
``app.services.data_matching_service`` -- never the protected plaintext. The
uploaded dataset/document is consumed at index time and discarded; this row is
not enough to reconstruct a record or a document.

Ported from a comparable model in CyberSentinel-DLP (a competitor product);
uses plain JSON rather than the Postgres-specific JSONB dialect type to match
the convention already used by every other SeceoKnight model (see
app/models/classified_file.py), rather than introducing a new import pattern
for this one table.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Integer, Float, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class DataMatchSource(Base):
    __tablename__ = "data_match_sources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # 'edm' (structured records) | 'fingerprint' (document)
    source_type = Column(String(20), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(String(1000), nullable=True)

    # The keyed one-way index (output of build_edm_index / build_fingerprint_index).
    # Contains only HMAC digests + coordinates -- no plaintext.
    index = Column(JSON, nullable=False)

    # Display / audit metadata (safe, non-reversible counts).
    row_count = Column(Integer, nullable=True)        # EDM records indexed
    shingle_count = Column(Integer, nullable=True)    # fingerprint shingles kept
    columns = Column(JSON, nullable=True)             # EDM: indexed column names

    # Per-source detection thresholds (policy-tunable).
    min_fields = Column(Integer, nullable=False, default=2)          # EDM combination
    min_shingles = Column(Integer, nullable=False, default=4)        # fingerprint abs overlap
    min_containment = Column(Float, nullable=False, default=0.25)    # fingerprint ratio

    # Classification assigned when this source matches.
    classification = Column(String(30), nullable=False, default="Restricted")

    enabled = Column(Boolean, nullable=False, default=True, index=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    def __repr__(self):
        return f"<DataMatchSource {self.source_type}:{self.name}>"

    def to_dict(self, include_index: bool = False):
        from app.core.timezone import format_iso
        d = {
            "id": str(self.id),
            "source_type": self.source_type,
            "name": self.name,
            "description": self.description,
            "row_count": self.row_count,
            "shingle_count": self.shingle_count,
            "columns": self.columns,
            "min_fields": self.min_fields,
            "min_shingles": self.min_shingles,
            "min_containment": self.min_containment,
            "classification": self.classification,
            "enabled": self.enabled,
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
        }
        # The index is never returned by default -- it is detection material,
        # not display data. Callers that genuinely need it must ask explicitly.
        if include_index:
            d["index"] = self.index
        return d
