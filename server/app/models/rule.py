"""
Rule Database Model (PostgreSQL)
Manages detection rules for data classification
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, JSON, Text, Float, ForeignKey, Index, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Rule(Base):
    """
    Detection Rule Model

    Supports three types:
    - regex: Pattern-based detection
    - keyword: Keyword matching
    - dictionary: External wordlist matching
    """
    __tablename__ = "rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)

    # Rule type: 'regex', 'keyword', 'dictionary'
    type = Column(String(20), nullable=False)

    # For regex rules
    pattern = Column(Text, nullable=True)
    regex_flags = Column(JSON, nullable=True)

    # For keyword rules
    keywords = Column(JSON, nullable=True)
    case_sensitive = Column(Boolean, default=False, nullable=True)

    # For dictionary rules
    dictionary_path = Column(Text, nullable=True)
    dictionary_hash = Column(String(64), nullable=True)

    # Applicable file types (NULL = all types)
    file_types = Column(ARRAY(String), nullable=True)

    # Detection configuration
    threshold = Column(Integer, default=1, nullable=False)
    weight = Column(Float, default=0.5, nullable=False)
    priority = Column(Integer, default=100, nullable=False)

    # Classification impact
    label_id = Column(UUID(as_uuid=True), ForeignKey("data_labels.id", ondelete="SET NULL"), nullable=True, index=True)
    classification_labels = Column(JSON, nullable=True)
    severity = Column(String(20), nullable=True)  # low, medium, high, critical

    # Relationships
    label = relationship("DataLabel", backref="rules", foreign_keys=[label_id])

    # Metadata
    category = Column(String(100), nullable=True)
    tags = Column(JSON, nullable=True)

    # Audit fields
    created_by = Column(UUID(as_uuid=True), nullable=False)

    # Soft delete
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Statistics
    match_count = Column(Integer, default=0, nullable=False)
    last_matched_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index('idx_rule_file_types', 'file_types', postgresql_using='gin'),
        CheckConstraint("severity IS NULL OR severity IN ('low', 'medium', 'high', 'critical', 'info')", name="ck_rule_severity"),
    )

    def __repr__(self):
        return f"<Rule {self.name} ({self.type})>"

    def to_dict(self):
        from app.core.timezone import format_iso
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "type": self.type,
            "pattern": self.pattern,
            "regex_flags": self.regex_flags,
            "keywords": self.keywords,
            "case_sensitive": self.case_sensitive,
            "dictionary_path": self.dictionary_path,
            "dictionary_hash": self.dictionary_hash,
            "threshold": self.threshold,
            "weight": self.weight,
            "classification_labels": self.classification_labels,
            "severity": self.severity,
            "category": self.category,
            "tags": self.tags,
            "created_by": str(self.created_by),
            "created_at": format_iso(self.created_at),
            "updated_at": format_iso(self.updated_at),
            "match_count": self.match_count,
            "last_matched_at": format_iso(self.last_matched_at),
        }
