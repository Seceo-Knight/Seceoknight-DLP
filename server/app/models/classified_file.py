"""
ClassifiedFile Database Model (PostgreSQL)
Represents files that have been scanned and classified by the DLP system
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Float, Text, JSON, Index
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class ClassifiedFile(Base):
    __tablename__ = "classified_files"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id = Column(String(64), unique=True, nullable=False, index=True)

    # File information
    file_name = Column(Text, nullable=False)
    file_path = Column(Text, nullable=False)
    file_size = Column(Integer, nullable=False)
    file_type = Column(String(100), nullable=True)  # pdf, docx, xlsx, txt, etc.
    mime_type = Column(String(100), nullable=True)

    # File hashes
    file_hash = Column(String(64), nullable=False, index=True)  # SHA256
    md5_hash = Column(String(32), nullable=True)

    # Source information
    source_type = Column(String(50), nullable=False)  # agent, collector, connector, manual
    source_id = Column(String(64), nullable=True)
    agent_id = Column(String(64), nullable=True, index=True)

    # Location information
    location = Column(Text, nullable=True)  # Full path where file was found
    storage_type = Column(String(50), nullable=True)  # local, network, cloud, usb
    storage_location = Column(String(255), nullable=True)  # Specific storage location

    # Owner information
    owner_email = Column(String(255), nullable=True, index=True)
    owner_id = Column(UUID(as_uuid=True), nullable=True)
    owner_username = Column(String(255), nullable=True)

    # Classification results
    classification = Column(String(50), nullable=False, index=True)  # public, internal, confidential, restricted
    classification_labels = Column(JSON, nullable=True)  # ["PAN", "SSN", "PII", "PHI"]
    confidence_score = Column(Float, nullable=True)
    classification_method = Column(String(50), nullable=True)  # regex, ml, fingerprint, entropy, manual

    # Sensitive data found
    sensitive_patterns = Column(JSON, nullable=True)  # {"credit_card": 2, "ssn": 1, "email": 5}
    sensitive_data_count = Column(Integer, default=0, nullable=False)

    # Risk assessment
    risk_score = Column(Float, nullable=True)  # 0.0 to 1.0
    risk_level = Column(String(20), nullable=True)  # low, medium, high, critical

    # Content analysis
    content_preview = Column(Text, nullable=True)  # First 500 chars (sanitized)
    content_length = Column(Integer, nullable=True)  # Character count
    language = Column(String(10), nullable=True)  # en, es, fr, etc.

    # Entropy and complexity
    entropy_score = Column(Float, nullable=True)
    is_encrypted = Column(Boolean, default=False, nullable=False)
    is_compressed = Column(Boolean, default=False, nullable=False)

    # Policy matches
    policy_matches = Column(JSON, nullable=True)  # [{"policy_id": "...", "policy_name": "..."}]
    policies_violated = Column(Integer, default=0, nullable=False)

    # Compliance tags
    compliance_tags = Column(JSON, nullable=True)  # ["pci-dss", "gdpr", "hipaa"]

    # Quarantine information
    quarantined = Column(Boolean, default=False, nullable=False)
    quarantine_path = Column(Text, nullable=True)
    quarantine_reason = Column(Text, nullable=True)
    quarantined_at = Column(DateTime(timezone=True), nullable=True)

    # Access control
    access_restricted = Column(Boolean, default=False, nullable=False)
    access_restrictions = Column(JSON, nullable=True)

    # Review status
    reviewed = Column(Boolean, default=False, nullable=False)
    reviewed_by = Column(UUID(as_uuid=True), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)

    # Additional metadata
    file_metadata = Column("metadata", JSON, nullable=True)
    tags = Column(JSON, nullable=True)

    # Processing status
    scan_status = Column(String(20), nullable=False, default="completed")  # pending, scanning, completed, failed, skipped
    scan_duration_ms = Column(Integer, nullable=True)
    last_scanned_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    # Timestamps
    first_seen = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_modified = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Indexes for common queries
    __table_args__ = (
        Index('idx_file_classification_risk', 'classification', 'risk_level'),
        Index('idx_file_owner_classification', 'owner_email', 'classification'),
        Index('idx_file_source_scanned', 'source_type', 'last_scanned_at'),
        Index('idx_file_quarantined', 'quarantined', 'quarantined_at'),
        Index('idx_file_hash_classification', 'file_hash', 'classification'),
    )

    def __repr__(self):
        return f"<ClassifiedFile {self.file_id} - {self.file_name}>"

    def to_dict(self):
        """Convert classified file to dictionary"""
        return {
            "id": str(self.id),
            "file_id": self.file_id,
            "file_name": self.file_name,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "mime_type": self.mime_type,
            "file_hash": self.file_hash,
            "md5_hash": self.md5_hash,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "agent_id": self.agent_id,
            "location": self.location,
            "storage_type": self.storage_type,
            "storage_location": self.storage_location,
            "owner_email": self.owner_email,
            "owner_id": str(self.owner_id) if self.owner_id else None,
            "owner_username": self.owner_username,
            "classification": self.classification,
            "classification_labels": self.classification_labels,
            "confidence_score": self.confidence_score,
            "classification_method": self.classification_method,
            "sensitive_patterns": self.sensitive_patterns,
            "sensitive_data_count": self.sensitive_data_count,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "content_preview": self.content_preview,
            "content_length": self.content_length,
            "language": self.language,
            "entropy_score": self.entropy_score,
            "is_encrypted": self.is_encrypted,
            "is_compressed": self.is_compressed,
            "policy_matches": self.policy_matches,
            "policies_violated": self.policies_violated,
            "compliance_tags": self.compliance_tags,
            "quarantined": self.quarantined,
            "quarantine_path": self.quarantine_path,
            "quarantine_reason": self.quarantine_reason,
            "quarantined_at": self.quarantined_at.isoformat() if self.quarantined_at else None,
            "access_restricted": self.access_restricted,
            "access_restrictions": self.access_restrictions,
            "reviewed": self.reviewed,
            "reviewed_by": str(self.reviewed_by) if self.reviewed_by else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_notes": self.review_notes,
            "metadata": self.file_metadata,
            "tags": self.tags,
            "scan_status": self.scan_status,
            "scan_duration_ms": self.scan_duration_ms,
            "last_scanned_at": self.last_scanned_at.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
