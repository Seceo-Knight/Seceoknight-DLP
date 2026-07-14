"""
Threat-intel IOC store + TAXII feed configuration.

IOC        — a single indicator (ingested from a feed / added manually, or
             internally derived from a DLP detection). Matched against event
             destinations + file hashes; opt-in ``is_shared`` publishes it via
             the TAXII 2.1 sharing server.
TAXIIFeed  — a configured remote TAXII 2.1 collection we poll for IOCs.
"""
from datetime import datetime

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, Integer, String, Text,
    UniqueConstraint, Index,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid

from app.core.database import Base


# Indicator value types we understand + match on.
IOC_TYPES = (
    "ipv4", "ipv6", "domain", "url", "email",
    "file_sha256", "file_sha1", "file_md5",
)


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
        Index("ix_iocs_value", "value"),
        Index("ix_iocs_active_shared", "is_active", "is_shared"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    stix_id = Column(String(255), unique=True, nullable=True)   # indicator--<uuid>

    ioc_type = Column(String(24), nullable=False)               # see IOC_TYPES
    value = Column(String(2048), nullable=False)                # normalized indicator
    pattern = Column(Text, nullable=True)                       # STIX pattern string

    name = Column(String(512), nullable=True)
    description = Column(Text, nullable=True)
    labels = Column(JSONB, nullable=True)                       # ["malicious-activity", ...]
    confidence = Column(Integer, nullable=True)                 # 0..100
    tlp = Column(String(8), nullable=True, default="amber")     # white|green|amber|red

    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_until = Column(DateTime(timezone=True), nullable=True)

    source = Column(String(255), nullable=True)                 # feed name / "internal" / "manual"
    direction = Column(String(16), nullable=False, default="ingested")  # ingested | internal
    external_id = Column(String(255), nullable=True)

    is_shared = Column(Boolean, default=False, nullable=False, server_default="false")
    is_active = Column(Boolean, default=True, nullable=False, server_default="true")

    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow,
                        onupdate=datetime.utcnow, nullable=False)


class TAXIIFeed(Base):
    __tablename__ = "taxii_feeds"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(128), unique=True, nullable=False)
    server_url = Column(String(1024), nullable=False)           # discovery or collection URL
    collection_id = Column(String(255), nullable=True)          # optional specific collection
    username = Column(String(255), nullable=True)
    secrets_enc = Column(Text, nullable=True)                   # Fernet JSON {password|token}

    poll_enabled = Column(Boolean, default=True, nullable=False, server_default="true")
    last_polled_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(String(512), nullable=True)
    total_imported = Column(Integer, default=0, nullable=False, server_default="0")

    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class TAXIIShareConfig(Base):
    """Single-row config for the outbound TAXII 2.1 sharing server: whether
    sharing is on and the Basic-auth credential partner vendors use to poll.
    The password is Fernet-encrypted in ``secret_enc`` (never stored plaintext).
    When no row exists, the server falls back to the TAXII_SHARE_* env vars."""
    __tablename__ = "taxii_share_config"
    __table_args__ = (CheckConstraint("id = 1", name="ck_taxii_share_singleton"),)

    id = Column(Integer, primary_key=True, default=1)
    enabled = Column(Boolean, nullable=False, default=False, server_default="false")
    username = Column(String(255), nullable=False, default="partner", server_default="partner")
    secret_enc = Column(Text, nullable=True)                     # Fernet(password)

    updated_by = Column(UUID(as_uuid=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow,
                        onupdate=datetime.utcnow, nullable=False)
