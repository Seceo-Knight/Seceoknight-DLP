"""
Persisted SIEM connector configuration.

The in-memory SIEMIntegrationService registry is rebuilt from these rows on
startup so connectors survive restarts. Secret material (passwords, API keys,
HEC tokens) is stored Fernet-encrypted in ``secrets_enc`` (app.core.crypto),
never in plaintext.
"""
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


class SIEMConnectorConfigModel(Base):
    __tablename__ = "siem_connectors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(128), unique=True, nullable=False, index=True)
    siem_type = Column(String(32), nullable=False)

    host = Column(String(253), nullable=False)
    port = Column(Integer, nullable=False)

    # Syslog-specific
    protocol = Column(String(8), nullable=True)        # udp | tcp | tls
    log_format = Column(String(8), nullable=True)      # cef | leef
    facility = Column(String(16), nullable=True)       # local0..local7
    min_severity = Column(String(16), nullable=True)   # info|low|medium|high|critical

    # HTTP-push (Splunk/ELK) specific
    use_ssl = Column(Boolean, default=True, nullable=False, server_default="true")
    verify_certs = Column(Boolean, default=True, nullable=False, server_default="true")
    index_prefix = Column(String(128), nullable=True)
    index = Column(String(128), nullable=True)
    source = Column(String(128), nullable=True)
    sourcetype = Column(String(128), nullable=True)
    username = Column(String(255), nullable=True)

    # Fernet-encrypted JSON of {password, api_key, hec_token}
    secrets_enc = Column(Text, nullable=True)

    enabled = Column(Boolean, default=True, nullable=False, server_default="true")
    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
