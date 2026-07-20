"""
Cloud upload monitored hosts — admin-managed additions to the browser
extension's (Cloud Upload Guard) built-in destination list.

The extension ships with a hardcoded baseline list of cloud destinations
(Gmail, Outlook, Drive, Dropbox, ...) compiled into its code — adding a new
destination previously meant editing that file and redeploying it to every
machine. This table lets an admin add extra destinations from the dashboard
instead; the native host fetches the enabled rows and the extension merges
them with its baseline list at runtime, no redeploy required.

This is purely ADDITIVE: it can only extend the monitored-destination list,
never remove/disable a baseline entry — so a dashboard mistake here can't
silently turn off protection for a destination that ships built in.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class CloudUploadHost(Base):
    __tablename__ = "cloud_upload_hosts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # A bare domain the extension will match on (and its subdomains), e.g.
    # "sharefile.com" — matched the same way as the built-in CLOUD_HOSTS list
    # (host === domain || host.endsWith("." + domain)).
    domain = Column(String(255), nullable=False, unique=True)
    label = Column(String(255), nullable=True)
    is_enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def __repr__(self):
        return f"<CloudUploadHost {self.domain} enabled={self.is_enabled}>"
