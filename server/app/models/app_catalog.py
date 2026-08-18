"""
App catalog — classifies web destinations for Web Activity Control (GenAI /
web-activity policy). See migration 039_app_catalog for the seeded baseline
and rationale.

A row maps a hostname (matched suffix-wise, like cloud_upload_hosts and the
IP allowlist's CIDR matching) to one of four categories: webmail |
file_sharing | collaboration | genai. ``other``/unmatched hosts are not
watched by web-activity policies at all -- this is an allowlist of
*destinations to classify*, not a blocklist.

``is_builtin`` distinguishes the seeded baseline (migration-managed) from
admin-added rows (dashboard/API-managed) purely for display -- both are
enforced identically.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class AppCatalogEntry(Base):
    __tablename__ = "app_catalog"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), nullable=False, unique=True)
    category = Column(String(20), nullable=False)   # webmail | file_sharing | collaboration | genai
    vendor_name = Column(String(255), nullable=True)
    is_builtin = Column(Boolean, nullable=False, default=False, server_default="false")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def __repr__(self):
        return f"<AppCatalogEntry {self.domain} category={self.category}>"
