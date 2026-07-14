"""
Log-retention policy (single-row config).

Holds the admin-portal-managed retention windows for end-user logs. The daily
``cleanup_old_events`` task and any log-store cleanup read the effective value
from here (falling back to the RETENTION env defaults when no row exists). A DB
CHECK plus the API enforce a hard 90-day floor so the policy can never be set
below the compliance minimum.
"""
from datetime import datetime

from sqlalchemy import CheckConstraint, Column, DateTime, Integer
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base

# Compliance floor — retention can never be configured below this.
MIN_RETENTION_DAYS = 90


class RetentionConfig(Base):
    __tablename__ = "retention_config"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_retention_singleton"),
        CheckConstraint(
            "event_retention_days >= 90 AND opensearch_retention_days >= 90",
            name="ck_retention_floor",
        ),
    )

    id = Column(Integer, primary_key=True, default=1)
    event_retention_days = Column(Integer, nullable=False, default=180, server_default="180")
    opensearch_retention_days = Column(Integer, nullable=False, default=90, server_default="90")

    updated_by = Column(UUID(as_uuid=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow,
                        onupdate=datetime.utcnow, nullable=False)
