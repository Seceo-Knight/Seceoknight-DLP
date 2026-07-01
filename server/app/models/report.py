"""
Report Database Model (PostgreSQL)
Tracks every generated report: on-demand and scheduled.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, Integer, JSON, Index
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Who / what generated it
    name = Column(String(500), nullable=False)
    report_type = Column(String(100), nullable=False, index=True)   # summary, violations, trends, ...
    frequency = Column(String(50), nullable=False, default="custom") # daily, weekly, monthly, custom
    generated_by = Column(String(255), nullable=True)                # "scheduler" or user email

    # Time range covered by the report
    period_start = Column(DateTime(timezone=True), nullable=True)
    period_end = Column(DateTime(timezone=True), nullable=True)

    # Delivery
    recipients = Column(JSON, nullable=True)    # list of email addresses
    formats = Column(JSON, nullable=True)       # ["pdf", "csv"]
    status = Column(String(30), nullable=False, default="pending", index=True)
    # pending → generating → completed | failed

    # File storage — relative paths under REPORTS_DIR
    file_path_pdf = Column(String(1000), nullable=True)
    file_path_csv = Column(String(1000), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)

    # Outcome
    error_message = Column(Text, nullable=True)
    email_sent = Column(String(10), nullable=True)  # "yes" | "no" | "skipped"
    email_error = Column(Text, nullable=True)

    # Metadata / summary stats embedded so the list endpoint is cheap
    summary = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_reports_created_at", "created_at"),
        Index("ix_reports_frequency_status", "frequency", "status"),
    )

    def __repr__(self):
        return f"<Report id={self.id} name={self.name!r} status={self.status}>"
