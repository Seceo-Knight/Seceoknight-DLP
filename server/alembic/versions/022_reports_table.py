"""Add reports table for tracking generated compliance reports.

Revision ID: 022_reports_table
Revises: 021_manager_view_alerts
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision = "022_reports_table"
down_revision = "021_manager_view_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("report_type", sa.String(100), nullable=False),
        sa.Column("frequency", sa.String(50), nullable=False, server_default="custom"),
        sa.Column("generated_by", sa.String(255), nullable=True),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recipients", JSON, nullable=True),
        sa.Column("formats", JSON, nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("file_path_pdf", sa.String(1000), nullable=True),
        sa.Column("file_path_csv", sa.String(1000), nullable=True),
        sa.Column("file_size_bytes", sa.Integer, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("email_sent", sa.String(10), nullable=True),
        sa.Column("email_error", sa.Text, nullable=True),
        sa.Column("summary", JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_reports_report_type", "reports", ["report_type"])
    op.create_index("ix_reports_status", "reports", ["status"])
    op.create_index("ix_reports_created_at", "reports", ["created_at"])
    op.create_index("ix_reports_frequency_status", "reports", ["frequency", "status"])


def downgrade() -> None:
    op.drop_index("ix_reports_frequency_status", table_name="reports")
    op.drop_index("ix_reports_created_at", table_name="reports")
    op.drop_index("ix_reports_status", table_name="reports")
    op.drop_index("ix_reports_report_type", table_name="reports")
    op.drop_table("reports")
