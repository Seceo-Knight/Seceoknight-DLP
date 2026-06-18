"""Phase 3-v2: additive config_v2 column on dashboard_widgets.

Holds the field-driven (Graylog-style) widget definition when the
``dashboard_v2`` feature flag is ON. The v1 code path never reads or
writes this column, so flipping the flag off is a clean revert.

Revision ID: 015_dashboard_v2_config
Revises: 014_filter_dashboards
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "015_dashboard_v2_cfg"
down_revision = "014_filter_dashboards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dashboard_widgets",
        sa.Column("config_v2", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dashboard_widgets", "config_v2")
