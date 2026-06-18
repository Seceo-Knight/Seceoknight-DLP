"""Phase 4: dashboard meta — description, tags, abac_roles.

All three columns are additive + nullable. Existing dashboards keep their
behaviour; the new fields are populated by the v2 panel builder. DOWN
drops them and is safe at any time.

Revision ID: 016_dashboard_meta
Revises: 015_dashboard_v2_cfg
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "016_dashboard_meta"
down_revision = "015_dashboard_v2_cfg"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dashboards", sa.Column("description", sa.Text(), nullable=True))
    op.add_column(
        "dashboards",
        sa.Column("tags", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "dashboards",
        sa.Column("abac_roles", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dashboards", "abac_roles")
    op.drop_column("dashboards", "tags")
    op.drop_column("dashboards", "description")
