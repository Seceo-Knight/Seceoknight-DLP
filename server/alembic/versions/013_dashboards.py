"""Phase 3: dashboards + dashboard_widgets.

Two additive tables; no existing schema touched. ``created_by`` is a soft
reference to ``users.id`` so a deleted user doesn't cascade-delete their
dashboards — admin can still see/reassign them.

Revision ID: 013_dashboards
Revises: 012_incident_abac_cols
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "013_dashboards"
down_revision = "012_incident_abac_cols"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dashboards",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("is_shared", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("idx_dashboards_created_by", "dashboards", ["created_by"])

    op.create_table(
        "dashboard_widgets",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("dashboard_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("type", sa.String(30), nullable=False),
        sa.Column("query_key", sa.String(100), nullable=False),
        sa.Column("filters", postgresql.JSONB(), nullable=True),
        sa.Column("position", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["dashboard_id"], ["dashboards.id"],
                                ondelete="CASCADE"),
        sa.CheckConstraint("type IN ('bar','pie','line','table')",
                           name="ck_widget_type"),
    )
    op.create_index("idx_widgets_dashboard_id", "dashboard_widgets", ["dashboard_id"])


def downgrade() -> None:
    op.drop_index("idx_widgets_dashboard_id", table_name="dashboard_widgets")
    op.drop_table("dashboard_widgets")
    op.drop_index("idx_dashboards_created_by", table_name="dashboards")
    op.drop_table("dashboards")
