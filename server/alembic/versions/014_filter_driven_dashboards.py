"""Phase 3 redesign: filter-driven dashboards.

Two schema deltas:

1. ``events.classification_level`` — denormalized TEXT column so dashboards
   can filter on classification tier (Public / Internal / Confidential /
   Restricted) without touching the raw ``classification`` JSON.

2. ``dashboard_widgets`` — add ``group_by`` and ``query_type`` to support
   the dynamic-filter widget model. ``query_key`` is demoted to nullable
   so freshly-created widgets can skip it; legacy rows remain valid.

Revision ID: 014_filter_dashboards
Revises: 013_dashboards
"""
from alembic import op
import sqlalchemy as sa


revision = "014_filter_dashboards"
down_revision = "013_dashboards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Events: denormalized classification_level (nullable for existing rows).
    op.add_column(
        "events",
        sa.Column("classification_level", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_events_classification_level",
        "events",
        ["classification_level"],
    )

    # 2. Widget: filter-driven shape.
    op.add_column(
        "dashboard_widgets",
        sa.Column("group_by", sa.String(64), nullable=True),
    )
    op.add_column(
        "dashboard_widgets",
        sa.Column(
            "query_type",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'aggregate'"),
        ),
    )
    op.create_check_constraint(
        "ck_widget_query_type",
        "dashboard_widgets",
        "query_type IN ('aggregate','raw')",
    )
    # Legacy rows still have a query_key; make it nullable for new rows.
    op.alter_column(
        "dashboard_widgets",
        "query_key",
        existing_type=sa.String(100),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "dashboard_widgets",
        "query_key",
        existing_type=sa.String(100),
        nullable=False,
    )
    op.drop_constraint("ck_widget_query_type", "dashboard_widgets", type_="check")
    op.drop_column("dashboard_widgets", "query_type")
    op.drop_column("dashboard_widgets", "group_by")

    op.drop_index(
        "idx_events_classification_level", table_name="events"
    )
    op.drop_column("events", "classification_level")
