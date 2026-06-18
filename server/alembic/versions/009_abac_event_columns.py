"""ABAC Phase 2 (PostgreSQL): add event.department + event.required_clearance
and backfill users.department.

What this migration does:

1. ``events.department``        — TEXT NOT NULL DEFAULT 'DEFAULT'. PG catalog
                                  default backfills existing rows atomically
                                  on PG 11+, no table-rewrite required.
2. ``events.required_clearance``— INTEGER NOT NULL DEFAULT 0. Same trick.
3. ``idx_events_department``    — plain b-tree on (department). Query shape
                                  we're optimizing is equality filter; a
                                  composite isn't required at current load.
4. ``users.department`` backfill — any existing NULL becomes 'DEFAULT'. The
                                  column remains nullable at the DDL level
                                  to avoid coordinating with the admin UI,
                                  but the ABAC filter treats NULL user dept
                                  as deny-all (see abac_service.py).

The MongoDB side is handled by app/scripts/abac_backfill.py — it runs AFTER
this migration so the Python ORM and the backfill script share a consistent
understanding of the schema.

Revision ID: 009_abac_event_columns
Revises: 008_user_permissions
"""
from alembic import op
import sqlalchemy as sa


revision = "009_abac_event_columns"
down_revision = "008_user_permissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. events.department
    op.add_column(
        "events",
        sa.Column(
            "department",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'DEFAULT'"),
        ),
    )
    # 2. events.required_clearance
    op.add_column(
        "events",
        sa.Column(
            "required_clearance",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    # 3. index
    op.create_index("idx_events_department", "events", ["department"])

    # 4. Backfill users.department where NULL. We do this as a bulk UPDATE
    # rather than adding a server_default + NOT NULL because the admin UI
    # already exposes department as optional — keeping it nullable in the
    # schema means create-without-department requests don't silently fail.
    op.execute(
        "UPDATE users SET department = 'DEFAULT' WHERE department IS NULL"
    )


def downgrade() -> None:
    op.drop_index("idx_events_department", table_name="events")
    op.drop_column("events", "required_clearance")
    op.drop_column("events", "department")
    # users.department is left as-is — we don't null-out rows we backfilled
    # since the ABAC filter still needs a sensible value and reverting would
    # simply re-break the filter.
