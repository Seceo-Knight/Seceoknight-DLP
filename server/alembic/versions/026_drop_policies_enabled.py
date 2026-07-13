"""Drop policies.enabled — a leftover physical column from
001_initial_schema.py (Boolean, NOT NULL, no default).

The Policy model (app/models/policy.py) no longer has `enabled` as a real
Column; it's derived via @hybrid_property from `status` instead. Because
no migration ever dropped the old physical column, every INSERT generated
by the ORM omits it, and Postgres rejects the row:

    NotNullViolationError: null value in column "enabled" of relation
    "policies" violates not-null constraint

...which surfaced in the UI as "Request Failed with Status code 500" on
every attempt to create a policy.

Revision ID: 026_drop_policies_enabled
Revises: 025_fix_remaining_drift
"""
from alembic import op
import sqlalchemy as sa


revision = "026_drop_policies_enabled"
down_revision = "025_fix_remaining_drift"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("policies", "enabled")


def downgrade() -> None:
    # Best-effort reverse: recreate the column, backfilled from status so
    # the two stay consistent for any rows created after the upgrade.
    op.add_column(
        "policies",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.execute("UPDATE policies SET enabled = (status = 'active')")
