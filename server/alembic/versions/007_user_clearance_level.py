"""Add users.clearance_level (forward-deploy for ABAC Phase 2).

Single-column additive migration. Required by the User Management UI form
so an admin can assign a numeric clearance level at user-create time. The
enforcement side (event-level required_clearance + visibility filter) is
still Phase 2 and does not ship with this migration.

Backfill: every existing user gets clearance_level = 1, matching the Phase
2 decision ("option b"). Users inserted after this migration receive the
same default via the DB-side DEFAULT.

Revision ID: 007_user_clearance_level
Revises: 006_rbac_permissions
"""
from alembic import op
import sqlalchemy as sa


revision = "007_user_clearance_level"
down_revision = "006_rbac_permissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add the column nullable first so we can backfill, then NOT NULL it.
    op.add_column(
        "users",
        sa.Column("clearance_level", sa.Integer(), nullable=True),
    )
    op.execute(
        "UPDATE users SET clearance_level = 1 WHERE clearance_level IS NULL"
    )
    op.alter_column(
        "users",
        "clearance_level",
        nullable=False,
        server_default=sa.text("1"),
    )


def downgrade() -> None:
    op.drop_column("users", "clearance_level")
