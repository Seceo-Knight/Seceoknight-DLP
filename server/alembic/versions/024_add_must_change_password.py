"""Add users.must_change_password and users.deleted_at — both exist on the
User model (app/models/user.py) but were never added by any migration, so
any query that selects the full User row (e.g. login) fails with
UndefinedColumnError on a fresh install.

Revision ID: 024_must_change_password
Revises: 023_browser_upload_policy
"""
from alembic import op
import sqlalchemy as sa


revision = "024_must_change_password"
down_revision = "023_browser_upload_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "users",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "deleted_at")
    op.drop_column("users", "must_change_password")
