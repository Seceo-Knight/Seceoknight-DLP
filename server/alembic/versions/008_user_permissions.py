"""Add user_permissions join table for per-user direct grants.

Direct grants are *additional* permissions on top of whatever the user's
role provides. The resolver unions role_permissions and user_permissions.
ADMIN stays a global wildcard and cannot be narrowed via direct grants —
the enforcement for that lives in permission_service, not the schema.

Revision ID: 008_user_permissions
Revises: 007_user_clearance_level
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "008_user_permissions"
down_revision = "007_user_clearance_level"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_permissions",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.PrimaryKeyConstraint("user_id", "permission_id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["permission_id"], ["permissions.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_user_permissions_user_id", "user_permissions", ["user_id"]
    )
    op.create_index(
        "ix_user_permissions_permission_id",
        "user_permissions",
        ["permission_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_user_permissions_permission_id", table_name="user_permissions"
    )
    op.drop_index("ix_user_permissions_user_id", table_name="user_permissions")
    op.drop_table("user_permissions")
