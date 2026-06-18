"""add OneDrive connection tables

Revision ID: add_onedrive_tables
Revises: caa6530e7d81
Create Date: 2025-12-18 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "add_onedrive_tables"
down_revision = "9b1d3c2d5f24"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "onedrive_connections",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("connection_name", sa.String(length=255), nullable=True),
        sa.Column("microsoft_user_id", sa.String(length=255), nullable=False),
        sa.Column("microsoft_user_email", sa.String(length=255), nullable=True),
        sa.Column("tenant_id", sa.String(length=255), nullable=True),
        sa.Column("refresh_token", sa.Text(), nullable=False),
        sa.Column("access_token", sa.Text(), nullable=True),
        sa.Column("token_expiry", sa.DateTime(), nullable=True),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("last_delta_token", sa.String(length=512), nullable=True),
        sa.Column("last_polled_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_onedrive_connections_user_status",
        "onedrive_connections",
        ["user_id", "status"],
    )
    op.create_unique_constraint(
        "uq_onedrive_connections_user_microsoft",
        "onedrive_connections",
        ["user_id", "microsoft_user_id"],
    )

    op.create_table(
        "onedrive_protected_folders",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "connection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("onedrive_connections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("folder_id", sa.String(length=255), nullable=False),
        sa.Column("folder_name", sa.String(length=512), nullable=True),
        sa.Column("folder_path", sa.Text(), nullable=True),
        sa.Column("sensitivity_level", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("last_seen_timestamp", sa.DateTime(), nullable=True),
        sa.Column("delta_token", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("connection_id", "folder_id", name="uq_onedrive_folder_per_connection"),
    )
    op.create_index(
        "ix_onedrive_protected_folders_connection",
        "onedrive_protected_folders",
        ["connection_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_onedrive_protected_folders_connection", table_name="onedrive_protected_folders")
    op.drop_table("onedrive_protected_folders")
    op.drop_constraint("uq_onedrive_connections_user_microsoft", "onedrive_connections", type_="unique")
    op.drop_index("ix_onedrive_connections_user_status", table_name="onedrive_connections")
    op.drop_table("onedrive_connections")

