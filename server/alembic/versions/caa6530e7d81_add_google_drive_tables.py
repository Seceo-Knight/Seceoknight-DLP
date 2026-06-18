"""add Google Drive connection tables

Revision ID: caa6530e7d81
Revises: 4a08eecdb2f5
Create Date: 2025-11-24 08:25:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "caa6530e7d81"
down_revision = "4a08eecdb2f5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "google_drive_connections",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("connection_name", sa.String(length=255), nullable=True),
        sa.Column("google_user_id", sa.String(length=255), nullable=False),
        sa.Column("google_user_email", sa.String(length=255), nullable=True),
        sa.Column("refresh_token", sa.Text(), nullable=False),
        sa.Column("access_token", sa.Text(), nullable=True),
        sa.Column("token_expiry", sa.DateTime(), nullable=True),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("last_activity_cursor", sa.String(length=255), nullable=True),
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
        "ix_google_drive_connections_user_status",
        "google_drive_connections",
        ["user_id", "status"],
    )
    op.create_unique_constraint(
        "uq_google_drive_connections_user_google",
        "google_drive_connections",
        ["user_id", "google_user_id"],
    )

    op.create_table(
        "google_drive_protected_folders",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "connection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("google_drive_connections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("folder_id", sa.String(length=255), nullable=False),
        sa.Column("folder_name", sa.String(length=512), nullable=True),
        sa.Column("folder_path", sa.Text(), nullable=True),
        sa.Column("sensitivity_level", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("last_seen_timestamp", sa.DateTime(), nullable=True),
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
        sa.UniqueConstraint("connection_id", "folder_id", name="uq_drive_folder_per_connection"),
    )
    op.create_index(
        "ix_google_drive_protected_folders_connection",
        "google_drive_protected_folders",
        ["connection_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_google_drive_protected_folders_connection", table_name="google_drive_protected_folders")
    op.drop_table("google_drive_protected_folders")
    op.drop_constraint("uq_google_drive_connections_user_google", "google_drive_connections", type_="unique")
    op.drop_index("ix_google_drive_connections_user_status", table_name="google_drive_connections")
    op.drop_table("google_drive_connections")






























