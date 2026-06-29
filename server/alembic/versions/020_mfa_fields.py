"""Add MFA fields to users table.

Adds two columns to support TOTP-based multi-factor authentication:

  mfa_enabled  BOOLEAN NOT NULL DEFAULT FALSE
               Toggled to TRUE after the user completes the setup flow
               (scans QR code and verifies their first TOTP code).

  mfa_secret   VARCHAR(255) NULL
               Fernet-encrypted base32 TOTP secret. NULL until the user
               initiates MFA setup. Encrypted at the application layer so
               the raw secret is never stored in plaintext.

Both columns are additive — existing rows get the defaults automatically
and the application continues to work without any data backfill.

Revision ID: 020_mfa_fields
Revises: 019_fix_role_perms
"""

from alembic import op
import sqlalchemy as sa

revision = "020_mfa_fields"
down_revision = "019_fix_role_perms"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "mfa_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "mfa_secret",
            sa.String(255),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "mfa_secret")
    op.drop_column("users", "mfa_enabled")
