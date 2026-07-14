"""IP allowlist table — authorized source networks for the admin portal.

Ported from CyberSentinel DLP (their 020_mfa_and_ip_allowlist.py bundled this
with MFA columns SeceoKnight already has from its own 020_mfa_fields.py, so
only the table creation is needed here).

Idempotent (IF NOT EXISTS), safe to re-run.

Revision ID: 028_ip_allowlist
Revises: 027_domain_scoped_rbac
"""
from alembic import op
import sqlalchemy as sa


revision = "028_ip_allowlist"
down_revision = "027_domain_scoped_rbac"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS ip_allowlist (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            cidr        VARCHAR(64) NOT NULL UNIQUE,
            label       VARCHAR(255),
            is_enabled  BOOLEAN NOT NULL DEFAULT true,
            created_by  UUID,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS ip_allowlist"))
