"""Log-retention policy (single-row config).

Backs the admin-portal-managed retention windows (app/api/v1/system.py,
app/services/retention_service.py). CyberSentinel DLP shipped the
`RetentionConfig` model and the `/system/retention` endpoints that query it
but never wrote an Alembic migration to create the table — only a fresh
`create_all` install would have it. Adding the migration here so `alembic
upgrade head` on an existing SeceoKnight install actually creates the table.

Idempotent (IF NOT EXISTS), safe to re-run.

Revision ID: 030_retention_config
Revises: 029_threat_intel_iocs
"""
from alembic import op
import sqlalchemy as sa


revision = "030_retention_config"
down_revision = "029_threat_intel_iocs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS retention_config (
            id                        INTEGER PRIMARY KEY DEFAULT 1,
            event_retention_days      INTEGER NOT NULL DEFAULT 180,
            opensearch_retention_days INTEGER NOT NULL DEFAULT 90,
            updated_by                UUID,
            updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_retention_singleton CHECK (id = 1),
            CONSTRAINT ck_retention_floor CHECK (
                event_retention_days >= 90 AND opensearch_retention_days >= 90
            )
        )
        """
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS retention_config"))
