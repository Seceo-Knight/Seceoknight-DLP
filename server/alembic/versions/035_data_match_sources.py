"""data_match_sources — EDM + document fingerprinting index storage (ported from CyberSentinel-DLP)

Revision ID: 035_data_match_sources
Revises: 034_usb_device_decision_alias
Create Date: 2026-08-06
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "035_data_match_sources"
down_revision = "034_usb_device_decision_alias"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(sa.text("""
        CREATE TABLE IF NOT EXISTS data_match_sources (
            id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            source_type       VARCHAR(20) NOT NULL,
            name              VARCHAR(255) NOT NULL,
            description       VARCHAR(1000),
            -- Keyed one-way index only (HMAC digests + coordinates) --
            -- never the protected plaintext. See
            -- app/services/data_matching_service.py.
            index             JSON NOT NULL,
            row_count         INTEGER,
            shingle_count     INTEGER,
            columns           JSON,
            min_fields        INTEGER NOT NULL DEFAULT 2,
            min_shingles      INTEGER NOT NULL DEFAULT 4,
            min_containment   DOUBLE PRECISION NOT NULL DEFAULT 0.25,
            classification    VARCHAR(30) NOT NULL DEFAULT 'Restricted',
            enabled           BOOLEAN NOT NULL DEFAULT true,
            created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at        TIMESTAMPTZ
        )
    """))
    op.get_bind().execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_data_match_sources_source_type "
        "ON data_match_sources (source_type)"
    ))
    op.get_bind().execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_data_match_sources_enabled "
        "ON data_match_sources (enabled)"
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS data_match_sources"))
