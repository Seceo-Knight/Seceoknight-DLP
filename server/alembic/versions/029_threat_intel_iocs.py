"""Threat-intel IOC store + TAXII feed config + outbound sharing config.

- iocs               (indicators; ingested / internal; opt-in shareable)
- taxii_feeds        (remote TAXII 2.1 collections we poll)
- taxii_share_config (single-row config for the outbound TAXII 2.1 server)

Ported from CyberSentinel DLP's 022_ioc_threat_intel.py, with one fix: their
migration created `iocs` and `taxii_feeds` but never created
`taxii_share_config` even though `app/models/ioc.py::TAXIIShareConfig` and
`api/v1/taxii.py` query it on every request — on a real `alembic upgrade
head` deploy (as opposed to the fresh-install `create_all` path) that table
would simply not exist and GET /api/v1/threat-intel/sharing would 500. Adding
it here instead of silently reproducing that gap.

Idempotent (IF NOT EXISTS), safe to re-run.

Revision ID: 029_threat_intel_iocs
Revises: 028_ip_allowlist
"""
from alembic import op
import sqlalchemy as sa


revision = "029_threat_intel_iocs"
down_revision = "028_ip_allowlist"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS iocs (
            id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            stix_id      VARCHAR(255) UNIQUE,
            ioc_type     VARCHAR(24)  NOT NULL,
            value        VARCHAR(2048) NOT NULL,
            pattern      TEXT,
            name         VARCHAR(512),
            description  TEXT,
            labels       JSONB,
            confidence   INTEGER,
            tlp          VARCHAR(8) DEFAULT 'amber',
            valid_from   TIMESTAMPTZ,
            valid_until  TIMESTAMPTZ,
            source       VARCHAR(255),
            direction    VARCHAR(16) NOT NULL DEFAULT 'ingested',
            external_id  VARCHAR(255),
            is_shared    BOOLEAN NOT NULL DEFAULT false,
            is_active    BOOLEAN NOT NULL DEFAULT true,
            created_by   UUID,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_ioc_type_value UNIQUE (ioc_type, value)
        )
        """
    ))
    bind.execute(sa.text("CREATE INDEX IF NOT EXISTS ix_iocs_value ON iocs (value)"))
    bind.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_iocs_active_shared ON iocs (is_active, is_shared)"
    ))

    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS taxii_feeds (
            id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name           VARCHAR(128) NOT NULL UNIQUE,
            server_url     VARCHAR(1024) NOT NULL,
            collection_id  VARCHAR(255),
            username       VARCHAR(255),
            secrets_enc    TEXT,
            poll_enabled   BOOLEAN NOT NULL DEFAULT true,
            last_polled_at TIMESTAMPTZ,
            last_status    VARCHAR(512),
            total_imported INTEGER NOT NULL DEFAULT 0,
            created_by     UUID,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    ))

    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS taxii_share_config (
            id          INTEGER PRIMARY KEY DEFAULT 1,
            enabled     BOOLEAN NOT NULL DEFAULT false,
            username    VARCHAR(255) NOT NULL DEFAULT 'partner',
            secret_enc  TEXT,
            updated_by  UUID,
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_taxii_share_singleton CHECK (id = 1)
        )
        """
    ))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DROP TABLE IF EXISTS taxii_share_config"))
    bind.execute(sa.text("DROP TABLE IF EXISTS taxii_feeds"))
    bind.execute(sa.text("DROP TABLE IF EXISTS iocs"))
