"""SIEM connector persistence table.

Backs app/models/siem_connector.py + app/integrations/siem/registry.py.
Lets registered SIEM/syslog forwarding connectors (Splunk, ELK, and the new
generic Syslog/CEF/LEEF connector for Wazuh, QRadar, ArcSight, etc.) survive
a server restart instead of living only in the in-memory registry.

Idempotent (IF NOT EXISTS), safe to re-run.

Revision ID: 031_siem_connectors
Revises: 030_retention_config
"""
from alembic import op
import sqlalchemy as sa


revision = "031_siem_connectors"
down_revision = "030_retention_config"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS siem_connectors (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name          VARCHAR(128) NOT NULL UNIQUE,
            siem_type     VARCHAR(32) NOT NULL,

            host          VARCHAR(253) NOT NULL,
            port          INTEGER NOT NULL,

            protocol      VARCHAR(8),
            log_format    VARCHAR(8),
            facility      VARCHAR(16),
            min_severity  VARCHAR(16),

            use_ssl       BOOLEAN NOT NULL DEFAULT true,
            verify_certs  BOOLEAN NOT NULL DEFAULT true,
            index_prefix  VARCHAR(128),
            index         VARCHAR(128),
            source        VARCHAR(128),
            sourcetype    VARCHAR(128),
            username      VARCHAR(255),

            secrets_enc   TEXT,

            enabled       BOOLEAN NOT NULL DEFAULT true,
            created_by    UUID,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    ))
    bind.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_siem_connectors_name ON siem_connectors (name)"
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS siem_connectors"))
