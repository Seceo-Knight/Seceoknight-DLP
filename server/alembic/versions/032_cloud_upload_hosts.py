"""cloud upload hosts — admin-managed extra destinations for Cloud Upload Guard

Revision ID: 032_cloud_upload_hosts
Revises: 031_siem_connectors
Create Date: 2026-07-20
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "032_cloud_upload_hosts"
down_revision = "031_siem_connectors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(sa.text("""
        CREATE TABLE IF NOT EXISTS cloud_upload_hosts (
            id UUID PRIMARY KEY,
            domain VARCHAR(255) NOT NULL UNIQUE,
            label VARCHAR(255),
            is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS cloud_upload_hosts"))
