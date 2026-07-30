"""sanctioned USB devices + printers — allowlist tables (ported from CyberSentinel-DLP)

Revision ID: 033_sanctioned_devices
Revises: 032_cloud_upload_hosts
Create Date: 2026-07-30
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "033_sanctioned_devices"
down_revision = "032_cloud_upload_hosts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(sa.text("""
        CREATE TABLE IF NOT EXISTS sanctioned_usb_devices (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            serial_number VARCHAR(255) NOT NULL UNIQUE,
            label         VARCHAR(255),
            vendor_id     VARCHAR(16),
            product_id    VARCHAR(16),
            product_name  VARCHAR(255),
            manufacturer  VARCHAR(255),
            is_enabled    BOOLEAN NOT NULL DEFAULT true,
            notes         VARCHAR(1000),
            approved_by   UUID,
            approved_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))

    op.get_bind().execute(sa.text("""
        CREATE TABLE IF NOT EXISTS sanctioned_printers (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            printer_name  VARCHAR(500) NOT NULL UNIQUE,
            label         VARCHAR(255),
            printer_type  VARCHAR(20),
            is_enabled    BOOLEAN NOT NULL DEFAULT true,
            notes         VARCHAR(1000),
            approved_by   UUID,
            approved_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS sanctioned_printers"))
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS sanctioned_usb_devices"))
