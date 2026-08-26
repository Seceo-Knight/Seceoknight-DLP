"""Dismissed USB devices -- triage-queue bookkeeping for "Seen on endpoints".

Ported from CyberSentinel-DLP commit 7ae4671, gap-scan of August 26 2026
(the "dismiss a seen-but-not-yet-decided device" half of that commit --
the connection-state accuracy half shipped separately in an earlier pass
with no schema change needed).

A dismissal is NOT an allow or a deny -- it is pure "seen, not enrolling it
right now" bookkeeping so a device an admin has already looked at stops
re-appearing in the triage queue every page load. See
DismissedUsbDevice's docstring and _clear_dismissal() in usb_devices.py.

Revision ID: 041_dismissed_usb_devices
Revises: 040_app_catalog_drive_usercontent
"""
from alembic import op
import sqlalchemy as sa


revision = "041_dismissed_usb_devices"
down_revision = "040_app_catalog_drive_usercontent"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS dismissed_usb_devices (
            id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            serial_number  VARCHAR(255) NOT NULL UNIQUE,
            product_name   VARCHAR(255),
            manufacturer   VARCHAR(255),
            note           VARCHAR(1000),
            dismissed_by   UUID,
            dismissed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS dismissed_usb_devices"))
