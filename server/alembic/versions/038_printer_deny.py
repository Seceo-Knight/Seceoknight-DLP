"""Printer explicit-deny decision (task port, August 2026).

Ported from CyberSentinel DLP (commit b7dc3f3, "allow a printer to be
explicitly disapproved, not just unlisted").

Problem: ``sanctioned_printers`` was allow-only (a plain ``is_enabled``
boolean), and the agent-facing printer-policy endpoint only ever shipped
that list to the Windows agent when the policy's ``scope`` was
"allowlist" (see server/app/api/v1/agents.py's get_printer_policy). Every
other scope (block_all / block_network / block_local) ignored the
registry entirely. So "block this one specific printer, leave the rest of
the fleet alone" wasn't expressible -- you had to move the whole estate
into allowlist scope and enrol every other printer just to deny one.
Suspending a row (is_enabled=false) doesn't help either: outside allowlist
scope, withdrawing an approval blocks nothing, because nothing outside
that scope even reads the table.

Fix: add ``decision`` ('allow' | 'deny'), mirroring the column
``sanctioned_usb_devices`` already has (migration 034 / tasks #58-59). A
deny row is checked in EVERY scope and beats an allow row for the same
name, so it's a real disapproval rather than the absence of an approval.
Existing rows become 'allow', which is what they already meant.

Idempotent (IF NOT EXISTS), safe to re-run.

Revision ID: 038_printer_deny
Revises: 037_ip_allowlist_master_toggle
"""
from alembic import op
import sqlalchemy as sa


revision = "038_printer_deny"
down_revision = "037_ip_allowlist_master_toggle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        """
        ALTER TABLE sanctioned_printers
        ADD COLUMN IF NOT EXISTS decision VARCHAR(10) NOT NULL DEFAULT 'allow'
        """
    ))
    # Backfill safety net -- server_default covers new rows; this covers any
    # row written by application code between the column landing and the
    # server picking up the ORM change, or a NULL slipping in some other way.
    bind.execute(sa.text(
        "UPDATE sanctioned_printers SET decision = 'allow' WHERE decision IS NULL"
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text(
        "ALTER TABLE sanctioned_printers DROP COLUMN IF EXISTS decision"
    ))
