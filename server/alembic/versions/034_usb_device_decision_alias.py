"""sanctioned USB devices — decision (allow/deny) + alias columns

Ported from the CyberSentinel-DLP reference project's USB device
enhancements (see SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md): admins can
now explicitly DENY a device (sticky, audited "never allow this" — distinct
from simply never approving it, since a denied serial is removed from the
"Seen" enrolment queue instead of sitting there waiting to be clicked) and
give an approved/denied device a friendly inline-editable alias separate
from the free-text ``label`` field already on the row.

``decision`` defaults to 'allow' so every existing sanctioned row keeps
its current (allowing) behavior with no data migration needed beyond the
column add itself.

Revision ID: 034_usb_device_decision_alias
Revises: 033_sanctioned_devices
Create Date: 2026-07-31
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "034_usb_device_decision_alias"
down_revision = "033_sanctioned_devices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(sa.text("""
        ALTER TABLE sanctioned_usb_devices
            ADD COLUMN IF NOT EXISTS decision VARCHAR(10) NOT NULL DEFAULT 'allow'
    """))
    op.get_bind().execute(sa.text("""
        ALTER TABLE sanctioned_usb_devices
            ADD COLUMN IF NOT EXISTS alias VARCHAR(255)
    """))
    # Belt-and-suspenders: constrain to the two known values so a typo'd
    # direct SQL write can't silently create a third, unhandled state.
    op.get_bind().execute(sa.text("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'sanctioned_usb_devices_decision_check'
            ) THEN
                ALTER TABLE sanctioned_usb_devices
                    ADD CONSTRAINT sanctioned_usb_devices_decision_check
                    CHECK (decision IN ('allow', 'deny'));
            END IF;
        END $$;
    """))


def downgrade() -> None:
    op.get_bind().execute(sa.text("""
        ALTER TABLE sanctioned_usb_devices DROP CONSTRAINT IF EXISTS sanctioned_usb_devices_decision_check
    """))
    op.get_bind().execute(sa.text("ALTER TABLE sanctioned_usb_devices DROP COLUMN IF EXISTS alias"))
    op.get_bind().execute(sa.text("ALTER TABLE sanctioned_usb_devices DROP COLUMN IF EXISTS decision"))
