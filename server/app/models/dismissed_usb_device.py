"""
Dismissed (seen, not enrolling it) USB devices.

Ported from CyberSentinel-DLP commit 7ae4671, gap-scan of August 26 2026.
The "Seen on endpoints" list on the USB Devices page is derived entirely
from events -- there is no registry row backing an unsanctioned device, so
there is nothing to literally delete, and the only real delete available
would be purging the device's own events, destroying the audit trail of
something that was actually plugged into a corporate endpoint.

Dismissing is pure bookkeeping, not policy: it does NOT authorize the
device (the strict allowlist still blocks it if USB device control is
enforced), does not stop monitoring it, and is fully reversible. It just
clears a triage-queue row an admin has already looked at and decided not to
act on, so it stops re-appearing every time the page loads. A later allow
or deny (see _clear_dismissal() in usb_devices.py) clears the dismissal
automatically -- a real decision always supersedes a "not now".
"""
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class DismissedUsbDevice(Base):
    __tablename__ = "dismissed_usb_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    serial_number = Column(String(255), nullable=False, unique=True)
    product_name = Column(String(255), nullable=True)
    manufacturer = Column(String(255), nullable=True)
    note = Column(String(1000), nullable=True)
    dismissed_by = Column(UUID(as_uuid=True), nullable=True)
    dismissed_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def __repr__(self):
        return f"<DismissedUsbDevice {self.serial_number}>"
