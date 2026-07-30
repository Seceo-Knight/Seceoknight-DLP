"""
Sanctioned USB devices — the allowlist of storage devices permitted on
endpoints.

Ported from the CyberSentinel-DLP reference project (see
SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md). Enforcement posture is STRICT
ALLOWLIST (default-deny): when USB device control is enabled (an active
``usb_device_control`` policy), a removable storage device is allowed only if
its SERIAL NUMBER has an enabled row here; every other device is blocked.
Device identity is matched on ``serial_number`` alone (VID/PID/model are
stored for display and enrolment context only).
"""
from datetime import datetime, timezone

from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class SanctionedUsbDevice(Base):
    __tablename__ = "sanctioned_usb_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # The match key. A device is authorized iff its serial matches an enabled row.
    serial_number = Column(String(255), nullable=False, unique=True)
    label = Column(String(255), nullable=True)          # e.g. "Finance dept #3"
    # Captured for display / enrolment context; NOT used for matching.
    vendor_id = Column(String(16), nullable=True)
    product_id = Column(String(16), nullable=True)
    product_name = Column(String(255), nullable=True)
    manufacturer = Column(String(255), nullable=True)
    # Lets an admin suspend an approval without deleting the enrolment history.
    is_enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    notes = Column(String(1000), nullable=True)
    approved_by = Column(UUID(as_uuid=True), nullable=True)
    approved_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    def __repr__(self):
        return f"<SanctionedUsbDevice {self.serial_number} enabled={self.is_enabled}>"
