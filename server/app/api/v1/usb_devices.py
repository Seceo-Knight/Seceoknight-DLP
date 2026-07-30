"""
Sanctioned USB device registry — the allowlist that USB device control
enforces. Ported from the CyberSentinel-DLP reference project (see
SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md).

Strict allowlist (default-deny): when USB device control is enabled (an
active ``usb_device_control`` policy row exists), a removable storage device
is authorized only if its serial number has an enabled row here. Everything
else is blocked by the Windows agent, which pulls this list via
GET /agents/{agent_id}/usb-allowlist and enforces it locally (see agents.py
and agent.cpp's HandleUsbDeviceArrival / ExtractUsbSerialFromDeviceId).

This module also owns a lightweight on/off "enforcement" toggle
(POST .../enforcement) that finds-or-creates the backing ``usb_device_control``
policy row directly — unlike CyberSentinel, SeceoKnight's general policy
creator UI doesn't (yet) have a form for this policy type, so the allowlist
page itself drives the one Policy row that turns enforcement on/off.

Writes are admin-only; reads are analyst.
"""
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import require_role
from app.core.database import get_db, get_mongodb
from app.models.user import User
from app.models.policy import Policy
from app.models.sanctioned_usb_device import SanctionedUsbDevice
from app.services.audit_service import audit_log

logger = structlog.get_logger()
router = APIRouter()

DEVICE_CONTROL_TYPE = "usb_device_control"
DEVICE_CONTROL_POLICY_NAME = "USB Device Control (Allowlist)"


class DeviceApprove(BaseModel):
    serial_number: str = Field(..., min_length=1, max_length=255,
                               description="Device serial number — the match key")
    label: Optional[str] = Field(None, max_length=255)
    vendor_id: Optional[str] = Field(None, max_length=16)
    product_id: Optional[str] = Field(None, max_length=16)
    product_name: Optional[str] = Field(None, max_length=255)
    manufacturer: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = Field(None, max_length=1000)


class DeviceUpdate(BaseModel):
    label: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = Field(None, max_length=1000)
    is_enabled: Optional[bool] = None


class EnforcementUpdate(BaseModel):
    enabled: bool = Field(..., description="Turn USB device-control allowlist enforcement on/off")
    mode: str = Field("enforce", description="'enforce' (block unsanctioned devices) or 'audit' (log only)")


def _device_out(d: SanctionedUsbDevice) -> dict:
    return {
        "id": str(d.id),
        "serial_number": d.serial_number,
        "label": d.label,
        "vendor_id": d.vendor_id,
        "product_id": d.product_id,
        "product_name": d.product_name,
        "manufacturer": d.manufacturer,
        "is_enabled": d.is_enabled,
        "notes": d.notes,
        "approved_at": d.approved_at.isoformat() if d.approved_at else None,
    }


async def _device_control_policy(db: AsyncSession) -> Optional[Policy]:
    return (await db.execute(
        select(Policy).where(
            Policy.type == DEVICE_CONTROL_TYPE,
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()


async def _device_control_status(db: AsyncSession) -> dict:
    """Whether the allowlist is being enforced, and in which mode."""
    policy = await _device_control_policy(db)
    enforced = bool(policy and policy.status == "active")
    mode = ((policy.config or {}).get("mode") or "enforce") if enforced else "off"
    return {"enforced": enforced, "mode": mode}


@router.get("/")
async def list_devices(
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """The sanctioned-device allowlist, plus whether control is being enforced."""
    rows = (await db.execute(
        select(SanctionedUsbDevice).order_by(SanctionedUsbDevice.approved_at.desc())
    )).scalars().all()
    devices = [_device_out(d) for d in rows]
    control = await _device_control_status(db)
    return {
        "devices": devices,
        "count": len(devices),
        "enabled_count": sum(1 for d in devices if d["is_enabled"]),
        **control,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def approve_device(
    body: DeviceApprove,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Approve (sanction) a device by serial number. Idempotent: re-approving an
    existing serial updates its details and re-enables it."""
    serial = body.serial_number.strip()
    if not serial:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "serial_number is required")

    existing = (await db.execute(
        select(SanctionedUsbDevice).where(SanctionedUsbDevice.serial_number == serial)
    )).scalar_one_or_none()

    if existing:
        existing.label = body.label or existing.label
        existing.vendor_id = body.vendor_id or existing.vendor_id
        existing.product_id = body.product_id or existing.product_id
        existing.product_name = body.product_name or existing.product_name
        existing.manufacturer = body.manufacturer or existing.manufacturer
        existing.notes = body.notes if body.notes is not None else existing.notes
        existing.is_enabled = True
        existing.approved_by = current_user.id
        existing.approved_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(existing)
        await audit_log(current_user.id, "security.usb_devices.reapprove", {"serial_number": serial})
        return _device_out(existing)

    dev = SanctionedUsbDevice(
        serial_number=serial,
        label=body.label,
        vendor_id=body.vendor_id,
        product_id=body.product_id,
        product_name=body.product_name,
        manufacturer=body.manufacturer,
        notes=body.notes,
        approved_by=current_user.id,
    )
    db.add(dev)
    await db.commit()
    await db.refresh(dev)
    await audit_log(current_user.id, "security.usb_devices.approve", {"serial_number": serial})
    return _device_out(dev)


@router.patch("/{device_id}")
async def update_device(
    device_id: str,
    body: DeviceUpdate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Edit a device's label/notes or suspend/resume its approval (is_enabled)."""
    dev = (await db.execute(
        select(SanctionedUsbDevice).where(SanctionedUsbDevice.id == device_id)
    )).scalar_one_or_none()
    if not dev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    if body.label is not None:
        dev.label = body.label
    if body.notes is not None:
        dev.notes = body.notes
    if body.is_enabled is not None:
        dev.is_enabled = body.is_enabled
    await db.commit()
    await db.refresh(dev)
    await audit_log(current_user.id, "security.usb_devices.update", {"serial_number": dev.serial_number})
    return _device_out(dev)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_device(
    device_id: str,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Revoke (delete) a device's approval. It becomes unsanctioned again."""
    res = await db.execute(
        delete(SanctionedUsbDevice).where(SanctionedUsbDevice.id == device_id)
    )
    await db.commit()
    if res.rowcount == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    await audit_log(current_user.id, "security.usb_devices.revoke", {"device_id": device_id})


@router.get("/seen")
async def seen_devices(
    limit: int = 200,
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """USB devices observed on endpoints (from events) that are NOT yet
    sanctioned — the enrolment candidates. Deduped by serial, most-recent first."""
    approved = {
        s for (s,) in (await db.execute(select(SanctionedUsbDevice.serial_number))).all()
    }
    # serial_number is populated by ExtractUsbSerialFromDeviceId() in agent.cpp
    # (agent versions before this feature only sent device_name/device_id/
    # vendor_id/product_id — those older events simply won't have a serial and
    # are excluded here, same as CyberSentinel's own "no serial => can't
    # sanction" handling).
    mongo = get_mongodb()["dlp_events"]
    pipeline = [
        {"$match": {"event_type": "usb", "serial_number": {"$nin": [None, ""]}}},
        {"$sort": {"timestamp": -1}},
        {"$group": {
            "_id": "$serial_number",
            "serial_number": {"$first": "$serial_number"},
            "vendor_id": {"$first": "$vendor_id"},
            "product_id": {"$first": "$product_id"},
            "product_name": {"$first": "$device_name"},
            "agent_id": {"$first": "$agent_id"},
            "last_seen": {"$first": "$timestamp"},
        }},
        {"$limit": max(1, min(limit, 1000))},
    ]
    out: List[dict] = []
    async for r in mongo.aggregate(pipeline):
        if r.get("serial_number") in approved:
            continue
        ls = r.get("last_seen")
        out.append({
            "serial_number": r.get("serial_number"),
            "vendor_id": r.get("vendor_id"),
            "product_id": r.get("product_id"),
            "product_name": r.get("product_name"),
            "agent_id": r.get("agent_id"),
            "last_seen": ls.isoformat() if hasattr(ls, "isoformat") else ls,
            "sanctioned": False,
        })
    return {"devices": out, "count": len(out)}


@router.post("/enforcement")
async def set_enforcement(
    body: EnforcementUpdate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Turn USB device-control allowlist enforcement on/off (and set its mode)
    by finding-or-creating the single backing ``usb_device_control`` policy row."""
    mode = body.mode if body.mode in ("enforce", "audit") else "enforce"
    policy = await _device_control_policy(db)
    if policy:
        policy.status = "active" if body.enabled else "inactive"
        policy.config = {**(policy.config or {}), "mode": mode}
        policy.updated_at = datetime.now(timezone.utc)
    else:
        policy = Policy(
            name=DEVICE_CONTROL_POLICY_NAME,
            description="Blocks any USB storage device whose serial number is not on the sanctioned-devices allowlist.",
            status="active" if body.enabled else "inactive",
            priority=100,
            type=DEVICE_CONTROL_TYPE,
            domain="access_control",
            severity="high",
            config={"mode": mode},
            conditions={},
            actions={},
            compliance_tags=[],
            created_by=current_user.id,
        )
        db.add(policy)
    await db.commit()
    await audit_log(current_user.id, "security.usb_devices.enforcement", {"enabled": body.enabled, "mode": mode})
    return await _device_control_status(db)
