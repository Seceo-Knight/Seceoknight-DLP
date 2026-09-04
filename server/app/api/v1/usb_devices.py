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
from typing import Optional, List, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
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
    alias: Optional[str] = Field(None, max_length=255, description="Friendly display name, editable later")
    decision: str = Field("allow", description="'allow' (default) or 'deny' — deny is a sticky, audited rejection")
    vendor_id: Optional[str] = Field(None, max_length=16)
    product_id: Optional[str] = Field(None, max_length=16)
    product_name: Optional[str] = Field(None, max_length=255)
    manufacturer: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = Field(None, max_length=1000)


class DeviceUpdate(BaseModel):
    label: Optional[str] = Field(None, max_length=255)
    alias: Optional[str] = Field(None, max_length=255)
    decision: Optional[str] = Field(None, description="'allow' or 'deny' — switch a row's decision after the fact")
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
        "alias": d.alias,
        "decision": d.decision or "allow",
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


async def _annotate_connection_state(devices: List[dict]) -> None:
    """Mutates ``devices`` in place, adding a live ``connection_state``
    ('connected' | 'disconnected' | 'unknown'), a legacy ``connected`` bool
    (True only for 'connected', kept for callers/UI that haven't moved to
    the 3-state field yet), ``reporting_agent_online``, and
    ``last_activity_at``, computed from the most recent
    ``usb_device_authorization`` event (which carries a ``usb_event`` of
    'connect' or 'disconnect' — see agent.cpp's ReportUsbDeviceAuthorization()
    and agents.py's log_device_authorization()).

    Fix (ported from CyberSentinel-DLP commit 7ae4671, August 26 2026): a
    connect with no matching disconnect does NOT mean the device is still
    plugged in. Only a running agent emits a disconnect, so a machine that
    was shut down, slept, lost power, or simply had its agent stopped leaves
    its last connect standing forever — the serial renders as "connected"
    months after it was actually pulled. The absence of a disconnect is not
    evidence of presence.

    So a connect is trusted only while the reporting agent is still beating
    (the same freshness rule _compute_lifecycle_status() applies on the
    Agents page: 'active' = heartbeat within AGENT_TIMEOUT_SECONDS). When
    that agent has gone quiet, the honest answer is 'unknown', not a live
    green dot. An explicit disconnect is trusted regardless -- it's a
    positive fact, not an absence of one.
    """
    serials = [d["serial_number"] for d in devices if d.get("serial_number")]
    if not serials:
        return
    mongo = get_mongodb()["dlp_events"]
    pipeline = [
        {"$match": {
            "event_type": "usb",
            "event_subtype": "usb_device_authorization",
            "serial_number": {"$in": serials},
        }},
        {"$sort": {"timestamp": -1}},
        {"$group": {
            "_id": "$serial_number",
            "usb_event": {"$first": "$usb_event"},
            "timestamp": {"$first": "$timestamp"},
            "agent_id": {"$first": "$agent_id"},
        }},
    ]
    latest: Dict[str, dict] = {}
    async for r in mongo.aggregate(pipeline):
        latest[r["_id"]] = r

    # Liveness of every agent that reported one of these events, by the same
    # rule the Agents page uses. SeceoKnight's agent registry lives in Mongo
    # (unlike CyberSentinel's Postgres Agent model), so this is a direct find
    # rather than a SQL join.
    from app.api.v1.agents import _compute_lifecycle_status

    agent_ids = {r.get("agent_id") for r in latest.values() if r.get("agent_id")}
    live: Dict[str, bool] = {}
    if agent_ids:
        agents_collection = get_mongodb()["agents"]
        async for doc in agents_collection.find(
            {"agent_id": {"$in": list(agent_ids)}},
            {"_id": 0, "agent_id": 1, "last_seen": 1, "last_heartbeat": 1},
        ):
            last_seen = doc.get("last_heartbeat") or doc.get("last_seen")
            live[doc["agent_id"]] = _compute_lifecycle_status(last_seen) == "active"

    for d in devices:
        entry = latest.get(d.get("serial_number"))
        if not entry:
            d["connected"] = False
            d["connection_state"] = None
            d["reporting_agent_online"] = None
            d["last_activity_at"] = None
            continue
        ts = entry.get("timestamp")
        is_connect = (entry.get("usb_event") or "connect") == "connect"
        agent_id = entry.get("agent_id")
        # None (not False) when we never resolved the reporting agent at
        # all -- unknown-liveness, distinct from confirmed-offline.
        agent_online = live.get(agent_id) if agent_id else None
        if is_connect:
            state = "connected" if agent_online else "unknown"
        else:
            state = "disconnected"
        d["connection_state"] = state
        d["connected"] = state == "connected"
        d["reporting_agent_online"] = agent_online
        d["last_activity_at"] = ts.isoformat() if hasattr(ts, "isoformat") else ts


@router.get("/")
async def list_devices(
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """The sanctioned-device allowlist, plus whether control is being enforced.

    Returns both allow- and deny-decisioned rows in ``devices`` (each tagged
    with its ``decision``) — the dashboard splits them into "Sanctioned" and
    "Disallowed" sections client-side. ``allow_count``/``deny_count`` are
    provided so the page doesn't need to recompute them from the full list.
    """
    rows = (await db.execute(
        select(SanctionedUsbDevice).order_by(SanctionedUsbDevice.approved_at.desc())
    )).scalars().all()
    devices = [_device_out(d) for d in rows]
    await _annotate_connection_state(devices)
    control = await _device_control_status(db)
    return {
        "devices": devices,
        "count": len(devices),
        "enabled_count": sum(1 for d in devices if d["is_enabled"]),
        "allow_count": sum(1 for d in devices if d["decision"] == "allow"),
        "deny_count": sum(1 for d in devices if d["decision"] == "deny"),
        **control,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def approve_device(
    body: DeviceApprove,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Approve (allow) or disallow (deny) a device by serial number, per
    ``body.decision``. Idempotent: re-submitting an existing serial updates
    its details (including flipping its decision) and re-enables it."""
    serial = body.serial_number.strip()
    if not serial:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "serial_number is required")
    decision = body.decision if body.decision in ("allow", "deny") else "allow"

    existing = (await db.execute(
        select(SanctionedUsbDevice).where(SanctionedUsbDevice.serial_number == serial)
    )).scalar_one_or_none()

    audit_action = "security.usb_devices.reapprove" if decision == "allow" else "security.usb_devices.redeny"

    if existing:
        existing.label = body.label or existing.label
        existing.alias = body.alias if body.alias is not None else existing.alias
        existing.decision = decision
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
        await audit_log(current_user.id, audit_action, {"serial_number": serial, "decision": decision})
        await _clear_dismissal(db, serial)
        return _device_out(existing)

    dev = SanctionedUsbDevice(
        serial_number=serial,
        label=body.label,
        alias=body.alias,
        decision=decision,
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
    audit_action = "security.usb_devices.approve" if decision == "allow" else "security.usb_devices.deny"
    await audit_log(current_user.id, audit_action, {"serial_number": serial, "decision": decision})
    await _clear_dismissal(db, serial)
    return _device_out(dev)


async def _clear_dismissal(db: AsyncSession, serial: Optional[str]) -> None:
    """Drop any dismissal for this serial -- a real allow/deny decision
    always supersedes a "not now". Without this, removing the resulting
    SanctionedUsbDevice row later would drop the device back into hiding
    instead of back into the triage queue where it belongs."""
    serial = (serial or "").strip()
    if not serial:
        return
    from app.models.dismissed_usb_device import DismissedUsbDevice

    await db.execute(delete(DismissedUsbDevice).where(
        DismissedUsbDevice.serial_number == serial
    ))
    await db.commit()


@router.patch("/{device_id}")
async def update_device(
    device_id: str,
    body: DeviceUpdate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Edit a device's label/alias/notes, flip its allow/deny decision, or
    suspend/resume its approval (is_enabled)."""
    dev = (await db.execute(
        select(SanctionedUsbDevice).where(SanctionedUsbDevice.id == device_id)
    )).scalar_one_or_none()
    if not dev:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    if body.label is not None:
        dev.label = body.label
    if body.alias is not None:
        dev.alias = body.alias
    if body.decision is not None:
        if body.decision not in ("allow", "deny"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "decision must be 'allow' or 'deny'")
        dev.decision = body.decision
    if body.notes is not None:
        dev.notes = body.notes
    if body.is_enabled is not None:
        dev.is_enabled = body.is_enabled
    await db.commit()
    await db.refresh(dev)
    await audit_log(current_user.id, "security.usb_devices.update", {
        "serial_number": dev.serial_number, "decision": dev.decision,
    })
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
    include_dismissed: bool = False,
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """USB devices observed on endpoints (from events) with no registry rule --
    the enrolment candidates. Deduped by serial, most-recent first.

    Dismissed devices are hidden by default (ported from CyberSentinel-DLP
    commit 7ae4671, gap-scan of August 26 2026) -- they're triage noise the
    admin already looked at, not a decision. Pass ``include_dismissed=true``
    to see them anyway, each flagged ``dismissed: true`` so they can be
    restored to the active queue. ``dismissed_count`` is always returned so
    the UI can offer that without a second call.
    """
    from app.models.dismissed_usb_device import DismissedUsbDevice

    approved = {
        s for (s,) in (await db.execute(select(SanctionedUsbDevice.serial_number))).all()
    }
    dismissed = {
        s for (s,) in (await db.execute(select(DismissedUsbDevice.serial_number))).all()
    }
    # serial_number is populated by ExtractUsbSerialFromDeviceId() in agent.cpp
    # (agent versions before this feature only sent device_name/device_id/
    # vendor_id/product_id — those older events simply won't have a serial and
    # are excluded here, same as CyberSentinel's own "no serial => can't
    # sanction" handling).
    capped_limit = max(1, min(limit, 1000))
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
        {"$limit": capped_limit},
    ]
    out: List[dict] = []
    # Distinct from len(out): the $limit above caps how many *distinct
    # serials ever seen* get considered, before approved/dismissed rows are
    # filtered back out below -- so hitting the cap doesn't necessarily mean
    # len(out) == capped_limit. Track it separately so the UI can warn that
    # older not-yet-decided serials may be missing from the triage queue,
    # the same silent-fetch-cap class of bug fixed on Rules/Policies.
    raw_seen_count = 0
    async for r in mongo.aggregate(pipeline):
        raw_seen_count += 1
        serial = r.get("serial_number")
        if serial in approved:
            continue
        if serial in dismissed and not include_dismissed:
            continue
        ls = r.get("last_seen")
        out.append({
            "dismissed": serial in dismissed,
            "serial_number": serial,
            "vendor_id": r.get("vendor_id"),
            "product_id": r.get("product_id"),
            "product_name": r.get("product_name"),
            "agent_id": r.get("agent_id"),
            "last_seen": ls.isoformat() if hasattr(ls, "isoformat") else ls,
            "sanctioned": False,
        })

    # Resolve agent_id -> a real agent name/code, same batch-lookup pattern
    # as events.py's _attach_agent_info(): events and agents both live in
    # MongoDB, so there's no SQL join to lean on. Without this the "Agent"
    # column just showed the raw agent_id UUID, which looks like a random
    # string to anyone reading the page.
    agent_ids = {d["agent_id"] for d in out if d.get("agent_id")}
    if agent_ids:
        agents_collection = get_mongodb()["agents"]
        agent_info = {
            doc["agent_id"]: doc
            async for doc in agents_collection.find(
                {"agent_id": {"$in": list(agent_ids)}},
                {"_id": 0, "agent_id": 1, "name": 1, "agent_code": 1},
            )
            if doc.get("agent_id")
        }
        for d in out:
            match = agent_info.get(d.get("agent_id"))
            if match:
                d["agent_name"] = match.get("name")
                d["agent_code"] = match.get("agent_code")

    await _annotate_connection_state(out)

    return {
        "devices": out,
        "count": len(out),
        "dismissed_count": len(dismissed),
        "include_dismissed": include_dismissed,
        "truncated": raw_seen_count >= capped_limit,
    }


class DeviceDismiss(BaseModel):
    serial_number: str = Field(..., min_length=1, max_length=255)
    product_name: Optional[str] = Field(None, max_length=255)
    manufacturer: Optional[str] = Field(None, max_length=255)
    note: Optional[str] = Field(None, max_length=1000)


@router.post("/seen/dismiss")
async def dismiss_seen_device(
    body: DeviceDismiss,
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Clear a "seen but not yet decided" device off the triage queue,
    without approving or denying it (ported from CyberSentinel-DLP commit
    7ae4671, gap-scan of August 26 2026). Reversible via the DELETE below;
    superseded automatically the moment a real allow/deny is made for the
    same serial (see _clear_dismissal()).

    Idempotent -- dismissing an already-dismissed serial just refreshes who/
    when, and reports ``already: true`` rather than erroring.
    """
    from app.models.dismissed_usb_device import DismissedUsbDevice

    serial = body.serial_number.strip()
    if not serial:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "serial_number is required")

    existing = (await db.execute(
        select(DismissedUsbDevice).where(DismissedUsbDevice.serial_number == serial)
    )).scalar_one_or_none()
    already = existing is not None
    if existing:
        existing.product_name = body.product_name or existing.product_name
        existing.manufacturer = body.manufacturer or existing.manufacturer
        existing.note = body.note if body.note is not None else existing.note
        existing.dismissed_by = current_user.id
        existing.dismissed_at = datetime.now(timezone.utc)
    else:
        db.add(DismissedUsbDevice(
            serial_number=serial,
            product_name=body.product_name,
            manufacturer=body.manufacturer,
            note=body.note,
            dismissed_by=current_user.id,
        ))
    await db.commit()
    await audit_log(current_user.id, "security.usb_devices.dismiss", {"serial_number": serial})
    return {"serial_number": serial, "dismissed": True, "already": already}


@router.delete("/seen/dismiss/{serial_number}")
async def restore_seen_device(
    serial_number: str,
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Undo a dismissal -- the device returns to the active triage queue.
    Does not touch its event history or any SanctionedUsbDevice row."""
    from app.models.dismissed_usb_device import DismissedUsbDevice

    serial = (serial_number or "").strip()
    res = await db.execute(delete(DismissedUsbDevice).where(
        DismissedUsbDevice.serial_number == serial
    ))
    await db.commit()
    if res.rowcount == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no dismissal found for that serial")
    await audit_log(current_user.id, "security.usb_devices.restore_dismissed", {"serial_number": serial})


@router.get("/activity")
async def device_activity(
    serial_number: str,
    limit: int = 100,
    current_user: User = Depends(require_role("analyst")),
):
    """Insertion history for a single serial: every connect/disconnect the
    agent has reported, most-recent first, with which agent (host) it was
    seen on. Click-through view from a row on the USB Devices page — see
    _annotate_connection_state() for how the live 'connected' dot on that
    same page is derived from this same event stream.
    """
    serial = (serial_number or "").strip()
    if not serial:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "serial_number is required")

    mongo = get_mongodb()["dlp_events"]
    cursor = mongo.find(
        {
            "event_type": "usb",
            "event_subtype": "usb_device_authorization",
            "serial_number": serial,
        },
        {"_id": 0, "timestamp": 1, "usb_event": 1, "action": 1, "agent_id": 1,
         "drive_letter": 1, "device_name": 1},
    ).sort("timestamp", -1).limit(max(1, min(limit, 500)))

    rows: List[dict] = []
    async for r in cursor:
        ts = r.get("timestamp")
        rows.append({
            "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else ts,
            "event": r.get("usb_event") or "connect",
            "action": r.get("action"),
            "agent_id": r.get("agent_id"),
            "drive_letter": r.get("drive_letter"),
            "device_name": r.get("device_name"),
        })

    agent_ids = {r["agent_id"] for r in rows if r.get("agent_id")}
    if agent_ids:
        agents_collection = get_mongodb()["agents"]
        agent_info = {
            doc["agent_id"]: doc
            async for doc in agents_collection.find(
                {"agent_id": {"$in": list(agent_ids)}},
                {"_id": 0, "agent_id": 1, "name": 1, "agent_code": 1},
            )
            if doc.get("agent_id")
        }
        for r in rows:
            match = agent_info.get(r.get("agent_id"))
            if match:
                r["agent_name"] = match.get("name")
                r["agent_code"] = match.get("agent_code")

    return {"serial_number": serial, "events": rows, "count": len(rows)}


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
    if not policy:
        # policies.name is globally UNIQUE, and DEVICE_CONTROL_POLICY_NAME is
        # a fixed, reserved name for this one system-managed row -- same
        # latent bug class fixed on the Printers page's set_enforcement: if
        # a row under that name exists but wasn't matched above (soft-
        # deleted via the Policies tab, or its `type` changed by editing it
        # through the Policy Creator), blindly INSERTing a fresh row throws
        # an uncaught IntegrityError -> bare 500. Revive/repurpose it instead.
        policy = (await db.execute(
            select(Policy).where(Policy.name == DEVICE_CONTROL_POLICY_NAME)
        )).scalar_one_or_none()
        if policy:
            policy.type = DEVICE_CONTROL_TYPE
            policy.domain = "access_control"
            policy.deleted_at = None
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
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Could not update USB device enforcement -- a conflicting policy row "
            "exists. Refresh the page and try again; if this persists, check the "
            "Policies tab for a policy named 'USB Device Control (Allowlist)'.",
        )
    await audit_log(current_user.id, "security.usb_devices.enforcement", {"enabled": body.enabled, "mode": mode})
    return await _device_control_status(db)
