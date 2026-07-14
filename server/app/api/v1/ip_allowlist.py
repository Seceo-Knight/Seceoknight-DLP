"""
Authorized-IP management — Super Admin only.

Manages the ``ip_allowlist`` table enforced by IPAllowlistMiddleware. When the
first entry is added, the caller's current IP is auto-included so the admin
enabling the control can't lock themselves out. Loopback is always allowed by
the middleware regardless of the table.
"""
import ipaddress
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import require_role
from app.core.database import get_db
from app.models.user import User
from app.models.ip_allowlist import IPAllowlistEntry
from app.middleware.ip_allowlist import get_client_ip, bump_ip_allowlist_cache
from app.services.audit_service import audit_log

logger = structlog.get_logger()
router = APIRouter()


class IPEntryCreate(BaseModel):
    cidr: str = Field(..., description="A single IP (203.0.113.7) or CIDR (203.0.113.0/24)")
    label: Optional[str] = Field(None, description="Human-readable note")


def _normalize_cidr(cidr: str) -> str:
    try:
        return str(ipaddress.ip_network(cidr.strip(), strict=False))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{cidr}' is not a valid IP or CIDR range.")


def _entry_out(e: IPAllowlistEntry) -> dict:
    return {
        "id": str(e.id),
        "cidr": e.cidr,
        "label": e.label,
        "is_enabled": e.is_enabled,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


@router.get("/ip-allowlist")
async def list_ip_allowlist(
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(IPAllowlistEntry).order_by(IPAllowlistEntry.created_at))).scalars().all()
    entries = [_entry_out(e) for e in rows]
    enabled = any(e["is_enabled"] for e in entries)
    return {
        "entries": entries,
        "your_ip": get_client_ip(request),
        "enforced": enabled,  # True once ≥1 enabled entry exists (control is on)
    }


@router.post("/ip-allowlist", status_code=status.HTTP_201_CREATED)
async def add_ip_allowlist(
    body: IPEntryCreate,
    request: Request,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    cidr = _normalize_cidr(body.cidr)

    existing = (await db.execute(select(IPAllowlistEntry).where(IPAllowlistEntry.cidr == cidr))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"{cidr} is already on the allowlist.")

    db.add(IPAllowlistEntry(cidr=cidr, label=body.label, created_by=current_user.id, is_enabled=True))

    # Lock-out safeguard: ensure the caller's own IP is covered by the enabled
    # set after this change; if not, auto-add it (loopback is always allowed by
    # the middleware, so localhost admins are fine regardless).
    caller_ip = get_client_ip(request)
    auto_added = None
    try:
        ip = ipaddress.ip_address(caller_ip)
        all_rows = (await db.execute(
            select(IPAllowlistEntry.cidr).where(IPAllowlistEntry.is_enabled == True)  # noqa: E712
        )).scalars().all()
        nets = []
        for c in list(all_rows) + [cidr]:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
        if not ip.is_loopback and not any(ip in n for n in nets):
            auto = f"{caller_ip}/32" if ip.version == 4 else f"{caller_ip}/128"
            auto = str(ipaddress.ip_network(auto, strict=False))
            if not (await db.execute(select(IPAllowlistEntry).where(IPAllowlistEntry.cidr == auto))).scalar_one_or_none():
                db.add(IPAllowlistEntry(cidr=auto, label="auto — your IP", created_by=current_user.id, is_enabled=True))
                auto_added = auto
    except ValueError:
        pass

    await db.commit()
    bump_ip_allowlist_cache()
    await audit_log(current_user.id, "security.ip_allowlist.add", {"cidr": cidr, "auto_added": auto_added})
    return {"added": cidr, "auto_added_your_ip": auto_added}


@router.delete("/ip-allowlist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ip_allowlist(
    entry_id: str,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(delete(IPAllowlistEntry).where(IPAllowlistEntry.id == entry_id))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Entry not found.")
    await db.commit()
    bump_ip_allowlist_cache()
    await audit_log(current_user.id, "security.ip_allowlist.delete", {"id": entry_id})
    return None
