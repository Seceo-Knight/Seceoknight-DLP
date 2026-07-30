"""
Sanctioned printer registry — the allowlist that printer control enforces in
"allowlist" scope. Ported from the CyberSentinel-DLP reference project (see
SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md).

NOTE: SeceoKnight's Windows agent does not currently monitor print jobs, so
unlike the USB device allowlist there is no agent-side enforcement wired up
yet — this ships the management surface (API + dashboard) now so it's ready
the moment print-job monitoring is added. The "enforced" flag below reflects
whether an admin has turned this on, not whether anything is actually being
blocked today.

When a printer_control policy is active with scope "allowlist", a print job
would be allowed only if its printer NAME has an enabled row here. Printers
are matched on ``printer_name`` (what an endpoint would report at print
time). Writes admin-only, reads analyst.
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import require_role
from app.core.database import get_db
from app.models.user import User
from app.models.policy import Policy
from app.models.sanctioned_printer import SanctionedPrinter
from app.services.audit_service import audit_log

logger = structlog.get_logger()
router = APIRouter()

PRINTER_CONTROL_TYPE = "printer_control"
PRINTER_CONTROL_POLICY_NAME = "Printer Control (Allowlist)"


class PrinterApprove(BaseModel):
    printer_name: str = Field(..., min_length=1, max_length=500,
                              description="Printer name — the match key")
    label: Optional[str] = Field(None, max_length=255)
    printer_type: Optional[str] = Field(None, max_length=20, description="local | network | unknown")
    notes: Optional[str] = Field(None, max_length=1000)


class PrinterUpdate(BaseModel):
    label: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = Field(None, max_length=1000)
    is_enabled: Optional[bool] = None


class EnforcementUpdate(BaseModel):
    enabled: bool = Field(..., description="Turn printer allowlist enforcement on/off")


def _printer_out(p: SanctionedPrinter) -> dict:
    return {
        "id": str(p.id),
        "printer_name": p.printer_name,
        "label": p.label,
        "printer_type": p.printer_type,
        "is_enabled": p.is_enabled,
        "notes": p.notes,
        "approved_at": p.approved_at.isoformat() if p.approved_at else None,
    }


async def _allowlist_policy(db: AsyncSession):
    return (await db.execute(
        select(Policy).where(
            Policy.type == PRINTER_CONTROL_TYPE,
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()


async def _allowlist_status(db: AsyncSession) -> dict:
    policy = await _allowlist_policy(db)
    enforced = bool(policy and policy.status == "active")
    return {"enforced": enforced}


@router.get("/")
async def list_printers(
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """The sanctioned-printer allowlist, plus whether allowlist enforcement is on."""
    rows = (await db.execute(
        select(SanctionedPrinter).order_by(SanctionedPrinter.approved_at.desc())
    )).scalars().all()
    printers = [_printer_out(p) for p in rows]
    status_ = await _allowlist_status(db)
    return {
        "printers": printers,
        "count": len(printers),
        "enabled_count": sum(1 for p in printers if p["is_enabled"]),
        **status_,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def approve_printer(
    body: PrinterApprove,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Approve (sanction) a printer by name. Idempotent: re-approving updates it."""
    name = body.printer_name.strip()
    if not name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "printer_name is required")

    existing = (await db.execute(
        select(SanctionedPrinter).where(SanctionedPrinter.printer_name == name)
    )).scalar_one_or_none()

    if existing:
        existing.label = body.label or existing.label
        existing.printer_type = body.printer_type or existing.printer_type
        existing.notes = body.notes if body.notes is not None else existing.notes
        existing.is_enabled = True
        existing.approved_by = current_user.id
        existing.approved_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(existing)
        await audit_log(current_user.id, "security.printers.reapprove", {"printer_name": name})
        return _printer_out(existing)

    p = SanctionedPrinter(
        printer_name=name, label=body.label, printer_type=body.printer_type,
        notes=body.notes, approved_by=current_user.id,
    )
    db.add(p)
    await db.commit()
    await db.refresh(p)
    await audit_log(current_user.id, "security.printers.approve", {"printer_name": name})
    return _printer_out(p)


@router.patch("/{printer_id}")
async def update_printer(
    printer_id: str,
    body: PrinterUpdate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Edit a printer's label/notes or suspend/resume its approval."""
    p = (await db.execute(
        select(SanctionedPrinter).where(SanctionedPrinter.id == printer_id)
    )).scalar_one_or_none()
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "printer not found")
    if body.label is not None:
        p.label = body.label
    if body.notes is not None:
        p.notes = body.notes
    if body.is_enabled is not None:
        p.is_enabled = body.is_enabled
    await db.commit()
    await db.refresh(p)
    await audit_log(current_user.id, "security.printers.update", {"printer_name": p.printer_name})
    return _printer_out(p)


@router.delete("/{printer_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_printer(
    printer_id: str,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Revoke (delete) a printer's approval."""
    res = await db.execute(
        delete(SanctionedPrinter).where(SanctionedPrinter.id == printer_id)
    )
    await db.commit()
    if res.rowcount == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "printer not found")
    await audit_log(current_user.id, "security.printers.revoke", {"printer_id": printer_id})


@router.post("/enforcement")
async def set_enforcement(
    body: EnforcementUpdate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Turn printer allowlist enforcement on/off by finding-or-creating the
    single backing ``printer_control`` policy row (scope=allowlist).

    See the module docstring: this flag has no agent-side effect yet since
    SeceoKnight doesn't monitor print jobs. It's a readiness switch for when
    that lands, and keeps parity with the "enforced" concept CyberSentinel
    uses for the same feature.
    """
    policy = await _allowlist_policy(db)
    if policy:
        policy.status = "active" if body.enabled else "inactive"
        policy.config = {**(policy.config or {}), "scope": "allowlist"}
        policy.updated_at = datetime.now(timezone.utc)
    else:
        policy = Policy(
            name=PRINTER_CONTROL_POLICY_NAME,
            description="Restricts printing to printers on the sanctioned-printers allowlist (no agent enforcement yet).",
            status="active" if body.enabled else "inactive",
            priority=100,
            type=PRINTER_CONTROL_TYPE,
            domain="threat",
            severity="medium",
            config={"scope": "allowlist"},
            conditions={},
            actions={},
            compliance_tags=[],
            created_by=current_user.id,
        )
        db.add(policy)
    await db.commit()
    await audit_log(current_user.id, "security.printers.enforcement", {"enabled": body.enabled})
    return await _allowlist_status(db)
