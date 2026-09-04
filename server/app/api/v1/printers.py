"""
Sanctioned printer registry — the allow/deny list printer control enforces.
Ported from the CyberSentinel-DLP reference project (see
SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md), extended with an explicit
allow/deny ``decision`` (ported from their commit b7dc3f3).

CORRECTION: this module's docstring previously said the Windows agent
doesn't monitor print jobs, so nothing was actually enforced. That's stale
-- print-job device control and content inspection both have real agent-side
enforcement now (see GET /agents/{agent_id}/printer-policy and
ShouldBlockPrinter()/EvaluatePrintContent() in agent.cpp, tasks #114/#130-133).
The "enforced" flag below reflects whether the printer_control policy is
active, and IS acted on by the agent.

When a printer_control policy is active with scope "allowlist", a print job
is allowed only if its printer NAME has an enabled allow-decision row here.
A deny-decision row is different: it's checked in EVERY scope (not just
allowlist) and blocks that printer regardless of what else is or isn't
enrolled -- see SanctionedPrinter's docstring. Printers are matched on
``printer_name`` (what an endpoint would report at print time). Writes
admin-only, reads analyst.
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
    decision: str = Field("allow", description="'allow' (default) or 'deny' — deny is a sticky, audited rejection checked in every scope")
    notes: Optional[str] = Field(None, max_length=1000)


class PrinterUpdate(BaseModel):
    label: Optional[str] = Field(None, max_length=255)
    decision: Optional[str] = Field(None, description="'allow' or 'deny' — switch a row's decision after the fact")
    notes: Optional[str] = Field(None, max_length=1000)
    is_enabled: Optional[bool] = None


SCOPE_VALUES = ("block_all", "block_network", "block_local", "allowlist")


class EnforcementUpdate(BaseModel):
    enabled: bool = Field(..., description="Turn printer control enforcement on/off")
    scope: str = Field(
        "allowlist",
        description="'block_all' (no printer at all) | 'block_network' | 'block_local' | "
                    "'allowlist' (only sanctioned-printer rows below) -- same options as the "
                    "printer_control policy type in the general Policy Creator, since this "
                    "endpoint finds-or-creates that same policy row.",
    )
    mode: str = Field(
        "enforce",
        description="'enforce' (actually cancel matching print jobs) or 'audit' (log only)",
    )


def _printer_out(p: SanctionedPrinter) -> dict:
    return {
        "id": str(p.id),
        "printer_name": p.printer_name,
        "label": p.label,
        "printer_type": p.printer_type,
        "decision": p.decision or "allow",
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
    """Whether printer control is enforced, plus its scope/mode -- mirrors
    the normalization agents.py's get_printer_policy() applies, so this
    page's badge/description always describes what the agent will actually
    do rather than assuming allowlist/enforce. A printer_control policy can
    be created or edited through the general Policy Creator
    (PrinterControlPolicyForm.tsx) with any of the four scopes and either
    mode -- this reads back whatever that produced instead of guessing."""
    policy = await _allowlist_policy(db)
    enforced = bool(policy and policy.status == "active")
    cfg = (policy.config or {}) if policy else {}
    scope = str(cfg.get("scope") or "block_network").lower() if enforced else "none"
    if scope not in SCOPE_VALUES:
        scope = "block_network"
    mode = str(cfg.get("mode") or "enforce").lower() if enforced else "off"
    if mode not in ("enforce", "audit"):
        mode = "enforce"
    return {"enforced": enforced, "scope": scope, "mode": mode}


@router.get("/")
async def list_printers(
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """The sanctioned-printer registry, plus whether allowlist enforcement is on.

    Returns both allow- and deny-decisioned rows in ``printers`` (each tagged
    with its ``decision``) — the dashboard splits them into "Sanctioned" and
    "Disallowed" sections client-side, same pattern as USB Devices."""
    rows = (await db.execute(
        select(SanctionedPrinter).order_by(SanctionedPrinter.approved_at.desc())
    )).scalars().all()
    printers = [_printer_out(p) for p in rows]
    status_ = await _allowlist_status(db)
    return {
        "printers": printers,
        "count": len(printers),
        "enabled_count": sum(1 for p in printers if p["is_enabled"]),
        "allow_count": sum(1 for p in printers if p["decision"] == "allow"),
        "deny_count": sum(1 for p in printers if p["decision"] == "deny"),
        **status_,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def approve_printer(
    body: PrinterApprove,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Approve (allow) or disallow (deny) a printer by name, per
    ``body.decision``. Idempotent: re-submitting an existing name updates its
    details (including flipping its decision) and re-enables it."""
    name = body.printer_name.strip()
    if not name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "printer_name is required")
    decision = body.decision if body.decision in ("allow", "deny") else "allow"

    existing = (await db.execute(
        select(SanctionedPrinter).where(SanctionedPrinter.printer_name == name)
    )).scalar_one_or_none()

    audit_action = "security.printers.reapprove" if decision == "allow" else "security.printers.redeny"

    if existing:
        existing.label = body.label or existing.label
        existing.printer_type = body.printer_type or existing.printer_type
        existing.decision = decision
        existing.notes = body.notes if body.notes is not None else existing.notes
        existing.is_enabled = True
        existing.approved_by = current_user.id
        existing.approved_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(existing)
        await audit_log(current_user.id, audit_action, {"printer_name": name, "decision": decision})
        return _printer_out(existing)

    p = SanctionedPrinter(
        printer_name=name, label=body.label, printer_type=body.printer_type,
        decision=decision, notes=body.notes, approved_by=current_user.id,
    )
    db.add(p)
    await db.commit()
    await db.refresh(p)
    audit_action = "security.printers.approve" if decision == "allow" else "security.printers.deny"
    await audit_log(current_user.id, audit_action, {"printer_name": name, "decision": decision})
    return _printer_out(p)


@router.patch("/{printer_id}")
async def update_printer(
    printer_id: str,
    body: PrinterUpdate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Edit a printer's label/notes, flip its allow/deny decision, or
    suspend/resume its approval."""
    p = (await db.execute(
        select(SanctionedPrinter).where(SanctionedPrinter.id == printer_id)
    )).scalar_one_or_none()
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "printer not found")
    if body.label is not None:
        p.label = body.label
    if body.decision is not None:
        if body.decision not in ("allow", "deny"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "decision must be 'allow' or 'deny'")
        p.decision = body.decision
    if body.notes is not None:
        p.notes = body.notes
    if body.is_enabled is not None:
        p.is_enabled = body.is_enabled
    await db.commit()
    await db.refresh(p)
    await audit_log(current_user.id, "security.printers.update", {
        "printer_name": p.printer_name, "decision": p.decision,
    })
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
    """Turn printer control enforcement on/off, and set its scope/mode, by
    finding-or-creating the single backing ``printer_control`` policy row --
    the SAME row the general Policy Creator's PrinterControlPolicyForm edits.

    This used to hardcode ``scope: "allowlist"`` on every call regardless of
    what body.scope said (the field didn't even exist), so clicking On/Off
    here could silently clobber a block_all/block_network/block_local or
    audit-mode configuration an admin had set up through the Policy Creator
    -- the policy row is shared, but only this endpoint's opinion of scope
    ever got written. Persisting the caller's actual scope/mode instead
    means both control surfaces agree on what's enforced.

    Acted on by the agent (see get_printer_policy() in agents.py and
    ShouldBlockPrinter() in agent.cpp). Deny-decision rows are enforced
    regardless of scope, in every scope.
    """
    scope = body.scope if body.scope in SCOPE_VALUES else "allowlist"
    mode = body.mode if body.mode in ("enforce", "audit") else "enforce"
    policy = await _allowlist_policy(db)
    if policy:
        policy.status = "active" if body.enabled else "inactive"
        policy.config = {**(policy.config or {}), "scope": scope, "mode": mode}
        policy.updated_at = datetime.now(timezone.utc)
    else:
        policy = Policy(
            name=PRINTER_CONTROL_POLICY_NAME,
            description="Restricts printing per the configured scope (all / network / local / allowlist).",
            status="active" if body.enabled else "inactive",
            priority=100,
            type=PRINTER_CONTROL_TYPE,
            domain="threat",
            severity="medium",
            config={"scope": scope, "mode": mode},
            conditions={},
            actions={},
            compliance_tags=[],
            created_by=current_user.id,
        )
        db.add(policy)
    await db.commit()
    await audit_log(current_user.id, "security.printers.enforcement", {"enabled": body.enabled, "scope": scope, "mode": mode})
    return await _allowlist_status(db)
