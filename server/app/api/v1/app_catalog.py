"""
App catalog management — the destination classification Web Activity
Control policies key off. See server/app/models/app_catalog.py and
migration 039_app_catalog for the seeded baseline and rationale.

Writes admin-only, reads analyst -- same RBAC pattern as printers.py/
usb_devices.py/ip_allowlist.py.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import require_role
from app.core.database import get_db
from app.core.web_activity import APP_CATEGORIES
from app.models.user import User
from app.models.app_catalog import AppCatalogEntry
from app.services.audit_service import audit_log

logger = structlog.get_logger()
router = APIRouter()


class AppCatalogCreate(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255, description="Hostname or domain suffix — the match key")
    category: str = Field(..., description="webmail | file_sharing | collaboration | genai")
    vendor_name: Optional[str] = Field(None, max_length=255)


class AppCatalogUpdate(BaseModel):
    category: Optional[str] = None
    vendor_name: Optional[str] = Field(None, max_length=255)


def _entry_out(e: AppCatalogEntry) -> dict:
    return {
        "id": str(e.id),
        "domain": e.domain,
        "category": e.category,
        "vendor_name": e.vendor_name,
        "is_builtin": e.is_builtin,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


@router.get("/")
async def list_app_catalog(
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """The full destination catalog (seeded baseline + admin-added), grouped
    by category counts for the dashboard summary."""
    rows = (await db.execute(
        select(AppCatalogEntry).order_by(AppCatalogEntry.category, AppCatalogEntry.domain)
    )).scalars().all()
    entries = [_entry_out(e) for e in rows]
    counts = {c: sum(1 for e in entries if e["category"] == c) for c in APP_CATEGORIES}
    return {"entries": entries, "count": len(entries), "counts_by_category": counts, "categories": APP_CATEGORIES}


@router.post("/", status_code=status.HTTP_201_CREATED)
async def add_app_catalog_entry(
    body: AppCatalogCreate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Add a destination on top of the seeded baseline. Idempotent:
    re-submitting an existing domain updates its category/vendor name."""
    domain = body.domain.strip().lower()
    if not domain:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "domain is required")
    if body.category not in APP_CATEGORIES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"category must be one of {APP_CATEGORIES}")

    existing = (await db.execute(
        select(AppCatalogEntry).where(AppCatalogEntry.domain == domain)
    )).scalar_one_or_none()

    if existing:
        existing.category = body.category
        existing.vendor_name = body.vendor_name or existing.vendor_name
        await db.commit()
        await db.refresh(existing)
        await audit_log(current_user.id, "security.app_catalog.update", {"domain": domain, "category": body.category})
        return _entry_out(existing)

    e = AppCatalogEntry(domain=domain, category=body.category, vendor_name=body.vendor_name, is_builtin=False)
    db.add(e)
    await db.commit()
    await db.refresh(e)
    await audit_log(current_user.id, "security.app_catalog.add", {"domain": domain, "category": body.category})
    return _entry_out(e)


@router.patch("/{entry_id}")
async def update_app_catalog_entry(
    entry_id: str,
    body: AppCatalogUpdate,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    e = (await db.execute(
        select(AppCatalogEntry).where(AppCatalogEntry.id == entry_id)
    )).scalar_one_or_none()
    if not e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "entry not found")
    if body.category is not None:
        if body.category not in APP_CATEGORIES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"category must be one of {APP_CATEGORIES}")
        e.category = body.category
    if body.vendor_name is not None:
        e.vendor_name = body.vendor_name
    await db.commit()
    await db.refresh(e)
    await audit_log(current_user.id, "security.app_catalog.update", {"domain": e.domain, "category": e.category})
    return _entry_out(e)


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_app_catalog_entry(
    entry_id: str,
    current_user: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """Remove an entry. Builtin (seeded) entries can be removed too --
    ``is_builtin`` is display-only, not a protection flag; the migration
    won't re-add a deleted row on the next deploy since it's INSERT ... ON
    CONFLICT DO NOTHING."""
    res = await db.execute(delete(AppCatalogEntry).where(AppCatalogEntry.id == entry_id))
    await db.commit()
    if res.rowcount == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "entry not found")
    await audit_log(current_user.id, "security.app_catalog.delete", {"entry_id": entry_id})
