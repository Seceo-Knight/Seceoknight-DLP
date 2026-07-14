"""
System settings API — admin-portal-managed log-retention policy.

Retention is DB-backed (``retention_config``) with the RETENTION env values as
the fallback default. A hard 90-day floor is enforced here and by a DB CHECK,
so the policy can never be set below the compliance minimum.
"""
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_role
from app.core.config import settings
from app.core.database import get_db
from app.models.retention_config import RetentionConfig, MIN_RETENTION_DAYS
from app.services.audit_service import audit_log

router = APIRouter()


def _uid(user):
    return getattr(user, "id", None) if not isinstance(user, dict) else user.get("sub")


class RetentionUpdate(BaseModel):
    event_retention_days: int
    opensearch_retention_days: int


def _retention_out(row: Optional[RetentionConfig]) -> Dict[str, Any]:
    if row is None:  # env fallback (clamped to the floor)
        return {
            "event_retention_days": max(MIN_RETENTION_DAYS, settings.EVENT_RETENTION_DAYS),
            "opensearch_retention_days": max(MIN_RETENTION_DAYS, settings.OPENSEARCH_RETENTION_DAYS),
            "minimum_days": MIN_RETENTION_DAYS,
            "source": "environment",
            "updated_at": None,
        }
    return {
        "event_retention_days": row.event_retention_days,
        "opensearch_retention_days": row.opensearch_retention_days,
        "minimum_days": MIN_RETENTION_DAYS,
        "source": "database",
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.get("/retention")
async def get_retention(
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(RetentionConfig).where(RetentionConfig.id == 1))).scalar_one_or_none()
    return _retention_out(row)


@router.put("/retention")
async def update_retention(
    body: RetentionUpdate,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    if body.event_retention_days < MIN_RETENTION_DAYS or body.opensearch_retention_days < MIN_RETENTION_DAYS:
        raise HTTPException(400, f"Retention must be at least {MIN_RETENTION_DAYS} days for compliance.")
    row = (await db.execute(select(RetentionConfig).where(RetentionConfig.id == 1))).scalar_one_or_none()
    if row is None:
        row = RetentionConfig(id=1)
        db.add(row)
    row.event_retention_days = body.event_retention_days
    row.opensearch_retention_days = body.opensearch_retention_days
    row.updated_by = _uid(current_user)
    await db.commit()
    await db.refresh(row)
    await audit_log(_uid(current_user), "system.retention.update",
                    {"event_retention_days": row.event_retention_days,
                     "opensearch_retention_days": row.opensearch_retention_days})
    return _retention_out(row)
