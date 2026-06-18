"""
Audit Log API Endpoints
Query immutable audit trail of user and system actions
"""

from typing import Optional, List
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import get_current_user, require_role
from app.core.database import get_db
from app.services.audit_service import AuditService

logger = structlog.get_logger()
router = APIRouter()


class AuditLogOut(BaseModel):
    id: str
    user_id: Optional[str] = None
    action: str
    details: Optional[dict] = None
    created_at: datetime


class AuditLogListResponse(BaseModel):
    logs: List[AuditLogOut]
    total: int


@router.get("/", response_model=AuditLogListResponse)
async def list_audit_logs(
    user_id: Optional[UUID] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    start_date: Optional[datetime] = Query(None, description="Filter from date"),
    end_date: Optional[datetime] = Query(None, description="Filter to date"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    List audit logs with optional filters.

    SECURITY: admin role required. Audit logs include every admin
    action and login event across all users; must not be readable by
    VIEWERs or analysts.
    """
    svc = AuditService(db)
    logs = await svc.get_logs(
        skip=skip,
        limit=limit,
        user_id=user_id,
        action=action,
        start_date=start_date,
        end_date=end_date,
    )
    total = await svc.count_logs(
        user_id=user_id,
        action=action,
        start_date=start_date,
        end_date=end_date,
    )
    return {
        "logs": [
            AuditLogOut(
                id=str(log.id),
                user_id=str(log.user_id) if log.user_id else None,
                action=log.action,
                details=log.details,
                created_at=log.created_at,
            )
            for log in logs
        ],
        "total": total,
    }


@router.get("/actions", response_model=List[str])
async def list_audit_actions(
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    List distinct action types for filter dropdowns.
    """
    svc = AuditService(db)
    return await svc.get_distinct_actions()
