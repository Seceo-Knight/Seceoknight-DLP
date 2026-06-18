"""
Data Discovery Scan API Endpoints
Create and monitor scan jobs and their results
"""

from typing import Optional, List
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field, ConfigDict
import structlog

from app.core.security import get_current_user, require_role
from app.core.database import get_db
from app.services.scan_service import ScanService
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()
router = APIRouter()


# --------------- Pydantic Models ---------------

class ScanJobCreate(BaseModel):
    target: str = Field(..., min_length=1, description="Scan target (endpoint, path, database, etc.)")


class ScanJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime


class ScanResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    job_id: UUID
    file_path: str
    label_id: Optional[UUID] = None
    matched_rule: Optional[UUID] = None
    created_at: datetime


# --------------- Endpoints ---------------

@router.post("/", response_model=ScanJobOut, status_code=status.HTTP_201_CREATED)
async def create_scan_job(
    body: ScanJobCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """Create a new data-discovery scan job. Requires analyst role."""
    svc = ScanService(db)
    job = await svc.create_job(body.target)
    await db.commit()
    await db.refresh(job)
    return job


@router.get("/", response_model=List[ScanJobOut])
async def list_scan_jobs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List scan jobs with optional status filter."""
    svc = ScanService(db)
    return await svc.list_jobs(skip=skip, limit=limit, status=status_filter)


@router.get("/{job_id}", response_model=ScanJobOut)
async def get_scan_job(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get details of a specific scan job."""
    svc = ScanService(db)
    job = await svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    return job


@router.get("/{job_id}/results", response_model=List[ScanResultOut])
async def get_scan_results(
    job_id: UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get results for a specific scan job."""
    svc = ScanService(db)
    # Verify job exists
    job = await svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    return await svc.get_results(job_id, skip=skip, limit=limit)
