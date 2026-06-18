"""
File Fingerprint API Endpoints
Manage known file hashes for exact-match classification
"""

from typing import Optional, List
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field, ConfigDict
import structlog

from app.core.security import get_current_user, require_role
from app.core.database import get_db
from app.services.fingerprint_service import FingerprintService
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()
router = APIRouter()


# --------------- Pydantic Models ---------------

class FingerprintCreate(BaseModel):
    hash: str = Field(..., min_length=1, max_length=128, description="SHA-256 hash of the file content")
    file_name: Optional[str] = Field(None, max_length=500, description="Original file name")
    label_id: Optional[str] = Field(None, description="Associated data-label UUID")


class FingerprintFromContent(BaseModel):
    content: str = Field(..., min_length=1, description="Raw text content to fingerprint")
    file_name: Optional[str] = Field(None, max_length=500, description="Original file name")
    label_id: Optional[str] = Field(None, description="Associated data-label UUID")


class FingerprintCheck(BaseModel):
    hash: str = Field(..., min_length=1, max_length=128, description="SHA-256 hash to look up")


class FingerprintOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    hash: str
    file_name: Optional[str] = None
    label_id: Optional[UUID] = None
    created_at: datetime


# --------------- Endpoints ---------------

@router.post("/", response_model=FingerprintOut, status_code=status.HTTP_201_CREATED)
async def add_fingerprint(
    body: FingerprintCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """Register a known file fingerprint (hash). Requires analyst role —
    a malicious VIEWER could otherwise add false fingerprints to bypass
    detection."""
    svc = FingerprintService(db)

    existing = await svc.get_by_hash(body.hash)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A fingerprint with this hash already exists",
        )

    label_uuid = UUID(body.label_id) if body.label_id else None
    fp = await svc.add_fingerprint(body.hash, body.file_name, label_uuid)
    await db.commit()
    await db.refresh(fp)
    return fp


@router.post("/from-content", response_model=FingerprintOut, status_code=status.HTTP_201_CREATED)
async def add_fingerprint_from_content(
    body: FingerprintFromContent,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """Compute a SHA-256 hash from raw content and register it."""
    svc = FingerprintService(db)
    computed_hash = FingerprintService.compute_hash(body.content)

    existing = await svc.get_by_hash(computed_hash)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A fingerprint with this hash already exists",
        )

    label_uuid = UUID(body.label_id) if body.label_id else None
    fp = await svc.add_fingerprint(computed_hash, body.file_name, label_uuid)
    await db.commit()
    await db.refresh(fp)
    return fp


@router.post("/check", response_model=FingerprintOut)
async def check_fingerprint(
    body: FingerprintCheck,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Check whether a hash exists in the fingerprint store."""
    svc = FingerprintService(db)
    fp = await svc.get_by_hash(body.hash)
    if not fp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No matching fingerprint found")
    return fp


@router.get("/", response_model=List[FingerprintOut])
async def list_fingerprints(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    label_id: Optional[UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List registered fingerprints with optional label filter."""
    svc = FingerprintService(db)
    return await svc.list_fingerprints(skip=skip, limit=limit, label_id=label_id)


@router.delete("/{fingerprint_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_fingerprint(
    fingerprint_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """Delete a fingerprint by ID."""
    svc = FingerprintService(db)
    deleted = await svc.delete_fingerprint(fingerprint_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Fingerprint not found")
    await db.commit()
