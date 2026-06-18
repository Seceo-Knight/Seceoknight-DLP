"""
Incidents API Endpoints
Security incident management and tracking
"""

from typing import Optional, List, Any
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import get_current_user, require_role
from app.core.database import get_db
from app.services.incident_service import IncidentService

logger = structlog.get_logger()
router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class IncidentCreate(BaseModel):
    event_id: Optional[str] = None
    severity: int = Field(default=2, ge=0, le=4, description="0=info, 1=low, 2=medium, 3=high, 4=critical")
    title: Optional[str] = Field(default=None, max_length=500)
    description: Optional[str] = None
    policy_id: Optional[UUID] = None


class IncidentUpdate(BaseModel):
    status: Optional[str] = Field(default=None, description="open, investigating, resolved, closed")
    assigned_to: Optional[UUID] = None


class CommentCreate(BaseModel):
    comment: str = Field(..., min_length=1)


class CommentOut(BaseModel):
    id: str
    incident_id: str
    user_id: Optional[str] = None
    comment: str
    created_at: datetime

    class Config:
        from_attributes = True


class IncidentOut(BaseModel):
    id: str
    event_id: Optional[str] = None
    severity: int
    status: str
    assigned_to: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    policy_id: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class IncidentDetailOut(IncidentOut):
    comments: List[CommentOut] = []


class IncidentListResponse(BaseModel):
    incidents: List[IncidentOut]
    total: int


class IncidentStatisticsResponse(BaseModel):
    total: int
    status_counts: dict
    severity_counts: dict


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _incident_to_out(incident: Any) -> IncidentOut:
    d = incident.to_dict()
    return IncidentOut(
        id=d["id"],
        event_id=d["event_id"],
        severity=d["severity"],
        status=d["status"],
        assigned_to=d["assigned_to"],
        title=d["title"],
        description=d["description"],
        policy_id=d["policy_id"],
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


def _comment_to_out(comment: Any) -> CommentOut:
    d = comment.to_dict()
    return CommentOut(
        id=d["id"],
        incident_id=d["incident_id"],
        user_id=d["user_id"],
        comment=d["comment"],
        created_at=comment.created_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", response_model=IncidentListResponse)
async def list_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[int] = Query(None, ge=0, le=4),
    status: Optional[str] = Query(None),
    assigned_to: Optional[UUID] = Query(None),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List incidents with optional filtering (ABAC-scoped via underlying event)."""
    from app.services.abac_service import build_abac_sql_filter

    abac = await build_abac_sql_filter(db, current_user)

    svc = IncidentService(db)
    incidents = await svc.list_incidents(
        skip=skip,
        limit=limit,
        severity=severity,
        status=status,
        assigned_to=assigned_to,
        abac_clause=abac,
    )
    total = await svc.count_incidents_abac(
        severity=severity,
        status=status,
        assigned_to=assigned_to,
        abac_clause=abac,
    )
    return IncidentListResponse(
        incidents=[_incident_to_out(i) for i in incidents],
        total=total,
    )


@router.get("/statistics", response_model=IncidentStatisticsResponse)
async def get_statistics(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get incident statistics (counts by status and severity), ABAC-scoped."""
    from app.services.abac_service import build_abac_sql_filter

    abac = await build_abac_sql_filter(db, current_user)
    svc = IncidentService(db)
    stats = await svc.get_statistics(abac_clause=abac)
    return IncidentStatisticsResponse(**stats)


@router.get("/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(
    incident_id: UUID,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single incident with its comments (ABAC-scoped)."""
    from app.services.abac_service import build_abac_sql_filter
    abac = await build_abac_sql_filter(db, current_user)

    svc = IncidentService(db)
    incident = await svc.get_incident(incident_id, abac_clause=abac)
    if not incident:
        # If a row exists but ABAC filtered it out, this is a DENY not a 404.
        # We surface 404 to the user either way (avoid existence oracles).
        if abac is not None:
            exists = await svc.get_incident(incident_id, abac_clause=None)
            if exists is not None:
                try:
                    from app.services.audit_service import audit_abac_deny
                    await audit_abac_deny(
                        user=current_user,
                        resource_type="incident",
                        resource_id=str(incident_id),
                        reason="dept_or_clearance_mismatch",
                    )
                except Exception:
                    pass
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    comments = await svc.get_comments(incident_id)

    out = IncidentDetailOut(
        **_incident_to_out(incident).model_dump(),
        comments=[_comment_to_out(c) for c in comments],
    )
    return out


@router.post("/", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
async def create_incident(
    body: IncidentCreate,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new incident. Requires analyst role."""
    svc = IncidentService(db)
    incident = await svc.create_incident(
        event_id=body.event_id,
        severity=body.severity,
        title=body.title,
        description=body.description,
        policy_id=body.policy_id,
    )
    await db.commit()
    await db.refresh(incident)

    logger.info(
        "incident_created_via_api",
        incident_id=str(incident.id),
        severity=body.severity,
    )
    return _incident_to_out(incident)


@router.patch("/{incident_id}", response_model=IncidentOut)
async def update_incident(
    incident_id: UUID,
    body: IncidentUpdate,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Update incident status and/or assignment. Requires analyst role."""
    svc = IncidentService(db)
    incident = await svc.update_incident(
        incident_id=incident_id,
        status=body.status,
        assigned_to=body.assigned_to,
    )
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    await db.commit()
    await db.refresh(incident)

    logger.info(
        "incident_updated_via_api",
        incident_id=str(incident_id),
        new_status=body.status,
    )
    return _incident_to_out(incident)


@router.post("/{incident_id}/comments", response_model=CommentOut, status_code=status.HTTP_201_CREATED)
async def add_comment(
    incident_id: UUID,
    body: CommentCreate,
    current_user: dict = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Add a comment to an incident"""
    svc = IncidentService(db)

    # Verify the incident exists
    incident = await svc.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    user_id = current_user.get("id") or current_user.get("user_id")
    comment = await svc.add_comment(
        incident_id=incident_id,
        user_id=user_id,
        comment_text=body.comment,
    )
    await db.commit()
    await db.refresh(comment)

    return _comment_to_out(comment)


@router.get("/{incident_id}/comments", response_model=List[CommentOut])
async def list_comments(
    incident_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all comments for an incident"""
    svc = IncidentService(db)

    # Verify the incident exists
    incident = await svc.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    comments = await svc.get_comments(incident_id)
    return [_comment_to_out(c) for c in comments]


# ---------------------------------------------------------------------------
# MongoDB-backed auto-incident endpoints
# ---------------------------------------------------------------------------

from app.core.database import get_mongodb
from datetime import timezone


@router.get("/auto/list")
async def list_auto_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[int] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(get_current_user),
    pg_db: AsyncSession = Depends(get_db),
):
    """List auto-generated incidents from MongoDB (ABAC-scoped).

    Auto-incident docs carry the source event's ``department`` and
    ``required_clearance`` (stamped at creation; see events.py). The same
    Mongo filter we use for dlp_events applies unchanged here.
    """
    from app.services.abac_service import (
        build_abac_mongo_filter,
        merge_mongo_filter,
    )

    db = get_mongodb()
    col = db["incidents"]
    abac = await build_abac_mongo_filter(pg_db, current_user)

    query: dict = {}
    if status:
        query["status"] = status
    if severity is not None:
        query["severity"] = severity
    query = merge_mongo_filter(query, abac)

    cursor = col.find(query).sort("created_at", -1).limit(limit)
    incidents = []
    async for doc in cursor:
        doc.pop("_id", None)
        for f in ("created_at", "updated_at"):
            if f in doc and isinstance(doc[f], datetime):
                doc[f] = doc[f].isoformat()
        incidents.append(doc)

    # Stats (ABAC-scoped) — same dept/clearance filter merged with status.
    stats_base = merge_mongo_filter({}, abac)
    stats = {
        "total": await col.count_documents(stats_base),
        "open": await col.count_documents(
            merge_mongo_filter({**stats_base, "status": "open"}, None)
        ),
        "investigating": await col.count_documents(
            merge_mongo_filter({**stats_base, "status": "investigating"}, None)
        ),
        "resolved": await col.count_documents(
            merge_mongo_filter({**stats_base, "status": "resolved"}, None)
        ),
    }

    from app.services.audit_service import log_abac_scope
    log_abac_scope(
        current_user,
        endpoint="GET /incidents/auto/list",
        visible_count=stats.get("total", 0),
        extra={"has_abac_filter": abac is not None},
    )
    return {"incidents": incidents, "stats": stats}


@router.patch("/auto/{incident_id}")
async def update_auto_incident(
    incident_id: str,
    update: IncidentUpdate,
    current_user=Depends(get_current_user),
    pg_db: AsyncSession = Depends(get_db),
):
    """Update an auto-generated incident status/assignment (ABAC-scoped)."""
    from app.services.abac_service import (
        build_abac_mongo_filter,
        merge_mongo_filter,
    )

    db = get_mongodb()
    col = db["incidents"]
    abac = await build_abac_mongo_filter(pg_db, current_user)

    update_fields: dict = {"updated_at": datetime.now(timezone.utc)}
    if update.status:
        update_fields["status"] = update.status
    if update.assigned_to:
        update_fields["assigned_to"] = str(update.assigned_to)

    # Lookups honour ABAC — callers cannot update a doc they can't see.
    result = await col.update_one(
        merge_mongo_filter({"id": incident_id}, abac),
        {"$set": update_fields},
    )
    if result.matched_count == 0:
        result = await col.update_one(
            merge_mongo_filter({"event_id": incident_id}, abac),
            {"$set": update_fields},
        )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {"status": "updated"}


@router.get("/auto/{incident_id}")
async def get_auto_incident(
    incident_id: str,
    current_user=Depends(get_current_user),
    pg_db: AsyncSession = Depends(get_db),
):
    """Get a single auto-generated incident with related events (ABAC-scoped)."""
    from app.services.abac_service import (
        build_abac_mongo_filter,
        merge_mongo_filter,
    )

    db = get_mongodb()
    col = db["incidents"]
    events_col = db["dlp_events"]
    abac = await build_abac_mongo_filter(pg_db, current_user)

    doc = await col.find_one(
        merge_mongo_filter(
            {"$or": [{"id": incident_id}, {"event_id": incident_id}]},
            abac,
        )
    )
    if not doc:
        # Audit the denial (distinguishable from a true not-found only in logs).
        try:
            from app.services.audit_service import audit_abac_deny
            await audit_abac_deny(
                user=current_user,
                resource_type="incident_auto",
                resource_id=incident_id,
                reason="not_found_or_dept_mismatch",
            )
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="Incident not found")

    doc.pop("_id", None)
    for f in ("created_at", "updated_at"):
        if f in doc and isinstance(doc[f], datetime):
            doc[f] = doc[f].isoformat()

    # Get related events (same user, same hour)
    related = []
    if doc.get("user_email"):
        cursor = events_col.find({
            "user_email": doc["user_email"],
            "severity": {"$in": ["critical", "high"]},
        }).sort("timestamp", -1).limit(20)
        async for ev in cursor:
            ev.pop("_id", None)
            for f in ("timestamp", "created_at", "processed_at"):
                if f in ev and isinstance(ev[f], datetime):
                    ev[f] = ev[f].isoformat()
            related.append(ev)

    doc["related_events"] = related
    return doc
