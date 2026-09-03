"""
Behavioral risk-scoring API -- SeceoKnight-original (task #120).

Surfaces app/services/risk_scoring_service.py: a per-user 0-100 score built
from event volume, channel diversity, off-hours activity, block ratio, and
severity mix over a rolling window, computed from data both SeceoKnight and
CyberSentinel already collect (the Event table) but that neither product
currently aggregates across events or channels -- both only ever look at
one event at a time. See risk_scoring_service.py's module docstring for the
full rationale and the exact scoring algorithm.

No scheduler is wired up in this pass -- there's no way to verify a
cron-style background job actually fires correctly without a running
deployment to observe it in. POST /risk-scoring/recompute is the interim
trigger; wiring an APScheduler/Celery-beat job to call it periodically
(e.g. hourly) is a natural follow-up once this can be tested against a
real database with real event volume.
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_role
from app.services.risk_scoring_service import RiskScoringService

router = APIRouter()


@router.get("/users")
async def list_risk_scores(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    min_level: Optional[str] = Query(
        None, pattern="^(low|medium|high|critical)$",
        description="Only return users at or above this risk level."),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """Ranked risk scores, highest first. Returns an empty list if
    recompute has never been run -- see POST /recompute."""
    svc = RiskScoringService(db)
    scores = await svc.list_scores(limit=limit, offset=offset, min_level=min_level)
    counts = await svc.count_by_level()
    return {
        "scores": [s.to_dict() for s in scores],
        "counts_by_level": counts,
    }


@router.get("/users/{user_email}")
async def get_risk_score(
    user_email: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """One user's score plus the breakdown and the most recent events that
    fed into it -- a score is never returned without a way to see why."""
    svc = RiskScoringService(db)
    score = await svc.get_score(user_email)
    if not score:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                             "No risk score for this user yet -- try POST /risk-scoring/recompute")
    recent_events = await svc.get_recent_events_for_user(
        user_email, limit=50,
        window_start=score.window_start, window_end=score.window_end,
    )
    return {
        **score.to_dict(),
        "recent_events": [e.to_dict() for e in recent_events],
    }


@router.post("/recompute", status_code=status.HTTP_200_OK)
async def recompute_risk_scores(
    window_days: int = Query(14, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    """Recompute every user's score from the last `window_days` of events.
    Admin-only: this is a real (if cheap) query over the events table, and
    while read-only in effect, triggering it shouldn't be exposed to every
    analyst. Idempotent -- safe to call from an external scheduler."""
    svc = RiskScoringService(db)
    updated = await svc.recompute_all(window_days=window_days)
    return {
        "recomputed_users": len(updated),
        "window_days": window_days,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }
