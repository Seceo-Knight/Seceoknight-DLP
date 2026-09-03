"""
Dashboard API Endpoints
Real-time statistics and metrics for dashboard
Returns actual data from database (populated by agents)
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
import structlog

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.core.database import get_mongodb, get_db

logger = structlog.get_logger()
router = APIRouter()


@router.get("/overview")
async def get_dashboard_overview(
    hours: Optional[int] = Query(
        None, ge=1, le=2160,
        description="Restrict event-derived metrics to the last N hours (omit for all-time)",
    ),
    current_user=Depends(get_current_user),
    pg_db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get dashboard overview statistics (ABAC-scoped on event counts).

    Agent counts are *not* ABAC-gated — visibility of agents is an
    operational concern, not a DLP record. Event-derived metrics (total
    events / critical / blocked) respect the viewer's ABAC scope, and are
    scoped to the last `hours` hours when given -- this mirrors the
    dashboard's time-range selector so "Total Events" etc. actually change
    when the user picks a different window instead of always showing an
    all-time count next to a chart that's showing 24h.
    """
    from datetime import datetime, timedelta, timezone
    from app.services.abac_service import (
        build_abac_mongo_filter,
        merge_mongo_filter,
    )

    db = get_mongodb()
    abac = await build_abac_mongo_filter(pg_db, current_user)

    # Query agents from MongoDB
    agents_collection = db["agents"]

    # Total agents
    total_agents = await agents_collection.count_documents({})

    # Active agents (agents with a recent heartbeat). Reuses agents.py's
    # AGENT_TIMEOUT_SECONDS (5 min, sized for the default 30s heartbeat
    # interval plus room for network jitter / brief drops) rather than a
    # locally-hardcoded value. This tile used to define "active" as
    # last_seen within 60 SECONDS -- a completely different, much tighter
    # threshold than the Agents page (which uses the 5-minute window
    # everywhere: the default agent list, lifecycle_status, etc). With a
    # 30s heartbeat interval, 60s leaves almost no slack, so this tile
    # could show 0 active agents while the Agents page correctly showed
    # the same agent as online -- two different definitions of "active"
    # disagreeing with each other on the same dashboard.
    #
    # Deliberately NOT scoped by the `hours` time-range filter -- "active"
    # is a live/current-state concept, not a historical one, so it stays
    # the same regardless of which reporting window is selected.
    from app.api.v1.agents import AGENT_TIMEOUT_SECONDS
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=AGENT_TIMEOUT_SECONDS)
    cutoff_naive = datetime.utcnow() - timedelta(seconds=AGENT_TIMEOUT_SECONDS)

    active_agents = await agents_collection.count_documents({
        "$or": [
            {"last_seen": {"$gte": cutoff_time}},
            {"last_seen": {"$gte": cutoff_naive}},
        ]
    })

    # Query events from MongoDB (using correct collection name)
    events_collection = db.dlp_events

    time_filter: Dict[str, Any] = {}
    if hours is not None:
        time_filter = {"timestamp": {"$gte": datetime.utcnow() - timedelta(hours=hours)}}

    # Total events (all time, or last `hours`), ABAC-scoped
    total_events = await events_collection.count_documents(
        merge_mongo_filter(dict(time_filter), abac)
    )

    # Critical alerts/events, ABAC-scoped
    critical_alerts = await events_collection.count_documents(
        merge_mongo_filter({**time_filter, "severity": "critical"}, abac)
    )

    # Blocked events, ABAC-scoped
    blocked_events = await events_collection.count_documents(
        merge_mongo_filter({**time_filter, "blocked": True}, abac)
    )

    return {
        "total_agents": total_agents,
        "active_agents": active_agents,
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "blocked_events": blocked_events,
    }


@router.get("/timeline")
async def get_event_timeline(
    hours: int = Query(24, ge=1, le=2160, description="Number of hours to retrieve (up to 90 days)"),
    current_user=Depends(get_current_user),
    pg_db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """
    Get event timeline data for charts (ABAC-scoped).

    Buckets by hour for ranges up to 7 days (168h); beyond that, buckets by
    day instead -- a 90-day range bucketed hourly would be ~2,160 points,
    which is unreadable on a line chart and would send a huge payload for
    no benefit. The dashboard's time-range selector offers 12h/24h/3d/7d
    (hourly) and 30d/90d (daily) to match.
    """
    from app.services.abac_service import (
        build_abac_mongo_filter,
        merge_mongo_filter,
    )

    db = get_mongodb()
    events_collection = db.dlp_events

    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)
    daily = hours > 168

    abac = await build_abac_mongo_filter(pg_db, current_user)
    match_stage = merge_mongo_filter({"timestamp": {"$gte": start_time}}, abac)

    # Aggregate events by hour (or by day for long ranges)
    pipeline = [
        {"$match": match_stage},
        {
            "$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%dT00:00:00Z" if daily else "%Y-%m-%dT%H:00:00Z",
                        "date": "$timestamp"
                    }
                },
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}}
    ]

    cursor = events_collection.aggregate(pipeline)
    timeline_data = []

    async for item in cursor:
        timeline_data.append({
            "timestamp": item["_id"],
            "count": item["count"],
        })

    return timeline_data


@router.get("/stats/agents")
async def get_agents_stats(
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get agent statistics

    Returns counts for:
    - total: All agents ever registered
    - active: Agents with heartbeat within last 5 minutes
    - disconnected: Agents that haven't sent heartbeat in over 5 minutes
    """
    from datetime import datetime, timedelta, timezone

    db = get_mongodb()
    agents_collection = db["agents"]

    # Agent is considered active if heartbeat within 5 seconds
    AGENT_TIMEOUT_SECONDS = 60
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=AGENT_TIMEOUT_SECONDS)
    cutoff_naive = datetime.utcnow() - timedelta(seconds=AGENT_TIMEOUT_SECONDS)

    # Total agents
    total = await agents_collection.count_documents({})

    # Active agents (recent heartbeat - handle both timezone-aware and naive datetimes)
    active = await agents_collection.count_documents({
        "$or": [
            {"last_seen": {"$gte": cutoff_time}},
            {"last_seen": {"$gte": cutoff_naive}},
        ]
    })

    # Disconnected agents (old heartbeat or no heartbeat)
    disconnected = await agents_collection.count_documents({
        "$and": [
            {"last_seen": {"$exists": True}},
            {
                "$and": [
                    {"last_seen": {"$lt": cutoff_time}},
                    {"last_seen": {"$lt": cutoff_naive}},
                ]
            }
        ]
    })

    return {
        "total": total,
        "active": active,
        "online": active,  # Keep for backwards compatibility
        "disconnected": disconnected,
        "offline": disconnected,  # Keep for backwards compatibility
        "warning": 0,  # Deprecated field
    }


@router.get("/stats/classification")
async def get_classification_stats(
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get data classification statistics
    """
    db = get_mongodb()
    files_collection = db["classified_files"]

    total = await files_collection.count_documents({})
    public = await files_collection.count_documents({"classification": "public"})
    internal = await files_collection.count_documents({"classification": "internal"})
    confidential = await files_collection.count_documents({"classification": "confidential"})
    restricted = await files_collection.count_documents({"classification": "restricted"})

    return {
        "total": total,
        "public": public,
        "internal": internal,
        "confidential": confidential,
        "restricted": restricted,
    }
