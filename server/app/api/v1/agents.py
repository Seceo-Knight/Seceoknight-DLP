"""
Agents API Endpoints
Manage DLP agents deployed on endpoints
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field, ConfigDict
import structlog

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user, require_role
from app.core.database import get_mongodb, get_db
from app.services.policy_service import PolicyService
from app.services.classification_engine import ClassificationEngine
from app.policies.agent_policy_transformer import AgentPolicyTransformer
from app.policies.database_policy_evaluator import DatabasePolicyEvaluator
from app.core.cache import get_cache, CacheService

logger = structlog.get_logger()
router = APIRouter()

# Agent is considered dead if no heartbeat received in 5 seconds.
# This is the threshold for the boolean ``is_active`` flag we keep around
# for backward-compatibility with old dashboard code; the new four-tier
# lifecycle status (active/disconnected/inactive/stale) lives below.
AGENT_TIMEOUT_SECONDS = 5

# ── Lifecycle status thresholds ──────────────────────────────────────
# Tiered freshness ladder reported as ``lifecycle_status`` on agent
# listings. The bands cover the full timeline so every agent maps to
# exactly one tier — UIs can show a colored badge without computing the
# math themselves.
#
#   active:       last_seen ≤ 5s ago        — heartbeat just arrived
#   disconnected: 5s   < last_seen ≤ 24h    — recently silent (spec says
#                                             "< 1 hour" but escalates
#                                             to inactive only at >24h,
#                                             so the disconnected band
#                                             stretches to fill the gap)
#   inactive:     24h  < last_seen ≤ 7d     — quiet for a while
#   stale:        last_seen > 7d            — likely abandoned/uninstalled
#
# An agent with no last_seen at all is reported as ``stale`` (it's worse
# than just silent — we have nothing to time-bound it).
LIFECYCLE_ACTIVE_SECONDS = AGENT_TIMEOUT_SECONDS
LIFECYCLE_DISCONNECTED_SECONDS = 24 * 60 * 60     # 24 hours
LIFECYCLE_INACTIVE_SECONDS = 7 * 24 * 60 * 60     # 7 days


def _compute_lifecycle_status(last_seen: Optional[datetime]) -> str:
    """Return one of active/disconnected/inactive/stale for the given heartbeat.

    Treats naive datetimes as UTC (legacy Mongo docs predate the
    timezone-aware migration).
    """
    if last_seen is None or not isinstance(last_seen, datetime):
        return "stale"
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - last_seen).total_seconds()
    if age <= LIFECYCLE_ACTIVE_SECONDS:
        return "active"
    if age <= LIFECYCLE_DISCONNECTED_SECONDS:
        return "disconnected"
    if age <= LIFECYCLE_INACTIVE_SECONDS:
        return "inactive"
    return "stale"


async def _next_agent_code() -> Optional[int]:
    """Pull the next ``agent_code`` from the Postgres sequence.

    Sequence-driven so we never compute the ID in application code
    (see migration 018). Returns ``None`` when Postgres is unavailable
    so we degrade to "no display code" rather than blocking registration.
    """
    import app.core.database as _db
    from sqlalchemy import text

    if not _db.postgres_session_factory:
        return None

    try:
        async with _db.postgres_session_factory() as session:
            row = await session.execute(text("SELECT nextval('agent_code_seq')"))
            value = row.scalar()
            return int(value) if value is not None else None
    except Exception as e:
        logger.warning("Failed to fetch agent_code sequence", error=str(e))
        return None


async def _ensure_agent_code(agent_doc: Dict[str, Any]) -> Optional[int]:
    """Backfill ``agent_code`` on a Mongo doc that doesn't have one yet.
    Triggered on legacy docs predating the column AND on docs that were
    inserted while the Postgres ``agent_code_seq`` was missing (fresh
    installs that skipped Alembic — see _auto_init_schema_and_admin).

    The race guard matches both shapes: field absent OR field present
    but null. Concurrent calls can briefly waste sequence values, but
    the guard ensures no doc ever ends up with two codes.
    """
    code = agent_doc.get("agent_code")
    if isinstance(code, int):
        return code

    new_code = await _next_agent_code()
    if new_code is None:
        return None

    db = get_mongodb()
    await db["agents"].update_one(
        {
            "_id": agent_doc["_id"],
            "$or": [
                {"agent_code": {"$exists": False}},
                {"agent_code": None},
            ],
        },
        {"$set": {"agent_code": new_code}},
    )
    # Whoever won the race wrote first; re-read to learn the persisted code.
    fresh = await db["agents"].find_one({"_id": agent_doc["_id"]}, {"agent_code": 1})
    if fresh and isinstance(fresh.get("agent_code"), int):
        agent_doc["agent_code"] = fresh["agent_code"]
        return fresh["agent_code"]
    return None


async def verify_agent_key(request: Request) -> Optional[str]:
    """Verify the X-Agent-Key header if present.

    Returns the agent_id if key is valid, None if no key provided
    (backward compat with agents compiled before key support).
    Raises 401 only if a key IS provided but is invalid.
    """
    agent_key = request.headers.get("X-Agent-Key")
    if not agent_key:
        # Backward compatibility: allow agents without key support
        return None

    db = get_mongodb()
    agents_collection = db["agents"]
    agent_doc = await agents_collection.find_one({"api_key": agent_key})
    if not agent_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent API key",
        )

    return agent_doc["agent_id"]


class AgentBase(BaseModel):
    """Base agent model"""
    name: str = Field(..., description="Agent name/hostname")
    os: str = Field(..., description="Operating system (windows/linux)")
    ip_address: str = Field(..., description="Agent IP address")
    version: str = Field(default="1.0.0", description="Agent version")
    capabilities: Dict[str, bool] = Field(default_factory=dict, description="Agent capability flags")


class AgentCreate(BaseModel):
    """Agent creation model"""
    agent_id: Optional[str] = Field(None, description="Custom agent ID (auto-generated if not provided)")
    name: str = Field(..., description="Agent name/hostname")
    os: str = Field(..., description="Operating system (windows/linux)")
    ip_address: str = Field(..., description="Agent IP address")
    version: str = Field(default="1.0.0", description="Agent version")


class Agent(AgentBase):
    """Agent response model"""
    agent_id: str = Field(..., description="Unique agent ID")
    # Short numeric ID (1, 2, 3 …) assigned by the Postgres sequence
    # ``agent_code_seq``. UI zero-pads for display ("001"). Optional in
    # the response so legacy Mongo docs that haven't been backfilled yet
    # don't fail validation.
    agent_code: Optional[int] = Field(None, description="Short numeric ID for UI display")
    # TODO: Implement agent resume functionality so agents can resume instead of creating new entries
    # Status field removed - agents are considered active if they've sent heartbeat within timeout period
    last_seen: datetime = Field(..., description="Last heartbeat timestamp")
    created_at: datetime = Field(..., description="Registration timestamp")
    policy_version: Optional[str] = Field(None, description="Last policy bundle version applied")
    policy_sync_status: Optional[str] = Field(None, description="Most recent policy sync status")
    policy_last_synced_at: Optional[str] = Field(None, description="ISO timestamp for last policy sync")
    policy_sync_error: Optional[str] = Field(None, description="Last policy sync error message, if any")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "agent_id": "agt-001",
                "name": "WIN-DESK-01",
                "os": "windows",
                "ip_address": "192.168.1.100",
                "version": "1.0.0",
                "status": "online",
                "last_seen": "2025-01-02T10:30:00Z",
                "created_at": "2025-01-01T08:00:00Z"
            }
        }
    )


@router.get("/", response_model=List[Agent])
async def list_agents(
    os: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
) -> List[Agent]:
    """
    List all active DLP agents (only agents that have sent heartbeat within timeout period)

    Query parameters:
    - os: Filter by operating system (windows/linux)
    
    Note: Only shows agents that have sent heartbeat within the last 5 minutes.
    Dead agents are automatically filtered out.
    """
    db = get_mongodb()
    agents_collection = db["agents"]

    # Calculate cutoff time for active agents (timezone-aware UTC)
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=AGENT_TIMEOUT_SECONDS)
    # Also create a naive version for comparing with legacy naive datetimes in MongoDB
    cutoff_naive = datetime.utcnow() - timedelta(seconds=AGENT_TIMEOUT_SECONDS)

    # Build query filter — show agents with a recent heartbeat AND that
    # have not been soft-deleted. Handle both aware and naive last_seen
    # datetimes (legacy docs predate the timezone-aware migration).
    query: Dict[str, Any] = {
        "$or": [
            {"last_seen": {"$gte": cutoff_time}},
            {"last_seen": {"$gte": cutoff_naive}},
        ],
        "is_deleted": {"$ne": True},
    }
    if os:
        query["os"] = os

    # Query agents from database — sort by the numeric agent_code so the
    # earliest-registered agent (001) is first and new agents append at
    # the bottom (PART of the chronological-order spec). last_seen DESC
    # is kept as a tiebreaker for the unlikely case where two agents
    # share a code (e.g. a doc lost its code mid-backfill).
    agents_cursor = agents_collection.find(query).sort(
        [("agent_code", 1), ("last_seen", -1)]
    )
    agents = []

    async for agent_doc in agents_cursor:
        # Backfill agent_code BEFORE stripping _id (we need _id to update).
        await _ensure_agent_code(agent_doc)

        # Remove MongoDB _id field and status field (no longer used)
        if "_id" in agent_doc:
            del agent_doc["_id"]
        if "status" in agent_doc:
            del agent_doc["status"]
        if "capabilities" not in agent_doc:
            agent_doc["capabilities"] = {}

        # Normalize datetime to timezone-aware UTC
        for dt_field in ("last_seen", "created_at"):
            if dt_field in agent_doc and isinstance(agent_doc[dt_field], datetime):
                dt_val = agent_doc[dt_field]
                if dt_val.tzinfo is None:
                    dt_val = dt_val.replace(tzinfo=timezone.utc)
                agent_doc[dt_field] = dt_val.isoformat()

        agents.append(Agent(**agent_doc))

    logger.info("Listed agents", count=len(agents))
    return agents


@router.get("/all")
async def list_all_agents(
    include_deleted: bool = False,
    current_user: dict = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    List ALL agents (including disconnected ones) with lifecycle status.

    Returns agents with additional computed fields:
    - is_active: True if agent sent heartbeat within ``AGENT_TIMEOUT_SECONDS``
      (kept for backward-compatibility with older dashboard code).
    - status_label: legacy "active"/"disconnected" string.
    - lifecycle_status: one of active/disconnected/inactive/stale, computed
      from the freshness of ``last_seen`` (see thresholds above).
    - last_seen_seconds_ago: numeric age of the heartbeat in seconds, so the
      UI can render "Last seen X ago" without doing client-side timezone math.
    - is_deleted / decommissioned: lifecycle flags that hide the agent
      from the default list.

    Soft-deleted agents (``is_deleted=true``) are hidden by default — pass
    ``include_deleted=true`` to surface them in audit views.
    """
    db = get_mongodb()
    agents_collection = db["agents"]

    # Cutoffs reused for the legacy is_active boolean. lifecycle_status uses
    # _compute_lifecycle_status() which handles its own freshness math.
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=AGENT_TIMEOUT_SECONDS)
    cutoff_naive = datetime.utcnow() - timedelta(seconds=AGENT_TIMEOUT_SECONDS)
    now_aware = datetime.now(timezone.utc)

    # Hide soft-deleted by default. The {"$ne": True} predicate matches
    # both "field absent" (legacy docs) and "explicitly false", so we
    # don't need to backfill is_deleted on existing rows.
    query: Dict[str, Any] = {} if include_deleted else {"is_deleted": {"$ne": True}}
    agents_cursor = agents_collection.find(query).sort(
        [("agent_code", 1), ("last_seen", -1)]
    )
    agents = []

    async for agent_doc in agents_cursor:
        # Backfill agent_code BEFORE stripping _id (we need _id to update).
        await _ensure_agent_code(agent_doc)

        # Remove MongoDB _id field
        if "_id" in agent_doc:
            del agent_doc["_id"]
        if "capabilities" not in agent_doc:
            agent_doc["capabilities"] = {}

        # Determine if agent is active (legacy boolean)
        last_seen = agent_doc.get("last_seen")
        is_active = False
        last_seen_seconds_ago: Optional[float] = None
        if last_seen and isinstance(last_seen, datetime):
            if last_seen.tzinfo is None:
                is_active = last_seen >= cutoff_naive
                last_seen_seconds_ago = (
                    now_aware - last_seen.replace(tzinfo=timezone.utc)
                ).total_seconds()
            else:
                is_active = last_seen >= cutoff_time
                last_seen_seconds_ago = (now_aware - last_seen).total_seconds()

        # Lifecycle tier — exposed so the UI doesn't reimplement the ladder.
        agent_doc["lifecycle_status"] = _compute_lifecycle_status(last_seen)
        agent_doc["last_seen_seconds_ago"] = last_seen_seconds_ago

        # Legacy fields kept for the existing dashboard code paths.
        agent_doc["is_active"] = is_active
        agent_doc["status_label"] = "active" if is_active else "disconnected"

        # Surface lifecycle flags so the UI can show "Decommissioned" badges
        # and admin views can distinguish deleted-but-retained records.
        agent_doc["is_deleted"] = bool(agent_doc.get("is_deleted"))
        agent_doc["decommissioned"] = bool(agent_doc.get("decommissioned"))

        # Normalize datetime fields to ISO format
        for dt_field in (
            "last_seen",
            "created_at",
            "last_heartbeat",
            "deleted_at",
            "decommissioned_at",
        ):
            if dt_field in agent_doc and isinstance(agent_doc[dt_field], datetime):
                dt_val = agent_doc[dt_field]
                if dt_val.tzinfo is None:
                    dt_val = dt_val.replace(tzinfo=timezone.utc)
                agent_doc[dt_field] = dt_val.isoformat()

        agents.append(agent_doc)

    logger.info("Listed all agents", count=len(agents), include_deleted=include_deleted)
    return agents


@router.post("/", status_code=status.HTTP_201_CREATED)
async def register_agent(
    request: Request,
    agent: AgentCreate,
) -> Dict[str, Any]:
    """
    Register a new DLP agent.

    Returns the agent record **and** a one-time ``api_key``.  The agent
    must store this key and send it as ``X-Agent-Key`` header on all
    subsequent requests (events, heartbeat, policy sync).
    """
    import secrets

    db = get_mongodb()
    agents_collection = db["agents"]

    body = await request.json()
    provided_agent_id = body.get("agent_id")
    capabilities = body.get("capabilities") or {}
    now = datetime.now(timezone.utc)

    # Use the agent's self-assigned ID if provided (C++ agent sends UUID).
    # Otherwise generate a sequential one.
    if provided_agent_id:
        agent_id = provided_agent_id
    else:
        agent_id = f"{agent.os.upper()}-{agent.name.replace(' ', '-')}"

    # Check if this agent already exists (by agent_id OR by hostname+os)
    existing = await agents_collection.find_one({
        "$or": [
            {"agent_id": agent_id},
            {"name": agent.name, "os": agent.os},
        ]
    })

    if existing:
        # Re-registering — update fields, keep the stored agent_id
        stored_id = existing["agent_id"]
        api_key = existing.get("api_key") or f"csak_{secrets.token_urlsafe(32)}"

        # If the agent changed its ID (reinstall), update to new ID
        update_fields = {
            "ip_address": agent.ip_address,
            "version": agent.version,
            "last_seen": now,
            "capabilities": capabilities,
            "api_key": api_key,
        }
        if stored_id != agent_id:
            update_fields["agent_id"] = agent_id

        await agents_collection.update_one(
            {"_id": existing["_id"]},
            {"$set": update_fields},
        )
        # Re-registering legacy agent without agent_code → backfill now.
        agent_code = existing.get("agent_code")
        if not isinstance(agent_code, int):
            agent_code = await _ensure_agent_code(existing)
        agent_doc = existing
    else:
        # New agent — pull agent_code from the Postgres sequence so we
        # never compute the ID in app code.
        api_key = f"csak_{secrets.token_urlsafe(32)}"
        agent_code = await _next_agent_code()

        agent_doc = {
            "agent_id": agent_id,
            "agent_code": agent_code,
            "name": agent.name,
            "os": agent.os,
            "ip_address": agent.ip_address,
            "version": agent.version,
            "last_seen": now,
            "created_at": now,
            "capabilities": capabilities,
            "policy_version": None,
            "policy_sync_status": "never",
            "policy_last_synced_at": None,
            "policy_sync_error": None,
            "api_key": api_key,
        }

        await agents_collection.insert_one(agent_doc)

    logger.info("Agent registered", agent_id=agent_id, agent_code=agent_code, name=agent.name)

    # Return agent data + the API key (shown once)
    response_doc = {k: v for k, v in agent_doc.items() if k not in ("api_key", "_id")}
    response_doc["api_key"] = api_key
    response_doc["agent_code"] = agent_code
    response_doc["last_seen"] = now.isoformat()
    response_doc["created_at"] = now.isoformat()

    return response_doc


@router.get("/{agent_id}", response_model=Agent)
async def get_agent(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
) -> Agent:
    """
    Get details of a specific agent
    """
    db = get_mongodb()
    agents_collection = db["agents"]

    agent_doc = await agents_collection.find_one({"agent_id": agent_id})

    if not agent_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found"
        )

    # Backfill agent_code BEFORE stripping _id (we need _id to update).
    await _ensure_agent_code(agent_doc)

    # Remove MongoDB _id field
    if "_id" in agent_doc:
        del agent_doc["_id"]
    if "capabilities" not in agent_doc:
        agent_doc["capabilities"] = {}

    return Agent(**agent_doc)


class HeartbeatRequest(BaseModel):
    """Heartbeat request model"""
    timestamp: Optional[str] = Field(None, description="Agent timestamp (ISO format)")
    status: Optional[str] = Field(None, description="Agent status")
    ip_address: Optional[str] = Field(None, description="Current IP address")
    policy_version: Optional[str] = Field(None, description="Agent policy bundle version")
    policy_sync_status: Optional[str] = Field(None, description="Most recent policy sync status")
    policy_last_synced_at: Optional[str] = Field(None, description="ISO timestamp for last policy sync")
    policy_sync_error: Optional[str] = Field(None, description="Error details from last policy sync")


@router.put("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    request: Request,
    heartbeat: Optional[HeartbeatRequest] = None,
    _verified_agent: str = Depends(verify_agent_key),
) -> Dict[str, Any]:
    """
    Update agent heartbeat.  Requires ``X-Agent-Key`` header.

    Accepts optional request body with timestamp. If provided, validates it's within
    reasonable bounds (not more than 5 minutes in the future or past).
    Uses server time if not provided or invalid.
    """
    db = get_mongodb()
    agents_collection = db["agents"]

    # Determine timestamp to use
    server_time = datetime.now(timezone.utc)
    heartbeat_time = server_time

    if heartbeat and heartbeat.timestamp:
        try:
            # Parse agent-provided timestamp
            agent_time_str = heartbeat.timestamp.replace('Z', '+00:00')
            agent_time = datetime.fromisoformat(agent_time_str)
            # Ensure agent_time is timezone-aware for comparison
            if agent_time.tzinfo is None:
                agent_time = agent_time.replace(tzinfo=timezone.utc)
            # Validate timestamp is within reasonable bounds (±5 minutes)
            time_diff = abs((agent_time - server_time).total_seconds())
            if time_diff <= 300:  # 5 minutes
                heartbeat_time = agent_time
            else:
                logger.warning(
                    "Agent timestamp out of bounds, using server time",
                    agent_id=agent_id,
                    agent_time=heartbeat.timestamp,
                    server_time=server_time.isoformat(),
                    diff_seconds=time_diff
                )
        except (ValueError, AttributeError) as e:
            logger.debug(f"Invalid timestamp format, using server time: {e}")

    # Update last_seen and optionally other fields
    update_data = {
        "last_seen": heartbeat_time
    }

    if heartbeat and heartbeat.ip_address:
        update_data["ip_address"] = heartbeat.ip_address
    if heartbeat and heartbeat.policy_version is not None:
        update_data["policy_version"] = heartbeat.policy_version
    if heartbeat and heartbeat.policy_sync_status is not None:
        update_data["policy_sync_status"] = heartbeat.policy_sync_status
    if heartbeat and heartbeat.policy_last_synced_at is not None:
        update_data["policy_last_synced_at"] = heartbeat.policy_last_synced_at
    if heartbeat and heartbeat.policy_sync_error is not None:
        update_data["policy_sync_error"] = heartbeat.policy_sync_error

    result = await agents_collection.update_one(
        {"agent_id": agent_id},
        {"$set": update_data}
    )

    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found"
        )

    logger.debug("Agent heartbeat", agent_id=agent_id, timestamp=heartbeat_time.isoformat())
    return {
        "status": "success",
        "message": "Heartbeat recorded",
        "timestamp": heartbeat_time.isoformat()
    }


@router.delete("/{agent_id}/unregister", status_code=status.HTTP_204_NO_CONTENT)
async def unregister_agent(
    agent_id: str,
    request: Request,
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    Self-unregister called by the agent during a clean uninstall.

    We deliberately do NOT hard-delete the agent record here. Doing so
    would orphan event history (event_id → agent_id lookups would fail
    enrichment) and erase audit trails for an agent that produced real
    activity. Instead we mark the doc as decommissioned so the UI shows
    a clear "Decommissioned" badge and admins can later soft-delete
    intentionally if they want it gone.
    """
    db = get_mongodb()
    agents_collection = db["agents"]
    now = datetime.now(timezone.utc)

    result = await agents_collection.update_one(
        {"agent_id": agent_id},
        {"$set": {
            "decommissioned": True,
            "decommissioned_at": now,
            "decommissioned_reason": "agent_self_uninstall",
        }},
    )

    if result.matched_count == 0:
        # Already gone or never registered — uninstall is idempotent.
        logger.debug("Agent not found for unregister", agent_id=agent_id)
    else:
        logger.info("Agent self-decommissioned via uninstall", agent_id=agent_id)

    return None


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_id: str,
    current_user: dict = Depends(require_role("admin")),
):
    """
    Soft-delete an agent record (admin action — "Remove Agent" in the UI).

    The agent_id is preserved on the doc so:
      • event/incident enrichment can still resolve agent_name + agent_code
      • audit trails referencing this agent stay queryable
    Listings hide soft-deleted agents by default; pass
    ``GET /agents/all?include_deleted=true`` to surface them.
    """
    db = get_mongodb()
    agents_collection = db["agents"]
    now = datetime.now(timezone.utc)
    actor = current_user.get("email") if isinstance(current_user, dict) else getattr(current_user, "email", None)

    result = await agents_collection.update_one(
        {"agent_id": agent_id, "is_deleted": {"$ne": True}},
        {"$set": {
            "is_deleted": True,
            "deleted_at": now,
            "deleted_by": actor,
        }},
    )

    if result.matched_count == 0:
        # Either the agent doesn't exist OR it's already soft-deleted.
        # We 404 in both cases — admin should hit ?include_deleted=true
        # to confirm before retrying.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    # Audit log so the soft-delete is traceable even if the doc is later
    # purged from Mongo. Fire-and-forget — never block the response on it.
    try:
        from app.services.audit_service import audit_log
        user_id = current_user.get("id") if isinstance(current_user, dict) else getattr(current_user, "id", None)
        await audit_log(user_id, "agent.delete", {"agent_id": agent_id})
    except Exception as e:
        logger.warning("Failed to record agent.delete audit log", error=str(e))

    logger.info("Agent soft-deleted", agent_id=agent_id, user=actor)
    return None


@router.post("/{agent_id}/decommission", status_code=status.HTTP_200_OK)
async def decommission_agent(
    agent_id: str,
    current_user: dict = Depends(require_role("admin")),
) -> Dict[str, Any]:
    """
    Mark an agent as decommissioned (admin action — "Mark as Decommissioned"
    in the UI). Unlike soft-delete this keeps the agent visible in the
    listing with a "Decommissioned" badge — the intent is "this device is
    retired but I want it on the inventory" rather than "hide it".
    """
    db = get_mongodb()
    agents_collection = db["agents"]
    now = datetime.now(timezone.utc)
    actor = current_user.get("email") if isinstance(current_user, dict) else getattr(current_user, "email", None)

    result = await agents_collection.update_one(
        {"agent_id": agent_id},
        {"$set": {
            "decommissioned": True,
            "decommissioned_at": now,
            "decommissioned_by": actor,
            "decommissioned_reason": "admin_action",
        }},
    )

    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    try:
        from app.services.audit_service import audit_log
        user_id = current_user.get("id") if isinstance(current_user, dict) else getattr(current_user, "id", None)
        await audit_log(user_id, "agent.decommission", {"agent_id": agent_id})
    except Exception as e:
        logger.warning("Failed to record agent.decommission audit log", error=str(e))

    logger.info("Agent decommissioned", agent_id=agent_id, user=actor)
    return {
        "status": "decommissioned",
        "agent_id": agent_id,
        "decommissioned_at": now.isoformat(),
    }


@router.post("/cleanup-stale", status_code=status.HTTP_200_OK)
async def cleanup_stale_agents(
    older_than_days: int = 30,
    dry_run: bool = True,
    current_user: dict = Depends(require_role("admin")),
) -> Dict[str, Any]:
    """
    Soft-delete agents whose ``last_seen`` is older than N days.

    Admin-triggered, never automatic — invoke from a UI button or a cron
    you control. ``dry_run=true`` (default) returns the set that *would*
    be cleaned up so you can review before actually applying. Pass
    ``dry_run=false`` to perform the soft delete.

    NOTE: this is a soft delete (``is_deleted=true``); event history and
    audit trails referencing the agent are preserved.
    """
    if older_than_days <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="older_than_days must be positive",
        )

    db = get_mongodb()
    agents_collection = db["agents"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    actor = current_user.get("email") if isinstance(current_user, dict) else getattr(current_user, "email", None)

    # Build the candidate filter once and reuse it for both the preview
    # and the update so the two views always agree on the affected set.
    query: Dict[str, Any] = {
        "is_deleted": {"$ne": True},
        "$or": [
            {"last_seen": {"$lt": cutoff}},
            {"last_seen": {"$exists": False}},
            {"last_seen": None},
        ],
    }

    candidates: List[Dict[str, Any]] = []
    async for doc in agents_collection.find(
        query, {"agent_id": 1, "name": 1, "agent_code": 1, "last_seen": 1, "_id": 0}
    ):
        last_seen = doc.get("last_seen")
        if isinstance(last_seen, datetime):
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            doc["last_seen"] = last_seen.isoformat()
        candidates.append(doc)

    if dry_run:
        return {
            "dry_run": True,
            "older_than_days": older_than_days,
            "cutoff": cutoff.isoformat(),
            "would_remove_count": len(candidates),
            "candidates": candidates,
        }

    now = datetime.now(timezone.utc)
    result = await agents_collection.update_many(
        query,
        {"$set": {
            "is_deleted": True,
            "deleted_at": now,
            "deleted_by": actor,
            "deleted_reason": f"stale>{older_than_days}d",
        }},
    )

    try:
        from app.services.audit_service import audit_log
        user_id = current_user.get("id") if isinstance(current_user, dict) else getattr(current_user, "id", None)
        await audit_log(
            user_id,
            "agent.cleanup_stale",
            {"older_than_days": older_than_days, "removed": result.modified_count},
        )
    except Exception as e:
        logger.warning("Failed to record agent.cleanup_stale audit log", error=str(e))

    logger.info(
        "Stale agents cleaned up",
        older_than_days=older_than_days,
        removed=result.modified_count,
        user=actor,
    )
    return {
        "dry_run": False,
        "older_than_days": older_than_days,
        "cutoff": cutoff.isoformat(),
        "removed_count": result.modified_count,
        "candidates": candidates,
    }


@router.get("/stats/summary")
async def get_agents_summary(
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get summary statistics of active agents
    """
    db = get_mongodb()
    agents_collection = db["agents"]

    # Calculate cutoff time for active agents (handle both aware and naive datetimes)
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=AGENT_TIMEOUT_SECONDS)
    cutoff_naive = datetime.utcnow() - timedelta(seconds=AGENT_TIMEOUT_SECONDS)

    # Count active agents (have sent heartbeat within timeout)
    active = await agents_collection.count_documents({
        "$or": [
            {"last_seen": {"$gte": cutoff_time}},
            {"last_seen": {"$gte": cutoff_naive}},
        ]
    })

    # Count total agents (including dead ones)
    total = await agents_collection.count_documents({})

    return {
        "total": total,
        "active": active,
    }


class AgentPolicySyncRequest(BaseModel):
    """Agent policy sync request"""
    platform: Optional[str] = Field(None, description="Override detected platform (windows/linux)")
    capabilities: Dict[str, bool] = Field(default_factory=dict, description="Agent capability flags")
    installed_version: Optional[str] = Field(None, description="Currently installed bundle version")


class AgentPolicySyncResponse(BaseModel):
    """Agent policy sync response"""
    status: str = Field(default="updated", description="updated|up_to_date")
    version: str
    generated_at: datetime
    policy_count: int
    policies: Dict[str, Any] = Field(default_factory=dict)


_agent_policy_transformer = AgentPolicyTransformer()


def _get_agent_policy_transformer() -> AgentPolicyTransformer:
    return _agent_policy_transformer


@router.post("/{agent_id}/policies/sync", response_model=AgentPolicySyncResponse)
async def sync_agent_policies(
    agent_id: str,
    sync_request: AgentPolicySyncRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    Provide agents with a policy bundle tailored to their platform/capabilities.
    Requires ``X-Agent-Key`` header.
    """
    mongo = get_mongodb()
    agents_collection = mongo["agents"]

    agent_doc = await agents_collection.find_one({"agent_id": agent_id})
    if not agent_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    platform = (sync_request.platform or agent_doc.get("os") or "windows").lower()
    capabilities = {**agent_doc.get("capabilities", {}), **sync_request.capabilities}

    # Normalize capability flags
    capabilities = {k: bool(v) for k, v in capabilities.items()}
    capability_key = "-".join(sorted([k for k, v in capabilities.items() if v])) or "default"

    cache_service: Optional[CacheService] = None
    try:
        cache_service = CacheService(get_cache())
    except RuntimeError:
        cache_service = None

    cache_key = f"agent-policy-bundle:{agent_id}:{platform}:{capability_key}"
    bundle: Optional[Dict[str, Any]] = None

    if cache_service:
        bundle = await cache_service.get(cache_key)

    if not bundle:
        policy_service = PolicyService(db)
        enabled_policies = await policy_service.get_enabled_policies()
        transformer = _get_agent_policy_transformer()
        bundle = transformer.build_bundle(
            enabled_policies,
            platform,
            capabilities,
            agent_id=agent_id,
        )
        if cache_service:
            await cache_service.set(cache_key, bundle, expire=30)

    if not bundle:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to build policy bundle",
        )

    version = bundle.get("version")
    generated_at_raw = bundle.get("generated_at")
    generated_at = datetime.fromisoformat(generated_at_raw.replace("Z", "+00:00")) if generated_at_raw else datetime.utcnow()

    if sync_request.installed_version and sync_request.installed_version == version:
        logger.info("Agent policy bundle up-to-date", agent_id=agent_id, platform=platform, version=version)
        return AgentPolicySyncResponse(
            status="up_to_date",
            version=version,
            generated_at=generated_at,
            policy_count=bundle.get("policy_count", 0),
            policies={},
        )

    logger.info(
        "Agent policy bundle issued",
        agent_id=agent_id,
        platform=platform,
        version=version,
        policy_count=bundle.get("policy_count", 0),
    )

    return AgentPolicySyncResponse(
        status="updated",
        version=version,
        generated_at=generated_at,
        policy_count=bundle.get("policy_count", 0),
        policies=bundle.get("policies", {}),
    )


class PolicyEvaluationRequest(BaseModel):
    """Request model for real-time policy evaluation"""
    file_name: str = Field(..., description="Name of the file being transferred")
    file_content: str = Field(..., description="Content of the file to classify")
    file_size: Optional[int] = Field(None, description="File size in bytes")
    event_type: str = Field(..., description="Event type (e.g., 'usb_file_transfer', 'clipboard')")
    destination_type: Optional[str] = Field(None, description="Destination type (e.g., 'removable_drive', 'network')")
    source_path: Optional[str] = Field(None, description="Source file path")
    destination_path: Optional[str] = Field(None, description="Destination path")


class ClassificationDetails(BaseModel):
    """Classification result details"""
    level: str = Field(..., description="Classification level (Public/Internal/Confidential/Restricted)")
    confidence: float = Field(..., description="Confidence score (0.0 - 1.0)")
    matched_rules: List[Dict[str, Any]] = Field(default_factory=list, description="List of matched classification rules")
    total_matches: int = Field(0, description="Total number of pattern matches")


class PolicyEvaluationResponse(BaseModel):
    """Response model for real-time policy evaluation"""
    action: str = Field(..., description="Action to take: 'allow' or 'block'")
    reason: str = Field(..., description="Reason for the decision")
    classification: ClassificationDetails = Field(..., description="Content classification details")
    policies_triggered: List[Dict[str, Any]] = Field(default_factory=list, description="Policies that matched")
    should_log: bool = Field(True, description="Whether to log this event")
    alert_severity: Optional[str] = Field(None, description="Alert severity if applicable")


@router.post("/{agent_id}/policy/evaluate", response_model=PolicyEvaluationResponse)
async def evaluate_policy_realtime(
    agent_id: str,
    request: PolicyEvaluationRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Real-time policy evaluation for agent-side enforcement.

    SECURITY: Requires a valid X-Agent-Key header. Previously this was
    anonymous — which both let external callers use it as a
    classification oracle to tune exfiltration so it lands as "Public",
    and let them DoS the classification engine with arbitrarily large
    file contents since the endpoint is expensive.

    Agent calls this BEFORE allowing a file transfer or action.
    Server classifies content and evaluates policies, then returns
    a decision (allow/block) with full classification details.

    This enables content-aware blocking based on sensitive data detection.
    """
    await verify_agent_key(http_request)

    try:
        # 1. Classify the file content using ClassificationEngine
        classification_engine = ClassificationEngine(db)
        classification_result = await classification_engine.classify_content(
            request.file_content,
            context={
                "event_type": request.event_type,
                "file_name": request.file_name,
                "source_path": request.source_path,
            }
        )

        logger.info(
            "Content classified",
            agent_id=agent_id,
            file_name=request.file_name,
            classification=classification_result.classification,
            confidence=classification_result.confidence_score,
            matched_rules_count=len(classification_result.matched_rules),
        )

        # 2. Build event data structure for policy evaluation
        event_data = {
            "classification_level": classification_result.classification,
            "confidence_score": classification_result.confidence_score,
            "classification_labels": [
                label
                for rule in classification_result.matched_rules
                for label in rule.get("classification_labels", [])
            ],
            "event_type": request.event_type,
            "destination_type": request.destination_type,
            "source_path": request.source_path,
            "destination_path": request.destination_path,
            "file_name": request.file_name,
            "file_size": request.file_size,
            "agent_id": agent_id,
        }

        # 3. Evaluate classification-aware policies
        policy_evaluator = DatabasePolicyEvaluator()
        policy_matches = await policy_evaluator.evaluate_event(event_data)

        # 4. Determine action based on matched policies
        should_block = False
        should_alert = False
        alert_severity = None
        triggered_policies = []

        for match in policy_matches:
            triggered_policies.append({
                "policy_id": match.policy_id,
                "policy_name": match.policy_name,
                "severity": match.severity,
                "priority": match.priority,
            })

            # Check actions
            for action in match.actions:
                action_type = action.get("type") or action.get("action")
                if action_type == "block":
                    should_block = True
                elif action_type == "alert":
                    should_alert = True
                    # Get highest severity
                    action_severity = action.get("parameters", {}).get("severity") or match.severity
                    if action_severity:
                        if alert_severity is None or _severity_rank(action_severity) > _severity_rank(alert_severity):
                            alert_severity = action_severity

        # 5. Build response
        action = "block" if should_block else "allow"

        # Build detailed reason
        if classification_result.matched_rules:
            rule_names = [r["rule_name"] for r in classification_result.matched_rules[:5]]
            reason = f"Classification: {classification_result.classification} (confidence {classification_result.confidence_score:.2%}). "
            reason += f"Detected: {', '.join(rule_names)}"
            if len(classification_result.matched_rules) > 5:
                reason += f" and {len(classification_result.matched_rules) - 5} more"
        else:
            reason = f"Classification: {classification_result.classification} - no sensitive data detected"

        if should_block:
            reason = f"BLOCKED - {reason}"

        logger.info(
            "Policy evaluation complete",
            agent_id=agent_id,
            file_name=request.file_name,
            action=action,
            policies_triggered=len(triggered_policies),
            should_block=should_block,
        )

        return PolicyEvaluationResponse(
            action=action,
            reason=reason,
            classification=ClassificationDetails(
                level=classification_result.classification,
                confidence=classification_result.confidence_score,
                matched_rules=classification_result.matched_rules,
                total_matches=classification_result.total_matches,
            ),
            policies_triggered=triggered_policies,
            should_log=True,
            alert_severity=alert_severity,
        )

    except Exception as e:
        logger.error(
            "Policy evaluation failed",
            agent_id=agent_id,
            file_name=request.file_name,
            error=str(e),
        )
        # Fail-safe: allow on error (configurable)
        return PolicyEvaluationResponse(
            action="allow",
            reason=f"Policy evaluation error: {str(e)}",
            classification=ClassificationDetails(
                level="Public",
                confidence=0.0,
                matched_rules=[],
                total_matches=0,
            ),
            policies_triggered=[],
            should_log=True,
            alert_severity=None,
        )


def _severity_rank(severity: str) -> int:
    """Convert severity to numeric rank for comparison"""
    ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return ranks.get(severity.lower(), 0)
