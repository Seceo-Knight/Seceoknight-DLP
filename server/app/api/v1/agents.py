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

# Agent is considered active if heartbeat received within 5 minutes.
# Default agent heartbeat interval is 30s. 5 minutes gives room for
# brief network drops, sleep/wake cycles, and HTTP client reconnection
# (agent reinitializes WinHTTP after 3 consecutive failures ~90s).
AGENT_TIMEOUT_SECONDS = 300

# ── Lifecycle status thresholds ──────────────────────────────────────
# Tiered freshness ladder reported as ``lifecycle_status`` on agent
# listings. The bands cover the full timeline so every agent maps to
# exactly one tier — UIs can show a colored badge without computing the
# math themselves.
#
#   active:       last_seen ≤ 5min ago      — heartbeat recently received
#   disconnected: 5min < last_seen ≤ 24h   — recently silent
#   inactive:     24h  < last_seen ≤ 7d    — quiet for a while
#   stale:        last_seen > 7d           — likely abandoned/uninstalled
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


async def require_agent_key(request: Request) -> str:
    """Like ``verify_agent_key``, but a missing key is also rejected.

    Several endpoints (real-time policy evaluation, classification,
    decision, policy bundle download, ...) carry a docstring reading
    "SECURITY: Requires a valid X-Agent-Key header" — added specifically
    because being anonymous let external callers use them as a
    classification oracle to tune content until it scored "Public", or
    flood/DoS the classification engine. Every one of those endpoints was
    calling ``verify_agent_key(...)`` and discarding the return value:
    ``verify_agent_key`` only raises 401 when a key is PRESENT but wrong —
    a request with no key at all returns ``None`` and is let through, so
    every "Requires a valid key" endpoint was still fully anonymous-
    accessible despite the comment (found in a policy-engine audit,
    August 28 2026). Callers that genuinely need the old backward-
    compatible "key optional" behavior (plain event ingestion from an
    agent build predating key support) should keep calling
    ``verify_agent_key`` directly instead of this function.
    """
    agent_id = await verify_agent_key(request)
    if agent_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Agent-Key header is required for this endpoint",
        )
    return agent_id


class AgentBase(BaseModel):
    """Base agent model"""
    name: str = Field(..., description="Agent name/hostname")
    os: str = Field(..., description="Operating system (windows/linux)")
    ip_address: str = Field(..., description="Agent IP address")
    version: str = Field(default="1.0.0", description="Agent version")
    capabilities: Dict[str, bool] = Field(default_factory=dict, description="Agent capability flags")
    # Precision fields ported from CyberSentinel-DLP (see
    # SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md). The C++ agent has sent
    # ``hostname`` in its registration payload since the beginning, but this
    # model never declared the field so pydantic silently dropped it on
    # every registration — the Agents page has shown an (always-empty)
    # hostname column for that reason. ``os_version``/``username`` are new:
    # the agent previously hardcoded "Windows 10" for os_version and never
    # reported the logged-in user at all.
    hostname: Optional[str] = Field(None, description="Machine hostname, as reported by the agent")
    os_version: Optional[str] = Field(None, description="Precise OS build string, e.g. 'Windows 11 Pro 23H2 (Build 22631.3007)'")
    username: Optional[str] = Field(None, description="Currently logged-in Windows user, refreshed every heartbeat")


class AgentCreate(BaseModel):
    """Agent creation model"""
    agent_id: Optional[str] = Field(None, description="Custom agent ID (auto-generated if not provided)")
    name: str = Field(..., description="Agent name/hostname")
    os: str = Field(..., description="Operating system (windows/linux)")
    ip_address: str = Field(..., description="Agent IP address")
    version: str = Field(default="1.0.0", description="Agent version")
    hostname: Optional[str] = Field(None, description="Machine hostname, as reported by the agent")
    os_version: Optional[str] = Field(None, description="Precise OS build string")
    username: Optional[str] = Field(None, description="Currently logged-in Windows user")


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
        # Only overwrite when the agent actually sent a value — older agent
        # builds predating this feature won't send these fields at all, and
        # we don't want a re-registration from one of those to blank out
        # data a newer build previously reported.
        if agent.hostname:
            update_fields["hostname"] = agent.hostname
        if agent.os_version:
            update_fields["os_version"] = agent.os_version
        if agent.username:
            update_fields["username"] = agent.username
        if stored_id != agent_id:
            update_fields["agent_id"] = agent_id

        # This machine is clearly alive and talking to us again — if the
        # record was previously marked decommissioned (self-unregister on a
        # prior uninstall, or an admin action) or soft-deleted, clear those
        # flags rather than leaving it stuck with a stale "Decommissioned"
        # badge / hidden from the default view forever. Without this, every
        # reinstall on a machine that was ever cleanly uninstalled (or a
        # false-positive "Mark as Decommissioned" click) would look wrong
        # or vanish even though it's actively heartbeating again.
        if existing.get("decommissioned") or existing.get("is_deleted"):
            update_fields["decommissioned"] = False
            update_fields["decommissioned_at"] = None
            update_fields["decommissioned_reason"] = None
            update_fields["is_deleted"] = False
            update_fields["deleted_at"] = None
            logger.info(
                "Agent re-registered after being decommissioned/deleted — reactivating",
                agent_id=agent_id, stored_id=stored_id,
            )

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
            "hostname": agent.hostname,
            "os_version": agent.os_version,
            "username": agent.username,
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
    username: Optional[str] = Field(None, description="Currently logged-in Windows user, refreshed every heartbeat")
    os_version: Optional[str] = Field(None, description="Precise OS build string, refreshed every heartbeat")
    version: Optional[str] = Field(None, description="Agent binary version, refreshed every heartbeat (post-auto-update)")


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
    if heartbeat and heartbeat.username:
        update_data["username"] = heartbeat.username
    if heartbeat and heartbeat.os_version:
        update_data["os_version"] = heartbeat.os_version
    if heartbeat and heartbeat.version:
        update_data["version"] = heartbeat.version

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


@router.get("/{agent_id}/cloud-upload-hosts")
async def get_cloud_upload_hosts(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    Extra cloud-upload destinations an admin has added from the dashboard, on
    top of the browser extension's built-in baseline CLOUD_HOSTS list. Polled
    by the extension's native host (skdlp_host.py) so admins can add a new
    monitored destination without redeploying inject.js to every machine.
    Requires ``X-Agent-Key`` header — same auth as policy sync/evaluate.
    """
    from app.models.cloud_upload_hosts import CloudUploadHost
    from sqlalchemy import select

    rows = (
        await db.execute(
            select(CloudUploadHost.domain).where(CloudUploadHost.is_enabled == True)  # noqa: E712
        )
    ).scalars().all()
    return {"domains": list(rows)}


@router.get("/{agent_id}/app-catalog")
async def get_agent_app_catalog(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    The watched-destination domain list for Web Activity Control, plus
    whether any web_activity_control policy is currently active. Polled by
    the browser extension's native host (skdlp_host.py) so it knows which
    hosts to intercept traffic for at all -- mirrors get_cloud_upload_hosts
    above, just for the broader webmail/file_sharing/collaboration/genai
    catalog instead of only cloud-upload destinations.

    ``web_activity_enforced`` lets the extension skip the more invasive
    response-buffering interception path (needed for redacting/blocking a
    GenAI reply, see ai_response in app/core/web_activity.py) entirely when
    nobody has configured this feature -- so installations that never touch
    Web Activity Control pay zero streaming-latency cost for it.
    Requires ``X-Agent-Key`` header — same auth as policy sync/evaluate.
    """
    from sqlalchemy import select as _select
    from app.models.app_catalog import AppCatalogEntry as _AppCatalogEntry
    from app.models.policy import Policy as _Policy

    domains = (await db.execute(_select(_AppCatalogEntry.domain))).scalars().all()
    active_policy = (await db.execute(
        _select(_Policy.id).where(
            _Policy.type == "web_activity_control",
            _Policy.status == "active",
            _Policy.deleted_at.is_(None),
        ).limit(1)
    )).scalar_one_or_none()
    return {"domains": list(domains), "web_activity_enforced": active_policy is not None}


@router.get("/{agent_id}/usb-allowlist")
async def get_usb_allowlist(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    The USB device allowlist the agent enforces locally (strict allowlist /
    default-deny by serial number). Ported from CyberSentinel-DLP — see
    SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md.

    The agent polls this on the same cadence as policy sync and caches the
    result; HandleUsbDeviceArrival() in agent.cpp then decides locally when a
    device connects, with no per-connect server round trip (works offline,
    no race with the ~1s Windows device-arrival window).

    enforced=false or mode="audit" -> agent must NOT block on this basis
    (audit mode still logs what it would have blocked). enforced=true and
    mode="enforce" -> block any serial not in ``serials``.
    Requires ``X-Agent-Key`` header — same auth as policy sync/evaluate.
    """
    from sqlalchemy import select as _select
    from app.models.policy import Policy
    from app.models.sanctioned_usb_device import SanctionedUsbDevice

    policy = (await db.execute(
        _select(Policy).where(
            Policy.type == "usb_device_control",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()
    enforced = policy is not None
    mode = ((policy.config or {}).get("mode") or "enforce").lower() if enforced else "off"
    if mode not in ("enforce", "audit"):
        mode = "enforce"

    # decision='deny' rows are deliberately excluded here (not just
    # is_enabled=False ones): a denied serial is never part of the agent's
    # allow set, same effect as it being unlisted in enforce mode, but it's
    # a distinct, audited "no" rather than "never decided" — see
    # SanctionedUsbDevice.decision and migration 034.
    rows = (await db.execute(
        _select(SanctionedUsbDevice).where(
            SanctionedUsbDevice.is_enabled.is_(True),
            SanctionedUsbDevice.decision == "allow",
        )
    )).scalars().all()
    devices = [{
        "serial_number": d.serial_number,
        "vendor_id": d.vendor_id,
        "product_id": d.product_id,
        "product_name": d.product_name,
    } for d in rows]
    return {
        "enforced": enforced,
        "mode": mode,
        "count": len(devices),
        "serials": [d["serial_number"] for d in devices],
        "devices": devices,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{agent_id}/network-share-policy")
async def get_network_share_policy(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    The network-share (mapped/UNC drive) transfer-control policy the agent
    enforces locally. Ported from CyberSentinel-DLP -- covers a real
    exfiltration path USB device-control and content DLP entirely missed:
    copying a file to a mapped network drive instead of a USB stick.

    Driven by a Policy row with type="network_share_transfer_control" (same
    pattern as usb_device_control above), rather than a dedicated table --
    there's no separate per-share allowlist identity to track the way there
    is for USB device serials, just a mode/action/exceptions config.

    mode: "block_all" (any file copied to any mapped network drive) |
    "content_aware" (only files the classification engine scores as
    Confidential/Restricted) | "off". action: "audit" (log/event only, never
    deletes) | "block" (quarantine + remove from the share). Any exception
    list match always allows regardless of mode.

    The agent polls this on the same cadence as policy sync and caches the
    result, same reasoning as usb-allowlist above (works offline, no
    per-file server round trip). Requires ``X-Agent-Key`` header.
    """
    from sqlalchemy import select as _select
    from app.models.policy import Policy

    policy = (await db.execute(
        _select(Policy).where(
            Policy.type == "network_share_transfer_control",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()

    enforced = policy is not None
    cfg = (policy.config or {}) if enforced else {}
    mode = str(cfg.get("mode") or "off").lower()
    if mode not in ("block_all", "content_aware", "off"):
        mode = "off"
    action = str(cfg.get("action") or "audit").lower()
    if action != "block":
        action = "audit"   # default safe -- never delete without an explicit opt-in

    def _str_list(key: str):
        v = cfg.get(key) or []
        return [str(x) for x in v] if isinstance(v, list) else []

    return {
        "enforced": enforced,
        "mode": mode,
        "action": action,
        "exception_shares": _str_list("exception_shares"),
        "exception_users": _str_list("exception_users"),
        "exception_paths": _str_list("exception_paths"),
        "exception_file_types": _str_list("exception_file_types"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{agent_id}/application-control")
async def get_application_control(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    The managed-application file-control policy the agent enforces locally.
    Ported from CyberSentinel-DLP -- allows/blocks a file ACTION (currently:
    network upload, via the CLI-transfer-tool interception in
    network_exfil_monitor.cpp) based on the APPLICATION performing it,
    independent of file content. E.g. block curl.exe entirely regardless of
    what it's uploading, or restrict uploads to only an approved allowlist of
    tools -- catches exfiltration attempts a pure content-classification
    check can miss (an unapproved tool moving data that doesn't happen to
    match any sensitive-data pattern).

    Driven by a Policy row with type="application_control" (same pattern as
    network_share_transfer_control above) -- no dedicated table, just a
    mode/applications/channels/exceptions config.

    Agent-side enforcement, for an action on <channel> by process P (user U,
    path F, type T):
      1. if channels is non-empty and <channel> not in channels -> not
         covered, ALLOW;
      2. if P in exception_applications, or U in exception_users, or F starts
         with any exception_paths, or T in exception_file_types -> exempt,
         ALLOW;
      3. else mode == "allowlist": BLOCK if P not in applications;
              mode == "blocklist": BLOCK if P in applications.

    The agent polls this on the same cadence as policy sync and caches the
    result (works offline, no per-file server round trip). Requires
    ``X-Agent-Key`` header.
    """
    from sqlalchemy import select as _select
    from app.models.policy import Policy

    policy = (await db.execute(
        _select(Policy).where(
            Policy.type == "application_control",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()

    enforced = policy is not None
    cfg = (policy.config or {}) if enforced else {}
    mode = str(cfg.get("mode") or "allowlist").lower()
    if mode not in ("allowlist", "blocklist"):
        mode = "allowlist"
    exc = cfg.get("exceptions") or {}

    def _str_list(v):
        return [str(x) for x in (v or []) if str(x).strip()] if isinstance(v, list) else []

    return {
        "enforced": enforced,
        "mode": mode if enforced else "off",
        "applications": [s.lower() for s in _str_list(cfg.get("applications"))],
        "channels": [s.lower() for s in _str_list(cfg.get("channels"))],
        "exception_applications": [s.lower() for s in _str_list(exc.get("applications"))],
        "exception_users": [s.lower() for s in _str_list(exc.get("users"))],
        "exception_paths": _str_list(exc.get("paths")),
        "exception_file_types": [s.lower().lstrip(".") for s in _str_list(exc.get("file_types"))],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{agent_id}/file-identity-denylist")
async def get_file_identity_denylist(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    Task #152. The file-identity denylist policy the agent enforces locally
    -- blocks/quarantines a file purely by extension or exact SHA-256 hash,
    the same way an antivirus denylist works, independent of what's inside
    the file. Driven by a Policy row with type="file_identity_denylist"
    (same pattern as application_control/wireless_transfer_control above)
    -- no dedicated table, just an extensions/hashes/action config.

    Previously this policy type had a dashboard form and a server-side
    config transform (_transform_file_identity_denylist_config in
    policy_transformer.py, producing valid conditions/actions in the Policy
    table) but NO agent-facing endpoint and NO agent-side enforcement code
    at all -- confirmed via a full grep across agent.cpp for "denylist"/
    "file_identity" turning up nothing. Configuring this policy did
    literally nothing on any endpoint. This endpoint plus
    FetchFileIdentityDenylist()/IsFileDenylisted() in agent.cpp close that
    gap.

    Picks the single highest-priority active file_identity_denylist policy,
    same simplified "one policy wins" pattern as application-control/
    wireless-policy above (not a union across multiple policies).

    The agent polls this on the same cadence as policy sync and caches the
    result. Requires ``X-Agent-Key`` header.
    """
    from sqlalchemy import select as _select
    from app.models.policy import Policy

    policy = (await db.execute(
        _select(Policy).where(
            Policy.type == "file_identity_denylist",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()

    cfg = (policy.config or {}) if policy else {}
    action = str(cfg.get("action") or "block").lower()
    if action not in ("block", "quarantine", "alert", "log"):
        action = "block"

    def _str_list(v):
        return [str(x) for x in (v or []) if str(x).strip()] if isinstance(v, list) else []

    extensions = [s.lower().lstrip(".") for s in _str_list(cfg.get("extensions"))]
    hashes = [s.lower() for s in _str_list(cfg.get("hashes"))]

    # Only actually enforced if a policy exists AND has at least one
    # extension or hash configured -- an empty denylist matching nothing
    # is functionally the same as no policy, and treating it as "enforced"
    # would just make the agent hash every file it sees for no reason.
    enforced = bool(policy) and (bool(extensions) or bool(hashes))

    return {
        "enforced": enforced,
        "action": action if enforced else "log",
        "extensions": extensions,
        "hashes": hashes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{agent_id}/wireless-policy")
async def get_wireless_policy(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    The wireless-transfer control policy the agent enforces locally. Ported
    from CyberSentinel-DLP. Blocks Bluetooth file transfer (the built-in
    fsquirt.exe wizard, via an Image File Execution Options redirect to the
    agent itself -- see SetIFEODebugger()/ApplyWirelessControls() in
    agent.cpp) and/or Wi-Fi Direct / Windows Nearby Sharing (via the
    Connected Devices Platform group policy), while leaving Bluetooth audio
    (A2DP/HFP headphones) and input (HID mice/keyboards) devices untouched --
    those profiles are never disabled by this control.

    mode: "enforce" (agent applies the OS-level disables) | "audit" (agent
    only logs what it would have blocked, no registry changes) | "off".
    block_bluetooth_file_transfer / block_nearby_sharing let each channel be
    toggled independently -- a site with a legitimate Bluetooth workflow can
    block only Nearby Sharing, for instance.

    The agent polls this on the same cadence as policy sync and only touches
    the registry when the effective enforcement actually changes (a
    reconciliation signature, not a write every sync tick). Requires
    ``X-Agent-Key`` header.
    """
    from sqlalchemy import select as _select
    from app.models.policy import Policy

    policy = (await db.execute(
        _select(Policy).where(
            Policy.type == "wireless_transfer_control",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()

    if not policy:
        return {
            "enforced": False,
            "mode": "off",
            "block_bluetooth_file_transfer": False,
            "block_nearby_sharing": False,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    cfg = policy.config or {}
    mode = str(cfg.get("mode") or "enforce").lower()
    # "off" is a real, documented, UI-selectable mode (see docstring above
    # and WirelessTransferControlPolicyForm.tsx's "Disable wireless
    # transfer control entirely" option) -- it was missing from this
    # whitelist, so selecting it got silently rewritten to "enforce",
    # meaning an admin choosing to DISABLE the control instead actively
    # BLOCKED Bluetooth file transfer / Nearby Sharing: the opposite of
    # what was selected. Found in a policy-engine audit, August 28 2026.
    if mode not in ("enforce", "audit", "off"):
        mode = "enforce"

    return {
        "enforced": mode != "off",
        "mode": mode,
        "block_bluetooth_file_transfer": bool(cfg.get("block_bluetooth_file_transfer", True)),
        "block_nearby_sharing": bool(cfg.get("block_nearby_sharing", True)),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{agent_id}/file-access-policy")
async def get_file_access_policy(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    Per-file/folder access control policies for this agent -- the GDPR
    Art. 32 "access control" measure. Unlike every other policy type this
    endpoint returns a LIST: a site typically wants one policy scoping
    "any file classified Confidential/Restricted" and a second scoping an
    explicit folder list, and both apply simultaneously.

    Enforcement is native NTFS DACLs (see ApplyFileAccessControl() in
    agent.cpp) -- SYSTEM and Administrators always keep full control so an
    admin can never lock themselves out; everyone else is denied unless
    named in authorized_users/authorized_groups (resolved as local Windows
    accounts or, if the endpoint is domain-joined, AD accounts/groups, via
    LookupAccountNameW).

    Two independent targeting modes, usable together on separate policies:
      - classification_levels: applied the moment the agent's existing
        file_system_monitoring pipeline classifies a newly written/modified
        file under a monitored path as one of these levels.
      - explicit_paths: applied/reconciled every policy-sync cycle,
        independent of classification, for admin-named files/folders.

    mode: "enforce" (agent sets the DACL) | "audit" (agent evaluates and
    logs what it WOULD restrict, no ACL changes) | "off".

    Unlike the DACL enforcement above, this endpoint does not yet report
    who was denied access after the fact -- that requires SACL-based
    Windows Security auditing and event-log forwarding, tracked as a
    separate follow-on, not built here. Requires a valid ``X-Agent-Key``
    (this response contains the authorized-user list, which is itself
    sensitive). Added August 2026.
    """
    from sqlalchemy import select as _select
    from app.models.policy import Policy

    policies = (await db.execute(
        _select(Policy).where(
            Policy.type == "file_access_control",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().all()

    out = []
    for policy in policies:
        cfg = policy.config or {}
        mode = str(cfg.get("mode") or "enforce").lower()
        if mode not in ("enforce", "audit", "off"):
            mode = "enforce"
        if mode == "off":
            continue

        classification_levels = [
            str(lvl).lower() for lvl in (cfg.get("classification_levels") or [])
            if str(lvl).strip()
        ]
        explicit_paths = [
            str(p) for p in (cfg.get("explicit_paths") or []) if str(p).strip()
        ]
        authorized_users = [
            str(u) for u in (cfg.get("authorized_users") or []) if str(u).strip()
        ]
        authorized_groups = [
            str(g) for g in (cfg.get("authorized_groups") or []) if str(g).strip()
        ]

        # A policy with no targeting at all and no authorized principals is
        # not actionable -- skip rather than have the agent silently lock
        # every file it happens to touch out from under every user.
        if not (classification_levels or explicit_paths):
            continue
        if not (authorized_users or authorized_groups):
            continue

        out.append({
            "id": str(policy.id),
            "name": policy.name,
            "mode": mode,
            "classification_levels": classification_levels,
            "explicit_paths": explicit_paths,
            "authorized_users": authorized_users,
            "authorized_groups": authorized_groups,
            "always_allow_admins": bool(cfg.get("always_allow_admins", True)),
        })

    return {
        "enforced": any(p["mode"] == "enforce" for p in out),
        "policies": out,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{agent_id}/printer-policy")
async def get_printer_policy(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    Combined printer DEVICE control + print CONTENT inspection policy for the
    endpoint. Ported from CyberSentinel-DLP. Closes the gap flagged in
    ``SanctionedPrinter``'s own docstring ("this allowlist has no agent-side
    enforcement yet ... shipped now so the management surface is ready the
    moment print monitoring lands") -- this is that moment.

    Device control (driven by a Policy row of type="printer_control"):
    enforced && mode=="enforce" -> agent cancels print jobs matching `scope`
    (block_all | block_network | block_local | allowlist, the last checked
    against the sanctioned_printers table below) regardless of document
    content. audit mode logs "would block" only. Independent of and additive
    to content inspection.

    Explicit deny (ported from CyberSentinel commit b7dc3f3): a
    SanctionedPrinter row with decision="deny" is returned in
    `denied_printers` UNCONDITIONALLY -- regardless of `scope` -- and beats
    an allow row for the same name. This is what makes "block this one
    printer, leave the rest of the fleet alone" expressible without moving
    the whole estate into allowlist scope (the allow list in `printers`
    below is still scope-gated as before).

    Content inspection (driven by a Policy row of type="print_content_prevention"):
    when active, the agent pauses the job, extracts real text from the
    spooled document (EMF/RAW ASCII + UTF-16LE string runs -- not just the
    filename), and evaluates it via the same POST /policy/evaluate endpoint
    the USB and network-share content-aware paths already use. content_mode
    enforce vs audit controls whether a sensitive verdict actually cancels
    the job or only logs it.

    The agent polls this on the same cadence as policy sync. Requires
    ``X-Agent-Key`` header.
    """
    from sqlalchemy import select as _select
    from app.models.policy import Policy
    from app.models.sanctioned_printer import SanctionedPrinter

    policy = (await db.execute(
        _select(Policy).where(
            Policy.type == "printer_control",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()
    enforced = policy is not None
    cfg = (policy.config or {}) if policy else {}
    mode = str(cfg.get("mode") or "enforce").lower() if enforced else "off"
    if mode not in ("enforce", "audit"):
        mode = "enforce"
    scope = str(cfg.get("scope") or "block_network").lower() if enforced else "none"
    if scope not in ("block_all", "block_network", "block_local", "allowlist", "none"):
        scope = "block_network"

    # Ship the sanctioned printer names only when allowlist scope is in play,
    # so the agent can enforce "block anything not on the list" offline.
    printers = []
    if enforced and scope == "allowlist":
        printers = [
            n for (n,) in (await db.execute(
                _select(SanctionedPrinter.printer_name).where(
                    SanctionedPrinter.is_enabled.is_(True),
                    SanctionedPrinter.decision == "allow",
                )
            )).all()
        ]

    # Deny rows ship unconditionally (any scope, as long as device control
    # is enforced at all) -- see the docstring above and SanctionedPrinter's
    # own module docstring for why this is deliberately not scope-gated.
    denied_printers = []
    if enforced:
        denied_printers = [
            n for (n,) in (await db.execute(
                _select(SanctionedPrinter.printer_name).where(
                    SanctionedPrinter.is_enabled.is_(True),
                    SanctionedPrinter.decision == "deny",
                )
            )).all()
        ]

    # CONFIRMED LIVE BUG (fixed here): two active print_content_prevention
    # policies existed at the same priority ("Block Sensitive Printing" with
    # no unknownContentAction key, and "Print Content" with
    # unknownContentAction="block"). The old code did
    # .order_by(Policy.priority.desc()).first() -- with a priority tie, SQL
    # doesn't guarantee which row comes back first, so this silently and
    # non-deterministically picked one policy's settings over the other's.
    # The admin configured "block" on the policy they were editing and it
    # was invisibly overridden by an unrelated leftover policy. Fixed by
    # fetching every active policy of this type and merging them: the
    # strictest setting from any policy wins (enforce beats audit, block
    # beats allow), so multiple admin-authored policies compose safely
    # instead of one arbitrarily shadowing another.
    content_policies = (await db.execute(
        _select(Policy).where(
            Policy.type == "print_content_prevention",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        )
    )).scalars().all()
    content_inspection = len(content_policies) > 0
    content_mode = "off"
    unknown_content_action = "allow"
    if content_inspection:
        content_mode = "audit"
        for _cp in content_policies:
            _cfg = _cp.config or {}
            _m = str(_cfg.get("mode") or "enforce").lower()
            if _m == "enforce":
                content_mode = "enforce"
            # "allow" | "block" -- what to do when content inspection is
            # active but genuinely could not read a job's real spooled data
            # (as opposed to reading it and finding it clean). Defaults to
            # "allow" so this is non-breaking for every existing
            # deployment. CONFIRMED LIVE: a real printer/driver/OS
            # combination was found where no spool file is ever observable
            # on disk for ANY print job, meaning "unavailable" isn't a rare
            # edge case for that endpoint -- it's the permanent state.
            # Fail-open there means content_inspection provides zero actual
            # protection while looking configured; this lets an admin
            # choose fail-closed instead, matching CyberSentinel's own
            # stated principle for file extraction ("content we could not
            # fully inspect must never be treated as clean") applied to the
            # print channel.
            _uca = str(_cfg.get("unknownContentAction") or "allow").lower()
            if _uca == "block":
                unknown_content_action = "block"
    if content_mode not in ("enforce", "audit", "off"):
        content_mode = "enforce"
    if unknown_content_action not in ("allow", "block"):
        unknown_content_action = "allow"

    # CONFIRMED LIVE: an admin set severity="critical" on the
    # print_content_prevention policy (the same top-level Policy.severity
    # field every other policy type has), but blocked/unverified print
    # events kept showing hardcoded "high"/"medium" -- the agent's print
    # event builder never had any way to know what severity the admin
    # actually configured, because this endpoint never returned it.
    # Mirrors the mode/unknownContentAction merge above: take the highest-
    # ranked severity across every active print_content_prevention policy,
    # so multiple policies compose the same way here too. Defaults to
    # "high" (the previous hardcoded value for a block) when no policy
    # carries an explicit severity, so this is non-breaking.
    content_severity = "high"
    if content_inspection:
        best_rank = -1
        for _cp in content_policies:
            _sev = str(_cp.severity or "").lower()
            if _sev and _severity_rank(_sev) > best_rank:
                best_rank = _severity_rank(_sev)
                content_severity = _sev
    if content_severity not in ("low", "medium", "high", "critical", "info"):
        content_severity = "high"

    return {
        "enforced": enforced,
        "mode": mode,
        "scope": scope,
        "printers": printers,
        "denied_printers": denied_printers,
        "content_inspection": content_inspection,
        "content_mode": content_mode,
        "unknown_content_action": unknown_content_action,
        "content_severity": content_severity,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# Built-in managed set used when a policy is active but names no apps of its
# own, so the feature works out of the box. Mirrors the agent's own fallback
# list in FetchMessagingAppPolicy() (agent.cpp).
# whatsapp.root.exe: current WhatsApp for Windows is a WebView2 app whose
# window belongs to WhatsApp.Root.exe -- such a machine has no whatsapp.exe
# at all, so this fallback silently never matched real installs until this
# was added (gap-scan of CyberSentinel-DLP commit 07ea6ba, August 21 2026).
_DEFAULT_MESSAGING_APPS = [
    "teams.exe", "ms-teams.exe", "msteams.exe", "whatsapp.exe", "whatsapp.root.exe",
    "telegram.exe", "slack.exe", "discord.exe", "signal.exe",
]

# Every type the local agent-side classifier can report for a typed message,
# so a typo in policy config is rejected rather than silently narrowing
# coverage to nothing. Ported from CyberSentinel-DLP, gap-scan of August 26
# 2026 -- mirrors NetworkExfilMonitor's NxTypeSeverity() table in agent.cpp.
_MESSAGING_DATA_TYPES = [
    "CREDIT_CARD", "AADHAAR", "PAN", "SSN", "INDIAN_PASSPORT",
    "AWS_KEY", "PRIVATE_KEY", "JWT_TOKEN", "IFSC", "UPI_ID", "INDIAN_PHONE",
]

# What a policy that hasn't chosen a data-type list gets: everything above
# EXCEPT INDIAN_PHONE. Not a blanket "everything", deliberately -- the
# endpoint treats an omitted key as "use this default", but an EXPLICIT empty
# selection (an operator unticking every box) as "inspection is off" -- see
# inspect_messages below. Naming a real default here is what keeps a phone
# number, the most ordinary thing typed into a chat app, from being the
# out-of-the-box thing that gets every message blocked.
_DEFAULT_MESSAGE_DATA_TYPES = [t for t in _MESSAGING_DATA_TYPES if t != "INDIAN_PHONE"]


def _message_data_types(cfg: dict) -> list:
    raw = cfg.get("message_data_types")
    if raw is None:
        return list(_DEFAULT_MESSAGE_DATA_TYPES)
    known = set(_MESSAGING_DATA_TYPES)
    return [t for t in (str(x).strip().upper() for x in raw) if t in known]


@router.get("/{agent_id}/messaging-app-policy")
async def get_messaging_app_policy(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    Managed messaging / thick-client app attachment-control policy. Ported
    from CyberSentinel-DLP. For a file selected in a managed app's (Teams /
    WhatsApp / Telegram / Slack / Discord / Signal) file picker, the agent
    reads + classifies it locally and, if Confidential/Restricted, alerts
    (default) or terminates the app (action == "block"), unless the user or
    file type is excepted.

    Same inspect-before-encryption model as the CLI-transfer-tool
    interception: the agent reads the file BEFORE it enters the app's
    (TLS-encrypted) upload, so pinned thick clients are covered without
    needing to break their TLS. action defaults to "alert" -- audit-first,
    so enabling a policy never kills an app until an admin opts into
    "block". Only file-picker attachments are seen; drag-and-drop into the
    app window bypasses the common dialog and would need a filesystem
    minifilter (out of scope for this user-mode agent).

    Also carries typed-message inspection (inspect_messages /
    message_data_types), ported from CyberSentinel-DLP in a gap-scan of
    August 26 2026. This is a different surface from the attachment path
    above -- the agent's messaging_text_monitor.cpp holds the Enter/send
    keystroke in a managed app via a low-level keyboard hook, reads the
    composer through UI Automation, classifies it locally, and re-injects
    the key if clean or drops it (in Block mode) if not. `action` above is
    SHARED between both surfaces once each is switched on; inspect_messages
    is the independent enable flag for the typed-message one specifically,
    and it defaults to FALSE and does NOT inherit from `enforced` -- an
    operator turning on attachment control should not silently also get a
    keyboard hook. See messaging_text_monitor.h's rollout note for why
    Alert mode should be validated before ever setting action to Block.

    Driven by a Policy row with type="messaging_app_control". The agent
    polls this on the same cadence as policy sync and caches the result.
    Requires ``X-Agent-Key`` header.
    """
    from sqlalchemy import select as _select
    from app.models.policy import Policy

    policy = (await db.execute(
        _select(Policy).where(
            Policy.type == "messaging_app_control",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        ).order_by(Policy.priority.desc())
    )).scalars().first()

    if not policy:
        return {
            "enforced": False,
            "action": "alert",
            "apps": [],
            "exception_users": [],
            "exempt_file_types": [],
            "inspect_messages": False,
            "message_data_types": [],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    cfg = policy.config or {}
    action = str(cfg.get("action") or "alert").lower()
    if action not in ("alert", "block"):
        action = "alert"

    def _lc_list(v):
        return [str(x).strip().lower() for x in (v or []) if str(x).strip()]

    apps = _lc_list(cfg.get("apps")) or list(_DEFAULT_MESSAGING_APPS)
    exc = cfg.get("exceptions") or {}

    data_types = _message_data_types(cfg)
    # An empty selection is resolved HERE, not on the agent: the agent can't
    # tell "operator picked nothing" from "server too old to send the field"
    # -- both arrive as an absent/empty array, and reading that as "every
    # Confidential/Restricted type" is the exact opposite of what unticking
    # every box means. So an explicit empty selection collapses inspection
    # to off, the one way that can't be misread.
    inspect_messages = bool(cfg.get("inspect_messages")) and bool(data_types)

    return {
        "enforced": True,
        "action": action,
        "apps": apps,
        "exception_users": _lc_list(exc.get("users")),
        "exempt_file_types": [s.lstrip(".") for s in _lc_list(exc.get("file_types"))],
        "inspect_messages": inspect_messages,
        "message_data_types": data_types,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


class DeviceAuthorizeRequest(BaseModel):
    """Device identity the agent reports when a USB storage device connects.
    This is a visibility/audit-trail call, logged as an event — the block/
    allow decision itself is made locally by the agent from the cached
    usb-allowlist response above (so it still works offline)."""
    serial_number: Optional[str] = Field(None, description="USB serial number — the match key")
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    product_name: Optional[str] = None
    device_name: Optional[str] = None
    drive_letter: Optional[str] = None
    action: str = Field("allow", description="What the agent actually did: allow | block | disconnect")
    sanctioned: bool = Field(False, description="Whether the serial matched an enabled allowlist row")
    enforced: bool = Field(False, description="Whether device-control enforcement was active at decision time")
    event: str = Field("connect", description="'connect' or 'disconnect' — lets the live connected/offline indicator on the USB Devices page tell the two apart")


@router.post("/{agent_id}/device/authorize")
async def log_device_authorization(
    agent_id: str,
    request: DeviceAuthorizeRequest,
    db: AsyncSession = Depends(get_db),
    _verified_agent: str = Depends(verify_agent_key),
):
    """
    Records the agent's local USB device connect/block decision as an event,
    so the device and verdict show up on the Events page (event_subtype
    "usb_device_authorization"). Purely for visibility — see the module note
    on get_usb_allowlist for why the decision is made locally by the agent
    rather than by this endpoint. Requires ``X-Agent-Key``.
    """
    import uuid as _uuid
    mongo = get_mongodb()["dlp_events"]
    now = datetime.now(timezone.utc)
    ident = request.product_name or request.device_name or request.serial_number or "USB device"
    usb_event = request.event if request.event in ("connect", "disconnect") else "connect"
    if usb_event == "disconnect":
        title, sev = f"USB device disconnected: {ident}", "info"
    elif request.action == "block":
        title, sev = f"USB device blocked (unsanctioned): {ident}", "high"
    elif request.enforced and request.sanctioned:
        title, sev = f"Sanctioned USB device allowed: {ident}", "low"
    else:
        title, sev = f"USB device connected: {ident}", "info"

    doc = {
        "event_id": f"devauth-{_uuid.uuid4()}",
        "timestamp": now,
        "event_type": "usb",
        "event_subtype": "usb_device_authorization",
        "severity": sev,
        "agent_id": agent_id,
        "source_type": "agent",
        "title": title,
        "description": title,
        "action": request.action,
        "blocked": request.action == "block",
        "device_sanctioned": request.sanctioned,
        "device_control_enforced": request.enforced,
        "serial_number": request.serial_number,
        "vendor_id": request.vendor_id,
        "product_id": request.product_id,
        "device_name": request.device_name or request.product_name,
        "drive_letter": request.drive_letter,
        # 'connect' or 'disconnect' — the live connected/offline indicator
        # and insertion-history view on the USB Devices page both key off
        # this (most recent event per serial: connect => still plugged in).
        "usb_event": usb_event,
    }
    try:
        await mongo.insert_one(doc)
    except Exception as e:  # noqa: BLE001 — logging must never fail the agent's call
        logger.warning("device authorization event log failed", agent_id=agent_id, error=str(e))

    logger.info(
        "USB device authorization", agent_id=agent_id, serial=request.serial_number or None,
        action=request.action, sanctioned=request.sanctioned, enforced=request.enforced,
    )
    return {"logged": True}


class PolicyEvaluationRequest(BaseModel):
    """Request model for real-time policy evaluation"""
    file_name: Optional[str] = Field(None, description="Name of the file being transferred (omit for clipboard)")
    file_content: Optional[str] = Field(
        None,
        description=(
            "Plain-text content to classify (clipboard, or OCR'd image text). "
            "Correct only for text formats — a binary file (pdf/docx/xlsx) "
            "decoded into this field is unreadable to the classifier and will "
            "look Public. Send file_content_b64 instead for any real file."
        ),
    )
    content: Optional[str] = Field(None, description="Clipboard or generic content (alias for file_content)")
    # Raw file bytes, base64-encoded. Preferred for any file transfer: the
    # server decodes and extracts real text (pdf/docx/xlsx/pptx/archives/
    # text), so binary documents are classified on their actual contents
    # rather than their compressed/binary bytes. See document_extract.py.
    file_content_b64: Optional[str] = Field(
        None, description="Base64 of the raw file bytes (preferred over file_content for real files)"
    )
    # Set by a caller that could NOT inspect the file at all (e.g. the agent
    # refusing to read a file over its size cap). Callers must send this
    # instead of silently allowing: the server marks the content
    # uninspectable so a policy decides, rather than an unread file being
    # classified Public and let through.
    inspection_skipped: Optional[str] = Field(
        None, description="Why the caller could not inspect: too_large | unreadable"
    )
    file_size: Optional[int] = Field(None, description="File size in bytes")
    event_type: str = Field("clipboard_copy", description="Event type (e.g., 'usb_file_transfer', 'clipboard_copy')")
    destination_type: Optional[str] = Field(None, description="Destination type (e.g., 'removable_drive', 'network')")
    source_path: Optional[str] = Field(None, description="Source file path")
    destination_path: Optional[str] = Field(None, description="Destination path")
    agent_id: Optional[str] = Field(None, description="Agent ID (also taken from URL path)")
    user_email: Optional[str] = Field(None, description="User email for ABAC")

    def get_content(self) -> str:
        """Return whichever plain-text content field is populated (fallback
        when there's no file_content_b64 to extract from)."""
        return self.file_content or self.content or ""


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
    # How the content was read. extraction_status="unreadable" means we could
    # NOT see inside (encrypted archive, scanned image, opaque binary) — the
    # classification below is therefore not evidence of being clean.
    extraction_status: str = Field("readable", description="readable | unreadable | too_large")
    extraction_kind: str = Field("text", description="pdf | docx | xlsx | pptx | archive | text | ...")


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
    await require_agent_key(http_request)

    try:
        # 0. Resolve the text to classify. When the caller sends raw bytes
        #    (file_content_b64) we extract real text from them first
        #    (pdf/docx/xlsx/pptx/archives/text) — this is what makes binary
        #    documents classifiable at all. Decoding their raw bytes directly
        #    into a text field yields compressed/binary garbage that always
        #    looks "Public" and lets sensitive documents through untouched.
        content_to_classify = request.get_content()
        extract_kind = "text"
        extraction_status = "readable"
        extraction_reason = ""
        if request.inspection_skipped:
            # The caller told us up front it couldn't look inside (too big to
            # read, etc). Don't pretend: mark it uninspectable and let policy rule.
            extraction_status = "too_large" if request.inspection_skipped == "too_large" else "unreadable"
            extract_kind = request.inspection_skipped
            extraction_reason = f"caller skipped inspection: {request.inspection_skipped}"
            content_to_classify = ""
            logger.info(
                "Caller skipped inspection",
                agent_id=agent_id, file_name=request.file_name,
                reason=request.inspection_skipped, file_size=request.file_size,
            )
        elif request.file_content_b64:
            import base64 as _b64
            from app.services.document_extract import extract_text as _extract_text
            try:
                raw = _b64.b64decode(request.file_content_b64, validate=False)
            except Exception as e:  # noqa: BLE001 — malformed base64 from an agent
                raise HTTPException(400, f"file_content_b64 is not valid base64: {e}")
            extracted = _extract_text(request.file_name or "", raw)
            content_to_classify = extracted.text
            extract_kind = extracted.kind
            extraction_reason = extracted.reason
            if not extracted.ok:
                # Unreadable (encrypted archive / scanned image / legacy .doc /
                # opaque binary) or simply bigger than we'll parse. Kept as two
                # distinct states so operators can treat them differently — an
                # encrypted archive is suspicious, a huge video usually isn't.
                extraction_status = "too_large" if extracted.kind == "too_large" else "unreadable"
                logger.info(
                    "Content not extractable",
                    agent_id=agent_id, file_name=request.file_name,
                    kind=extracted.kind, reason=extracted.reason,
                )
            elif extracted.truncated:
                # We read it, but not all of it — it outran the scan budget, or
                # an archive hit its safety limits. The text we DID get is
                # still classified below (it may convict the file on its own),
                # but we must not certify the part we never saw. Reported as
                # too_large so the same "block uninspectable content" policy
                # path governs it — otherwise padding a file with filler until
                # the secret falls past the budget would be a trivial bypass.
                extraction_status = "too_large"
                logger.info(
                    "Content only partially inspected",
                    agent_id=agent_id, file_name=request.file_name,
                    kind=extracted.kind, reason=extracted.reason,
                    scanned_chars=len(extracted.text),
                )

        # 1. Classify the file content using ClassificationEngine
        classification_engine = ClassificationEngine(db)
        classification_result = await classification_engine.classify_content(
            content_to_classify,
            context={
                "event_type": request.event_type,
                "file_name": request.file_name or "",
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
        # event_subtype mirrors event_type for USB file transfer requests so that
        # the DatabasePolicyEvaluator can match the "event_subtype == usb_file_transfer"
        # condition generated by _transform_usb_transfer_config.  The agent sends
        # event_type="usb_file_transfer" in the realtime evaluate request body,
        # which is equivalent to event_subtype in the background-processing path.
        event_data = {
            "classification_level": classification_result.classification,
            "confidence_score": classification_result.confidence_score,
            "classification_labels": [
                label
                for rule in classification_result.matched_rules
                for label in rule.get("classification_labels", [])
            ],
            "event_type": request.event_type,
            "event_subtype": request.event_type,  # agent sends subtype as event_type here
            "destination_type": request.destination_type,
            "source_path": request.source_path,
            "destination_path": request.destination_path,
            "file_name": request.file_name,
            "file_size": request.file_size,
            "agent_id": agent_id,
            # Policy-matchable: lets an operator write a rule like
            #   extraction_status equals unreadable -> block
            # to catch password-protected archives / scanned images / opaque
            # binaries, which we cannot inspect and which would otherwise
            # look "Public" with zero matches.
            "extraction_status": extraction_status,
            "extraction_kind": extract_kind,
        }

        # 3. Evaluate classification-aware policies
        policy_evaluator = DatabasePolicyEvaluator()
        policy_matches = await policy_evaluator.evaluate_event(event_data)

        # 4. Determine action based on matched policies
        should_block = False
        should_quarantine = False
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
                elif action_type == "quarantine":
                    # CRITICAL FIX: this case was missing entirely, so a
                    # quarantine-actioned USB file transfer policy always
                    # fell through to the final "allow" default below — the
                    # real-time evaluation had no way to tell the agent
                    # "quarantine this" instead of just "block" or "allow".
                    # The file was silently left in place with no
                    # enforcement action taken at all.
                    should_quarantine = True
                elif action_type == "alert":
                    should_alert = True
                    # Get highest severity
                    action_severity = action.get("parameters", {}).get("severity") or match.severity
                    if action_severity:
                        if alert_severity is None or _severity_rank(action_severity) > _severity_rank(alert_severity):
                            alert_severity = action_severity

        # 4b. Data Matching (EDM/fingerprint, task #123/#126) — force an
        # action directly from each matched source's own `classification`
        # field (Restricted/Confidential/Internal, chosen by the admin per
        # source when they uploaded it), independent of whatever Policy
        # rows exist. This is deliberately NOT routed through the same
        # classification_level -> Policy matching used above: the default
        # seeded policies (data/default_policies.json) only cover USB and
        # only exist for regex/ML classification, and their
        # Confidential->block mapping there is intentionally stricter than
        # what an admin configuring a Data Matching source separately asks
        # for. Doing it this way means data-matching enforcement works
        # identically across every channel that calls this endpoint (USB,
        # clipboard, browser upload, email, print) with zero policy setup
        # required, and never touches how regex/ML-only detections are
        # enforced. Purely additive — only ever turns should_block/
        # should_alert further ON, never off.
        data_match_sources_triggered = []
        for hit in classification_result.data_match_hits:
            data_match_sources_triggered.append({
                "source_id": hit["source_id"],
                "name": hit["name"],
                "type": hit["type"],
                "classification": hit["classification"],
            })
            if hit["classification"] == "Restricted":
                should_block = True
            else:  # Confidential or Internal
                should_alert = True
                hit_severity = "critical" if hit["classification"] == "Confidential" else "medium"
                if alert_severity is None or _severity_rank(hit_severity) > _severity_rank(alert_severity):
                    alert_severity = hit_severity

        # 5. Build response
        # Precedence: block > quarantine > alert > allow (matches the same
        # precedence used elsewhere for policy enforcement, e.g.
        # agent_policy_transformer.py's _serialize_policy()).
        if should_block:
            action = "block"
        elif should_quarantine:
            action = "quarantine"
        else:
            action = "allow"

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
        elif should_quarantine:
            reason = f"QUARANTINED - {reason}"

        logger.info(
            "Policy evaluation complete",
            agent_id=agent_id,
            file_name=request.file_name,
            action=action,
            policies_triggered=len(triggered_policies),
            should_block=should_block,
            data_match_sources_triggered=data_match_sources_triggered or None,
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
            extraction_status=extraction_status,
            extraction_kind=extract_kind,
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


# ── Web Activity Control (GenAI / web-activity, new capability) ────────────
# Ported in spirit from CyberSentinel-DLP commits f435920/d3ed5e4/f02edfe,
# adapted to SeceoKnight's own architecture (see app/core/web_activity.py
# and app/core/masking.py for the design rationale) rather than copied
# file-for-file. This is a SEPARATE endpoint from evaluate_policy_realtime
# above rather than a branch inside it: the matrix lives in policy.config
# and is read directly (see _transform_web_activity_config's docstring in
# policy_transformer.py for why), which is a different evaluation shape
# than DatabasePolicyEvaluator's generic conditions/rules matching every
# other channel through evaluate_policy_realtime uses.

_app_catalog_cache: Dict[str, Any] = {"rows": [], "expires_at": 0.0}
_APP_CATALOG_CACHE_TTL = 30  # seconds — short, admin edits should show up fast


async def _load_app_catalog(db: AsyncSession):
    import time as _time
    from sqlalchemy import select as _select
    from app.models.app_catalog import AppCatalogEntry as _AppCatalogEntry
    now = _time.monotonic()
    if _app_catalog_cache["expires_at"] > now and _app_catalog_cache["rows"]:
        return _app_catalog_cache["rows"]
    rows = (await db.execute(_select(_AppCatalogEntry.domain, _AppCatalogEntry.category))).all()
    pairs = [(r[0], r[1]) for r in rows]
    _app_catalog_cache["rows"] = pairs
    _app_catalog_cache["expires_at"] = now + _APP_CATALOG_CACHE_TTL
    return pairs


class WebActivityEvaluationRequest(BaseModel):
    """Request model for Web Activity Control evaluation. Sent by the
    browser extension (via the native host, same bridge pattern as the
    existing cloud-upload classify call) for a page action against a
    destination host."""
    host: str = Field(..., description="The destination hostname, e.g. 'chatgpt.com'")
    activity: str = Field(..., description="upload | download | attach | send | post | ai_response")
    content: Optional[str] = Field(None, description="Plain text to classify — a prompt, pasted body, or AI response text")
    file_name: Optional[str] = Field(None)
    file_content_b64: Optional[str] = Field(None, description="Base64 raw file bytes for upload/attach activities")


class WebActivityEvaluationResponse(BaseModel):
    app_category: Optional[str] = Field(None, description="webmail | file_sharing | collaboration | genai | null if unclassified")
    action: str = Field(..., description="allow | alert | block | redact")
    reason: str
    classification_level: str = Field("Public")
    confidence: float = Field(0.0)
    matched_rules: List[Dict[str, Any]] = Field(default_factory=list)
    # Only populated when action == "redact" and at least one span was
    # actually substituted — see app/core/masking.py. The caller (extension)
    # forwards THIS text instead of the original when present.
    redacted_content: Optional[str] = Field(None)
    labels_redacted: List[str] = Field(default_factory=list)
    # The web_activity_control policy that produced this decision (when one
    # was actually loaded/consulted -- null for "unclassified host" / "no
    # active policy" responses). The native host echoes this straight back
    # on its /events/ POST for the resulting event so that event carries a
    # trusted policy_id -- see create_event()'s handling of EventCreate.policy_id
    # in events.py. Without this, the dashboard's Policies page "Violations"
    # count (which aggregates matched_policies on stored events) stayed at 0
    # for Web Activity Control even while matching events showed up fine in
    # the Events log, because web_activity events never carried a policy_id
    # for anything to aggregate on (found August 19, 2026).
    policy_id: Optional[str] = Field(None)
    policy_name: Optional[str] = Field(None)


@router.post("/{agent_id}/web-activity/evaluate", response_model=WebActivityEvaluationResponse)
async def evaluate_web_activity(
    agent_id: str,
    request: WebActivityEvaluationRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Real-time evaluation for Web Activity Control (GenAI / web-activity).

    Flow:
      1. classify the destination host into an app_category via app_catalog
         (unrecognized host -> allow immediately, not a watched destination)
      2. find the active web_activity_control policy (none configured ->
         allow) and look up its matrix cell for (category, activity)
      3. classify the content (when provided) same as every other channel
      4. gate the cell's configured action on what was actually found:
         "block"/"alert" only fire when the content is genuinely sensitive
         (Confidential/Restricted for block, Internal+ for alert) --
         otherwise this degrades to "allow", same content-aware philosophy
         used everywhere else in this product (never punish innocuous
         data). "redact" only fires when there's something to redact.

    Requires ``X-Agent-Key`` header, same as evaluate_policy_realtime.
    """
    await require_agent_key(http_request)

    from sqlalchemy import select as _select
    from app.core import web_activity as wa
    from app.core.masking import redact_content as _redact_content
    from app.models.policy import Policy as _Policy

    try:
        catalog = await _load_app_catalog(db)
        category = wa.classify_host(request.host, catalog)
        if not category:
            return WebActivityEvaluationResponse(
                app_category=None, action="allow", reason="destination not in app catalog",
            )

        # The extension (web-activity.js) always sends activity="post" for
        # every REQUEST-side call, genai or not — it only has a flat domain
        # list from app_catalog, not per-domain categories, so it can't
        # cheaply tell "prompt to a genai host" (post) apart from "composed
        # message to a webmail/collaboration host" (send) before making the
        # call. That's fine for genai (it's the correct label already), but
        # for webmail/collaboration hosts it meant every request was looked
        # up as (webmail/collaboration, "post") — not a MEANINGFUL_CELLS
        # entry — so lookup_action() always fell through to DEFAULT_ACTION
        # ("allow") no matter what an admin configured for "Webmail Send" /
        # "Collaboration Send" in the matrix UI: those two cells were
        # silently unreachable end to end (found during a Nov 2026 DLP
        # quality audit). Re-derive the correct activity here from the
        # CATEGORY this function just resolved authoritatively from the
        # host — the one thing the server already doesn't trust the client
        # to self-report — instead of changing the extension/client
        # contract (which would need a new extension version rolled out
        # fleet-wide before the fix took effect anywhere).
        activity = request.activity
        if activity == "post" and category in ("webmail", "collaboration"):
            activity = "send"

        policy = (await db.execute(
            _select(_Policy).where(
                _Policy.type == "web_activity_control",
                _Policy.status == "active",
                _Policy.deleted_at.is_(None),
            ).order_by(_Policy.priority.desc())
        )).scalars().first()

        if not policy:
            return WebActivityEvaluationResponse(
                app_category=category, action="allow", reason="no active web_activity_control policy",
            )

        matrix = wa.normalize_matrix((policy.config or {}).get("matrix") or {})
        cell_action = wa.lookup_action(matrix, category, activity)

        # Resolve content to classify — same extraction path as
        # evaluate_policy_realtime for file bytes, plain content otherwise.
        content_to_classify = request.content or ""
        if request.file_content_b64:
            import base64 as _b64
            from app.services.document_extract import extract_text as _extract_text
            try:
                raw = _b64.b64decode(request.file_content_b64, validate=False)
                extracted = _extract_text(request.file_name or "", raw)
                content_to_classify = extracted.text
            except Exception:
                content_to_classify = content_to_classify or ""

        if cell_action == "allow" or not content_to_classify:
            return WebActivityEvaluationResponse(
                app_category=category, action="allow",
                reason=f"cell ({category}.{activity}) = {cell_action}" + ("" if content_to_classify else ", no content to inspect"),
                policy_id=str(policy.id), policy_name=policy.name,
            )

        classification_engine = ClassificationEngine(db)
        classification_result = await classification_engine.classify_content(
            content_to_classify,
            context={"event_type": "web_activity", "file_name": request.file_name or ""},
        )
        level = classification_result.classification
        is_sensitive_block = level in ("Confidential", "Restricted")
        is_sensitive_alert = level in ("Internal", "Confidential", "Restricted")
        has_matches = bool(classification_result.matched_rules)

        final_action = "allow"
        redacted_content = None
        labels_redacted: List[str] = []

        if cell_action == "block" and is_sensitive_block:
            final_action = "block"
        elif cell_action == "alert" and is_sensitive_alert:
            final_action = "alert"
        elif cell_action == "redact" and has_matches:
            redacted_content, labels_redacted = await _redact_content(
                db, content_to_classify, classification_result.matched_rules
            )
            final_action = "redact" if labels_redacted else "allow"

        reason = f"cell ({category}.{activity}) = {cell_action}; classified {level} ({classification_result.confidence_score:.0%})"

        logger.info(
            "Web activity evaluated",
            agent_id=agent_id, host=request.host, category=category, activity=activity,
            cell_action=cell_action, final_action=final_action, level=level,
        )

        return WebActivityEvaluationResponse(
            app_category=category, action=final_action, reason=reason,
            classification_level=level, confidence=classification_result.confidence_score,
            matched_rules=classification_result.matched_rules,
            redacted_content=redacted_content, labels_redacted=labels_redacted,
            policy_id=str(policy.id), policy_name=policy.name,
        )
    except Exception as e:
        logger.error("Web activity evaluation failed", agent_id=agent_id, host=request.host, error=str(e))
        # Fail-open, same posture as evaluate_policy_realtime — a DLP
        # server error must never brick the user's browser.
        return WebActivityEvaluationResponse(
            app_category=None, action="allow", reason=f"evaluation error: {e}",
        )
