"""
Real-time Decision API

Standalone endpoint for agent enforcement decisions.
Classify → Evaluate → Decide in a single call, targeting <100ms latency.

Also includes:
- Batch event ingestion
- Delta policy sync
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from hashlib import sha256
import json

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.database import get_db, get_mongodb
from app.services.classification_engine import ClassificationEngine
from app.policies.decision_engine import DecisionEngine

logger = structlog.get_logger()
router = APIRouter()


# ─── Request / Response Models ───────────────────────────────────────────────


class DecisionRequest(BaseModel):
    """Input for the real-time decision endpoint"""
    agent_id: str = Field(..., description="Agent identifier")
    event: Dict[str, Any] = Field(..., description="Event payload")

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "agt-001",
                "event": {
                    "type": "USB_COPY",
                    "file_name": "data.xlsx",
                    "file_hash": "abc123",
                    "file_size": 12345,
                    "channel": "USB",
                    "content": "SSN: 123-45-6789",
                }
            }
        }


class DecisionResponse(BaseModel):
    decision: str = Field(..., description="BLOCK, ALLOW, ALERT, ENCRYPT, QUARANTINE")
    reason: str = Field(..., description="Human-readable reason")
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    severity: Optional[str] = None
    cache_ttl: int = Field(300, description="Seconds the agent should cache this decision")
    classification_level: Optional[str] = None
    confidence_score: float = 0.0
    matched_policies: List[Dict[str, Any]] = Field(default_factory=list)
    should_log: bool = True
    should_create_incident: bool = False


class BatchEventItem(BaseModel):
    event_id: str
    event_type: str
    severity: str = "low"
    agent_id: str
    source_type: str = "agent"
    decision: Optional[str] = None
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    channel: Optional[str] = None
    content: Optional[str] = None
    action: str = "logged"
    timestamp: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    # Optional ABAC hints — if absent, server derives from user_email / defaults.
    user_email: Optional[str] = None
    department: Optional[str] = None
    required_clearance: Optional[int] = None


class BatchEventRequest(BaseModel):
    events: List[BatchEventItem] = Field(..., min_length=1, max_length=500)


class BatchEventResponse(BaseModel):
    accepted: int
    rejected: int
    errors: List[Dict[str, str]] = Field(default_factory=list)


class PolicySyncResponse(BaseModel):
    version: str
    policies: List[Dict[str, Any]]
    policy_count: int
    generated_at: str
    is_delta: bool = False


# ─── Decision Endpoint (Real-time, <100ms target) ───────────────────────────


@router.post("/", response_model=DecisionResponse)
async def make_decision(
    request: DecisionRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    **Real-time enforcement decision.**

    Agent sends event context, server returns BLOCK/ALLOW/ALERT decision.
    Requires ``X-Agent-Key`` header for authentication.

    Pipeline: Classify content → Evaluate policies → Resolve conflicts → Return decision

    Target latency: <100ms
    """
    from app.api.v1.agents import verify_agent_key
    await verify_agent_key(http_request)
    event = request.event
    content = event.get("content") or event.get("file_content", "")

    # Step 1: Classify content (if present)
    classification_level = "Public"
    confidence_score = 0.0

    if content:
        try:
            engine = ClassificationEngine(db)
            result = await engine.classify_content(content, context={
                "event_type": event.get("type"),
                "file_name": event.get("file_name"),
                "agent_id": request.agent_id,
            })
            classification_level = result.classification
            confidence_score = result.confidence_score
        except Exception as e:
            logger.warning("Classification failed in decision path", error=str(e))

    # Step 2: Build normalized event structure for policy evaluation
    eval_event = {
        "event": {"type": event.get("type", "unknown"), "severity": event.get("severity", "medium")},
        "agent": {"id": request.agent_id},
        "event_type": event.get("type", "unknown"),
        "file_name": event.get("file_name"),
        "file_path": event.get("file_path"),
        "file_hash": event.get("file_hash"),
        "file_size": event.get("file_size"),
        "channel": event.get("channel"),
        "destination_type": event.get("destination_type") or event.get("channel"),
        "source_path": event.get("source_path"),
        "classification_level": classification_level,
        "confidence_score": confidence_score,
        "classification_metadata": {
            "classification_level": classification_level,
            "confidence_score": confidence_score,
        },
    }

    # Step 3: Evaluate policies and resolve conflicts
    decision_engine = DecisionEngine()
    decision = await decision_engine.evaluate(
        eval_event,
        classification_level=classification_level,
        confidence_score=confidence_score,
    )

    return DecisionResponse(**decision.to_dict())


# ─── Batch Event Ingestion (Async) ──────────────────────────────────────────


@router.post("/events/batch", response_model=BatchEventResponse)
async def ingest_batch_events(
    request: BatchEventRequest,
    http_request: Request,
):
    """
    **Batch event upload.**

    SECURITY: Requires a valid X-Agent-Key header. Without this check an
    unauthenticated caller could flood MongoDB with forged events,
    poison SIEM dashboards, or drown real detections.

    Agent batches events and sends them periodically. Events are stored
    in MongoDB with minimal processing. Heavy processing (classification,
    policy eval) happens asynchronously.
    """
    from app.api.v1.agents import verify_agent_key
    await verify_agent_key(http_request)

    db = get_mongodb()
    events_collection = db["dlp_events"]

    accepted = 0
    rejected = 0
    errors = []

    # Prepare bulk insert. Tag each doc with ABAC attrs (spec: resolve from
    # user_email and fall back to DEFAULT / 0; honour explicit overrides).
    from app.services.user_dept_cache import resolve_user_attrs, DEFAULT_DEPARTMENT

    docs = []
    for item in request.events:
        try:
            abac = await resolve_user_attrs(item.user_email)
            department = (item.department or abac.department or DEFAULT_DEPARTMENT).strip() or DEFAULT_DEPARTMENT
            required_clearance = int(
                item.required_clearance
                if item.required_clearance is not None
                else 0
            )

            doc = {
                "event_id": item.event_id,
                "event_type": item.event_type,
                "severity": item.severity,
                "agent_id": item.agent_id,
                "source_type": item.source_type,
                "decision": item.decision,
                "file_path": item.file_path,
                "file_name": item.file_name,
                "file_hash": item.file_hash,
                "channel": item.channel,
                "action_taken": item.action,
                "timestamp": item.timestamp or datetime.now(timezone.utc).isoformat(),
                "metadata": item.metadata or {},
                "batch_ingested": True,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "user_email": item.user_email,
                "department": department,
                "required_clearance": required_clearance,
            }
            docs.append(doc)
            accepted += 1
        except Exception as e:
            rejected += 1
            errors.append({"event_id": item.event_id, "error": str(e)})

    if docs:
        try:
            # Use ordered=False for best throughput (continues on individual errors)
            result = await events_collection.insert_many(docs, ordered=False)
            logger.info("Batch events ingested", count=len(result.inserted_ids))
        except Exception as e:
            logger.error("Batch insert failed", error=str(e))
            # Partial failure: some may have been inserted
            rejected += accepted
            accepted = 0
            errors.append({"event_id": "batch", "error": str(e)})

        # PG mirror for the batch. Best-effort — a PG outage must not cause
        # the agent to retry the batch (Mongo already has it).
        try:
            from app.services.pg_event_mirror import mirror_events_bulk
            attempted, mirror_errors = await mirror_events_bulk(docs)
            if mirror_errors:
                logger.warning(
                    "Batch PG mirror had row errors",
                    attempted=attempted,
                    errors=mirror_errors,
                )
        except Exception as e:
            logger.warning("Batch PG mirror dispatch failed", error=str(e))

    return BatchEventResponse(accepted=accepted, rejected=rejected, errors=errors)


# ─── Delta Policy Sync ──────────────────────────────────────────────────────


@router.get("/policies/sync", response_model=PolicySyncResponse)
async def sync_policies(
    http_request: Request,
    agent_id: str,
    platform: str = "windows",
    current_version: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    **Delta policy sync for agents.**

    SECURITY: Requires a valid X-Agent-Key header. The policy bundle
    contains regex patterns, keyword lists, protected folder IDs and
    detection thresholds — i.e. the full playbook for evading DLP.
    It must not be handed out anonymously.

    Agent sends its current policy version. Server returns:
    - If version matches: empty delta (no changes)
    - If version differs: full policy bundle

    Agents should call this periodically (e.g., every 60 seconds).
    """
    from app.api.v1.agents import verify_agent_key
    await verify_agent_key(http_request)

    from app.services.policy_service import PolicyService
    from app.policies.agent_policy_transformer import AgentPolicyTransformer

    service = PolicyService(db)
    policies = await service.get_enabled_policies()

    transformer = AgentPolicyTransformer()
    bundle = transformer.build_bundle(
        policies,
        platform=platform,
        agent_id=agent_id,
    )

    server_version = bundle["version"]

    # Delta check: if agent already has this version, return minimal response
    if current_version and current_version == server_version:
        return PolicySyncResponse(
            version=server_version,
            policies=[],
            policy_count=0,
            generated_at=datetime.now(timezone.utc).isoformat() + "Z",
            is_delta=True,
        )

    # Full sync: flatten grouped policies into a list
    all_policies = []
    for policy_type, policy_list in bundle.get("policies", {}).items():
        for p in policy_list:
            p["policy_type"] = policy_type
            all_policies.append(p)

    return PolicySyncResponse(
        version=server_version,
        policies=all_policies,
        policy_count=len(all_policies),
        generated_at=bundle["generated_at"],
        is_delta=False,
    )


# ─── Versioned Policy Distribution (Section 4 of DLP spec) ────────────────


class PolicyLatestResponse(BaseModel):
    """Lightweight version check — no policy payload."""
    version: int = Field(..., description="Monotonic integer version")
    checksum: str = Field(..., description="SHA-256 of the serialized bundle")
    timestamp: str = Field(..., description="ISO-8601 generation time")
    policy_count: int = Field(0)


class PolicyDownloadResponse(BaseModel):
    """Full versioned policy bundle for agent download."""
    version: int
    checksum: str
    timestamp: str
    policies: List[Dict[str, Any]]
    policy_count: int


# In-memory version counter — protected by asyncio.Lock for atomicity
import asyncio
_policy_version_counter: int = 0
_policy_version_cache: Dict[str, Any] = {}
_version_lock = asyncio.Lock()


async def _build_versioned_bundle(
    db: AsyncSession,
    platform: str = "windows",
    agent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a versioned policy bundle with integer version and SHA-256 checksum."""
    global _policy_version_counter, _policy_version_cache

    from app.services.policy_service import PolicyService
    from app.policies.agent_policy_transformer import AgentPolicyTransformer

    service = PolicyService(db)
    policies = await service.get_enabled_policies()

    transformer = AgentPolicyTransformer()
    bundle = transformer.build_bundle(policies, platform=platform, agent_id=agent_id)

    # Flatten grouped policies into a list
    all_policies = []
    for policy_type, policy_list in bundle.get("policies", {}).items():
        for p in policy_list:
            p["policy_type"] = policy_type
            all_policies.append(p)

    # Serialize deterministically for checksum
    serialized = json.dumps(all_policies, sort_keys=True, default=str)
    checksum = sha256(serialized.encode("utf-8")).hexdigest()

    # Atomic version update under lock
    async with _version_lock:
        if checksum != _policy_version_cache.get("checksum"):
            _policy_version_counter += 1
            _policy_version_cache = {
                "version": _policy_version_counter,
                "checksum": checksum,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "policies": all_policies,
                "policy_count": len(all_policies),
            }

    return _policy_version_cache


@router.get("/policy/latest", response_model=PolicyLatestResponse)
async def get_policy_latest(
    http_request: Request,
    platform: str = Query("windows", description="Agent platform"),
    agent_id: Optional[str] = Query(None, description="Agent ID for scoped policies"),
    db: AsyncSession = Depends(get_db),
):
    """
    **GET /policy/latest** — Lightweight version check.

    SECURITY: Requires a valid X-Agent-Key header.

    Agent calls this periodically to check if a newer policy bundle is available.
    Returns only version + checksum (no policy payload).
    Agent compares with its local version and downloads only if newer.
    """
    from app.api.v1.agents import verify_agent_key
    await verify_agent_key(http_request)

    bundle = await _build_versioned_bundle(db, platform, agent_id)

    return PolicyLatestResponse(
        version=bundle["version"],
        checksum=bundle["checksum"],
        timestamp=bundle["timestamp"],
        policy_count=bundle["policy_count"],
    )


@router.get("/policy/download", response_model=PolicyDownloadResponse)
async def download_policy_bundle(
    http_request: Request,
    version: Optional[int] = Query(None, description="Specific version to download (latest if omitted)"),
    platform: str = Query("windows", description="Agent platform"),
    agent_id: Optional[str] = Query(None, description="Agent ID for scoped policies"),
    db: AsyncSession = Depends(get_db),
):
    """
    **GET /policy/download** — Full policy bundle download.

    SECURITY: Requires a valid X-Agent-Key header. Full policy bundle
    contains the detection playbook; never return anonymously.

    Agent calls this after discovering a newer version via /policy/latest.
    Returns the complete policy bundle with checksum for integrity validation.

    The agent must:
    1. Download to temp file
    2. Validate checksum
    3. Load into memory
    4. Swap policy pointer atomically
    """
    from app.api.v1.agents import verify_agent_key
    await verify_agent_key(http_request)

    bundle = await _build_versioned_bundle(db, platform, agent_id)

    # Version mismatch check (requested specific version but it's not current)
    if version is not None and version != bundle["version"]:
        # For now, we only serve the latest version.
        # In production, maintain a version history table.
        raise HTTPException(
            status_code=404,
            detail=f"Version {version} not found. Latest is {bundle['version']}.",
        )

    return PolicyDownloadResponse(
        version=bundle["version"],
        checksum=bundle["checksum"],
        timestamp=bundle["timestamp"],
        policies=bundle["policies"],
        policy_count=bundle["policy_count"],
    )
