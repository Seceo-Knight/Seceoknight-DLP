"""
Canonical Mongo → PostgreSQL mapping for DLP events.

Both the dual-write hot path (after Mongo ingest) and the one-time backfill
script consume this module, so the two cannot drift. Every field is
defensively defaulted to keep PG's NOT NULL constraints satisfied even when
the source Mongo doc is partial.

The mapper is *pure*: it takes a dict and returns a dict. No I/O.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID


# ── Clamps / lookups ─────────────────────────────────────────────────────

# PG event.severity has a CHECK: 'low','medium','high','critical','info'.
# Mongo data is already clean on this field (verified in prod sample), but
# clamp defensively for bad inputs.
_ALLOWED_SEVERITY = {"low", "medium", "high", "critical", "info"}


def _first_str(doc: dict, *keys: str, default: str = "") -> str:
    """Return the first string-valued key from the doc, else default."""
    for k in keys:
        v = doc.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return default


def _to_uuid(value: Any) -> Optional[UUID]:
    """Best-effort UUID coercion. Returns None on invalid / missing input."""
    if value is None or value == "":
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _to_datetime(value: Any) -> Optional[datetime]:
    """Mongo values may be datetime, ISO string, or absent."""
    if value is None:
        return None
    if isinstance(value, datetime):
        # Ensure tz-aware; Mongo stored UTC for us but asyncpg is stricter.
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None
    return None


def _to_ip(value: Any) -> Optional[str]:
    """Pass-through for IP strings; None for anything unusable.

    asyncpg validates INET encoding itself. We just filter obviously wrong
    inputs so a bad value doesn't poison a whole batch insert.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or s in ("-", "unknown"):
        return None
    # Very cheap sanity: must contain a digit; asyncpg does the real parse.
    return s if any(c.isdigit() for c in s) else None


# ── Main mapping ─────────────────────────────────────────────────────────


def mongo_doc_to_pg_event(doc: dict) -> dict:
    """
    Convert a single Mongo ``dlp_events`` document to a kwargs dict suitable
    for ``sqlalchemy.insert(Event).values(**kwargs)``.

    Returns a dict (never raises) with every NOT NULL field populated.
    Callers perform the actual insert with ON CONFLICT (event_id) DO NOTHING
    for idempotency.
    """
    event_id = _first_str(doc, "id", "event_id", default="")
    if not event_id:
        # Mongo's unique index on `id` guarantees non-empty in real data; a
        # missing event_id means the doc is malformed. The caller should
        # skip it (checked downstream).
        return {}

    # Required-NOT-NULL columns get safe fallbacks.
    severity_raw = _first_str(doc, "severity", default="info").lower()
    severity = severity_raw if severity_raw in _ALLOWED_SEVERITY else "info"

    event_type = _first_str(doc, "event_type", default="unknown")
    source_type = _first_str(doc, "source_type", "source", default="agent")
    action = _first_str(doc, "action_taken", "action", default="logged")

    description = _first_str(
        doc,
        "description",
        "title",
        default=f"{event_type} event",
    )

    timestamp = _to_datetime(doc.get("timestamp")) or datetime.now(timezone.utc)
    created_at = _to_datetime(doc.get("ingested_at") or doc.get("processed_at")) or timestamp

    # Classification: prefer the Mongo label array, else the raw classification field.
    classification = doc.get("classification_labels") or doc.get("classification")
    if classification is not None and not isinstance(classification, (list, dict)):
        # Coerce scalar to list so JSON type stores something structured.
        classification = [classification]

    details = doc.get("metadata") or doc.get("details")
    tags = doc.get("tags")
    confidence = doc.get("classification_score") or doc.get("confidence_score") or doc.get("confidence")
    try:
        confidence_score = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence_score = None

    return {
        "id": uuid.uuid4(),
        "event_id": event_id,
        "event_type": event_type,
        "event_subtype": _first_str(doc, "event_subtype", default="") or None,
        "agent_id": _first_str(doc, "agent_id", default="") or None,
        "source_type": source_type,
        "source_id": _first_str(doc, "source_id", default="") or None,
        "user_email": _first_str(doc, "user_email", default="") or None,
        "user_id": _to_uuid(doc.get("user_id")),
        "username": _first_str(doc, "username", default="") or None,
        "description": description,
        "severity": severity,
        "action": action,
        "file_path": _first_str(doc, "file_path", "source_path", default="") or None,
        "file_name": _first_str(doc, "file_name", default="") or None,
        "file_size": doc.get("file_size") if isinstance(doc.get("file_size"), int) else None,
        "file_hash": _first_str(doc, "file_hash", default="") or None,
        "classification": classification,
        "classification_label": _to_uuid(doc.get("classification_label")),
        # Denormalized classification tier for dashboard filtering.
        "classification_level": (
            _first_str(doc, "classification_level", "classification_category")
            or None
        ),
        "confidence_score": confidence_score,
        "policy_id": _to_uuid(doc.get("policy_id")),
        "policy_name": _first_str(doc, "policy_name", default="") or None,
        "policy_violated": _first_str(doc, "policy_violated", default="") or None,
        "channel": _first_str(doc, "channel", default="") or None,
        "decision": _first_str(doc, "decision", default="") or None,
        "destination": _first_str(doc, "destination", default="") or None,
        "destination_details": doc.get("destination_details") if isinstance(
            doc.get("destination_details"), (dict, list)
        ) else None,
        "source_ip": _to_ip(doc.get("source_ip")),
        "destination_ip": _to_ip(doc.get("destination_ip")),
        "protocol": _first_str(doc, "protocol", default="") or None,
        "details": details if isinstance(details, (dict, list)) else None,
        "tags": tags if isinstance(tags, (dict, list)) else None,
        "status": _first_str(doc, "processing_status", "status", default="new"),
        "reviewed": _first_str(doc, "reviewed", default="no"),
        "reviewed_by": _to_uuid(doc.get("reviewed_by")),
        "reviewed_at": _to_datetime(doc.get("reviewed_at")),
        "timestamp": timestamp,
        "created_at": created_at,
        # ABAC — defaults mirror the column defaults so the CHECK/NOT NULL
        # pass even if the source doc predates backfill 009.
        "department": _first_str(doc, "department", default="DEFAULT") or "DEFAULT",
        "required_clearance": int(doc.get("required_clearance") or 0),
        "endpoint_id": _to_uuid(doc.get("endpoint_id")),
    }
