"""
Threat Intelligence API — IOC management, TAXII feed ingest, and match review.

All endpoints require admin. IOCs can be added manually, imported (CSV / STIX
bundle), or pulled from configured TAXII 2.1 feeds. ``is_shared`` opt-in marks
an IOC for publication via the TAXII sharing server (see taxii.py).
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import require_role
from app.core.config import settings
from app.core.database import get_db, get_mongodb
from app.core.crypto import encrypt_str
from app.models.ioc import IOC, TAXIIFeed, TAXIIShareConfig, IOC_TYPES
from app.services.ioc_service import upsert_ioc, ioc_matcher, normalize_value
from app.services.taxii_ingest import ingest_feed
from app.services.audit_service import audit_log

logger = structlog.get_logger()
router = APIRouter()


def _uid(user):
    return getattr(user, "id", None) if not isinstance(user, dict) else user.get("sub")


# ── schemas ──────────────────────────────────────────────────────────────────
class IOCCreate(BaseModel):
    ioc_type: str = Field(..., description="One of: " + ", ".join(IOC_TYPES))
    value: str
    name: Optional[str] = None
    description: Optional[str] = None
    tlp: Optional[str] = "amber"
    confidence: Optional[int] = None
    labels: Optional[List[str]] = None


class IOCImport(BaseModel):
    format: str = Field("csv", description="csv | stix")
    content: str = Field(..., description="CSV text (type,value) or a STIX bundle JSON")


class ShareToggle(BaseModel):
    shared: bool


class SharingConfigUpdate(BaseModel):
    enabled: bool
    username: Optional[str] = None
    # None / omitted → leave the stored password unchanged; a non-empty string
    # sets/rotates it. Never returned by the API.
    password: Optional[str] = None


class FeedCreate(BaseModel):
    name: str
    server_url: str = Field(..., description="TAXII 2.1 API-root or collection URL")
    collection_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


def _ioc_out(i: IOC) -> Dict[str, Any]:
    return {
        "id": str(i.id), "ioc_type": i.ioc_type, "value": i.value,
        "name": i.name, "description": i.description, "labels": i.labels,
        "confidence": i.confidence, "tlp": i.tlp, "source": i.source,
        "direction": i.direction, "is_shared": i.is_shared, "is_active": i.is_active,
        "stix_id": i.stix_id,
        "valid_until": i.valid_until.isoformat() if i.valid_until else None,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }


# ── IOC CRUD ─────────────────────────────────────────────────────────────────
@router.get("/iocs")
async def list_iocs(
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    shared: Optional[bool] = None,
    q: Optional[str] = None,
    limit: int = 200,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(IOC).order_by(IOC.created_at.desc())
    if ioc_type:
        stmt = stmt.where(IOC.ioc_type == ioc_type)
    if source:
        stmt = stmt.where(IOC.source == source)
    if shared is not None:
        stmt = stmt.where(IOC.is_shared == shared)
    if q:
        stmt = stmt.where(IOC.value.ilike(f"%{q}%"))
    rows = (await db.execute(stmt.limit(min(limit, 1000)))).scalars().all()
    return {"iocs": [_ioc_out(r) for r in rows], "count": len(rows)}


@router.post("/iocs", status_code=status.HTTP_201_CREATED)
async def add_ioc(
    body: IOCCreate,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    if body.ioc_type not in IOC_TYPES:
        raise HTTPException(400, f"Invalid ioc_type. Must be one of: {', '.join(IOC_TYPES)}")
    if not normalize_value(body.ioc_type, body.value):
        raise HTTPException(400, "Empty indicator value.")
    created = await upsert_ioc(
        db, ioc_type=body.ioc_type, value=body.value, source="manual",
        direction="internal", name=body.name, description=body.description,
        labels=body.labels, confidence=body.confidence, tlp=body.tlp or "amber",
        created_by=_uid(current_user),
    )
    await db.commit()
    ioc_matcher.bump()
    await audit_log(_uid(current_user), "threat_intel.ioc.add",
                    {"type": body.ioc_type, "value": body.value, "new": created})
    return {"created": created, "ioc_type": body.ioc_type, "value": body.value}


@router.delete("/iocs/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(
    ioc_id: str,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(delete(IOC).where(IOC.id == ioc_id))
    if result.rowcount == 0:
        raise HTTPException(404, "IOC not found.")
    await db.commit()
    ioc_matcher.bump()
    return None


@router.post("/iocs/{ioc_id}/share")
async def toggle_share(
    ioc_id: str,
    body: ShareToggle,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(IOC).where(IOC.id == ioc_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "IOC not found.")
    row.is_shared = body.shared
    await db.commit()
    await audit_log(_uid(current_user), "threat_intel.ioc.share",
                    {"id": ioc_id, "shared": body.shared})
    return {"id": ioc_id, "is_shared": body.shared}


# ── partner sharing config (TAXII server credential) ─────────────────────────
_TAXII_PATH = "/api/v1/taxii2/"
_SHARE_COLLECTION = "dlp-shared-iocs"


def _sharing_out(row: Optional[TAXIIShareConfig]) -> Dict[str, Any]:
    """Public view of the sharing config. Never exposes the password itself —
    only whether one is set. The dashboard prepends its own origin to
    ``taxii_path`` to show the partner-facing URL."""
    if row is None:  # env fallback
        return {
            "enabled": bool(settings.TAXII_SHARE_PASSWORD),
            "username": settings.TAXII_SHARE_USER,
            "has_password": bool(settings.TAXII_SHARE_PASSWORD),
            "source": "environment",
            "taxii_path": _TAXII_PATH, "collection_id": _SHARE_COLLECTION,
            "updated_at": None,
        }
    return {
        "enabled": bool(row.enabled and row.secret_enc),
        "username": row.username,
        "has_password": bool(row.secret_enc),
        "source": "database",
        "taxii_path": _TAXII_PATH, "collection_id": _SHARE_COLLECTION,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.get("/sharing")
async def get_sharing_config(
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(TAXIIShareConfig).where(TAXIIShareConfig.id == 1))).scalar_one_or_none()
    return _sharing_out(row)


@router.put("/sharing")
async def update_sharing_config(
    body: SharingConfigUpdate,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(TAXIIShareConfig).where(TAXIIShareConfig.id == 1))).scalar_one_or_none()
    if row is None:
        # First write: seed from the existing env credential so turning sharing
        # on via the UI doesn't silently drop a password set in .env.
        row = TAXIIShareConfig(id=1, username=(settings.TAXII_SHARE_USER or "partner"))
        if settings.TAXII_SHARE_PASSWORD:
            row.secret_enc = encrypt_str(settings.TAXII_SHARE_PASSWORD)
        db.add(row)

    if body.username:
        row.username = body.username.strip()
    if body.password:  # non-empty → set / rotate
        row.secret_enc = encrypt_str(body.password)
    row.enabled = body.enabled
    row.updated_by = _uid(current_user)

    if body.enabled and not row.secret_enc:
        raise HTTPException(400, "Set a partner password before enabling sharing.")

    await db.commit()
    await db.refresh(row)
    await audit_log(_uid(current_user), "threat_intel.sharing.update",
                    {"enabled": row.enabled, "username": row.username,
                     "rotated": bool(body.password)})
    return _sharing_out(row)


@router.post("/iocs/import")
async def import_iocs(
    body: IOCImport,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    created = 0
    total = 0
    fmt = body.format.lower()

    if fmt == "csv":
        for line in body.content.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(("type,", "#")):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                ioc_type, value = parts[0], parts[1]
            else:
                ioc_type, value = _infer_type(parts[0]), parts[0]
            if ioc_type not in IOC_TYPES:
                continue
            total += 1
            if await upsert_ioc(db, ioc_type=ioc_type, value=value, source="import",
                                direction="internal", created_by=_uid(current_user)):
                created += 1

    elif fmt == "stix":
        try:
            bundle = json.loads(body.content)
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"Invalid STIX JSON: {e}")
        from app.services.ioc_service import extract_indicators_from_pattern
        for obj in (bundle.get("objects") or []):
            if obj.get("type") != "indicator":
                continue
            for ioc_type, value in extract_indicators_from_pattern(obj.get("pattern", "")):
                total += 1
                if await upsert_ioc(
                    db, ioc_type=ioc_type, value=value, source="import-stix",
                    direction="internal", stix_id=obj.get("id"),
                    pattern=obj.get("pattern"), name=obj.get("name"),
                    labels=obj.get("labels") or obj.get("indicator_types"),
                    created_by=_uid(current_user),
                ):
                    created += 1
    else:
        raise HTTPException(400, "format must be 'csv' or 'stix'.")

    await db.commit()
    ioc_matcher.bump()
    await audit_log(_uid(current_user), "threat_intel.ioc.import",
                    {"format": fmt, "created": created, "total": total})
    return {"created": created, "processed": total}


def _infer_type(value: str) -> str:
    import re
    v = value.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        return "ipv4"
    if "://" in v:
        return "url"
    if "@" in v:
        return "email"
    n = len(v)
    if n == 64:
        return "file_sha256"
    if n == 40:
        return "file_sha1"
    if n == 32:
        return "file_md5"
    return "domain"


@router.get("/stats")
async def ioc_stats(
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    total = (await db.execute(select(func.count(IOC.id)))).scalar() or 0
    shared = (await db.execute(select(func.count(IOC.id)).where(IOC.is_shared == True))).scalar() or 0  # noqa: E712
    active = (await db.execute(select(func.count(IOC.id)).where(IOC.is_active == True))).scalar() or 0  # noqa: E712
    by_type = (await db.execute(select(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type))).all()
    feeds = (await db.execute(select(func.count(TAXIIFeed.id)))).scalar() or 0
    return {
        "total": total, "active": active, "shared": shared, "feeds": feeds,
        "by_type": {t: c for t, c in by_type},
    }


@router.get("/matches")
async def recent_matches(
    limit: int = 50,
    current_user=Depends(require_role("admin")),
):
    db = get_mongodb()
    coll = db.get_collection("ioc_matches")
    cursor = coll.find({}).sort("timestamp", -1).limit(min(limit, 200))
    out = []
    async for m in cursor:
        m.pop("_id", None)
        ts = m.get("timestamp")
        if isinstance(ts, datetime):
            m["timestamp"] = ts.isoformat()
        out.append(m)
    return {"matches": out, "count": len(out)}


# ── TAXII feeds ──────────────────────────────────────────────────────────────
def _feed_out(f: TAXIIFeed) -> Dict[str, Any]:
    return {
        "id": str(f.id), "name": f.name, "server_url": f.server_url,
        "collection_id": f.collection_id, "poll_enabled": f.poll_enabled,
        "last_polled_at": f.last_polled_at.isoformat() if f.last_polled_at else None,
        "last_status": f.last_status, "total_imported": f.total_imported,
    }


@router.get("/feeds")
async def list_feeds(
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(TAXIIFeed).order_by(TAXIIFeed.created_at))).scalars().all()
    return {"feeds": [_feed_out(f) for f in rows]}


@router.post("/feeds", status_code=status.HTTP_201_CREATED)
async def add_feed(
    body: FeedCreate,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    existing = (await db.execute(select(TAXIIFeed).where(TAXIIFeed.name == body.name))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, f"A feed named '{body.name}' already exists.")
    secrets_enc = encrypt_str(json.dumps({"password": body.password})) if body.password else None
    feed = TAXIIFeed(
        name=body.name, server_url=body.server_url, collection_id=body.collection_id,
        username=body.username, secrets_enc=secrets_enc, created_by=_uid(current_user),
    )
    db.add(feed)
    await db.commit()
    await audit_log(_uid(current_user), "threat_intel.feed.add", {"name": body.name})
    return _feed_out(feed)


@router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_feed(
    feed_id: str,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(delete(TAXIIFeed).where(TAXIIFeed.id == feed_id))
    if result.rowcount == 0:
        raise HTTPException(404, "Feed not found.")
    await db.commit()
    return None


@router.post("/feeds/{feed_id}/poll")
async def poll_feed(
    feed_id: str,
    current_user=Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    feed = (await db.execute(select(TAXIIFeed).where(TAXIIFeed.id == feed_id))).scalar_one_or_none()
    if not feed:
        raise HTTPException(404, "Feed not found.")
    result = await ingest_feed(db, feed)
    return result
