"""
TAXII 2.1 sharing server — publishes opt-in (``is_shared``) DLP IOCs so partner
security vendors can poll them as STIX 2.1.

Endpoints (TAXII 2.1):
  GET /taxii2/                                  Discovery
  GET /taxii2/api/                              API Root
  GET /taxii2/api/collections/                  Collections
  GET /taxii2/api/collections/{id}/             Collection
  GET /taxii2/api/collections/{id}/objects/     STIX objects (envelope)

Read-only, HTTP Basic auth against TAXII_SHARE_USER / TAXII_SHARE_PASSWORD.
If no password is configured, every endpoint returns 503 (sharing disabled).
"""
import base64
import binascii
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt_str
from app.core.database import get_db
from app.models.ioc import IOC, TAXIIShareConfig
from app.services.ioc_service import build_stix_pattern

router = APIRouter()

TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
COLLECTION_ID = "dlp-shared-iocs"

# Well-known TLP v1 marking-definition IDs (STIX 2.1).
_TLP_MARKINGS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # NAMESPACE_URL


async def get_effective_share_config(db: AsyncSession) -> tuple[bool, str, str]:
    """Resolve the active sharing config. A dashboard-managed DB row wins;
    otherwise fall back to the TAXII_SHARE_* env vars (backward compatible).
    Returns (enabled, username, password)."""
    row = (await db.execute(
        select(TAXIIShareConfig).where(TAXIIShareConfig.id == 1)
    )).scalar_one_or_none()
    if row is not None:
        password = ""
        if row.secret_enc:
            try:
                password = decrypt_str(row.secret_enc)
            except Exception:  # noqa: BLE001 — treat undecryptable secret as unset
                password = ""
        return (bool(row.enabled and password),
                row.username or settings.TAXII_SHARE_USER, password)
    return (bool(settings.TAXII_SHARE_PASSWORD),
            settings.TAXII_SHARE_USER, settings.TAXII_SHARE_PASSWORD)


async def taxii_auth(request: Request, db: AsyncSession = Depends(get_db)) -> None:
    """HTTP Basic auth for partner vendors. 503 if sharing is off, 401 otherwise."""
    enabled, share_user, share_pw = await get_effective_share_config(db)
    if not enabled:
        raise HTTPException(status_code=503, detail="IOC sharing is disabled (no TAXII credential configured).")
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        raise HTTPException(status_code=401, detail="Authentication required.",
                            headers={"WWW-Authenticate": 'Basic realm="taxii"'})
    try:
        user, _, pw = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8").partition(":")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=401, detail="Malformed credentials.")
    ok = hmac.compare_digest(user, share_user) and hmac.compare_digest(pw, share_pw)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid credentials.",
                            headers={"WWW-Authenticate": 'Basic realm="taxii"'})


def _taxii(content: Dict[str, Any]) -> Response:
    import json
    return Response(content=json.dumps(content), media_type=TAXII_MEDIA)


def _stix(content: Dict[str, Any]) -> Response:
    import json
    return Response(content=json.dumps(content), media_type=STIX_MEDIA)


def _collection_obj(base: str) -> Dict[str, Any]:
    return {
        "id": COLLECTION_ID,
        "title": "CyberSentinel DLP — Shared Indicators",
        "description": "DLP-derived and curated IOCs shared with partner vendors.",
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_MEDIA],
    }


@router.get("/taxii2/")
async def discovery(request: Request, _: None = Depends(taxii_auth)):
    # Derive the api-root URL from the live request path so it stays correct
    # regardless of the mount prefix (the router sits under /api/v1).
    base = str(request.base_url).rstrip("/")
    disco_path = request.url.path.rstrip("/")   # e.g. /api/v1/taxii2
    api_root = f"{base}{disco_path}/api/"
    return _taxii({
        "title": "CyberSentinel DLP TAXII Server",
        "description": "TAXII 2.1 server publishing shared DLP threat indicators.",
        "contact": "security@cybersentinel",
        "default": api_root,
        "api_roots": [api_root],
    })


@router.get("/taxii2/api/")
async def api_root(_: None = Depends(taxii_auth)):
    return _taxii({
        "title": "CyberSentinel DLP",
        "description": "Shared DLP indicators API root.",
        "versions": [TAXII_MEDIA],
        "max_content_length": 10485760,
    })


@router.get("/taxii2/api/collections/")
async def collections(request: Request, _: None = Depends(taxii_auth)):
    base = str(request.base_url).rstrip("/")
    return _taxii({"collections": [_collection_obj(base)]})


@router.get("/taxii2/api/collections/{collection_id}/")
async def collection(collection_id: str, request: Request, _: None = Depends(taxii_auth)):
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="Unknown collection.")
    base = str(request.base_url).rstrip("/")
    return _taxii(_collection_obj(base))


@router.get("/taxii2/api/collections/{collection_id}/objects/")
async def collection_objects(
    collection_id: str,
    _: None = Depends(taxii_auth),
    db: AsyncSession = Depends(get_db),
):
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="Unknown collection.")

    rows = (await db.execute(
        select(IOC).where(IOC.is_shared == True, IOC.is_active == True)  # noqa: E712
    )).scalars().all()

    objects: List[Dict[str, Any]] = []
    used_tlps = set()
    for i in rows:
        objects.append(_to_stix_indicator(i))
        if i.tlp in _TLP_MARKINGS:
            used_tlps.add(i.tlp)

    # Include the referenced TLP marking-definition SDOs so the envelope is
    # self-contained.
    for tlp in used_tlps:
        objects.append({
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": _TLP_MARKINGS[tlp],
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": f"TLP:{tlp.upper()}",
            "definition": {"tlp": tlp},
        })

    return _stix({"objects": objects, "more": False})


def _iso(dt) -> str:
    if not dt:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _to_stix_indicator(i: IOC) -> Dict[str, Any]:
    stix_id = i.stix_id or f"indicator--{uuid.uuid5(_NS, f'{i.ioc_type}:{i.value}')}"
    pattern = i.pattern or build_stix_pattern(i.ioc_type, i.value)
    obj: Dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": _iso(i.created_at),
        "modified": _iso(i.updated_at or i.created_at),
        "name": i.name or f"{i.ioc_type}: {i.value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _iso(i.valid_from or i.created_at),
        "labels": i.labels or ["malicious-activity"],
    }
    if i.description:
        obj["description"] = i.description
    if i.confidence is not None:
        obj["confidence"] = int(i.confidence)
    if i.valid_until:
        obj["valid_until"] = _iso(i.valid_until)
    if i.tlp in _TLP_MARKINGS:
        obj["object_marking_refs"] = [_TLP_MARKINGS[i.tlp]]
    return obj
