"""
TAXII 2.1 ingest — poll a remote collection and upsert the indicators it
publishes as IOCs.

taxii2-client is synchronous (built on requests), so the network fetch runs in
a thread; parsing + upsert happen back on the event loop.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from dateutil import parser as dtparser

from app.core.crypto import decrypt_str
from app.services.ioc_service import (
    extract_indicators_from_pattern, upsert_ioc, ioc_matcher,
)

logger = structlog.get_logger()


def _feed_secrets(secrets_enc: Optional[str]) -> Dict[str, str]:
    if not secrets_enc:
        return {}
    try:
        return json.loads(decrypt_str(secrets_enc))
    except Exception:  # noqa: BLE001
        return {}


def _fetch_stix_objects_sync(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Blocking: connect to the TAXII 2.1 collection and return its STIX objects."""
    from taxii2client.v21 import Collection

    url = cfg["server_url"].rstrip("/") + "/"
    if cfg.get("collection_id"):
        url = f"{url}collections/{cfg['collection_id']}/"

    kwargs = {}
    if cfg.get("username"):
        kwargs["user"] = cfg["username"]
    secrets = _feed_secrets(cfg.get("secrets_enc"))
    if secrets.get("password"):
        kwargs["password"] = secrets["password"]

    collection = Collection(url, **kwargs)
    envelope = collection.get_objects()  # TAXII 2.1 envelope: {"objects": [...]}
    if isinstance(envelope, dict):
        return envelope.get("objects") or envelope.get("bundle", {}).get("objects") or []
    return []


def _parse_ts(value: Optional[str]):
    if not value:
        return None
    try:
        return dtparser.parse(value)
    except (ValueError, TypeError):
        return None


async def ingest_feed(db, feed) -> Dict[str, Any]:
    """Poll one feed, upsert its indicators, update the feed's status. Returns a
    summary dict."""
    cfg = {
        "server_url": feed.server_url,
        "collection_id": feed.collection_id,
        "username": feed.username,
        "secrets_enc": feed.secrets_enc,
    }
    created = 0
    seen = 0
    try:
        objects = await asyncio.to_thread(_fetch_stix_objects_sync, cfg)
    except Exception as e:  # noqa: BLE001
        feed.last_polled_at = datetime.now(timezone.utc)
        feed.last_status = f"error: {str(e)[:400]}"
        await db.commit()
        logger.warning("taxii_ingest_failed", feed=feed.name, error=str(e))
        return {"feed": feed.name, "ok": False, "error": str(e), "created": 0, "seen": 0}

    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        ptype = (obj.get("pattern_type") or "stix").lower()
        if ptype != "stix":
            continue
        seen += 1
        pairs = extract_indicators_from_pattern(obj.get("pattern", ""))
        labels = obj.get("labels") or obj.get("indicator_types")
        conf = obj.get("confidence")
        vf = _parse_ts(obj.get("valid_from"))
        vu = _parse_ts(obj.get("valid_until"))
        for ioc_type, value in pairs:
            try:
                if await upsert_ioc(
                    db, ioc_type=ioc_type, value=value, source=feed.name,
                    direction="ingested", stix_id=obj.get("id"),
                    pattern=obj.get("pattern"), name=obj.get("name"),
                    description=obj.get("description"), labels=labels,
                    confidence=conf, tlp=_extract_tlp(obj),
                    valid_from=vf, valid_until=vu, external_id=obj.get("id"),
                ):
                    created += 1
            except Exception as e:  # noqa: BLE001 — skip bad indicator, keep going
                logger.warning("ioc_upsert_failed", value=value, error=str(e))

    feed.last_polled_at = datetime.now(timezone.utc)
    feed.last_status = f"ok: +{created} new / {seen} indicators"
    feed.total_imported = (feed.total_imported or 0) + created
    await db.commit()
    ioc_matcher.bump()
    logger.info("taxii_ingest_ok", feed=feed.name, created=created, seen=seen)
    return {"feed": feed.name, "ok": True, "created": created, "seen": seen}


def _extract_tlp(obj: Dict[str, Any]) -> str:
    """Best-effort TLP from object_marking_refs (falls back to amber)."""
    _TLP = {
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "white",
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
    }
    for ref in obj.get("object_marking_refs") or []:
        if ref in _TLP:
            return _TLP[ref]
    return "amber"
