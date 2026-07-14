"""
IOC core service: normalization, STIX 2.1 pattern <-> value, and a cached
matcher used by the event pipeline.

The matcher keeps an in-memory index of active indicator values (refreshed on a
short TTL + explicit generation bump on writes) so per-event matching is a set
lookup, never a DB round-trip on the hot path.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

import structlog
from sqlalchemy import select, text

logger = structlog.get_logger()


# ── value normalization ──────────────────────────────────────────────────────
def normalize_value(ioc_type: str, value: str) -> str:
    v = (value or "").strip()
    if ioc_type in ("domain", "email", "ipv6"):
        return v.lower()
    if ioc_type in ("file_sha256", "file_sha1", "file_md5"):
        return v.lower()
    if ioc_type == "url":
        return v  # keep case (paths are case-sensitive); strip only whitespace
    return v  # ipv4 unchanged


# STIX object-path → our ioc_type
_STIX_PATH_TO_TYPE = {
    ("ipv4-addr", "value"): "ipv4",
    ("ipv6-addr", "value"): "ipv6",
    ("domain-name", "value"): "domain",
    ("url", "value"): "url",
    ("email-addr", "value"): "email",
    ("file", "hashes.'sha-256'"): "file_sha256",
    ("file", "hashes.'sha-1'"): "file_sha1",
    ("file", "hashes.'md5'"): "file_md5",
    ("file", "hashes.sha-256"): "file_sha256",
    ("file", "hashes.sha-1"): "file_sha1",
    ("file", "hashes.md5"): "file_md5",
    ("file", "hashes.'sha256'"): "file_sha256",
    ("file", "hashes.'sha1'"): "file_sha1",
}
_TYPE_TO_STIX_PATH = {
    "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "email": "email-addr:value",
    "file_sha256": "file:hashes.'SHA-256'",
    "file_sha1": "file:hashes.'SHA-1'",
    "file_md5": "file:hashes.'MD5'",
}

# Matches `<obj>:<path> = '<value>'` comparisons inside a STIX pattern.
_COMPARISON_RE = re.compile(
    r"([a-z0-9\-]+):([a-z0-9_.'\-]+)\s*(?:=|LIKE)\s*'([^']+)'",
    re.IGNORECASE,
)


def extract_indicators_from_pattern(pattern: str) -> List[Tuple[str, str]]:
    """Parse a STIX pattern into a list of (ioc_type, value). Handles the common
    single- and multi-comparison indicator patterns; unknown object paths are
    skipped."""
    out: List[Tuple[str, str]] = []
    if not pattern:
        return out
    for obj, path, value in _COMPARISON_RE.findall(pattern):
        key = (obj.lower(), path.lower())
        ioc_type = _STIX_PATH_TO_TYPE.get(key)
        if ioc_type is None and obj.lower() == "file" and "hashes" in path.lower():
            # tolerate other hash spellings → infer by value length
            n = len(value)
            ioc_type = {64: "file_sha256", 40: "file_sha1", 32: "file_md5"}.get(n)
        if ioc_type:
            out.append((ioc_type, normalize_value(ioc_type, value)))
    return out


def build_stix_pattern(ioc_type: str, value: str) -> str:
    path = _TYPE_TO_STIX_PATH.get(ioc_type)
    if not path:
        raise ValueError(f"Unsupported IOC type: {ioc_type}")
    safe = value.replace("'", "\\'")
    return f"[{path} = '{safe}']"


# ── upsert ───────────────────────────────────────────────────────────────────
async def upsert_ioc(
    session,
    *,
    ioc_type: str,
    value: str,
    source: str,
    direction: str = "ingested",
    stix_id: Optional[str] = None,
    pattern: Optional[str] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    labels: Optional[list] = None,
    confidence: Optional[int] = None,
    tlp: Optional[str] = "amber",
    valid_from=None,
    valid_until=None,
    external_id: Optional[str] = None,
    created_by=None,
) -> bool:
    """Insert or refresh one IOC (unique on type+value). Returns True if a new
    row was created. Does NOT commit — caller commits (batch-friendly)."""
    from app.models.ioc import IOC

    norm = normalize_value(ioc_type, value)
    if not norm:
        return False
    existing = (await session.execute(
        select(IOC).where(IOC.ioc_type == ioc_type, IOC.value == norm)
    )).scalar_one_or_none()

    if existing:
        # Refresh mutable attribution/validity; never downgrade is_shared.
        existing.source = source or existing.source
        existing.confidence = confidence if confidence is not None else existing.confidence
        existing.valid_until = valid_until or existing.valid_until
        existing.is_active = True
        if labels:
            existing.labels = labels
        return False

    session.add(IOC(
        ioc_type=ioc_type, value=norm, source=source, direction=direction,
        stix_id=stix_id, pattern=pattern or build_stix_pattern(ioc_type, norm),
        name=name, description=description, labels=labels, confidence=confidence,
        tlp=tlp or "amber", valid_from=valid_from, valid_until=valid_until,
        external_id=external_id, created_by=created_by,
    ))
    return True


# ── matcher (cached) ─────────────────────────────────────────────────────────
class IOCMatcher:
    """In-memory index of active indicator values for O(1) event matching."""

    _CACHE_TTL = 30  # seconds

    def __init__(self) -> None:
        self._index: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._loaded_at: float = 0.0
        self._gen = 0
        self._loaded_gen = -1

    def bump(self) -> None:
        """Force a refresh on the next match (call after IOC writes)."""
        self._gen += 1

    async def _ensure(self) -> None:
        now = time.monotonic()
        if self._loaded_gen == self._gen and (now - self._loaded_at) < self._CACHE_TTL:
            return
        try:
            import app.core.database as db
            if db.postgres_session_factory is None:
                return
            async with db.postgres_session_factory() as session:
                rows = await session.execute(text(
                    "SELECT ioc_type, value, id, source, tlp, name, confidence "
                    "FROM iocs WHERE is_active = true"
                ))
                index: Dict[Tuple[str, str], Dict[str, Any]] = {}
                for r in rows.mappings():
                    key = (r["ioc_type"], normalize_value(r["ioc_type"], r["value"]))
                    index[key] = {
                        "ioc_id": str(r["id"]), "ioc_type": r["ioc_type"],
                        "value": r["value"], "source": r["source"],
                        "tlp": r["tlp"], "name": r["name"], "confidence": r["confidence"],
                    }
            self._index = index
            self._loaded_at = now
            self._loaded_gen = self._gen
        except Exception as e:  # noqa: BLE001 — matching must never break ingestion
            logger.warning("ioc_matcher_load_failed", error=str(e))

    @staticmethod
    def _candidates(event: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Derive matchable (type, value) pairs from an event document."""
        cands: List[Tuple[str, str]] = []

        def add(t: str, v: Optional[str]):
            if v:
                cands.append((t, normalize_value(t, str(v))))

        # Network destinations
        dest = event.get("destination") or event.get("destination_host")
        if dest:
            d = str(dest)
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d):
                add("ipv4", d)
            elif "://" in d:
                add("url", d)
            elif ":" in d and d.count(":") >= 2:
                add("ipv6", d)
            else:
                add("domain", d)
        add("ipv4", event.get("destination_ip"))
        add("url", event.get("url"))

        # File hashes (any of the common lengths)
        fh = event.get("file_hash") or (event.get("metadata") or {}).get("file_hash")
        if fh:
            n = len(str(fh))
            t = {64: "file_sha256", 40: "file_sha1", 32: "file_md5"}.get(n)
            if t:
                add(t, str(fh))
        return cands

    async def match_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        await self._ensure()
        if not self._index:
            return []
        hits = []
        for key in self._candidates(event):
            hit = self._index.get(key)
            if hit:
                hits.append(hit)
        return hits


# module-level singleton
ioc_matcher = IOCMatcher()
