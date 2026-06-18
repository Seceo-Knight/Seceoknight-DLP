"""
User → department lookup with Redis caching.

Used only by event ingest paths. Events are immutable once stored: if a
user later moves to a different department, historical events stay tagged
with the department they had at ingest time. This matches the requirement
that events be a faithful record of what happened.

Cache design:
* Key: ``dlp:user_dept:{email_lower}``
* Value: JSON ``{"department": "...", "clearance_level": N}``
* TTL: 300 seconds (5 minutes)
* Unknown emails are also cached (as ``{"department": "DEFAULT",
  "clearance_level": 0}``) to avoid DB hammering on unauth-known senders
  like agent-generated events whose ``user_email`` isn't a real account.

On any Redis failure the function falls back to a fresh DB lookup — never
error out on the ingest hot path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import get_cache
from app.core.database import postgres_session_factory
from app.models.user import User

logger = structlog.get_logger()


DEFAULT_DEPARTMENT = "DEFAULT"
DEFAULT_CLEARANCE = 0
# 60s is a deliberate compromise: invalidate() is called on every user
# mutation path (update/soft-delete/hard-delete) so updates propagate
# immediately on the happy path. The TTL bounds the worst case — if the
# invalidate Redis DEL fails silently, stale department assignments on
# new events can persist at most ~60s instead of ~5 min.
CACHE_TTL_SECONDS = 60


@dataclass(frozen=True, slots=True)
class UserAttrs:
    department: str
    clearance_level: int

    @property
    def as_dict(self) -> dict:
        return {
            "department": self.department,
            "clearance_level": self.clearance_level,
        }


def _cache_key(email: str) -> str:
    return f"dlp:user_dept:{email.strip().lower()}"


async def _lookup_in_db(email: str) -> UserAttrs:
    """Resolve department via the users table. Unknown → DEFAULT / 0."""
    try:
        if postgres_session_factory is None:
            return UserAttrs(DEFAULT_DEPARTMENT, DEFAULT_CLEARANCE)
        async with postgres_session_factory() as session:  # type: AsyncSession
            stmt = (
                select(User.department, User.clearance_level)
                .where(User.email == email)
                .limit(1)
            )
            row = (await session.execute(stmt)).first()
    except Exception as e:
        logger.warning(
            "user_dept_cache: DB lookup failed, using DEFAULT",
            email=email,
            error=str(e),
        )
        return UserAttrs(DEFAULT_DEPARTMENT, DEFAULT_CLEARANCE)

    if not row:
        return UserAttrs(DEFAULT_DEPARTMENT, DEFAULT_CLEARANCE)

    dept = (row[0] or DEFAULT_DEPARTMENT).strip() or DEFAULT_DEPARTMENT
    clr = int(row[1]) if row[1] is not None else DEFAULT_CLEARANCE
    return UserAttrs(dept, clr)


async def resolve_user_attrs(email: Optional[str]) -> UserAttrs:
    """
    Resolve a user's ABAC attributes for ingest-time tagging.

    ``email`` may be None or an empty string (e.g. system-generated events,
    background scans). In that case we return the baseline — department
    ``DEFAULT`` and clearance 0.
    """
    if not email:
        return UserAttrs(DEFAULT_DEPARTMENT, DEFAULT_CLEARANCE)

    key = _cache_key(email)

    # 1. Cache lookup (non-fatal on any Redis error).
    try:
        cache = get_cache()
        raw = await cache.get(key)
        if raw:
            data = json.loads(raw)
            return UserAttrs(
                department=str(data.get("department", DEFAULT_DEPARTMENT)),
                clearance_level=int(data.get("clearance_level", DEFAULT_CLEARANCE)),
            )
    except Exception as e:
        logger.debug("user_dept_cache: redis GET failed", error=str(e))

    # 2. Miss → DB lookup.
    attrs = await _lookup_in_db(email)

    # 3. Best-effort cache populate; don't let a Redis outage poison ingest.
    try:
        cache = get_cache()
        await cache.set(key, json.dumps(attrs.as_dict), ex=CACHE_TTL_SECONDS)
    except Exception as e:
        logger.debug("user_dept_cache: redis SET failed", error=str(e))

    return attrs


async def invalidate(email: str) -> None:
    """Delete the cached entry for ``email``. Call this after user updates."""
    if not email:
        return
    try:
        cache = get_cache()
        await cache.delete(_cache_key(email))
    except Exception:
        pass
