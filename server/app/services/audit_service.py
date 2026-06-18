"""
Audit Logging Service
"""
from typing import Optional, List
from datetime import datetime
from uuid import UUID
from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.audit_log import AuditLog

logger = structlog.get_logger()


class AuditService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log_action(self, user_id: Optional[UUID], action: str, details: dict = None) -> AuditLog:
        entry = AuditLog(user_id=user_id, action=action, details=details)
        self.db.add(entry)
        await self.db.flush()
        return entry

    async def get_logs(self, skip=0, limit=100, user_id=None, action=None, start_date=None, end_date=None) -> List[AuditLog]:
        query = select(AuditLog)
        filters = []
        if user_id:
            filters.append(AuditLog.user_id == user_id)
        if action:
            filters.append(AuditLog.action == action)
        if start_date:
            filters.append(AuditLog.created_at >= start_date)
        if end_date:
            filters.append(AuditLog.created_at <= end_date)
        if filters:
            query = query.where(and_(*filters))
        query = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count_logs(self, user_id=None, action=None, start_date=None, end_date=None) -> int:
        query = select(func.count(AuditLog.id))
        filters = []
        if user_id:
            filters.append(AuditLog.user_id == user_id)
        if action:
            filters.append(AuditLog.action == action)
        if start_date:
            filters.append(AuditLog.created_at >= start_date)
        if end_date:
            filters.append(AuditLog.created_at <= end_date)
        if filters:
            query = query.where(and_(*filters))
        result = await self.db.execute(query)
        return result.scalar() or 0

    async def get_distinct_actions(self) -> List[str]:
        result = await self.db.execute(select(AuditLog.action).distinct().order_by(AuditLog.action))
        return [row[0] for row in result.fetchall()]


async def audit_log(user_id, action: str, details: dict = None):
    """Fire-and-forget audit log entry. Uses its own session."""
    import app.core.database as _db
    try:
        if _db.postgres_session_factory:
            async with _db.postgres_session_factory() as session:
                svc = AuditService(session)
                await svc.log_action(user_id, action, details)
                await session.commit()
    except Exception as e:
        logger.warning("Failed to write audit log", action=action, error=str(e))


async def audit_abac_deny(
    user,
    *,
    resource_type: str,
    resource_id: str,
    reason: str,
) -> None:
    """
    Record an ABAC visibility denial.

    Called by endpoints that 404 a specific resource because the viewer's
    department/clearance doesn't match. We deliberately do NOT log ALLOW
    decisions — ABAC allows happen on every read and would drown the log.

    Rate limiting: per-user bucket in Redis with a 60s window. The first
    ``_DENY_LOG_BUDGET`` denials (default 20) are logged in full; further
    denials in the window are counted but not logged, and when the window
    closes a single ``abac.deny.suppressed`` summary is emitted. This stops
    a loop-through-ids attack from flooding ``audit_logs`` without losing
    the forensic signal that something anomalous is happening.
    """
    try:
        user_id = getattr(user, "id", None)
        email = getattr(user, "email", None)
        role = getattr(user, "role", None)
        role_val = getattr(role, "value", str(role)) if role is not None else None
        user_dept = getattr(user, "department", None)
        user_clr = getattr(user, "clearance_level", None)

        allowed, dropped_so_far = await _deny_log_admit(user_id)
        if not allowed:
            # Over budget — increment the suppressed counter and return.
            # A single summary is emitted when the window key is first
            # seen to exceed budget; subsequent hits just bump the count.
            if dropped_so_far == 1:
                logger.info(
                    "abac.deny.suppressed",
                    user_id=str(user_id) if user_id else None,
                    email=email,
                    reason="rate_limit_exceeded",
                    budget=_DENY_LOG_BUDGET,
                    window_seconds=_DENY_LOG_WINDOW,
                )
            return

        logger.info(
            "abac.deny",
            user_id=str(user_id) if user_id else None,
            email=email,
            role=role_val,
            user_department=user_dept,
            user_clearance=user_clr,
            resource_type=resource_type,
            resource_id=str(resource_id),
            decision="DENY",
            reason=reason,
        )

        await audit_log(
            user_id,
            "abac.deny",
            {
                "resource_type": resource_type,
                "resource_id": str(resource_id),
                "reason": reason,
                "user_department": user_dept,
                "user_clearance": user_clr,
            },
        )
    except Exception as e:
        logger.debug("audit_abac_deny failed (non-fatal)", error=str(e))


# ── Rate-limit helpers ──────────────────────────────────────────────────
_DENY_LOG_BUDGET = 20          # max full-detail DENY logs per user per window
_DENY_LOG_WINDOW = 60          # window size in seconds


def log_abac_scope(
    user,
    endpoint: str,
    visible_count: int,
    extra: Optional[dict] = None,
) -> None:
    """
    Emit a single aggregated scope log line for a list-style request.

    Not an audit row — structlog-only — so list endpoints can be hit at
    dashboard frequencies without polluting ``audit_logs``. Callers pass
    the already-filtered visible count; we don't know (or need) what the
    unfiltered count would have been. The ``has_wildcard`` signal is
    enough for SOC to distinguish scoped vs unscoped reads.
    """
    try:
        user_id = getattr(user, "id", None)
        email = getattr(user, "email", None)
        role = getattr(user, "role", None)
        role_val = getattr(role, "value", str(role)) if role is not None else None
        payload = {
            "endpoint": endpoint,
            "user_id": str(user_id) if user_id else None,
            "email": email,
            "role": role_val,
            "user_department": getattr(user, "department", None),
            "visible_count": int(visible_count),
        }
        if extra:
            payload.update(extra)
        logger.info("abac.scope", **payload)
    except Exception:
        # Observability must never break the request.
        pass


async def _deny_log_admit(user_id) -> tuple[bool, int]:
    """
    Admit-or-drop decision for a DENY log event.

    Returns ``(allowed, over_count)``:
    * ``allowed=True`` → caller should emit the full log + audit row.
    * ``allowed=False`` → caller should NOT log; ``over_count`` is the
      number of drops so far in this window (1 on the first drop, used
      by the caller to emit a one-time "suppressed" summary).

    Fails open on Redis errors (logs everything) — ABAC observability is
    more important than absolute rate protection when infra degrades.
    """
    if user_id is None:
        return True, 0
    try:
        from app.core.cache import get_cache

        cache = get_cache()
        key = f"abac:deny:ratelim:{user_id}"
        current = await cache.incr(key)
        # Set TTL on first bump only — keeps the window sliding per-user.
        if current == 1:
            await cache.expire(key, _DENY_LOG_WINDOW)
        if current <= _DENY_LOG_BUDGET:
            return True, 0
        return False, int(current) - _DENY_LOG_BUDGET
    except Exception:
        return True, 0
