"""
Effective log-retention resolution.

A dashboard-managed ``retention_config`` DB row wins; otherwise the RETENTION
env defaults apply. Both values are clamped to ``MIN_RETENTION_DAYS`` so the
policy can never resolve below the compliance floor, regardless of source.
"""
from __future__ import annotations

from sqlalchemy import select

from app.core.config import settings
from app.models.retention_config import RetentionConfig, MIN_RETENTION_DAYS


async def get_effective_retention(session) -> tuple[int, int]:
    """Return (event_retention_days, opensearch_retention_days), each >= 90."""
    row = (await session.execute(
        select(RetentionConfig).where(RetentionConfig.id == 1)
    )).scalar_one_or_none()
    if row is not None:
        ev, osd = row.event_retention_days, row.opensearch_retention_days
    else:
        ev, osd = settings.EVENT_RETENTION_DAYS, settings.OPENSEARCH_RETENTION_DAYS
    return (max(MIN_RETENTION_DAYS, int(ev)), max(MIN_RETENTION_DAYS, int(osd)))
