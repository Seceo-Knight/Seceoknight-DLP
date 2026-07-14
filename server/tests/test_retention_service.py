"""
Tests for app.services.retention_service.get_effective_retention — the
dashboard-managed log-retention policy with a hard 90-day compliance floor.

Ported alongside the data-retention feature; CyberSentinel DLP shipped this
with zero tests (and, separately, no Alembic migration for the table at all
— see 030_retention_config.py for the fix).
"""
import pytest

from app.services.retention_service import get_effective_retention
from app.models.retention_config import MIN_RETENTION_DAYS


@pytest.mark.asyncio
async def test_env_fallback_when_no_db_row(db_session):
    """No retention_config row → falls back to the settings env defaults."""
    from app.core.config import settings

    ev, osd = await get_effective_retention(db_session)
    assert ev == max(MIN_RETENTION_DAYS, settings.EVENT_RETENTION_DAYS)
    assert osd == max(MIN_RETENTION_DAYS, settings.OPENSEARCH_RETENTION_DAYS)


@pytest.mark.asyncio
async def test_env_fallback_is_clamped_to_floor(db_session, monkeypatch):
    """Even a below-floor env default can never resolve below 90 days."""
    from app.core import config as config_module

    monkeypatch.setattr(config_module.settings, "EVENT_RETENTION_DAYS", 30)
    monkeypatch.setattr(config_module.settings, "OPENSEARCH_RETENTION_DAYS", 10)

    ev, osd = await get_effective_retention(db_session)
    assert ev == MIN_RETENTION_DAYS
    assert osd == MIN_RETENTION_DAYS


@pytest.mark.asyncio
async def test_db_row_wins_over_env_default(db_session):
    from app.models.retention_config import RetentionConfig

    db_session.add(RetentionConfig(id=1, event_retention_days=365, opensearch_retention_days=180))
    await db_session.commit()

    ev, osd = await get_effective_retention(db_session)
    assert ev == 365
    assert osd == 180


@pytest.mark.asyncio
async def test_retention_config_check_constraint_enforces_floor(db_session):
    """The DB CHECK constraint (ck_retention_floor) rejects below-floor
    values directly, independent of the API-level validation."""
    from app.models.retention_config import RetentionConfig
    from sqlalchemy.exc import IntegrityError

    db_session.add(RetentionConfig(id=1, event_retention_days=10, opensearch_retention_days=10))
    with pytest.raises(IntegrityError):
        await db_session.commit()
