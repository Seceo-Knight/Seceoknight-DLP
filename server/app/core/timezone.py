"""
Timezone utilities for SeceoKnight DLP.

Storage strategy:
    - All timestamps are stored in the database as UTC (timezone-aware).
    - ``utcnow()`` returns the current UTC time (timezone-aware).
    - ``to_display_tz()`` converts a UTC datetime to the configured
      ``APP_TIMEZONE`` for API responses and log display.
    - ``from_display_tz()`` converts a user-supplied local datetime to UTC.

Configure via the ``APP_TIMEZONE`` environment variable (default ``UTC``).
Examples: ``Asia/Kolkata``, ``US/Eastern``, ``Europe/London``.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app.core.config import settings

# Resolved once at import time; restart to pick up a new timezone.
_DISPLAY_TZ = ZoneInfo(settings.APP_TIMEZONE)

# Convenience constant for UTC
UTC = timezone.utc


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(UTC)


def display_tz() -> ZoneInfo:
    """Return the configured display timezone object."""
    return _DISPLAY_TZ


def to_display_tz(dt: datetime) -> datetime:
    """Convert a UTC datetime to the configured display timezone.

    If *dt* is naive it is assumed to be UTC.
    """
    if dt is None:
        return None  # type: ignore[return-value]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(_DISPLAY_TZ)


def from_display_tz(dt: datetime) -> datetime:
    """Convert a datetime in the display timezone to UTC.

    If *dt* is naive it is assumed to be in the display timezone.
    """
    if dt is None:
        return None  # type: ignore[return-value]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_DISPLAY_TZ)
    return dt.astimezone(UTC)


def format_iso(dt: datetime | None) -> str | None:
    """Format a datetime as ISO-8601 string in the display timezone.

    Returns ``None`` if *dt* is ``None``.
    """
    if dt is None:
        return None
    return to_display_tz(dt).isoformat()
