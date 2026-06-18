"""
Background Tasks
Celery tasks for async processing
"""

from .reporting_tasks import celery_app, generate_daily_reports, generate_weekly_reports, generate_monthly_reports, generate_custom_report
from .google_drive_polling_tasks import poll_google_drive_activity
from .onedrive_polling_tasks import poll_onedrive_activity
from .event_cleanup_tasks import cleanup_old_events

__all__ = [
    "celery_app",
    "generate_daily_reports",
    "generate_weekly_reports",
    "generate_monthly_reports",
    "generate_custom_report",
    "poll_google_drive_activity",
    "poll_onedrive_activity",
    "cleanup_old_events"
]
