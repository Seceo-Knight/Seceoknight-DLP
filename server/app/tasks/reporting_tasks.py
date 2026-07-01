"""
Celery Tasks for Scheduled Reporting
Background tasks for automated report generation and delivery.

BUG FIX: All tasks previously called the async generate_scheduled_report()
without await/asyncio.run(), so the coroutine was created but never executed.
Fixed by introducing _run_schedules() async helper and wrapping each task
body in asyncio.run().
"""

import asyncio
from datetime import datetime, timedelta

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings
from app.core.observability import StructuredLogger
from app.services.reporting_service import ReportingService, ReportSchedule, DEFAULT_SCHEDULES

logger = StructuredLogger(__name__)

# ── Celery app ────────────────────────────────────────────────────────────────

celery_app = Celery(
    "dlp_reporting",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,         # 30 minutes hard limit
    task_soft_time_limit=1500,    # 25 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=50,
)

celery_app.conf.beat_schedule = {
    "daily-reports": {
        "task": "app.tasks.reporting_tasks.generate_daily_reports",
        "schedule": crontab(hour=8, minute=0),                  # 8:00 AM UTC daily
    },
    "weekly-reports": {
        "task": "app.tasks.reporting_tasks.generate_weekly_reports",
        "schedule": crontab(hour=9, minute=0, day_of_week=1),   # Monday 9:00 AM UTC
    },
    "monthly-reports": {
        "task": "app.tasks.reporting_tasks.generate_monthly_reports",
        "schedule": crontab(hour=10, minute=0, day_of_month=1), # 1st of month 10:00 AM UTC
    },
    "google-drive-polling": {
        "task": "app.tasks.google_drive_polling_tasks.poll_google_drive_activity",
        "schedule": crontab(minute="*/5"),
    },
    "onedrive-polling": {
        "task": "app.tasks.onedrive_polling_tasks.poll_onedrive_activity",
        "schedule": crontab(minute="*/5"),
    },
    "event-cleanup": {
        "task": "app.tasks.event_cleanup_tasks.cleanup_old_events",
        "schedule": crontab(hour=2, minute=0),                  # 2:00 AM UTC daily
    },
}


# ── Async helper ──────────────────────────────────────────────────────────────

async def _run_schedules(
    schedules: list,
    start_date: datetime,
    end_date: datetime,
) -> list:
    """
    Execute a list of ReportSchedule objects asynchronously.

    Opens a fresh async DB session per report to avoid cross-task state
    contamination. Called via asyncio.run() from sync Celery task functions.
    """
    from app.core.database import postgres_session_factory
    from app.core.opensearch import get_opensearch_client

    results = []
    for schedule in schedules:
        async with postgres_session_factory() as db:
            try:
                opensearch = get_opensearch_client()
                service = ReportingService(db_session=db, opensearch=opensearch)
                result = await service.generate_scheduled_report(
                    schedule=schedule,
                    start_date=start_date,
                    end_date=end_date,
                )
                results.append(result)
                logger.logger.info(
                    "scheduled_report_ok",
                    report_name=schedule.name,
                    success=result.get("success"),
                )
            except Exception as exc:
                logger.log_error(exc, {"report_name": schedule.name})
                results.append({
                    "success": False,
                    "report_name": schedule.name,
                    "error": str(exc),
                })
    return results


# ── Tasks ─────────────────────────────────────────────────────────────────────

@celery_app.task(
    name="app.tasks.reporting_tasks.generate_daily_reports",
    bind=True,
    max_retries=2,
)
def generate_daily_reports(self):
    """
    Generate and email daily reports covering the previous day's activity.
    Scheduled: 8:00 AM UTC every day.
    """
    try:
        end_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        start_date = end_date - timedelta(days=1)
        schedules = [s for s in DEFAULT_SCHEDULES if s.frequency == "daily" and s.enabled]

        logger.logger.info(
            "starting_daily_reports",
            count=len(schedules),
            start=start_date.isoformat(),
            end=end_date.isoformat(),
        )

        # FIX: asyncio.run() correctly executes the async helper from sync Celery context
        results = asyncio.run(_run_schedules(schedules, start_date, end_date))

        logger.logger.info(
            "daily_reports_done",
            total=len(schedules),
            successful=sum(1 for r in results if r.get("success")),
        )
        return {
            "task": "daily_reports",
            "completed_at": datetime.utcnow().isoformat(),
            "reports_generated": len(results),
            "results": results,
        }
    except Exception as exc:
        logger.log_error(exc, {"task": "generate_daily_reports"})
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(
    name="app.tasks.reporting_tasks.generate_weekly_reports",
    bind=True,
    max_retries=2,
)
def generate_weekly_reports(self):
    """
    Generate and email weekly reports covering the previous Mon–Sun.
    Scheduled: Monday 9:00 AM UTC.
    """
    try:
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        days_since_monday = today.weekday() % 7
        start_date = today - timedelta(days=days_since_monday + 7)
        end_date = start_date + timedelta(days=7)
        schedules = [s for s in DEFAULT_SCHEDULES if s.frequency == "weekly" and s.enabled]

        logger.logger.info(
            "starting_weekly_reports",
            count=len(schedules),
            start=start_date.isoformat(),
            end=end_date.isoformat(),
        )

        results = asyncio.run(_run_schedules(schedules, start_date, end_date))

        logger.logger.info(
            "weekly_reports_done",
            total=len(schedules),
            successful=sum(1 for r in results if r.get("success")),
        )
        return {
            "task": "weekly_reports",
            "completed_at": datetime.utcnow().isoformat(),
            "reports_generated": len(results),
            "results": results,
        }
    except Exception as exc:
        logger.log_error(exc, {"task": "generate_weekly_reports"})
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(
    name="app.tasks.reporting_tasks.generate_monthly_reports",
    bind=True,
    max_retries=2,
)
def generate_monthly_reports(self):
    """
    Generate and email monthly reports covering the previous calendar month.
    Scheduled: 1st of each month at 10:00 AM UTC.
    """
    try:
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        first_of_month = today.replace(day=1)
        end_date = first_of_month - timedelta(days=1)
        start_date = end_date.replace(day=1)
        schedules = [s for s in DEFAULT_SCHEDULES if s.frequency == "monthly" and s.enabled]

        logger.logger.info(
            "starting_monthly_reports",
            count=len(schedules),
            start=start_date.isoformat(),
            end=end_date.isoformat(),
        )

        results = asyncio.run(_run_schedules(schedules, start_date, end_date))

        logger.logger.info(
            "monthly_reports_done",
            total=len(schedules),
            successful=sum(1 for r in results if r.get("success")),
        )
        return {
            "task": "monthly_reports",
            "completed_at": datetime.utcnow().isoformat(),
            "reports_generated": len(results),
            "results": results,
        }
    except Exception as exc:
        logger.log_error(exc, {"task": "generate_monthly_reports"})
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(
    name="app.tasks.reporting_tasks.generate_custom_report",
    bind=True,
    max_retries=1,
)
def generate_custom_report(
    self,
    report_name: str,
    report_types: list,
    recipients: list,
    start_date_iso: str,
    end_date_iso: str,
    formats: list = None,
):
    """
    Generate a custom on-demand report and optionally email it.
    Called from the /api/v1/reports/generate endpoint.
    """
    try:
        start_date = datetime.fromisoformat(start_date_iso.replace("Z", "+00:00")).replace(tzinfo=None)
        end_date = datetime.fromisoformat(end_date_iso.replace("Z", "+00:00")).replace(tzinfo=None)

        schedule = ReportSchedule(
            name=report_name,
            frequency="custom",
            report_types=report_types,
            recipients=recipients,
            formats=formats or ["pdf"],
            enabled=True,
        )

        logger.logger.info(
            "starting_custom_report",
            report_name=report_name,
            recipients=recipients,
        )

        results = asyncio.run(_run_schedules([schedule], start_date, end_date))
        result = results[0] if results else {"success": False, "error": "No results returned"}

        logger.logger.info(
            "custom_report_done",
            report_name=report_name,
            success=result.get("success"),
        )
        return result

    except Exception as exc:
        logger.log_error(exc, {"task": "generate_custom_report", "report_name": report_name})
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.tasks.reporting_tasks.test_reporting_system")
def test_reporting_system():
    """Health-check — verify Celery and reporting plumbing are operational."""
    return {
        "status": "success",
        "message": "Reporting system is operational",
        "timestamp": datetime.utcnow().isoformat(),
        "celery_version": celery_app.version,
    }
