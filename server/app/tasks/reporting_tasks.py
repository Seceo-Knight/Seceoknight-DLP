"""
Celery Tasks for Scheduled Reporting
Background tasks for automated report generation
"""

from datetime import datetime, timedelta
from celery import Celery
from celery.schedules import crontab

from app.core.config import settings
from app.core.database import get_db_session
from app.services.reporting_service import ReportingService, DEFAULT_SCHEDULES
from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)

# Initialize Celery
celery_app = Celery(
    "dlp_reporting",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,  # 30 minutes
    task_soft_time_limit=1500,  # 25 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=50
)

# Define beat schedule for automated reports
celery_app.conf.beat_schedule = {
    "daily-reports": {
        "task": "app.tasks.reporting_tasks.generate_daily_reports",
        "schedule": crontab(hour=8, minute=0),  # 8:00 AM UTC every day
    },
    "weekly-reports": {
        "task": "app.tasks.reporting_tasks.generate_weekly_reports",
        "schedule": crontab(hour=9, minute=0, day_of_week=1),  # Monday 9:00 AM UTC
    },
    "monthly-reports": {
        "task": "app.tasks.reporting_tasks.generate_monthly_reports",
        "schedule": crontab(hour=10, minute=0, day_of_month=1),  # 1st of month, 10:00 AM UTC
    },
    "google-drive-polling": {
        "task": "app.tasks.google_drive_polling_tasks.poll_google_drive_activity",
        "schedule": crontab(minute="*/5"),  # Run every 5 minutes
    },
    "onedrive-polling": {
        "task": "app.tasks.onedrive_polling_tasks.poll_onedrive_activity",
        "schedule": crontab(minute="*/5"),  # Run every 5 minutes
    },
    "event-cleanup": {
        "task": "app.tasks.event_cleanup_tasks.cleanup_old_events",
        "schedule": crontab(hour=2, minute=0),  # 2:00 AM UTC daily
    },
}


@celery_app.task(name="app.tasks.reporting_tasks.generate_daily_reports")
def generate_daily_reports():
    """
    Generate and send daily reports

    Scheduled to run daily at 8:00 AM UTC
    Reports on the previous day's activity
    """
    try:
        logger.logger.info("starting_daily_reports")

        # Calculate date range (previous day)
        end_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        start_date = end_date - timedelta(days=1)

        # Find daily schedules
        daily_schedules = [s for s in DEFAULT_SCHEDULES if s.frequency == "daily" and s.enabled]

        results = []
        for schedule in daily_schedules:
            # Get database session
            db_session = next(get_db_session())

            try:
                # Create reporting service
                reporting = ReportingService(db_session=db_session)

                # Generate report
                result = reporting.generate_scheduled_report(
                    schedule=schedule,
                    start_date=start_date,
                    end_date=end_date
                )

                results.append(result)

                logger.logger.info("daily_report_completed",
                                  report_name=schedule.name,
                                  success=result.get("success"))

            finally:
                db_session.close()

        logger.logger.info("daily_reports_completed",
                          total_schedules=len(daily_schedules),
                          successful=sum(1 for r in results if r.get("success")))

        return {
            "task": "daily_reports",
            "completed_at": datetime.utcnow().isoformat(),
            "reports_generated": len(results),
            "results": results
        }

    except Exception as e:
        logger.log_error(e, {"task": "generate_daily_reports"})
        raise


@celery_app.task(name="app.tasks.reporting_tasks.generate_weekly_reports")
def generate_weekly_reports():
    """
    Generate and send weekly reports

    Scheduled to run every Monday at 9:00 AM UTC
    Reports on the previous week's activity (Monday-Sunday)
    """
    try:
        logger.logger.info("starting_weekly_reports")

        # Calculate date range (previous week)
        end_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        # Go back to previous Monday
        days_since_monday = (end_date.weekday()) % 7
        start_date = end_date - timedelta(days=days_since_monday + 7)
        end_date = start_date + timedelta(days=7)

        # Find weekly schedules
        weekly_schedules = [s for s in DEFAULT_SCHEDULES if s.frequency == "weekly" and s.enabled]

        results = []
        for schedule in weekly_schedules:
            db_session = next(get_db_session())

            try:
                reporting = ReportingService(db_session=db_session)

                result = reporting.generate_scheduled_report(
                    schedule=schedule,
                    start_date=start_date,
                    end_date=end_date
                )

                results.append(result)

                logger.logger.info("weekly_report_completed",
                                  report_name=schedule.name,
                                  success=result.get("success"))

            finally:
                db_session.close()

        logger.logger.info("weekly_reports_completed",
                          total_schedules=len(weekly_schedules),
                          successful=sum(1 for r in results if r.get("success")))

        return {
            "task": "weekly_reports",
            "completed_at": datetime.utcnow().isoformat(),
            "reports_generated": len(results),
            "results": results
        }

    except Exception as e:
        logger.log_error(e, {"task": "generate_weekly_reports"})
        raise


@celery_app.task(name="app.tasks.reporting_tasks.generate_monthly_reports")
def generate_monthly_reports():
    """
    Generate and send monthly reports

    Scheduled to run on the 1st of each month at 10:00 AM UTC
    Reports on the previous month's activity
    """
    try:
        logger.logger.info("starting_monthly_reports")

        # Calculate date range (previous month)
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        # First day of current month
        first_of_month = today.replace(day=1)
        # Last day of previous month
        end_date = first_of_month - timedelta(days=1)
        # First day of previous month
        start_date = end_date.replace(day=1)

        # Find monthly schedules
        monthly_schedules = [s for s in DEFAULT_SCHEDULES if s.frequency == "monthly" and s.enabled]

        results = []
        for schedule in monthly_schedules:
            db_session = next(get_db_session())

            try:
                reporting = ReportingService(db_session=db_session)

                result = reporting.generate_scheduled_report(
                    schedule=schedule,
                    start_date=start_date,
                    end_date=end_date
                )

                results.append(result)

                logger.logger.info("monthly_report_completed",
                                  report_name=schedule.name,
                                  success=result.get("success"))

            finally:
                db_session.close()

        logger.logger.info("monthly_reports_completed",
                          total_schedules=len(monthly_schedules),
                          successful=sum(1 for r in results if r.get("success")))

        return {
            "task": "monthly_reports",
            "completed_at": datetime.utcnow().isoformat(),
            "reports_generated": len(results),
            "results": results
        }

    except Exception as e:
        logger.log_error(e, {"task": "generate_monthly_reports"})
        raise


@celery_app.task(name="app.tasks.reporting_tasks.generate_custom_report")
def generate_custom_report(
    report_name: str,
    report_types: list,
    recipients: list,
    start_date_iso: str,
    end_date_iso: str,
    formats: list = None
):
    """
    Generate a custom report on-demand

    Args:
        report_name: Name of the report
        report_types: List of report types to generate
        recipients: List of email recipients
        start_date_iso: Start date in ISO format
        end_date_iso: End date in ISO format
        formats: List of formats (pdf, csv)

    Returns:
        Task result dictionary
    """
    try:
        logger.logger.info("starting_custom_report",
                          report_name=report_name,
                          recipients=recipients)

        # Parse dates
        start_date = datetime.fromisoformat(start_date_iso.replace('Z', '+00:00'))
        end_date = datetime.fromisoformat(end_date_iso.replace('Z', '+00:00'))

        # Create schedule
        from app.services.reporting_service import ReportSchedule

        schedule = ReportSchedule(
            name=report_name,
            frequency="custom",
            report_types=report_types,
            recipients=recipients,
            formats=formats or ["pdf"],
            enabled=True
        )

        # Get database session
        db_session = next(get_db_session())

        try:
            reporting = ReportingService(db_session=db_session)

            result = reporting.generate_scheduled_report(
                schedule=schedule,
                start_date=start_date,
                end_date=end_date
            )

            logger.logger.info("custom_report_completed",
                              report_name=report_name,
                              success=result.get("success"))

            return result

        finally:
            db_session.close()

    except Exception as e:
        logger.log_error(e, {"task": "generate_custom_report"})
        raise


@celery_app.task(name="app.tasks.reporting_tasks.test_reporting_system")
def test_reporting_system():
    """
    Test task to verify reporting system is working

    Can be triggered manually to test Celery configuration
    """
    try:
        logger.logger.info("testing_reporting_system")

        return {
            "status": "success",
            "message": "Reporting system is operational",
            "timestamp": datetime.utcnow().isoformat(),
            "celery_version": celery_app.version
        }

    except Exception as e:
        logger.log_error(e, {"task": "test_reporting_system"})
        raise
