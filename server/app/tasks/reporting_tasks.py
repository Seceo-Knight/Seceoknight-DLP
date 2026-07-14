"""
Celery Tasks for Scheduled and On-Demand Reporting

Key design decisions:
- Celery workers are separate processes that never go through FastAPI's lifespan
  startup, so postgres_session_factory and opensearch_client module globals are
  None in worker context. Each task must call init_databases() / init_opensearch()
  before using them.
- generate_custom_report accepts report_ids so it can update the Report DB records
  (status, file paths, error) that the API pre-creates before dispatching the task.
"""

import asyncio
import os
import uuid
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


# ── DB / OpenSearch bootstrap helper ─────────────────────────────────────────

# Track the event loop that the current DB connection pool was created on.
# Each asyncio.run() call creates a NEW event loop — asyncpg connections
# from a previous loop are attached to that loop and cannot be reused.
# Comparing loop IDs lets us detect this and reinitialize cleanly.
_celery_loop_id: int | None = None


async def _ensure_connections() -> object:
    """
    Initialize Postgres and OpenSearch, reinitializing if the event loop has
    changed (which happens on every asyncio.run() call in Celery prefork workers).

    Returns the opensearch client (may be None if unavailable).
    """
    global _celery_loop_id
    import app.core.database as _db_mod
    import app.core.opensearch as _os_mod
    from app.core.database import init_databases
    from app.core.opensearch import init_opensearch

    loop_id = id(asyncio.get_running_loop())
    need_db_reinit = (_db_mod.postgres_session_factory is None or loop_id != _celery_loop_id)

    if need_db_reinit:
        # Dispose the old engine (ignore errors — the old loop may already be gone)
        if _db_mod.postgres_engine is not None:
            try:
                await _db_mod.postgres_engine.dispose()
            except Exception:
                pass
            _db_mod.postgres_session_factory = None
            _db_mod.postgres_engine = None

        logger.logger.info("celery_worker_init_databases")
        await init_databases()
        _celery_loop_id = loop_id

    if _os_mod.opensearch_client is None:
        logger.logger.info("celery_worker_init_opensearch")
        await init_opensearch()   # never raises; logs warning on failure

    return _os_mod.opensearch_client  # may be None — that's OK


# ── Scheduled-report helper ───────────────────────────────────────────────────

async def _run_schedules(
    schedules: list,
    start_date: datetime,
    end_date: datetime,
) -> list:
    """
    Execute a list of ReportSchedule objects (used by daily/weekly/monthly tasks).
    Opens a fresh DB session per report to avoid cross-task state contamination.
    """
    import app.core.database as _db_mod

    opensearch = await _ensure_connections()

    results = []
    for schedule in schedules:
        async with _db_mod.postgres_session_factory() as db:
            try:
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


# ── On-demand report data fetcher ─────────────────────────────────────────────

async def _fetch_report_data(
    service: ReportingService,
    report_type: str,
    start_date: datetime,
    end_date: datetime,
) -> dict:
    """
    Fetch analytics data for a single report type.
    Maps the API's report_types to AnalyticsService methods.
    """
    if report_type in ("gdpr_art30", "hipaa_breach", "pci_scope"):
        # Compliance report templates query the DB directly via
        # ComplianceReportService rather than going through AnalyticsService.
        if service.db is None:
            return {}
        from app.services.compliance_report_service import ComplianceReportService
        compliance = ComplianceReportService(service.db)
        if report_type == "gdpr_art30":
            return await compliance.get_gdpr_article_30_data(start_date, end_date)
        elif report_type == "hipaa_breach":
            return await compliance.get_hipaa_breach_notification_data(start_date, end_date)
        else:
            return await compliance.get_pci_dss_scope_data(start_date, end_date)

    analytics = service.analytics
    if analytics is None:
        return {}

    if report_type in ("summary", "compliance"):
        return await analytics.get_summary_statistics(start_date, end_date)
    elif report_type in ("violations", "policies"):
        return await analytics.get_policy_violation_breakdown(start_date, end_date)
    elif report_type == "trends":
        return await analytics.get_incident_trends(start_date, end_date, "day", group_by="severity")
    elif report_type == "violators":
        return await analytics.get_top_violators(start_date, end_date, limit=20, by="agent")
    elif report_type == "incident_detail":
        return await analytics.get_incident_detail(start_date, end_date, limit=500)
    else:
        return {}


# ── On-demand report core async logic ────────────────────────────────────────

async def _run_custom_reports(
    report_name: str,
    report_types: list,
    recipients: list,
    start_date: datetime,
    end_date: datetime,
    formats: list,
    report_ids: list,  # one UUID str per report_type, same order
) -> list:
    """
    Generate on-demand reports, save files to disk, and update Report DB records.
    """
    from sqlalchemy import select
    import app.core.database as _db_mod
    from app.models.report import Report

    opensearch = await _ensure_connections()

    # Ensure reports directory exists
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)

    # Map report_type → report_id string (same ordering as the API created them)
    id_map: dict[str, str] = {}
    for i, rtype in enumerate(report_types):
        if i < len(report_ids):
            id_map[rtype] = report_ids[i]

    results = []

    for report_type in report_types:
        report_id_str = id_map.get(report_type)

        async with _db_mod.postgres_session_factory() as db:
            # Fetch the pre-created Report row
            report_row = None
            if report_id_str:
                try:
                    res = await db.execute(
                        select(Report).where(Report.id == uuid.UUID(report_id_str))
                    )
                    report_row = res.scalar_one_or_none()
                except Exception:
                    pass

            # Mark as generating so the UI shows progress
            if report_row:
                report_row.status = "generating"
                await db.commit()

            try:
                service = ReportingService(db_session=db, opensearch=opensearch)

                # Fetch analytics data
                data = await _fetch_report_data(service, report_type, start_date, end_date)

                pdf_path: str | None = None
                csv_path: str | None = None
                file_size = None

                # ── Generate PDF ──────────────────────────────────────────────
                if "pdf" in formats:
                    type_titles = {
                        "summary": "DLP Summary Report",
                        "violations": "Policy Violations Report",
                        "trends": "Incident Trends Report",
                        "incident_detail": "Incident Detail Report",
                        "violators": "Top Violators Report",
                        "policies": "Policy Analysis Report",
                        "compliance": "Compliance Overview Report",
                        "gdpr_art30": "GDPR Article 30 — Records of Processing Activities",
                        "hipaa_breach": "HIPAA Breach Notification Report",
                        "pci_scope": "PCI DSS Scope Report",
                    }
                    title = f"{report_name} — {type_titles.get(report_type, report_type.title() + ' Report')}"
                    try:
                        pdf_bytes = service.export.export_to_pdf(
                            title, data, report_type,
                            period_start=start_date.strftime("%Y-%m-%d"),
                            period_end=end_date.strftime("%Y-%m-%d"),
                            generated_by=report_row.generated_by if report_row else None,
                        )
                        if pdf_bytes:
                            fname = f"{report_id_str or str(uuid.uuid4())}_{report_type}.pdf"
                            abs_path = os.path.join(settings.REPORTS_DIR, fname)
                            with open(abs_path, "wb") as fh:
                                fh.write(pdf_bytes)
                            pdf_path = fname
                            file_size = os.path.getsize(abs_path)
                    except Exception as pdf_exc:
                        logger.log_error(pdf_exc, {"step": "pdf_generation", "report_type": report_type})

                # ── Generate CSV ──────────────────────────────────────────────
                if "csv" in formats:
                    try:
                        csv_str = service.export.export_analytics_to_csv(data, report_type)
                        if csv_str:
                            fname = f"{report_id_str or str(uuid.uuid4())}_{report_type}.csv"
                            abs_path = os.path.join(settings.REPORTS_DIR, fname)
                            with open(abs_path, "w", encoding="utf-8") as fh:
                                fh.write(csv_str)
                            csv_path = fname
                    except Exception as csv_exc:
                        logger.log_error(csv_exc, {"step": "csv_generation", "report_type": report_type})

                # ── Update DB record ──────────────────────────────────────────
                if report_row:
                    report_row.status = "completed"
                    report_row.file_path_pdf = pdf_path
                    report_row.file_path_csv = csv_path
                    report_row.completed_at = datetime.utcnow()
                    report_row.file_size_bytes = file_size
                    # Store a compact summary dict (for the UI stats cards)
                    if isinstance(data, dict):
                        report_row.summary = {
                            k: v for k, v in data.items()
                            if isinstance(v, (int, float, str, bool, type(None)))
                        }
                    await db.commit()

                logger.logger.info(
                    "custom_report_completed",
                    report_type=report_type,
                    report_id=report_id_str,
                    pdf=pdf_path,
                    csv=csv_path,
                )
                results.append({
                    "success": True,
                    "report_type": report_type,
                    "report_id": report_id_str,
                    "pdf": pdf_path,
                    "csv": csv_path,
                })

            except Exception as exc:
                logger.log_error(exc, {
                    "report_type": report_type,
                    "report_id": report_id_str,
                })
                # Mark the DB record as failed
                if report_row:
                    try:
                        report_row.status = "failed"
                        report_row.error_message = str(exc)[:1000]
                        await db.commit()
                    except Exception:
                        pass
                results.append({
                    "success": False,
                    "report_type": report_type,
                    "report_id": report_id_str,
                    "error": str(exc),
                })

    return results


# ── Celery tasks ──────────────────────────────────────────────────────────────

@celery_app.task(
    name="app.tasks.reporting_tasks.generate_daily_reports",
    bind=True,
    max_retries=2,
)
def generate_daily_reports(self):
    """Generate and email daily reports (previous day). Runs at 8:00 AM UTC."""
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
    """Generate and email weekly reports (previous Mon–Sun). Runs Monday 9:00 AM UTC."""
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
    """Generate and email monthly reports (previous calendar month). Runs 1st at 10:00 AM UTC."""
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
    report_ids: list = None,   # UUIDs of pre-created Report rows (same order as report_types)
):
    """
    Generate an on-demand report set and update the pre-created Report DB records.
    Called from POST /api/v1/reports/generate.
    """
    try:
        start_date = datetime.fromisoformat(start_date_iso.replace("Z", "+00:00")).replace(tzinfo=None)
        end_date = datetime.fromisoformat(end_date_iso.replace("Z", "+00:00")).replace(tzinfo=None)
        # Normalize to full day range regardless of what time the frontend sends.
        # The frontend may send the current time on the selected date rather than
        # midnight, which would exclude events that occurred later in the day.
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
        _formats = formats or ["pdf"]
        _report_ids = report_ids or []

        logger.logger.info(
            "starting_custom_report",
            report_name=report_name,
            report_types=report_types,
            report_ids=_report_ids,
            formats=_formats,
        )

        results = asyncio.run(
            _run_custom_reports(
                report_name=report_name,
                report_types=report_types,
                recipients=recipients,
                start_date=start_date,
                end_date=end_date,
                formats=_formats,
                report_ids=_report_ids,
            )
        )

        ok_count = sum(1 for r in results if r.get("success"))
        logger.logger.info(
            "custom_report_done",
            report_name=report_name,
            successful=ok_count,
            total=len(results),
        )
        return {
            "success": ok_count == len(results),
            "report_name": report_name,
            "results": results,
        }

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
