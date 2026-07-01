"""
Reports API Endpoints
On-demand report generation, history listing, and file download.
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.core.config import settings
from app.core.observability import StructuredLogger
from app.models.report import Report
from app.tasks.reporting_tasks import generate_custom_report

router = APIRouter()
logger = StructuredLogger(__name__)


# ── Schemas ───────────────────────────────────────────────────────────────────

class GenerateReportRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=500)
    report_types: List[str] = Field(
        ...,
        description="One or more of: summary, violations, trends, violators, policies, compliance",
        min_items=1,
    )
    start_date: datetime
    end_date: datetime
    formats: List[str] = Field(
        default=["pdf"],
        description="One or more of: pdf, csv",
    )
    recipients: List[str] = Field(
        default=[],
        description="Email addresses to send the report to (optional)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Weekly Security Summary",
                "report_types": ["summary", "violations"],
                "start_date": "2025-06-01T00:00:00",
                "end_date": "2025-06-30T23:59:59",
                "formats": ["pdf", "csv"],
                "recipients": ["ciso@company.com"],
            }
        }


class ReportResponse(BaseModel):
    id: str
    name: str
    report_type: str
    frequency: str
    status: str
    generated_by: Optional[str]
    period_start: Optional[datetime]
    period_end: Optional[datetime]
    formats: Optional[list]
    recipients: Optional[list]
    file_path_pdf: Optional[str]
    file_path_csv: Optional[str]
    file_size_bytes: Optional[int]
    error_message: Optional[str]
    email_sent: Optional[str]
    summary: Optional[dict]
    created_at: datetime
    completed_at: Optional[datetime]
    # Derived convenience flags
    has_pdf: bool = False
    has_csv: bool = False

    class Config:
        from_attributes = True


def _report_to_response(r: Report) -> ReportResponse:
    return ReportResponse(
        id=str(r.id),
        name=r.name,
        report_type=r.report_type,
        frequency=r.frequency,
        status=r.status,
        generated_by=r.generated_by,
        period_start=r.period_start,
        period_end=r.period_end,
        formats=r.formats,
        recipients=r.recipients,
        file_path_pdf=r.file_path_pdf,
        file_path_csv=r.file_path_csv,
        file_size_bytes=r.file_size_bytes,
        error_message=r.error_message,
        email_sent=r.email_sent,
        summary=r.summary,
        created_at=r.created_at,
        completed_at=r.completed_at,
        has_pdf=bool(r.file_path_pdf and os.path.exists(os.path.join(settings.REPORTS_DIR, r.file_path_pdf))),
        has_csv=bool(r.file_path_csv and os.path.exists(os.path.join(settings.REPORTS_DIR, r.file_path_csv))),
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/generate", status_code=202)
async def generate_report(
    body: GenerateReportRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger on-demand report generation.

    The report is generated asynchronously via Celery. Returns the report ID
    immediately so the frontend can poll /reports/{id} for status.
    """
    # Validate report_types
    valid_types = {"summary", "violations", "trends", "violators", "policies", "compliance", "incident_detail"}
    invalid = [t for t in body.report_types if t not in valid_types]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid report_types: {invalid}. Valid options: {sorted(valid_types)}",
        )

    # Validate formats
    valid_formats = {"pdf", "csv"}
    invalid_fmt = [f for f in body.formats if f not in valid_formats]
    if invalid_fmt:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid formats: {invalid_fmt}. Valid options: pdf, csv",
        )

    if body.start_date >= body.end_date:
        raise HTTPException(status_code=400, detail="start_date must be before end_date")

    user_email = getattr(current_user, "email", None) or "unknown"

    # Create a DB record for each report_type so the UI can track them individually
    report_ids = []
    for rtype in body.report_types:
        report = Report(
            id=uuid.uuid4(),
            name=body.name,
            report_type=rtype,
            frequency="custom",
            generated_by=user_email,
            period_start=body.start_date,
            period_end=body.end_date,
            formats=body.formats,
            recipients=body.recipients,
            status="pending",
        )
        db.add(report)
        report_ids.append(str(report.id))

    await db.commit()

    # Dispatch Celery task — pass report_ids so the worker can update each row
    generate_custom_report.delay(
        report_name=body.name,
        report_types=body.report_types,
        recipients=body.recipients,
        start_date_iso=body.start_date.isoformat(),
        end_date_iso=body.end_date.isoformat(),
        formats=body.formats,
        report_ids=report_ids,
    )

    logger.logger.info(
        "report_generation_queued",
        user=user_email,
        report_types=body.report_types,
        report_ids=report_ids,
    )

    return {
        "message": "Report generation queued",
        "report_ids": report_ids,
        "status": "pending",
    }


@router.get("/", response_model=List[ReportResponse])
async def list_reports(
    status: Optional[str] = Query(None, regex="^(pending|generating|completed|failed)$"),
    report_type: Optional[str] = Query(None),
    frequency: Optional[str] = Query(None, regex="^(daily|weekly|monthly|custom)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List generated reports with optional filters."""
    query = select(Report).order_by(desc(Report.created_at))

    if status:
        query = query.where(Report.status == status)
    if report_type:
        query = query.where(Report.report_type == report_type)
    if frequency:
        query = query.where(Report.frequency == frequency)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    reports = result.scalars().all()

    return [_report_to_response(r) for r in reports]


@router.get("/summary")
async def get_reports_summary(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Quick stats for the Reports dashboard — total, completed, failed, pending,
    and the 5 most recent completed reports.
    """
    from sqlalchemy import func

    # Count by status
    count_result = await db.execute(
        select(Report.status, func.count(Report.id))
        .group_by(Report.status)
    )
    counts = {row[0]: row[1] for row in count_result.all()}

    # Recent completed
    recent_result = await db.execute(
        select(Report)
        .where(Report.status == "completed")
        .order_by(desc(Report.completed_at))
        .limit(5)
    )
    recent = [_report_to_response(r) for r in recent_result.scalars().all()]

    return {
        "total": sum(counts.values()),
        "pending": counts.get("pending", 0),
        "generating": counts.get("generating", 0),
        "completed": counts.get("completed", 0),
        "failed": counts.get("failed", 0),
        "recent_completed": recent,
    }


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single report by ID (use for polling generation status)."""
    try:
        uid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID")

    result = await db.execute(select(Report).where(Report.id == uid))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return _report_to_response(report)


@router.get("/{report_id}/download/{fmt}")
async def download_report(
    report_id: str,
    fmt: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Download a completed report file.
    fmt must be 'pdf' or 'csv'.
    """
    if fmt not in ("pdf", "csv"):
        raise HTTPException(status_code=400, detail="Format must be 'pdf' or 'csv'")

    try:
        uid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID")

    result = await db.execute(select(Report).where(Report.id == uid))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report.status != "completed":
        raise HTTPException(
            status_code=409,
            detail=f"Report is not ready (status: {report.status})",
        )

    rel_path = report.file_path_pdf if fmt == "pdf" else report.file_path_csv
    if not rel_path:
        raise HTTPException(status_code=404, detail=f"No {fmt.upper()} file for this report")

    abs_path = os.path.join(settings.REPORTS_DIR, rel_path)
    if not os.path.exists(abs_path):
        raise HTTPException(
            status_code=404,
            detail="Report file not found on disk. It may have been cleaned up.",
        )

    media_type = "application/pdf" if fmt == "pdf" else "text/csv"
    filename = f"{report.name.replace(' ', '_')}_{report.period_start.date() if report.period_start else 'report'}.{fmt}"

    return FileResponse(
        path=abs_path,
        media_type=media_type,
        filename=filename,
    )


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a report record and its associated files."""
    # Only admins can delete reports
    user_role = str(getattr(current_user.role, "value", current_user.role)).upper()
    if user_role != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        uid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID")

    result = await db.execute(select(Report).where(Report.id == uid))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Clean up files
    for rel_path in [report.file_path_pdf, report.file_path_csv]:
        if rel_path:
            abs_path = os.path.join(settings.REPORTS_DIR, rel_path)
            if os.path.exists(abs_path):
                try:
                    os.remove(abs_path)
                except OSError:
                    pass  # best-effort

    await db.delete(report)
    await db.commit()
