"""
Export API Endpoints
Provides CSV and PDF export functionality
"""

from typing import Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
import io

from app.core.database import get_db
from app.core.security import get_current_user
from app.services.analytics_service import AnalyticsService
from app.services.abac_service import build_abac_sql_filter
from app.services.export_service import ExportService
from app.core.observability import StructuredLogger

router = APIRouter()
logger = StructuredLogger(__name__)


@router.get("/analytics/trends/csv")
async def export_trends_csv(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    interval: str = Query("day", regex="^(hour|day|week|month)$"),
    group_by: Optional[str] = Query(None, regex="^(severity|type|policy_id)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Export incident trends to CSV

    **Returns:** CSV file with time series data
    """
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=7)

        # Get analytics data
        _abac_clause = await build_abac_sql_filter(db, current_user)
        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        trends = await analytics.get_incident_trends(
            start_date=start_date,
            end_date=end_date,
            interval=interval,
            group_by=group_by
        )

        # Export to CSV
        csv_content = ExportService.export_analytics_to_csv(trends, "trends")

        # Log export
        logger.logger.info("csv_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="trends",
                          rows=len(csv_content.split('\n')) - 1)

        # Return as downloadable file
        filename = f"incident_trends_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.csv"

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_trends_csv"})
        raise HTTPException(status_code=500, detail="Failed to export trends to CSV")


@router.get("/analytics/trends/pdf")
async def export_trends_pdf(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    interval: str = Query("day", regex="^(hour|day|week|month)$"),
    group_by: Optional[str] = Query(None, regex="^(severity|type|policy_id)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Export incident trends to PDF

    **Returns:** PDF file with formatted report
    """
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=7)

        # Get analytics data
        _abac_clause = await build_abac_sql_filter(db, current_user)
        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        trends = await analytics.get_incident_trends(
            start_date=start_date,
            end_date=end_date,
            interval=interval,
            group_by=group_by
        )

        # Export to PDF
        title = f"Incident Trends Report ({interval.capitalize()})"
        pdf_bytes = ExportService.export_to_pdf(title, trends, "trends")

        # Log export
        logger.logger.info("pdf_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="trends",
                          size_bytes=len(pdf_bytes))

        # Return as downloadable file
        filename = f"incident_trends_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_trends_pdf"})
        raise HTTPException(status_code=500, detail="Failed to export trends to PDF")


@router.get("/analytics/violators/csv")
async def export_violators_csv(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(10, ge=1, le=100),
    by: str = Query("user", regex="^(user|agent|ip_address)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export top violators to CSV"""
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        _abac_clause = await build_abac_sql_filter(db, current_user)

        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        violators = await analytics.get_top_violators(
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            by=by
        )

        csv_content = ExportService.export_analytics_to_csv(violators, "violators")

        logger.logger.info("csv_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="violators",
                          by=by)

        filename = f"top_violators_{by}_{start_date.strftime('%Y%m%d')}.csv"

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_violators_csv"})
        raise HTTPException(status_code=500, detail="Failed to export violators to CSV")


@router.get("/analytics/violators/pdf")
async def export_violators_pdf(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(10, ge=1, le=100),
    by: str = Query("user", regex="^(user|agent|ip_address)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export top violators to PDF"""
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        _abac_clause = await build_abac_sql_filter(db, current_user)

        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        violators = await analytics.get_top_violators(
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            by=by
        )

        title = f"Top Violators Report (By {by.replace('_', ' ').title()})"
        pdf_bytes = ExportService.export_to_pdf(title, violators, "violators")

        logger.logger.info("pdf_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="violators",
                          by=by)

        filename = f"top_violators_{by}_{start_date.strftime('%Y%m%d')}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_violators_pdf"})
        raise HTTPException(status_code=500, detail="Failed to export violators to PDF")


@router.get("/analytics/data-types/csv")
async def export_data_types_csv(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export data type statistics to CSV"""
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        _abac_clause = await build_abac_sql_filter(db, current_user)

        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        data_types = await analytics.get_data_type_statistics(
            start_date=start_date,
            end_date=end_date
        )

        csv_content = ExportService.export_analytics_to_csv(data_types, "data_types")

        logger.logger.info("csv_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="data_types")

        filename = f"data_types_{start_date.strftime('%Y%m%d')}.csv"

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_data_types_csv"})
        raise HTTPException(status_code=500, detail="Failed to export data types to CSV")


@router.get("/analytics/data-types/pdf")
async def export_data_types_pdf(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export data type statistics to PDF"""
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        _abac_clause = await build_abac_sql_filter(db, current_user)

        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        data_types = await analytics.get_data_type_statistics(
            start_date=start_date,
            end_date=end_date
        )

        title = "Data Type Detection Statistics"
        pdf_bytes = ExportService.export_to_pdf(title, data_types, "data_types")

        logger.logger.info("pdf_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="data_types")

        filename = f"data_types_{start_date.strftime('%Y%m%d')}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_data_types_pdf"})
        raise HTTPException(status_code=500, detail="Failed to export data types to PDF")


@router.get("/analytics/policy-violations/csv")
async def export_policy_violations_csv(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export policy violations to CSV"""
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        _abac_clause = await build_abac_sql_filter(db, current_user)

        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        violations = await analytics.get_policy_violation_breakdown(
            start_date=start_date,
            end_date=end_date
        )

        csv_content = ExportService.export_analytics_to_csv(violations, "policy_violations")

        logger.logger.info("csv_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="policy_violations")

        filename = f"policy_violations_{start_date.strftime('%Y%m%d')}.csv"

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_policy_violations_csv"})
        raise HTTPException(status_code=500, detail="Failed to export policy violations to CSV")


@router.get("/analytics/policy-violations/pdf")
async def export_policy_violations_pdf(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export policy violations to PDF"""
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        _abac_clause = await build_abac_sql_filter(db, current_user)

        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        violations = await analytics.get_policy_violation_breakdown(
            start_date=start_date,
            end_date=end_date
        )

        title = "Policy Violations Breakdown"
        pdf_bytes = ExportService.export_to_pdf(title, violations, "policy_violations")

        logger.logger.info("pdf_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="policy_violations")

        filename = f"policy_violations_{start_date.strftime('%Y%m%d')}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_policy_violations_pdf"})
        raise HTTPException(status_code=500, detail="Failed to export policy violations to PDF")


@router.get("/analytics/summary/pdf")
async def export_summary_pdf(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Export comprehensive summary report to PDF

    **Returns:** PDF file with all key metrics and statistics
    """
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        _abac_clause = await build_abac_sql_filter(db, current_user)

        analytics = AnalyticsService(db, abac_clause=_abac_clause)
        summary = await analytics.get_summary_statistics(
            start_date=start_date,
            end_date=end_date
        )

        title = "DLP Comprehensive Summary Report"
        pdf_bytes = ExportService.export_to_pdf(title, summary, "summary")

        logger.logger.info("pdf_export",
                          user_id=getattr(current_user, "id", None),
                          report_type="summary",
                          total_incidents=summary.get("total_incidents"))

        filename = f"dlp_summary_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as e:
        logger.log_error(e, {"endpoint": "export_summary_pdf"})
        raise HTTPException(status_code=500, detail="Failed to export summary to PDF")
