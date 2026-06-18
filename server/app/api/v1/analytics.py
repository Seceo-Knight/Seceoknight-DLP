"""
Analytics API Endpoints
Provides aggregated data for dashboards and reports
"""

from typing import Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.services.analytics_service import AnalyticsService
from app.core.observability import StructuredLogger

router = APIRouter()
logger = StructuredLogger(__name__)


@router.get("/trends")
async def get_incident_trends(
    start_date: Optional[datetime] = Query(None, description="Start date (defaults to 7 days ago)"),
    end_date: Optional[datetime] = Query(None, description="End date (defaults to now)"),
    interval: str = Query("day", regex="^(hour|day|week|month)$"),
    group_by: Optional[str] = Query(None, regex="^(severity|type|policy_id)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get incident trends over time

    **Parameters:**
    - **start_date**: Start of time range (ISO 8601 format)
    - **end_date**: End of time range (ISO 8601 format)
    - **interval**: Time bucket interval (hour, day, week, month)
    - **group_by**: Optional grouping field (severity, type, policy_id)

    **Returns:**
    - Time series data with incident counts
    - If grouped, returns multiple series
    - Total incident count for the period

    **Example:**
    ```
    GET /api/v1/analytics/trends?interval=day&group_by=severity
    ```

    **Response:**
    ```json
    {
      "interval": "day",
      "start_date": "2025-01-06T00:00:00",
      "end_date": "2025-01-13T23:59:59",
      "group_by": "severity",
      "series": {
        "critical": [
          {"timestamp": "2025-01-06T00:00:00", "count": 15},
          {"timestamp": "2025-01-07T00:00:00", "count": 23}
        ],
        "high": [
          {"timestamp": "2025-01-06T00:00:00", "count": 45},
          {"timestamp": "2025-01-07T00:00:00", "count": 38}
        ]
      },
      "total_incidents": 1234
    }
    ```
    """
    try:
        # Default to last 7 days if not specified
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=7)

        # Validate date range
        if start_date >= end_date:
            raise HTTPException(status_code=400, detail="start_date must be before end_date")

        # Maximum 90 days range
        if (end_date - start_date).days > 90:
            raise HTTPException(status_code=400, detail="Date range cannot exceed 90 days")

        from app.services.abac_service import build_abac_sql_filter
        abac = await build_abac_sql_filter(db, current_user)
        analytics = AnalyticsService(db, abac_clause=abac)
        trends = await analytics.get_incident_trends(
            start_date=start_date,
            end_date=end_date,
            interval=interval,
            group_by=group_by
        )

        logger.logger.info("analytics_trends_requested",
                          user_id=getattr(current_user, "id", None),
                          interval=interval,
                          group_by=group_by,
                          total_incidents=trends.get("total_incidents"))

        return trends

    except HTTPException:
        raise
    except Exception as e:
        logger.log_error(e, {"endpoint": "get_incident_trends"})
        raise HTTPException(status_code=500, detail="Failed to retrieve incident trends")


@router.get("/top-violators")
async def get_top_violators(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    limit: int = Query(10, ge=1, le=100),
    by: str = Query("user", regex="^(user|agent|ip_address)$"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get top violators by incident count

    **Parameters:**
    - **start_date**: Start of time range
    - **end_date**: End of time range
    - **limit**: Number of results (1-100)
    - **by**: Group by field (user, agent, ip_address)

    **Returns:**
    - List of top violators with incident counts
    - Critical incident counts
    - Additional details (hostname for agents, etc.)

    **Example:**
    ```
    GET /api/v1/analytics/top-violators?by=agent&limit=5
    ```

    **Response:**
    ```json
    [
      {
        "agent_id": "AGENT-001",
        "agent_name": "Finance-PC-01",
        "hostname": "finance-pc-01.corp.com",
        "incident_count": 145,
        "critical_count": 23
      },
      {
        "agent_id": "AGENT-002",
        "agent_name": "HR-Laptop-05",
        "hostname": "hr-laptop-05.corp.com",
        "incident_count": 89,
        "critical_count": 12
      }
    ]
    ```
    """
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)  # Default to 30 days

        from app.services.abac_service import build_abac_sql_filter
        abac = await build_abac_sql_filter(db, current_user)
        analytics = AnalyticsService(db, abac_clause=abac)
        violators = await analytics.get_top_violators(
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            by=by
        )

        logger.logger.info("top_violators_requested",
                          user_id=getattr(current_user, "id", None),
                          by=by,
                          count=len(violators))

        return violators

    except Exception as e:
        logger.log_error(e, {"endpoint": "get_top_violators"})
        raise HTTPException(status_code=500, detail="Failed to retrieve top violators")


@router.get("/data-types")
async def get_data_type_statistics(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get statistics on detected PII/sensitive data types

    **Parameters:**
    - **start_date**: Start of time range
    - **end_date**: End of time range

    **Returns:**
    - List of data types with detection counts
    - Percentages and confidence scores

    **Example:**
    ```
    GET /api/v1/analytics/data-types
    ```

    **Response:**
    ```json
    [
      {
        "data_type": "credit_card",
        "count": 456,
        "percentage": 34.5,
        "avg_confidence": 0.95
      },
      {
        "data_type": "ssn",
        "count": 234,
        "percentage": 17.7,
        "avg_confidence": 0.92
      },
      {
        "data_type": "email",
        "count": 189,
        "percentage": 14.3,
        "avg_confidence": 0.98
      }
    ]
    ```
    """
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        from app.services.abac_service import build_abac_sql_filter
        abac = await build_abac_sql_filter(db, current_user)
        analytics = AnalyticsService(db, abac_clause=abac)
        data_types = await analytics.get_data_type_statistics(
            start_date=start_date,
            end_date=end_date
        )

        logger.logger.info("data_type_stats_requested",
                          user_id=getattr(current_user, "id", None),
                          types_count=len(data_types))

        return data_types

    except Exception as e:
        logger.log_error(e, {"endpoint": "get_data_type_statistics"})
        raise HTTPException(status_code=500, detail="Failed to retrieve data type statistics")


@router.get("/policy-violations")
async def get_policy_violation_breakdown(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get breakdown of policy violations

    **Parameters:**
    - **start_date**: Start of time range
    - **end_date**: End of time range

    **Returns:**
    - List of policies with violation counts
    - Block rates and enforcement statistics

    **Example:**
    ```
    GET /api/v1/analytics/policy-violations
    ```

    **Response:**
    ```json
    [
      {
        "policy_id": "gdpr-compliance-001",
        "policy_name": "GDPR Personal Data Protection",
        "violation_count": 234,
        "blocked_count": 187,
        "block_rate": 79.91
      },
      {
        "policy_id": "hipaa-compliance-001",
        "policy_name": "HIPAA PHI Protection",
        "violation_count": 156,
        "blocked_count": 156,
        "block_rate": 100.0
      }
    ]
    ```
    """
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        from app.services.abac_service import build_abac_sql_filter
        abac = await build_abac_sql_filter(db, current_user)
        analytics = AnalyticsService(db, abac_clause=abac)
        violations = await analytics.get_policy_violation_breakdown(
            start_date=start_date,
            end_date=end_date
        )

        logger.logger.info("policy_violations_requested",
                          user_id=getattr(current_user, "id", None),
                          policies_count=len(violations))

        return violations

    except Exception as e:
        logger.log_error(e, {"endpoint": "get_policy_violation_breakdown"})
        raise HTTPException(status_code=500, detail="Failed to retrieve policy violations")


@router.get("/severity-distribution")
async def get_severity_distribution(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get distribution of incident severities

    **Parameters:**
    - **start_date**: Start of time range
    - **end_date**: End of time range

    **Returns:**
    - Severity counts and percentages
    - Total incident count

    **Example:**
    ```
    GET /api/v1/analytics/severity-distribution
    ```

    **Response:**
    ```json
    {
      "total_incidents": 1234,
      "distribution": {
        "critical": {
          "count": 234,
          "percentage": 18.96
        },
        "high": {
          "count": 456,
          "percentage": 36.95
        },
        "medium": {
          "count": 345,
          "percentage": 27.96
        },
        "low": {
          "count": 199,
          "percentage": 16.13
        }
      }
    }
    ```
    """
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        from app.services.abac_service import build_abac_sql_filter
        abac = await build_abac_sql_filter(db, current_user)
        analytics = AnalyticsService(db, abac_clause=abac)
        distribution = await analytics.get_severity_distribution(
            start_date=start_date,
            end_date=end_date
        )

        logger.logger.info("severity_distribution_requested",
                          user_id=getattr(current_user, "id", None),
                          total=distribution.get("total_incidents"))

        return distribution

    except Exception as e:
        logger.log_error(e, {"endpoint": "get_severity_distribution"})
        raise HTTPException(status_code=500, detail="Failed to retrieve severity distribution")


@router.get("/summary")
async def get_summary_statistics(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get summary statistics for dashboard overview

    **Parameters:**
    - **start_date**: Start of time range
    - **end_date**: End of time range

    **Returns:**
    - Key metrics for dashboard overview
    - Total incidents, critical count, block rate, etc.

    **Example:**
    ```
    GET /api/v1/analytics/summary
    ```

    **Response:**
    ```json
    {
      "period": {
        "start": "2024-12-14T00:00:00",
        "end": "2025-01-13T23:59:59"
      },
      "total_incidents": 1234,
      "critical_incidents": 234,
      "blocked_incidents": 987,
      "active_agents": 45,
      "policy_violations": 789,
      "block_rate": 79.98,
      "most_common_datatype": "credit_card"
    }
    ```
    """
    try:
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        from app.services.abac_service import build_abac_sql_filter
        abac = await build_abac_sql_filter(db, current_user)
        analytics = AnalyticsService(db, abac_clause=abac)
        summary = await analytics.get_summary_statistics(
            start_date=start_date,
            end_date=end_date
        )

        logger.logger.info("summary_stats_requested",
                          user_id=getattr(current_user, "id", None),
                          total_incidents=summary.get("total_incidents"))

        return summary

    except Exception as e:
        logger.log_error(e, {"endpoint": "get_summary_statistics"})
        raise HTTPException(status_code=500, detail="Failed to retrieve summary statistics")
