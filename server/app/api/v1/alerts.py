"""
Alerts API Endpoints
Security alerts and notifications
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
import structlog

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user, require_role
from app.core.database import get_mongodb, get_db

logger = structlog.get_logger()
router = APIRouter()


class Alert(BaseModel):
    id: str
    timestamp: datetime
    title: str
    description: str
    severity: str
    status: str
    event_id: str
    agent_id: Optional[str] = None
    created_at: Optional[datetime] = None
    classification_category: Optional[str] = None
    classification_level: Optional[str] = None
    classification_score: Optional[float] = None
    classification_rules_matched: Optional[List[str]] = None
    action_taken: Optional[str] = None
    blocked: Optional[bool] = None
    detected_content: Optional[str] = None


class AlertsResponse(BaseModel):
    alerts: List[Alert]
    counts: Dict[str, int]


@router.get("/", response_model=AlertsResponse)
async def get_alerts(
    current_user=Depends(get_current_user),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    pg_db: AsyncSession = Depends(get_db),
):
    """
    Get all active alerts (ABAC-scoped).

    Generates alerts from critical/high severity events if no alerts exist
    in the database. Both the materialized-alerts path and the event-fallback
    path apply the viewer's ABAC visibility filter before counting/listing.
    """
    from app.services.abac_service import (
        build_abac_mongo_filter,
        merge_mongo_filter,
    )

    db = get_mongodb()
    abac = await build_abac_mongo_filter(pg_db, current_user)

    # Check if alerts collection exists and has alerts
    alerts_collection = db.get_collection("alerts")
    alert_count = await alerts_collection.count_documents({})

    alerts = []
    counts = {"new": 0, "acknowledged": 0, "resolved": 0, "total": 0}

    if alert_count > 0:
        # Query alerts from database
        query_filter: Dict[str, Any] = {}
        if severity:
            query_filter["severity"] = severity
        if status:
            query_filter["status"] = status

        query_filter = merge_mongo_filter(query_filter, abac)

        # Get total counts before limiting
        counts["total"] = await alerts_collection.count_documents(query_filter)
        counts["new"] = await alerts_collection.count_documents(
            merge_mongo_filter({**query_filter, "status": "new"}, None)
        )
        counts["acknowledged"] = await alerts_collection.count_documents(
            merge_mongo_filter({**query_filter, "status": "acknowledged"}, None)
        )
        counts["resolved"] = await alerts_collection.count_documents(
            merge_mongo_filter({**query_filter, "status": "resolved"}, None)
        )

        # Get limited list for display
        cursor = alerts_collection.find(query_filter).sort("timestamp", -1).limit(100)
        async for alert_doc in cursor:
            try:
                alert_dict = {k: v for k, v in alert_doc.items() if k != "_id"}
                # Normalize datetime fields
                for dt_field in ("timestamp", "created_at"):
                    if dt_field in alert_dict and isinstance(alert_dict[dt_field], datetime):
                        dt_val = alert_dict[dt_field]
                        if dt_val.tzinfo is None:
                            dt_val = dt_val.replace(tzinfo=timezone.utc)
                        alert_dict[dt_field] = dt_val.isoformat()
                alerts.append(Alert(**alert_dict))
            except Exception as e:
                logger.warning("Skipping malformed alert document", error=str(e))
    else:
        # Generate alerts from critical/high severity events
        events_collection = db.dlp_events

        # Query critical and high severity events
        query_filter = {"severity": {"$in": ["critical", "high"]}}
        if severity:
            query_filter["severity"] = severity

        query_filter = merge_mongo_filter(query_filter, abac)

        # Get total counts before limiting
        try:
            counts["total"] = await events_collection.count_documents(query_filter)
        except Exception:
            counts["total"] = 0
        counts["new"] = counts["total"]
        counts["acknowledged"] = 0
        counts["resolved"] = 0

        # Get limited list for display
        cursor = events_collection.find(query_filter).sort("timestamp", -1).limit(100)

        async for event_doc in cursor:
            try:
                alert_id = event_doc.get("id") or event_doc.get("event_id", str(event_doc.get("_id", "")))
                if not alert_id:
                    continue
                severity_level = event_doc.get("severity", "medium")

                event_type = event_doc.get("event_type", "unknown")
                file_path = event_doc.get("file_path", "")
                description_text = event_doc.get("description", "")

                if event_type == "file" and file_path:
                    title = "Sensitive Data Detected in File"
                    description = f"File: {file_path}\n{description_text}"
                elif event_type == "clipboard":
                    title = "Sensitive Data Copied to Clipboard"
                    description = description_text or "Sensitive data detected in clipboard content"
                elif event_type == "usb":
                    # Use event_subtype to determine connect vs disconnect
                    event_subtype = event_doc.get('event_subtype', 'usb_connect')
                    device_name = event_doc.get('device_name', 'Unknown Device')
                    device_id = event_doc.get('device_id', 'Unknown ID')

                    if event_subtype == 'usb_disconnect':
                        title = "USB Device Disconnected"
                        description = f"USB device {device_name} (ID: {device_id}) has been disconnected from this system"
                    else:
                        title = "USB Device Connected"
                        description = f"USB device {device_name} (ID: {device_id}) has been connected to this system"
                else:
                    title = "DLP Event Detected"
                    description = description_text or f"{event_type} event detected"

                alert_status = "new"
                if status:
                    alert_status = status

                ts = event_doc.get("timestamp", datetime.now(timezone.utc))
                if isinstance(ts, datetime) and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)

                alert = Alert(
                    id=alert_id,
                    timestamp=ts,
                    title=title,
                    description=description,
                    severity=severity_level,
                    status=alert_status,
                    event_id=alert_id,
                    agent_id=event_doc.get("agent_id"),
                    created_at=ts,
                    classification_category=event_doc.get("classification_category") or event_doc.get("classification_level"),
                    classification_level=event_doc.get("classification_level"),
                    classification_score=event_doc.get("classification_score"),
                    classification_rules_matched=event_doc.get("classification_rules_matched") or event_doc.get("classification_labels"),
                    action_taken=event_doc.get("action_taken"),
                    blocked=event_doc.get("blocked"),
                    detected_content=event_doc.get("detected_content"),
                )
                alerts.append(alert)
            except Exception as e:
                logger.warning("Skipping malformed event document", error=str(e))
    
    logger.info(
        "Alerts retrieved",
        user=current_user.get("email", "unknown") if isinstance(current_user, dict) else getattr(current_user, "email", "unknown"),
        count=len(alerts),
        total_count=counts["total"],
    )
    from app.services.audit_service import log_abac_scope
    log_abac_scope(
        current_user,
        endpoint="GET /alerts/",
        visible_count=counts["total"],
        extra={"has_abac_filter": abac is not None},
    )

    return AlertsResponse(alerts=alerts, counts=counts)


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: dict = Depends(require_role("analyst")),
):
    """
    Acknowledge an alert
    Updates the alert status to 'acknowledged' in the database
    """
    db = get_mongodb()
    alerts_collection = db.get_collection("alerts")

    # Try to update the alert in database
    result = await alerts_collection.update_one(
        {"id": alert_id},
        {
            "$set": {
                "status": "acknowledged",
                "acknowledged_at": datetime.now(timezone.utc),
                "acknowledged_by": getattr(current_user, "email", "unknown")
            }
        }
    )

    logger.info(
        "Alert acknowledged",
        alert_id=alert_id,
        user=getattr(current_user, "email", "unknown"),
        updated=result.modified_count > 0,
    )

    return {
        "message": "Alert acknowledged",
        "alert_id": alert_id,
        "status": "acknowledged"
    }


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    current_user: dict = Depends(require_role("analyst")),
):
    """
    Resolve an alert
    Updates the alert status to 'resolved' in the database
    """
    db = get_mongodb()
    alerts_collection = db.get_collection("alerts")

    # Try to update the alert in database
    result = await alerts_collection.update_one(
        {"id": alert_id},
        {
            "$set": {
                "status": "resolved",
                "resolved_at": datetime.now(timezone.utc),
                "resolved_by": getattr(current_user, "email", "unknown")
            }
        }
    )

    logger.info(
        "Alert resolved",
        alert_id=alert_id,
        user=getattr(current_user, "email", "unknown"),
        updated=result.modified_count > 0,
    )

    return {
        "message": "Alert resolved",
        "alert_id": alert_id,
        "status": "resolved"
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    current_user=Depends(get_current_user),
    pg_db: AsyncSession = Depends(get_db),
):
    """
    Get a specific alert by ID (ABAC-scoped on both alerts + event fallback).
    """
    from app.services.abac_service import (
        build_abac_mongo_filter,
        merge_mongo_filter,
    )

    db = get_mongodb()
    alerts_collection = db.get_collection("alerts")
    abac = await build_abac_mongo_filter(pg_db, current_user)

    # Try to find alert in database (ABAC-filtered).
    alert_doc = await alerts_collection.find_one(
        merge_mongo_filter({"id": alert_id}, abac)
    )

    if alert_doc:
        alert_dict = {k: v for k, v in alert_doc.items() if k != "_id"}
        # Normalize datetime fields
        for dt_field in ("timestamp", "created_at", "acknowledged_at", "resolved_at"):
            if dt_field in alert_dict and isinstance(alert_dict[dt_field], datetime):
                dt_val = alert_dict[dt_field]
                if dt_val.tzinfo is None:
                    dt_val = dt_val.replace(tzinfo=timezone.utc)
                alert_dict[dt_field] = dt_val.isoformat()

        logger.info("Alert retrieved", alert_id=alert_id)
        return alert_dict

    # If not found in alerts collection, try events (still ABAC-filtered).
    events_collection = db.dlp_events
    event_doc = await events_collection.find_one(
        merge_mongo_filter(
            {"$or": [{"id": alert_id}, {"event_id": alert_id}]},
            abac,
        )
    )

    if event_doc:
        # Create alert from event
        event_type = event_doc.get("event_type", "unknown")
        file_path = event_doc.get("file_path", "")
        description_text = event_doc.get("description", "")

        if event_type == "file" and file_path:
            title = "Sensitive Data Detected in File"
            description = f"File: {file_path}\n{description_text}"
        elif event_type == "clipboard":
            title = "Sensitive Data Copied to Clipboard"
            description = description_text or "Sensitive data detected in clipboard content"
        elif event_type == "usb":
            # Use event_subtype to determine connect vs disconnect
            event_subtype = event_doc.get('event_subtype', 'usb_connect')
            device_name = event_doc.get('device_name', 'Unknown Device')
            device_id = event_doc.get('device_id', 'Unknown ID')

            if event_subtype == 'usb_disconnect':
                title = "USB Device Disconnected"
                description = f"USB device {device_name} (ID: {device_id}) has been disconnected from this system"
            else:
                title = "USB Device Connected"
                description = f"USB device {device_name} (ID: {device_id}) has been connected to this system"
        else:
            title = "DLP Event Detected"
            description = description_text or f"{event_type} event detected"

        ts = event_doc.get("timestamp", datetime.now(timezone.utc))
        if isinstance(ts, datetime) and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return {
            "id": alert_id,
            "timestamp": ts.isoformat(),
            "title": title,
            "description": description,
            "severity": event_doc.get("severity", "medium"),
            "status": "new",
            "event_id": alert_id,
            "agent_id": event_doc.get("agent_id"),
            "created_at": ts.isoformat(),
        }

    return {"error": "Alert not found"}
