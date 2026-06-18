"""
Alert Service - Business logic for DLP alert management
"""

from typing import Optional, List
from datetime import datetime, timedelta
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert


class AlertService:
    """Service for alert-related operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """
        Fetch alert by database ID

        Args:
            alert_id: UUID of the alert

        Returns:
            Alert object or None if not found
        """
        result = await self.db.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        return result.scalar_one_or_none()

    async def get_alert_by_alert_id(self, alert_id: str) -> Optional[Alert]:
        """
        Fetch alert by alert_id field

        Args:
            alert_id: Alert identifier string

        Returns:
            Alert object or None if not found
        """
        result = await self.db.execute(
            select(Alert).where(Alert.alert_id == alert_id)
        )
        return result.scalar_one_or_none()

    async def get_all_alerts(
        self,
        skip: int = 0,
        limit: int = 100,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> List[Alert]:
        """
        Fetch all alerts with optional filtering

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            severity: Filter by severity
            alert_type: Filter by alert type
            status: Filter by status
            priority: Filter by priority
            assigned_to: Filter by assigned user

        Returns:
            List of Alert objects
        """
        query = select(Alert)

        filters = []
        if severity:
            filters.append(Alert.severity == severity)
        if alert_type:
            filters.append(Alert.alert_type == alert_type)
        if status:
            filters.append(Alert.status == status)
        if priority:
            filters.append(Alert.priority == priority)
        if assigned_to:
            filters.append(Alert.assigned_to == assigned_to)

        if filters:
            query = query.where(and_(*filters))

        query = query.offset(skip).limit(limit).order_by(Alert.created_at.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def create_alert(
        self,
        alert_id: str,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        source_type: str,
        source_id: Optional[str] = None,
        policy_id: Optional[str] = None,
        event_id: Optional[str] = None,
        user_email: Optional[str] = None,
        agent_id: Optional[str] = None,
        priority: str = "medium",
        assigned_to: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Alert:
        """
        Create a new alert

        Args:
            alert_id: Unique alert identifier
            alert_type: Type of alert (policy_violation, anomaly, system)
            severity: Alert severity (critical, high, medium, low)
            title: Alert title
            message: Alert message/description
            source_type: Source type (policy, ml, system)
            source_id: ID of the source
            policy_id: Related policy ID
            event_id: Related event ID
            user_email: Associated user email
            agent_id: Related agent ID
            priority: Priority level (urgent, high, medium, low)
            assigned_to: User assigned to handle alert
            metadata: Additional metadata (JSON)

        Returns:
            Created Alert object
        """
        alert = Alert(
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            source_type=source_type,
            source_id=source_id,
            policy_id=policy_id,
            event_id=event_id,
            user_email=user_email,
            agent_id=agent_id,
            status="new",
            priority=priority,
            assigned_to=assigned_to,
            resolved=False,
            escalation_level=0,
            metadata=metadata or {},
        )

        self.db.add(alert)
        await self.db.commit()
        await self.db.refresh(alert)

        return alert

    async def update_alert_status(
        self,
        alert_id: str,
        status: str,
        assigned_to: Optional[str] = None,
    ) -> Optional[Alert]:
        """
        Update alert status

        Args:
            alert_id: Alert identifier string
            status: New status (new, investigating, resolved, false_positive)
            assigned_to: User to assign to

        Returns:
            Updated Alert object or None if not found
        """
        alert = await self.get_alert_by_alert_id(alert_id)
        if not alert:
            return None

        alert.status = status
        if assigned_to is not None:
            alert.assigned_to = assigned_to
        alert.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(alert)
        return alert

    async def resolve_alert(
        self,
        alert_id: str,
        resolved_by: str,
        resolution_notes: Optional[str] = None,
    ) -> Optional[Alert]:
        """
        Resolve an alert

        Args:
            alert_id: Alert identifier string
            resolved_by: User who resolved the alert
            resolution_notes: Resolution notes

        Returns:
            Updated Alert object or None if not found
        """
        alert = await self.get_alert_by_alert_id(alert_id)
        if not alert:
            return None

        alert.status = "resolved"
        alert.resolved = True
        alert.resolved_by = resolved_by
        alert.resolved_at = datetime.utcnow()
        alert.resolution_notes = resolution_notes
        alert.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(alert)
        return alert

    async def escalate_alert(
        self,
        alert_id: str,
        escalation_notes: Optional[str] = None,
    ) -> Optional[Alert]:
        """
        Escalate an alert to higher level

        Args:
            alert_id: Alert identifier string
            escalation_notes: Escalation notes

        Returns:
            Updated Alert object or None if not found
        """
        alert = await self.get_alert_by_alert_id(alert_id)
        if not alert:
            return None

        alert.escalation_level += 1
        alert.status = "escalated"

        # Update priority based on escalation
        if alert.escalation_level >= 2:
            alert.priority = "urgent"

        # Store escalation notes in metadata
        if not alert.metadata:
            alert.metadata = {}
        if "escalation_history" not in alert.metadata:
            alert.metadata["escalation_history"] = []

        alert.metadata["escalation_history"].append({
            "level": alert.escalation_level,
            "timestamp": datetime.utcnow().isoformat(),
            "notes": escalation_notes,
        })

        alert.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(alert)
        return alert

    async def assign_alert(
        self,
        alert_id: str,
        assigned_to: str,
    ) -> Optional[Alert]:
        """
        Assign alert to a user

        Args:
            alert_id: Alert identifier string
            assigned_to: User ID to assign to

        Returns:
            Updated Alert object or None if not found
        """
        alert = await self.get_alert_by_alert_id(alert_id)
        if not alert:
            return None

        alert.assigned_to = assigned_to
        alert.status = "assigned"
        alert.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(alert)
        return alert

    async def delete_alert(self, alert_id: str) -> bool:
        """
        Delete an alert

        Args:
            alert_id: Alert identifier string

        Returns:
            True if alert was deleted, False if not found
        """
        alert = await self.get_alert_by_alert_id(alert_id)
        if not alert:
            return False

        await self.db.delete(alert)
        await self.db.commit()
        return True

    async def get_alert_count(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        resolved: Optional[bool] = None,
    ) -> int:
        """
        Get total count of alerts

        Args:
            severity: Optional severity filter
            status: Optional status filter
            resolved: Optional resolved status filter

        Returns:
            Number of alerts
        """
        from sqlalchemy import func

        query = select(func.count(Alert.id))

        filters = []
        if severity:
            filters.append(Alert.severity == severity)
        if status:
            filters.append(Alert.status == status)
        if resolved is not None:
            filters.append(Alert.resolved == resolved)

        if filters:
            query = query.where(and_(*filters))

        result = await self.db.execute(query)
        return result.scalar_one()

    async def get_unresolved_alerts(self, limit: int = 100) -> List[Alert]:
        """
        Get all unresolved alerts

        Args:
            limit: Maximum number of alerts to return

        Returns:
            List of unresolved Alert objects
        """
        return await self.get_all_alerts(
            limit=limit,
            status="new",
        )

    async def get_alerts_by_severity(self, days: int = 7) -> dict:
        """
        Get alert counts grouped by severity for the last N days

        Args:
            days: Number of days to look back

        Returns:
            Dictionary with severity counts
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        query_base = select(Alert).where(Alert.created_at >= start_date)

        critical_query = query_base.where(Alert.severity == "critical")
        high_query = query_base.where(Alert.severity == "high")
        medium_query = query_base.where(Alert.severity == "medium")
        low_query = query_base.where(Alert.severity == "low")

        critical = len(list((await self.db.execute(critical_query)).scalars().all()))
        high = len(list((await self.db.execute(high_query)).scalars().all()))
        medium = len(list((await self.db.execute(medium_query)).scalars().all()))
        low = len(list((await self.db.execute(low_query)).scalars().all()))

        return {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        }

    async def get_alert_statistics(self) -> dict:
        """
        Get alert statistics

        Returns:
            Dictionary with alert statistics
        """
        total = await self.get_alert_count()
        unresolved = await self.get_alert_count(resolved=False)
        resolved = await self.get_alert_count(resolved=True)

        critical = await self.get_alert_count(severity="critical", resolved=False)
        high = await self.get_alert_count(severity="high", resolved=False)

        return {
            "total": total,
            "unresolved": unresolved,
            "resolved": resolved,
            "critical_unresolved": critical,
            "high_unresolved": high,
        }
