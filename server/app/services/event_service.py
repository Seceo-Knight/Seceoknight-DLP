"""
Event Service - Business logic for DLP event management
"""

from typing import Optional, List
from datetime import datetime, timedelta
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event


class EventService:
    """Service for event-related operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_event_by_id(self, event_id: str) -> Optional[Event]:
        """
        Fetch event by database ID

        Args:
            event_id: UUID of the event

        Returns:
            Event object or None if not found
        """
        result = await self.db.execute(
            select(Event).where(Event.id == event_id)
        )
        return result.scalar_one_or_none()

    async def get_event_by_event_id(self, event_id: str) -> Optional[Event]:
        """
        Fetch event by event_id field

        Args:
            event_id: Event identifier string

        Returns:
            Event object or None if not found
        """
        result = await self.db.execute(
            select(Event).where(Event.event_id == event_id)
        )
        return result.scalar_one_or_none()

    async def get_all_events(
        self,
        skip: int = 0,
        limit: int = 100,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        user_email: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        reviewed: Optional[bool] = None,
    ) -> List[Event]:
        """
        Fetch all events with optional filtering

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            severity: Filter by severity
            event_type: Filter by event type
            agent_id: Filter by agent ID
            user_email: Filter by user email
            start_date: Filter by start date
            end_date: Filter by end date
            reviewed: Filter by reviewed status

        Returns:
            List of Event objects
        """
        query = select(Event)

        # Apply filters
        filters = []
        if severity:
            filters.append(Event.severity == severity)
        if event_type:
            filters.append(Event.event_type == event_type)
        if agent_id:
            filters.append(Event.agent_id == agent_id)
        if user_email:
            filters.append(Event.user_email == user_email)
        if start_date:
            filters.append(Event.timestamp >= start_date)
        if end_date:
            filters.append(Event.timestamp <= end_date)
        if reviewed is not None:
            filters.append(Event.reviewed == reviewed)

        if filters:
            query = query.where(and_(*filters))

        query = query.offset(skip).limit(limit).order_by(Event.timestamp.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def create_event(
        self,
        event_id: str,
        event_type: str,
        severity: str,
        agent_id: str,
        user_email: Optional[str] = None,
        file_path: Optional[str] = None,
        file_name: Optional[str] = None,
        file_size: Optional[int] = None,
        file_hash: Optional[str] = None,
        classification: Optional[dict] = None,
        confidence_score: Optional[float] = None,
        policy_id: Optional[str] = None,
        action: str = "detected",
        source_type: str = "endpoint",
        event_subtype: Optional[str] = None,
        destination: Optional[str] = None,
        destination_details: Optional[dict] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Event:
        """
        Create a new DLP event

        Args:
            event_id: Unique event identifier
            event_type: Type of event
            severity: Event severity (critical, high, medium, low, info)
            agent_id: Agent that reported the event
            user_email: User associated with event
            file_path: Path to file involved
            file_name: Name of file
            file_size: File size in bytes
            file_hash: SHA256 hash of file
            classification: Classification results (JSON)
            confidence_score: Classification confidence
            policy_id: Policy that triggered the event
            action: Action taken
            source_type: Source type (endpoint, network, cloud)
            event_subtype: Event subtype
            destination: Destination of data
            destination_details: Additional destination info (JSON)
            source_ip: Source IP address
            destination_ip: Destination IP address
            protocol: Network protocol
            tags: Event tags

        Returns:
            Created Event object
        """
        event = Event(
            event_id=event_id,
            event_type=event_type,
            event_subtype=event_subtype,
            severity=severity,
            agent_id=agent_id,
            source_type=source_type,
            user_email=user_email,
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            file_hash=file_hash,
            classification=classification or {},
            confidence_score=confidence_score,
            policy_id=policy_id,
            action=action,
            destination=destination,
            destination_details=destination_details or {},
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            tags=tags or [],
            status="new",
            reviewed=False,
        )

        self.db.add(event)
        await self.db.commit()
        await self.db.refresh(event)

        return event

    async def mark_event_reviewed(
        self,
        event_id: str,
        reviewed_by: str,
    ) -> Optional[Event]:
        """
        Mark event as reviewed

        Args:
            event_id: Event identifier string
            reviewed_by: User ID who reviewed

        Returns:
            Updated Event object or None if not found
        """
        event = await self.get_event_by_event_id(event_id)
        if not event:
            return None

        event.reviewed = True
        event.reviewed_by = reviewed_by
        event.reviewed_at = datetime.utcnow()
        event.status = "reviewed"
        event.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(event)
        return event

    async def update_event_status(
        self,
        event_id: str,
        status: str,
    ) -> Optional[Event]:
        """
        Update event status

        Args:
            event_id: Event identifier string
            status: New status

        Returns:
            Updated Event object or None if not found
        """
        event = await self.get_event_by_event_id(event_id)
        if not event:
            return None

        event.status = status
        event.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(event)
        return event

    async def delete_event(self, event_id: str) -> bool:
        """
        Delete an event

        Args:
            event_id: Event identifier string

        Returns:
            True if event was deleted, False if not found
        """
        event = await self.get_event_by_event_id(event_id)
        if not event:
            return False

        await self.db.delete(event)
        await self.db.commit()
        return True

    async def get_event_count(
        self,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        reviewed: Optional[bool] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> int:
        """
        Get total count of events

        Args:
            severity: Optional severity filter
            event_type: Optional event type filter
            reviewed: Optional reviewed status filter
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Number of events
        """
        from sqlalchemy import func

        query = select(func.count(Event.id))

        filters = []
        if severity:
            filters.append(Event.severity == severity)
        if event_type:
            filters.append(Event.event_type == event_type)
        if reviewed is not None:
            filters.append(Event.reviewed == reviewed)
        if start_date:
            filters.append(Event.timestamp >= start_date)
        if end_date:
            filters.append(Event.timestamp <= end_date)

        if filters:
            query = query.where(and_(*filters))

        result = await self.db.execute(query)
        return result.scalar_one()

    async def get_events_by_severity(self, days: int = 7) -> dict:
        """
        Get event counts grouped by severity for the last N days

        Args:
            days: Number of days to look back

        Returns:
            Dictionary with severity counts
        """
        start_date = datetime.utcnow() - timedelta(days=days)

        critical = await self.get_event_count(severity="critical", start_date=start_date)
        high = await self.get_event_count(severity="high", start_date=start_date)
        medium = await self.get_event_count(severity="medium", start_date=start_date)
        low = await self.get_event_count(severity="low", start_date=start_date)
        info = await self.get_event_count(severity="info", start_date=start_date)

        return {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        }

    async def get_top_users(self, limit: int = 10, days: int = 7) -> List[dict]:
        """
        Get top users by event count

        Args:
            limit: Number of users to return
            days: Number of days to look back

        Returns:
            List of dictionaries with user and count
        """
        from sqlalchemy import func

        start_date = datetime.utcnow() - timedelta(days=days)

        query = (
            select(Event.user_email, func.count(Event.id).label("count"))
            .where(Event.timestamp >= start_date)
            .where(Event.user_email.isnot(None))
            .group_by(Event.user_email)
            .order_by(func.count(Event.id).desc())
            .limit(limit)
        )

        result = await self.db.execute(query)
        rows = result.all()

        return [{"user_email": row[0], "count": row[1]} for row in rows]

    async def get_events_timeline(
        self,
        days: int = 7,
        interval: str = "day",
    ) -> List[dict]:
        """
        Get events timeline aggregated by interval

        Args:
            days: Number of days to look back
            interval: Aggregation interval (hour, day)

        Returns:
            List of dictionaries with timestamp and count
        """
        from sqlalchemy import func

        start_date = datetime.utcnow() - timedelta(days=days)

        # PostgreSQL date_trunc function
        if interval == "hour":
            time_bucket = func.date_trunc("hour", Event.timestamp)
        else:
            time_bucket = func.date_trunc("day", Event.timestamp)

        query = (
            select(
                time_bucket.label("bucket"),
                func.count(Event.id).label("count"),
            )
            .where(Event.timestamp >= start_date)
            .group_by("bucket")
            .order_by("bucket")
        )

        result = await self.db.execute(query)
        rows = result.all()

        return [
            {
                "timestamp": row[0].isoformat() if row[0] else None,
                "count": row[1],
            }
            for row in rows
        ]
