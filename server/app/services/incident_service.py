"""
Incident Service - Business logic for DLP incident management
"""

from typing import Optional, List
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.incident_comment import IncidentComment


class IncidentService:
    """Service for incident-related operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_incident(
        self,
        event_id: Optional[str] = None,
        severity: int = 2,
        title: Optional[str] = None,
        description: Optional[str] = None,
        policy_id: Optional[UUID] = None,
        assigned_to: Optional[UUID] = None,
    ) -> Incident:
        """
        Create a new incident

        Args:
            event_id: Related event ID
            severity: Severity level (0=info, 1=low, 2=medium, 3=high, 4=critical)
            title: Incident title
            description: Incident description
            policy_id: Related policy ID
            assigned_to: User UUID to assign to

        Returns:
            Created Incident object
        """
        incident = Incident(
            event_id=event_id,
            severity=severity,
            title=title,
            description=description,
            policy_id=policy_id,
            assigned_to=assigned_to,
            status="open",
        )

        self.db.add(incident)
        await self.db.flush()
        await self.db.refresh(incident)

        return incident

    async def get_incident(
        self,
        incident_id: UUID,
        abac_clause=None,
    ) -> Optional[Incident]:
        """
        Fetch a single incident by ID.

        ABAC: when ``abac_clause`` is provided (non-admin caller), the
        incident is only returned if it has an underlying event AND that
        event satisfies the predicate. Manual incidents (``event_id IS
        NULL``) are intentionally hidden from non-admins — they carry no
        department attribute and therefore cannot satisfy ABAC. Admins
        (``abac_clause is None``) still see everything.
        """
        query = select(Incident).where(Incident.id == incident_id)
        if abac_clause is not None:
            from app.models import Event as _Event
            query = query.join(_Event, Incident.event_id == _Event.id).where(abac_clause)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def list_incidents(
        self,
        skip: int = 0,
        limit: int = 50,
        severity: Optional[int] = None,
        status: Optional[str] = None,
        assigned_to: Optional[UUID] = None,
        abac_clause=None,
    ) -> List[Incident]:
        """
        Fetch incidents with optional filtering.

        ABAC: when ``abac_clause`` is provided, incidents are filtered by
        the visibility of their underlying event. Incidents without an
        event are always included (manual incidents).
        """
        query = select(Incident)

        filters = []
        if severity is not None:
            filters.append(Incident.severity == severity)
        if status is not None:
            filters.append(Incident.status == status)
        if assigned_to is not None:
            filters.append(Incident.assigned_to == assigned_to)

        if filters:
            query = query.where(and_(*filters))

        if abac_clause is not None:
            # Non-admin: require a matching underlying event. Manual incidents
            # (event_id IS NULL) have no department to verify and are hidden.
            from app.models import Event as _Event
            query = query.join(_Event, Incident.event_id == _Event.id).where(abac_clause)

        query = query.offset(skip).limit(limit).order_by(Incident.created_at.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def update_incident(
        self,
        incident_id: UUID,
        status: Optional[str] = None,
        assigned_to: Optional[UUID] = None,
    ) -> Optional[Incident]:
        """
        Update incident status and/or assignment

        Args:
            incident_id: UUID of the incident
            status: New status value
            assigned_to: New assignee UUID

        Returns:
            Updated Incident object or None if not found
        """
        incident = await self.get_incident(incident_id)
        if not incident:
            return None

        if status is not None:
            incident.status = status
        if assigned_to is not None:
            incident.assigned_to = assigned_to
        incident.updated_at = datetime.utcnow()

        await self.db.flush()
        await self.db.refresh(incident)
        return incident

    async def add_comment(
        self,
        incident_id: UUID,
        user_id: Optional[UUID],
        comment_text: str,
    ) -> IncidentComment:
        """
        Add a comment to an incident

        Args:
            incident_id: UUID of the incident
            user_id: UUID of the commenting user
            comment_text: Comment body

        Returns:
            Created IncidentComment object
        """
        comment = IncidentComment(
            incident_id=incident_id,
            user_id=user_id,
            comment=comment_text,
        )

        self.db.add(comment)
        await self.db.flush()
        await self.db.refresh(comment)

        return comment

    async def get_comments(self, incident_id: UUID) -> List[IncidentComment]:
        """
        Get all comments for an incident

        Args:
            incident_id: UUID of the incident

        Returns:
            List of IncidentComment objects ordered by creation time
        """
        result = await self.db.execute(
            select(IncidentComment)
            .where(IncidentComment.incident_id == incident_id)
            .order_by(IncidentComment.created_at.asc())
        )
        return list(result.scalars().all())

    async def get_statistics(self, abac_clause=None) -> dict:
        """
        Get incident statistics: counts by status and severity.

        ABAC: when ``abac_clause`` is provided, incidents whose underlying
        event fails the predicate are excluded from the counts, AND manual
        incidents (``event_id IS NULL``) are also excluded — they carry no
        department and cannot be evaluated against ABAC. Admins always see
        the full count.
        """
        def _with_abac(q):
            if abac_clause is None:
                return q
            from app.models import Event as _Event
            return q.join(_Event, Incident.event_id == _Event.id).where(abac_clause)

        status_query = _with_abac(
            select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
        )
        status_result = await self.db.execute(status_query)
        status_counts = {row[0]: row[1] for row in status_result.all()}

        severity_query = _with_abac(
            select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
        )
        severity_result = await self.db.execute(severity_query)
        severity_counts = {row[0]: row[1] for row in severity_result.all()}

        total = sum(status_counts.values())

        return {
            "total": total,
            "status_counts": status_counts,
            "severity_counts": severity_counts,
        }

    async def count_incidents_abac(
        self,
        severity: Optional[int] = None,
        status: Optional[str] = None,
        assigned_to: Optional[UUID] = None,
        abac_clause=None,
    ) -> int:
        """Variant of count_incidents that also applies an ABAC clause.

        Wraps the existing count_incidents path. When ``abac_clause`` is
        provided, incidents whose underlying event fails the predicate are
        excluded. Manual incidents (event_id IS NULL) still count.
        """
        query = select(func.count(Incident.id))
        filters = []
        if severity is not None:
            filters.append(Incident.severity == severity)
        if status is not None:
            filters.append(Incident.status == status)
        if assigned_to is not None:
            filters.append(Incident.assigned_to == assigned_to)
        if filters:
            query = query.where(and_(*filters))

        if abac_clause is not None:
            # Non-admin: require a matching underlying event; manual incidents
            # (event_id IS NULL) are hidden since they have no department.
            from app.models import Event as _Event
            query = query.join(_Event, Incident.event_id == _Event.id).where(abac_clause)

        result = await self.db.execute(query)
        return int(result.scalar() or 0)

    async def count_incidents(
        self,
        severity: Optional[int] = None,
        status: Optional[str] = None,
        assigned_to: Optional[UUID] = None,
    ) -> int:
        """
        Count incidents with optional filters

        Args:
            severity: Filter by severity level
            status: Filter by status string
            assigned_to: Filter by assigned user UUID

        Returns:
            Number of matching incidents
        """
        query = select(func.count(Incident.id))

        filters = []
        if severity is not None:
            filters.append(Incident.severity == severity)
        if status is not None:
            filters.append(Incident.status == status)
        if assigned_to is not None:
            filters.append(Incident.assigned_to == assigned_to)

        if filters:
            query = query.where(and_(*filters))

        result = await self.db.execute(query)
        return result.scalar_one()
