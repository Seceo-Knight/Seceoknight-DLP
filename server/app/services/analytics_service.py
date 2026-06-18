"""
Analytics Service
Provides aggregated data for dashboards and reports
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, case
from opensearchpy import AsyncOpenSearch

from app.models import Event, Agent, Policy
from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)


class AnalyticsService:
    """Service for analytics and reporting data aggregation.

    ABAC: when ``abac_clause`` is set on the instance, every SELECT executed
    by this service has the clause AND-ed into its WHERE. A ``None`` value
    means "no filter" — used when the caller carries ``view_all_departments``.
    """

    def __init__(
        self,
        db: AsyncSession,
        opensearch: Optional[AsyncOpenSearch] = None,
        abac_clause=None,
    ):
        self.db = db
        self.opensearch = opensearch
        self._abac_clause = abac_clause

    def _apply_abac(self, query):
        """Return ``query`` AND-merged with the configured ABAC predicate.

        A no-op when ``self._abac_clause`` is None (global-access caller).
        Adding ``.where(X)`` to an existing SELECT is safe regardless of
        chain order — SQLAlchemy composes the final SQL's WHERE clause by
        intersecting all registered criteria.
        """
        if self._abac_clause is None:
            return query
        return query.where(self._abac_clause)

    async def get_incident_trends(
        self,
        start_date: datetime,
        end_date: datetime,
        interval: str = "day",  # hour, day, week, month
        group_by: Optional[str] = None  # severity, type, policy_id
    ) -> Dict[str, Any]:
        """
        Get incident trends over time

        Args:
            start_date: Start of time range
            end_date: End of time range
            interval: Time bucket interval (hour, day, week, month)
            group_by: Optional field to group by

        Returns:
            Dictionary with time series data and statistics
        """
        try:
            # If OpenSearch is available, use it for better performance
            if self.opensearch:
                return await self._get_trends_from_opensearch(
                    start_date, end_date, interval, group_by
                )
            else:
                return await self._get_trends_from_db(
                    start_date, end_date, interval, group_by
                )
        except Exception as e:
            logger.log_error(e, {
                "operation": "get_incident_trends",
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat()
            })
            raise

    async def _get_trends_from_db(
        self,
        start_date: datetime,
        end_date: datetime,
        interval: str,
        group_by: Optional[str]
    ) -> Dict[str, Any]:
        """Get trends from PostgreSQL database"""

        # Build date truncation based on interval
        if interval == "hour":
            date_trunc = func.date_trunc('hour', Event.timestamp)
        elif interval == "day":
            date_trunc = func.date_trunc('day', Event.timestamp)
        elif interval == "week":
            date_trunc = func.date_trunc('week', Event.timestamp)
        else:  # month
            date_trunc = func.date_trunc('month', Event.timestamp)

        # Base query
        query = select(
            date_trunc.label('time_bucket'),
            func.count(Event.id).label('count')
        ).where(
            and_(
                Event.timestamp >= start_date,
                Event.timestamp <= end_date
            )
        )

        # Add grouping if specified
        if group_by:
            if group_by == "severity":
                query = select(
                    date_trunc.label('time_bucket'),
                    Event.severity,
                    func.count(Event.id).label('count')
                ).where(
                    and_(
                        Event.timestamp >= start_date,
                        Event.timestamp <= end_date
                    )
                ).group_by('time_bucket', Event.severity).order_by('time_bucket')
            elif group_by == "type":
                query = select(
                    date_trunc.label('time_bucket'),
                    Event.event_type,
                    func.count(Event.id).label('count')
                ).where(
                    and_(
                        Event.timestamp >= start_date,
                        Event.timestamp <= end_date
                    )
                ).group_by('time_bucket', Event.event_type).order_by('time_bucket')
            elif group_by == "policy_id":
                query = select(
                    date_trunc.label('time_bucket'),
                    Event.policy_id,
                    func.count(Event.id).label('count')
                ).where(
                    and_(
                        Event.timestamp >= start_date,
                        Event.timestamp <= end_date,
                        Event.policy_id.isnot(None)
                    )
                ).group_by('time_bucket', Event.policy_id).order_by('time_bucket')
        else:
            query = query.group_by('time_bucket').order_by('time_bucket')

        result = await self.db.execute(self._apply_abac(query))
        rows = result.all()

        # Format results
        if group_by:
            # Multiple series
            series_data = {}
            for row in rows:
                time_bucket = row.time_bucket.isoformat()
                series_key = getattr(row, group_by)

                if series_key not in series_data:
                    series_data[series_key] = []

                series_data[series_key].append({
                    "timestamp": time_bucket,
                    "count": row.count
                })

            return {
                "interval": interval,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "group_by": group_by,
                "series": series_data,
                "total_incidents": sum(row.count for row in rows)
            }
        else:
            # Single series
            data_points = [
                {
                    "timestamp": row.time_bucket.isoformat(),
                    "count": row.count
                }
                for row in rows
            ]

            return {
                "interval": interval,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "data": data_points,
                "total_incidents": sum(point["count"] for point in data_points)
            }

    async def _get_trends_from_opensearch(
        self,
        start_date: datetime,
        end_date: datetime,
        interval: str,
        group_by: Optional[str]
    ) -> Dict[str, Any]:
        """Get trends from OpenSearch with date histogram aggregation.

        ABAC guard: this branch does not (yet) translate ``self._abac_clause``
        into an OpenSearch query-body filter. Running it for a non-admin
        caller would leak cross-department data. The branch is currently
        dormant (no endpoint constructs AnalyticsService with an OpenSearch
        client), so we fail loudly instead of silently leaking. If OpenSearch
        is wired up later, add a term/terms filter on `department` (and a
        range filter on `required_clearance`) derived from the caller's
        attributes before removing this guard.
        """
        if self._abac_clause is not None:
            raise RuntimeError(
                "OpenSearch analytics path does not apply ABAC filters. "
                "Refusing to serve a non-admin request from this code path. "
                "Use the PostgreSQL fallback (construct AnalyticsService "
                "without opensearch=) or implement ABAC in the OS query body."
            )

        # Map interval to OpenSearch calendar interval
        interval_map = {
            "hour": "1h",
            "day": "1d",
            "week": "1w",
            "month": "1M"
        }

        # Build aggregation query
        agg_query = {
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date.isoformat(),
                        "lte": end_date.isoformat()
                    }
                }
            },
            "aggs": {
                "incidents_over_time": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": interval_map.get(interval, "1d"),
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": start_date.isoformat(),
                            "max": end_date.isoformat()
                        }
                    }
                }
            }
        }

        # Add sub-aggregation if grouping
        if group_by:
            agg_query["aggs"]["incidents_over_time"]["aggs"] = {
                "by_field": {
                    "terms": {
                        "field": f"{group_by}.keyword",
                        "size": 100
                    }
                }
            }

        result = await self.opensearch.search(
            index="dlp-events-*",
            body=agg_query
        )

        buckets = result["aggregations"]["incidents_over_time"]["buckets"]

        if group_by:
            # Multiple series
            series_data = {}
            total = 0

            for bucket in buckets:
                timestamp = bucket["key_as_string"]

                for sub_bucket in bucket["by_field"]["buckets"]:
                    series_key = sub_bucket["key"]
                    count = sub_bucket["doc_count"]
                    total += count

                    if series_key not in series_data:
                        series_data[series_key] = []

                    series_data[series_key].append({
                        "timestamp": timestamp,
                        "count": count
                    })

            return {
                "interval": interval,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "group_by": group_by,
                "series": series_data,
                "total_incidents": total
            }
        else:
            # Single series
            data_points = [
                {
                    "timestamp": bucket["key_as_string"],
                    "count": bucket["doc_count"]
                }
                for bucket in buckets
            ]

            return {
                "interval": interval,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "data": data_points,
                "total_incidents": sum(point["count"] for point in data_points)
            }

    async def get_top_violators(
        self,
        start_date: datetime,
        end_date: datetime,
        limit: int = 10,
        by: str = "user"  # user, agent, ip_address
    ) -> List[Dict[str, Any]]:
        """
        Get top violators by incident count

        Args:
            start_date: Start of time range
            end_date: End of time range
            limit: Number of results to return
            by: Field to group by (user, agent, ip_address)

        Returns:
            List of violators with counts and details
        """
        try:
            if by == "agent":
                # Query by agent
                query = select(
                    Event.agent_id,
                    Agent.name.label('agent_name'),
                    Agent.hostname,
                    func.count(Event.id).label('incident_count'),
                    func.count(
                        func.distinct(
                            case(
                                (Event.severity == 'critical', Event.id),
                                else_=None
                            )
                        )
                    ).label('critical_count')
                ).join(
                    # Agent has both `id` (UUID PK) and `agent_id` (String
                    # external identifier). Events carry the String external
                    # identifier, so the join predicate must compare like
                    # types. Comparing String → UUID fails at the planner.
                    Agent, Event.agent_id == Agent.agent_id
                ).where(
                    and_(
                        Event.timestamp >= start_date,
                        Event.timestamp <= end_date
                    )
                ).group_by(
                    Event.agent_id, Agent.name, Agent.hostname
                ).order_by(
                    desc('incident_count')
                ).limit(limit)

                result = await self.db.execute(self._apply_abac(query))
                rows = result.all()

                return [
                    {
                        "agent_id": row.agent_id,
                        "agent_name": row.agent_name,
                        "hostname": row.hostname,
                        "incident_count": row.incident_count,
                        "critical_count": row.critical_count
                    }
                    for row in rows
                ]

            elif by == "user":
                # Query by username (from event metadata)
                query = select(
                    Event.username,
                    func.count(Event.id).label('incident_count'),
                    func.count(
                        func.distinct(
                            case(
                                (Event.severity == 'critical', Event.id),
                                else_=None
                            )
                        )
                    ).label('critical_count')
                ).where(
                    and_(
                        Event.timestamp >= start_date,
                        Event.timestamp <= end_date,
                        Event.username.isnot(None)
                    )
                ).group_by(
                    Event.username
                ).order_by(
                    desc('incident_count')
                ).limit(limit)

                result = await self.db.execute(self._apply_abac(query))
                rows = result.all()

                return [
                    {
                        "username": row.username,
                        "incident_count": row.incident_count,
                        "critical_count": row.critical_count
                    }
                    for row in rows
                ]

            else:  # ip_address
                query = select(
                    Event.source_ip,
                    func.count(Event.id).label('incident_count'),
                    func.count(
                        func.distinct(
                            case(
                                (Event.severity == 'critical', Event.id),
                                else_=None
                            )
                        )
                    ).label('critical_count')
                ).where(
                    and_(
                        Event.timestamp >= start_date,
                        Event.timestamp <= end_date,
                        Event.source_ip.isnot(None)
                    )
                ).group_by(
                    Event.source_ip
                ).order_by(
                    desc('incident_count')
                ).limit(limit)

                result = await self.db.execute(self._apply_abac(query))
                rows = result.all()

                return [
                    {
                        "ip_address": row.source_ip,
                        "incident_count": row.incident_count,
                        "critical_count": row.critical_count
                    }
                    for row in rows
                ]

        except Exception as e:
            logger.log_error(e, {
                "operation": "get_top_violators",
                "by": by
            })
            raise

    async def get_data_type_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get statistics on detected PII/sensitive data types

        Returns:
            List of data types with counts and percentages
        """
        try:
            # Query classification types
            query = select(
                Event.event_type,
                func.count(Event.id).label('count'),
                func.avg(Event.confidence_score).label('avg_confidence')
            ).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date,
                    Event.event_type.isnot(None)
                )
            ).group_by(
                Event.event_type
            ).order_by(
                desc('count')
            )

            result = await self.db.execute(self._apply_abac(query))
            rows = result.all()

            total_detections = sum(row.count for row in rows)

            return [
                {
                    "data_type": row.event_type,
                    "count": row.count,
                    "percentage": round((row.count / total_detections * 100), 2) if total_detections > 0 else 0,
                    "avg_confidence": round(float(row.avg_confidence or 0), 2)
                }
                for row in rows
            ]

        except Exception as e:
            logger.log_error(e, {"operation": "get_data_type_statistics"})
            raise

    async def get_policy_violation_breakdown(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get breakdown of policy violations

        Returns:
            List of policies with violation counts
        """
        try:
            query = select(
                Event.policy_id,
                Policy.name.label('policy_name'),
                func.count(Event.id).label('violation_count'),
                func.count(
                    func.distinct(
                        case(
                            (Event.action == 'blocked', Event.id),
                            else_=None
                        )
                    )
                ).label('blocked_count')
            ).join(
                Policy, Event.policy_id == Policy.id, isouter=True
            ).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date,
                    Event.policy_id.isnot(None)
                )
            ).group_by(
                Event.policy_id, Policy.name
            ).order_by(
                desc('violation_count')
            )

            result = await self.db.execute(self._apply_abac(query))
            rows = result.all()

            return [
                {
                    "policy_id": row.policy_id,
                    "policy_name": row.policy_name or "Unknown",
                    "violation_count": row.violation_count,
                    "blocked_count": row.blocked_count,
                    "block_rate": round((row.blocked_count / row.violation_count * 100), 2)
                        if row.violation_count > 0 else 0
                }
                for row in rows
            ]

        except Exception as e:
            logger.log_error(e, {"operation": "get_policy_violation_breakdown"})
            raise

    async def get_severity_distribution(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Get distribution of incident severities

        Returns:
            Dictionary with severity counts and percentages
        """
        try:
            query = select(
                Event.severity,
                func.count(Event.id).label('count')
            ).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date
                )
            ).group_by(
                Event.severity
            ).order_by(
                desc('count')
            )

            result = await self.db.execute(self._apply_abac(query))
            rows = result.all()

            total = sum(row.count for row in rows)

            distribution = {
                row.severity: {
                    "count": row.count,
                    "percentage": round((row.count / total * 100), 2) if total > 0 else 0
                }
                for row in rows
            }

            return {
                "total_incidents": total,
                "distribution": distribution
            }

        except Exception as e:
            logger.log_error(e, {"operation": "get_severity_distribution"})
            raise

    async def get_summary_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Get summary statistics for dashboard overview

        Returns:
            Dictionary with key metrics
        """
        try:
            # Total incidents
            total_query = select(func.count(Event.id)).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date
                )
            )
            total_result = await self.db.execute(self._apply_abac(total_query))
            total_incidents = total_result.scalar()

            # Critical incidents
            critical_query = select(func.count(Event.id)).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date,
                    Event.severity == 'critical'
                )
            )
            critical_result = await self.db.execute(self._apply_abac(critical_query))
            critical_incidents = critical_result.scalar()

            # Blocked incidents
            blocked_query = select(func.count(Event.id)).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date,
                    Event.action == 'blocked'
                )
            )
            blocked_result = await self.db.execute(self._apply_abac(blocked_query))
            blocked_incidents = blocked_result.scalar()

            # Active agents
            agents_query = select(func.count(func.distinct(Event.agent_id))).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date
                )
            )
            agents_result = await self.db.execute(self._apply_abac(agents_query))
            active_agents = agents_result.scalar()

            # Policy violations
            policy_query = select(func.count(Event.id)).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date,
                    Event.policy_id.isnot(None)
                )
            )
            policy_result = await self.db.execute(self._apply_abac(policy_query))
            policy_violations = policy_result.scalar()

            # Most common data type
            datatype_query = select(
                Event.event_type,
                func.count(Event.id).label('count')
            ).where(
                and_(
                    Event.timestamp >= start_date,
                    Event.timestamp <= end_date,
                    Event.event_type.isnot(None)
                )
            ).group_by(
                Event.event_type
            ).order_by(
                desc('count')
            ).limit(1)

            datatype_result = await self.db.execute(self._apply_abac(datatype_query))
            datatype_row = datatype_result.first()
            most_common_datatype = datatype_row.event_type if datatype_row else None

            return {
                "period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                },
                "total_incidents": total_incidents,
                "critical_incidents": critical_incidents,
                "blocked_incidents": blocked_incidents,
                "active_agents": active_agents,
                "policy_violations": policy_violations,
                "block_rate": round((blocked_incidents / total_incidents * 100), 2)
                    if total_incidents > 0 else 0,
                "most_common_datatype": most_common_datatype
            }

        except Exception as e:
            logger.log_error(e, {"operation": "get_summary_statistics"})
            raise
