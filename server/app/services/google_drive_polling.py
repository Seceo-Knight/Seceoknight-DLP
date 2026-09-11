"""
Polling service that fetches Google Drive Activity events and ingests them into the DLP pipeline.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_mongodb
from app.models.google_drive import GoogleDriveConnection, GoogleDriveProtectedFolder
from app.models.policy import Policy
from app.services.event_processor import EventProcessor, get_event_processor
from app.services.google_drive_event_normalizer import (
    TRACKED_EVENT_SUBTYPES,
    normalize_drive_activity,
)
from app.services.google_drive_oauth import GoogleDriveOAuthService


# Celery Beat ticks poll_google_drive_activity every 5 minutes (see
# reporting_tasks.py's beat_schedule) -- that tick rate is the finest
# granularity any connection can actually be polled at, so it's also the
# default/floor a connection uses when no policy has configured its own
# (shorter or longer) pollingInterval.
_DEFAULT_POLL_INTERVAL_MINUTES = 5


logger = structlog.get_logger(__name__)


class GoogleDrivePollingService:
    """
    Pulls Drive Activity events for each connected account/folder and feeds them to EventProcessor.
    """

    def __init__(
        self,
        db: AsyncSession,
        events_collection=None,
        event_processor: Optional[EventProcessor] = None,
    ) -> None:
        self.db = db
        self.oauth_service = GoogleDriveOAuthService(db)
        self.event_processor = event_processor or get_event_processor()
        self.events_collection = events_collection or get_mongodb()["dlp_events"]

    async def poll_all_connections(self) -> int:
        """
        Poll every Google Drive connection. Returns number of processed events.
        """
        stmt = select(GoogleDriveConnection)
        result = await self.db.execute(stmt)
        connections = result.scalars().all()
        processed = 0
        for connection in connections:
            processed += await self.poll_connection(connection)
        return processed

    async def poll_connection(self, connection: GoogleDriveConnection) -> int:
        """
        Poll a single connection and ingest events.
        """
        await self.db.refresh(connection, attribute_names=["folders"])
        if not connection.folders:
            logger.debug("Skipping connection with no protected folders", connection_id=str(connection.id))
            return 0

        # Per-connection cadence -- GoogleDriveCloudPolicyForm.tsx lets the
        # user pick a "Polling Interval" (5/10/15/30/60 min, or custom) per
        # policy, but until now nothing server-side ever read it: this
        # function ran unconditionally on every 5-minute Celery Beat tick,
        # so the selector was pure decoration. The tick rate itself is still
        # fixed (changing that needs a dynamic beat schedule, a bigger
        # change than this warrants), but each connection now decides
        # whether it's actually due based on the shortest pollingInterval
        # configured across its own policies -- so a 30/60-minute policy
        # now visibly skips most ticks instead of the UI lying about it.
        if connection.last_polled_at:
            min_interval = await self._get_min_polling_interval(connection.id)
            last_polled = connection.last_polled_at
            if last_polled.tzinfo is None:
                last_polled = last_polled.replace(tzinfo=timezone.utc)
            elapsed = datetime.now(timezone.utc) - last_polled
            if elapsed < timedelta(minutes=min_interval):
                logger.debug(
                    "Skipping Google Drive connection -- not due yet",
                    connection_id=str(connection.id),
                    elapsed_seconds=elapsed.total_seconds(),
                    min_interval_minutes=min_interval,
                )
                return 0

        if connection.is_token_expired():
            await self.oauth_service.refresh_access_token(connection)

        credentials = self._build_credentials(connection)
        total = 0
        latest_connection_timestamp: Optional[datetime] = self._parse_timestamp(connection.last_activity_cursor)

        for folder in connection.folders:
            if not folder.last_seen_timestamp:
                folder.touch()
                logger.info(
                    "Initialized Google Drive folder baseline",
                    connection_id=str(connection.id),
                    folder_id=folder.folder_id,
                    baseline=folder.last_seen_timestamp,
                )
                continue

            events, latest_folder_timestamp = await self._fetch_folder_events(credentials, connection, folder)
            for event in events:
                await self._persist_event(event)
                total += 1

            if latest_folder_timestamp:
                folder.touch(self._as_naive_utc(latest_folder_timestamp))
                if not latest_connection_timestamp or latest_folder_timestamp > latest_connection_timestamp:
                    latest_connection_timestamp = latest_folder_timestamp

        connection.mark_polled(
            cursor=self._format_timestamp(latest_connection_timestamp) if latest_connection_timestamp else None
        )
        await self.db.commit()

        logger.info("Google Drive polling completed", connection_id=str(connection.id), events=total)
        return total

    async def _get_min_polling_interval(self, connection_id) -> int:
        """
        Shortest pollingInterval (minutes) configured across this
        connection's enabled google_drive_cloud_monitoring policies.
        Multiple policies can point at the same Drive account with
        different intervals configured -- a connection can only be polled
        at one cadence, so the most demanding (smallest) interval wins,
        same "most permissive/most demanding policy wins" precedence used
        elsewhere in this codebase for overlapping policy conditions.
        Falls back to _DEFAULT_POLL_INTERVAL_MINUTES if no matching policy
        sets one (e.g. a connection with no policy yet, or one that never
        touched the interval selector), which matches the 5-minute cadence
        this connection was already being polled at before this fix.

        Filters connectionId in Python rather than a JSON-path SQL query --
        deliberately: config is a generic JSON column with no index on
        connectionId, and the number of google_drive_cloud_monitoring
        policies in any real deployment is small, so fetching the type-
        filtered set and matching in Python (the same pattern
        DatabasePolicyEvaluator's own policy cache already uses) is simpler
        and more portable than a Postgres-specific JSON operator.
        """
        stmt = select(Policy).where(
            Policy.type == "google_drive_cloud_monitoring",
            Policy.status == "active",
            Policy.deleted_at.is_(None),
        )
        result = await self.db.execute(stmt)
        policies = result.scalars().all()

        intervals: List[int] = []
        for policy in policies:
            config = policy.config or {}
            if config.get("connectionId") != str(connection_id):
                continue
            interval = config.get("pollingInterval")
            if isinstance(interval, (int, float)) and interval > 0:
                intervals.append(int(interval))

        return min(intervals) if intervals else _DEFAULT_POLL_INTERVAL_MINUTES

    def _build_credentials(self, connection: GoogleDriveConnection) -> Credentials:
        config = self.oauth_service.get_client_config()
        return Credentials(
            token=connection.get_access_token(),
            refresh_token=connection.get_refresh_token(),
            token_uri=config.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            scopes=connection.scopes or list(GoogleDriveOAuthService.SCOPES),
        )

    async def _fetch_folder_events(
        self,
        credentials: Credentials,
        connection: GoogleDriveConnection,
        folder: GoogleDriveProtectedFolder,
    ) -> Tuple[List[Dict[str, Any]], Optional[datetime]]:
        """
        Query Drive Activity API for a single folder and return any new events plus
        the most recent activity timestamp observed.
        """
        service = self._build_drive_activity_service(credentials)
        normalized: List[Dict[str, Any]] = []
        latest_timestamp: Optional[datetime] = None

        body: Dict[str, Any] = {
            "ancestorName": f"items/{folder.folder_id}",
            "pageSize": 50,
        }

        if folder.last_seen_timestamp:
            start_iso = self._format_timestamp(self._as_aware_utc(folder.last_seen_timestamp))
            body["filter"] = f'time > "{start_iso}"'

        logger.info(
            "Google Drive Activity API Request",
            connection_id=str(connection.id),
            folder_id=folder.folder_id,
            folder_name=folder.folder_name,
            filter=body.get("filter"),
        )

        next_page_token: Optional[str] = None
        while True:
            request_body = dict(body)
            if next_page_token:
                request_body["pageToken"] = next_page_token

            response = await asyncio.to_thread(self._execute_activity_query, service, request_body)
            activities = response.get("activities", [])
            for activity in activities:
                normalized_event = normalize_drive_activity(activity, connection, folder)
                if normalized_event.get("event_subtype") not in TRACKED_EVENT_SUBTYPES:
                    continue

                normalized.append(normalized_event)
                event_ts = self._parse_timestamp(normalized_event.get("timestamp"))
                if event_ts and (latest_timestamp is None or event_ts > latest_timestamp):
                    latest_timestamp = event_ts

            next_page_token = response.get("nextPageToken")
            if not next_page_token:
                break

        return normalized, latest_timestamp

    def _build_drive_activity_service(self, credentials: Credentials):
        return build("driveactivity", "v2", credentials=credentials, cache_discovery=False)

    @staticmethod
    def _execute_activity_query(service, body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Google Drive Activity API query with detailed error logging.
        """
        import json
        logger.debug(
            "Executing Drive Activity API query",
            request_body=json.dumps(body, indent=2),
            body_type=type(body).__name__,
            body_keys=list(body.keys()) if isinstance(body, dict) else None,
        )
        try:
            result = service.activity().query(body=body).execute()
            logger.debug("Drive Activity API query succeeded", activities_count=len(result.get("activities", [])))
            return result
        except Exception as e:
            logger.error(
                "Drive Activity API query failed",
                error_type=type(e).__name__,
                error_message=str(e),
                request_body=json.dumps(body, indent=2),
                body_keys=list(body.keys()) if isinstance(body, dict) else None,
            )
            raise

    async def _persist_event(self, normalized_event: Dict[str, Any]) -> None:
        """
        Run event through EventProcessor and persist it to MongoDB.
        """
        if await self._is_duplicate(normalized_event["event_id"]):
            logger.debug("Skipping duplicate Google Drive event", event_id=normalized_event["event_id"])
            return

        payload = self._build_processor_payload(normalized_event)
        processed = await self.event_processor.process_event(payload)

        matched_policies = processed.get("matched_policies")
        if not matched_policies:
            logger.debug(
                "Skipping event with no policy matches",
                event_id=normalized_event["event_id"],
                folder_id=normalized_event["folder_id"],
            )
            return

        logger.info(
            "Google Drive event matched policies",
            event_id=normalized_event["event_id"],
            match_count=len(matched_policies),
            policies=[policy.get("policy_name") for policy in matched_policies],
        )

        doc = self._build_event_document(normalized_event, processed)
        await self.events_collection.insert_one(doc)

    async def _is_duplicate(self, event_id: str) -> bool:
        existing = await self.events_collection.find_one({"id": event_id})
        return existing is not None

    def _build_processor_payload(self, event: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "event_id": event["event_id"],
            "source": event["source"],
            "agent": {
                "id": f"gdrive-{event['connection_id']}",
                "name": "Google Drive Cloud",
                "type": "cloud",
            },
            "event": {
                "type": event["event_type"],
                "severity": event["severity"],
                "source_type": event["source"],
                "action": event.get("action", "logged"),
                "subtype": event.get("event_subtype"),
            },
            "metadata": {
                "ingest_source": "google_drive",
                "folder_id": event["folder_id"],
                "protected_folder_id": event.get("protected_folder_id"),
                "connection_id": event["connection_id"],
            },
            "tags": ["google_drive", "cloud"],
            "user": {"email": event.get("user_email", "unknown@drive")},
        }

        payload.setdefault("file", {})
        payload["file"]["path"] = event.get("folder_path")
        payload["file"]["name"] = event.get("file_name")
        payload["file"]["id"] = event.get("file_id")
        payload["file"]["mime_type"] = event.get("mime_type")

        return payload

    def _parse_timestamp(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return self._as_aware_utc(dt)

    @staticmethod
    def _as_aware_utc(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _as_naive_utc(self, dt: datetime) -> datetime:
        return self._as_aware_utc(dt).replace(tzinfo=None)

    def _format_timestamp(self, dt: datetime) -> str:
        return self._as_aware_utc(dt).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _build_event_document(self, event: Dict[str, Any], processed: Dict[str, Any]) -> Dict[str, Any]:
        event_ts = (
            self._parse_timestamp(event.get("timestamp"))
            or self._extract_activity_timestamp(event)
            or datetime.utcnow().replace(tzinfo=timezone.utc)
        )
        persisted_ts = self._as_naive_utc(event_ts)

        metadata = dict(processed.get("metadata", {}))
        metadata.setdefault("activity_timestamp", persisted_ts)

        return {
            "id": event["event_id"],
            "timestamp": persisted_ts,
            "event_type": event["event_type"],
            "event_subtype": event.get("event_subtype"),
            "description": event.get("description", "Google Drive file activity"),  # Include description
            "severity": processed.get("event", {}).get("severity", event["severity"]),
            "source": event["source"],
            "agent_id": f"gdrive-{event['connection_id']}",
            "user_email": event.get("user_email", "unknown@drive"),
            "classification_score": 0.0,
            "classification_labels": [],
            "action_taken": processed.get("event", {}).get("action", event.get("action", "logged")),
            "file_path": event.get("folder_path"),
            "file_name": event.get("file_name"),
            "file_id": event.get("file_id"),
            "mime_type": event.get("mime_type"),
            "folder_id": event.get("folder_id"),
            "protected_folder_id": event.get("protected_folder_id"),
            "folder_name": event.get("folder_name"),
            "folder_path": event.get("folder_path"),
            "blocked": False,
            "details": {
                "google_event_id": event.get("google_event_id"),
                "raw_activity": event.get("details"),
            },
            "matched_policies": processed.get("matched_policies", []),
            "policy_action_summaries": processed.get("policy_action_summaries", []),
            "metadata": metadata,
            "tags": processed.get("tags", ["google_drive"]),
            "policy_version": processed.get("policy_version"),
        }

    def _extract_activity_timestamp(self, event: Dict[str, Any]) -> Optional[datetime]:
        details = event.get("details")
        if not isinstance(details, dict):
            return None

        raw_activity = details.get("raw_activity") if isinstance(details.get("raw_activity"), dict) else details
        if not isinstance(raw_activity, dict):
            return None

        timestamp_str = raw_activity.get("timestamp")
        if timestamp_str:
            return self._parse_timestamp(timestamp_str)

        time_range = raw_activity.get("timeRange")
        if isinstance(time_range, dict):
            end = time_range.get("endTime")
            start = time_range.get("startTime")
            if end:
                return self._parse_timestamp(end)
            if start:
                return self._parse_timestamp(start)
        return None

