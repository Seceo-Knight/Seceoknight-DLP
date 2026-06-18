"""
Polling service that fetches OneDrive Graph API delta events and ingests them into the DLP pipeline.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import json
import structlog
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_mongodb
from app.core.cache import get_cache
from app.models.onedrive import OneDriveConnection, OneDriveProtectedFolder
from app.services.event_processor import EventProcessor, get_event_processor
from app.services.onedrive_event_normalizer import (
    TRACKED_EVENT_SUBTYPES,
    normalize_delta_item,
)
from app.services.onedrive_oauth import OneDriveOAuthService


logger = structlog.get_logger(__name__)


class OneDrivePollingService:
    """
    Pulls Graph API delta events for each connected account/folder and feeds them to EventProcessor.
    """

    def __init__(
        self,
        db: AsyncSession,
        events_collection=None,
        event_processor: Optional[EventProcessor] = None,
    ) -> None:
        self.db = db
        self.oauth_service = OneDriveOAuthService(db)
        self.event_processor = event_processor or get_event_processor()
        self.events_collection = events_collection or get_mongodb()["dlp_events"]
        # Redis client for file state storage (optional, gracefully handles if unavailable)
        try:
            self.redis_client = get_cache()
        except RuntimeError:
            logger.warning("Redis not available, file state tracking disabled")
            self.redis_client = None

    async def poll_all_connections(self) -> int:
        """
        Poll every OneDrive connection. Returns number of processed events.
        """
        stmt = select(OneDriveConnection)
        result = await self.db.execute(stmt)
        connections = result.scalars().all()
        processed = 0
        for connection in connections:
            processed += await self.poll_connection(connection)
        return processed

    async def poll_connection(self, connection: OneDriveConnection) -> int:
        """
        Poll a single connection and ingest events.
        """
        await self.db.refresh(connection, attribute_names=["folders"])
        if not connection.folders:
            logger.debug("Skipping connection with no protected folders", connection_id=str(connection.id))
            return 0

        if connection.is_token_expired():
            await self.oauth_service.refresh_access_token(connection)

        access_token = connection.get_access_token()
        if not access_token:
            logger.error("No access token available for connection", connection_id=str(connection.id))
            connection.mark_error("No access token available")
            await self.db.commit()
            return 0

        total = 0
        latest_connection_timestamp: Optional[datetime] = None

        for folder in connection.folders:
            if not folder.last_seen_timestamp:
                folder.touch()
                logger.info(
                    "Initialized OneDrive folder baseline",
                    connection_id=str(connection.id),
                    folder_id=folder.folder_id,
                    baseline=folder.last_seen_timestamp,
                )
                continue

            events, latest_folder_timestamp, delta_token = await self._fetch_folder_events(
                access_token, connection, folder
            )
            for event in events:
                await self._persist_event(event)
                total += 1

            if latest_folder_timestamp:
                folder.touch(self._as_naive_utc(latest_folder_timestamp))
                if not latest_connection_timestamp or latest_folder_timestamp > latest_connection_timestamp:
                    latest_connection_timestamp = latest_folder_timestamp

            # Store delta token for next incremental sync
            if delta_token:
                folder.set_delta_token(delta_token)

        # Update connection-level delta token if we have one
        connection.mark_polled(
            delta_token=None,  # Connection-level delta token not used (per-folder tokens instead)
            polled_at=datetime.utcnow(),
        )
        await self.db.commit()

        logger.info("OneDrive polling completed", connection_id=str(connection.id), events=total)
        return total

    async def _fetch_folder_events(
        self,
        access_token: str,
        connection: OneDriveConnection,
        folder: OneDriveProtectedFolder,
    ) -> Tuple[List[Dict[str, Any]], Optional[datetime], Optional[str]]:
        """
        Query Graph API delta endpoint for a single folder and return any new events plus
        the most recent timestamp observed and delta token for next sync.
        """
        normalized: List[Dict[str, Any]] = []
        latest_timestamp: Optional[datetime] = None
        delta_token: Optional[str] = None

        # Build delta query endpoint
        # Graph API delta works as follows:
        # 1. First sync: Use /delta endpoint to get all items + deltaLink
        # 2. Subsequent syncs: Use deltaLink from previous sync to get only changes
        # 
        # IMPORTANT: For personal OneDrive accounts, folder-specific delta endpoints
        # may require SPO license. Use root delta endpoint and filter client-side.
        use_root_delta = False
        if folder.delta_token:
            # Check if delta token is for a folder-specific endpoint (which may fail with SPO error)
            # For personal accounts, we'll use root delta and filter client-side
            if "/items/" in folder.delta_token and "/delta" in folder.delta_token:
                # This is a folder-specific delta token - may fail with SPO license error
                # We'll try it first, but fall back to root delta if it fails
                endpoint = folder.delta_token
                params: Dict[str, Any] = {}
            else:
                # Root delta token - safe to use
                endpoint = folder.delta_token
                params: Dict[str, Any] = {}
        else:
            # Initial sync: always use root delta for personal accounts to avoid SPO errors
            # We'll filter results client-side to only include items from the protected folder
            endpoint = "https://graph.microsoft.com/v1.0/me/drive/root/delta"
            use_root_delta = True
            params: Dict[str, Any] = {}

        logger.info(
            "OneDrive Graph API Delta Request",
            connection_id=str(connection.id),
            folder_id=folder.folder_id,
            folder_name=folder.folder_name,
            using_delta_token=bool(folder.delta_token),
        )

        next_link: Optional[str] = None
        while True:
            # Use next_link if available, otherwise use endpoint
            request_url = next_link or endpoint
            if next_link:
                # Extract delta token from next_link if it's a deltaLink
                parsed = urlparse(next_link)
                if "deltaLink" in parsed.path or "delta" in parsed.path:
                    delta_token = next_link

            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        request_url,
                        headers={"Authorization": f"Bearer {access_token}"},
                        params=params if not next_link else None,
                        timeout=30.0,
                    )
                    response.raise_for_status()
                    data = response.json()
            except httpx.HTTPStatusError as e:
                error_text = e.response.text
                status_code = e.response.status_code
                # Gracefully handle SPO license errors for personal accounts
                if status_code == 400 and "Tenant does not have a SPO license" in error_text:
                    # Delta queries not supported for personal accounts - use children endpoint fallback
                    logger.info(
                        "Delta query not supported for personal account, using children endpoint fallback",
                        folder_id=folder.folder_id,
                        connection_id=str(connection.id),
                    )
                    # Clear delta token and use children endpoint instead
                    folder.set_delta_token(None)
                    # Use children endpoint with timestamp filtering
                    return await self._fetch_folder_events_via_children(
                        access_token, connection, folder
                    )
                logger.error(
                    "Graph API delta query failed",
                    status_code=status_code,
                    error=error_text,
                    folder_id=folder.folder_id,
                    connection_id=str(connection.id),
                )
                raise
            except Exception as e:
                logger.error(
                    "Graph API delta query error",
                    error=str(e),
                    folder_id=folder.folder_id,
                )
                raise

            items = data.get("value", [])
            for item in items:
                # If using root delta, filter to only include items from the protected folder
                if use_root_delta and folder.folder_id != "root":
                    # Check if item is in the protected folder by comparing parentReference.id
                    parent_ref = item.get("parentReference", {})
                    item_parent_id = parent_ref.get("id")
                    
                    # Match if parent ID matches folder_id (item is directly in the folder)
                    # OR if the item itself is the folder (for folder-level changes)
                    if item_parent_id != folder.folder_id and item.get("id") != folder.folder_id:
                        # For nested items, check if the path contains our folder
                        # Path format: /drive/root:/folder/subfolder
                        item_path = parent_ref.get("path", "")
                        if not item_path or f"/{folder.folder_name}" not in item_path:
                            continue
                
                # Extract change type from item
                change_type = item.get("@microsoft.graph.changeType", "updated")
                
                # Skip folder-only items; we track files, not folder create/rename
                if item.get("folder") and not item.get("file") and not item.get("deleted"):
                    continue

                # Skip if not a tracked change type
                if change_type.lower() not in ["created", "updated", "deleted", "moved", "renamed", "copied"]:
                    continue

                file_id = item.get("id")
                normalized_event: Optional[Dict[str, Any]] = None

                # Handle different change types with hybrid approach
                if change_type.lower() == "deleted":
                    # Deletions are reliable from delta - use as-is
                    normalized_event = normalize_delta_item(item, change_type, connection, folder)
                    # Remove file state from Redis on deletion
                    if file_id:
                        try:
                            if self.redis_client:
                                key = f"onedrive:file_state:{connection.id}:{file_id}"
                                await self.redis_client.delete(key)
                        except Exception as e:
                            logger.debug(
                                "Failed to delete file state from Redis",
                                file_id=file_id,
                                error=str(e),
                            )
                elif change_type.lower() == "created":
                    # Check if file_id exists in Redis - if so, it's likely a modification misreported as creation
                    if file_id:
                        stored_state = await self._get_file_state(str(connection.id), file_id)
                        if stored_state:
                            # File exists in Redis - this is a suspected modification
                            logger.debug(
                                "Suspected modification (delta reports 'created' but file exists in Redis)",
                                file_id=file_id,
                                connection_id=str(connection.id),
                            )
                            # Detect modification using metadata comparison
                            normalized_event = await self._detect_file_modification(
                                item, access_token, connection, folder
                            )
                            if normalized_event:
                                # Modification detected and normalized
                                pass
                            else:
                                # Fallback: treat as creation (might be a re-upload)
                                normalized_event = normalize_delta_item(item, change_type, connection, folder)
                        else:
                            # Genuine creation - use delta as-is
                            normalized_event = normalize_delta_item(item, change_type, connection, folder)
                            # Store file state after normalization
                            if file_id and normalized_event:
                                file_meta = item.get("file", {})
                                await self._store_file_state(
                                    str(connection.id),
                                    file_id,
                                    etag=item.get("eTag"),
                                    last_modified=item.get("lastModifiedDateTime"),
                                    version=file_meta.get("version") if file_meta else None,
                                )
                    else:
                        # No file_id - use delta as-is
                        normalized_event = normalize_delta_item(item, change_type, connection, folder)
                elif change_type.lower() == "updated":
                    # Verify modification using metadata comparison
                    if file_id:
                        normalized_event = await self._detect_file_modification(
                            item, access_token, connection, folder
                        )
                        if not normalized_event:
                            # No modification detected or error - use delta as-is
                            normalized_event = normalize_delta_item(item, change_type, connection, folder)
                    else:
                        # No file_id - use delta as-is
                        normalized_event = normalize_delta_item(item, change_type, connection, folder)
                else:
                    # Moved, renamed, copied - use delta as-is
                    normalized_event = normalize_delta_item(item, change_type, connection, folder)
                
                if not normalized_event:
                    continue
                
                if normalized_event.get("event_subtype") not in TRACKED_EVENT_SUBTYPES:
                    continue

                # Store file state for created/updated files (if not already stored)
                if normalized_event.get("event_subtype") in ["file_created", "file_modified"]:
                    file_id = normalized_event.get("file_id")
                    if file_id and not await self._get_file_state(str(connection.id), file_id):
                        # Store state if not already stored
                        await self._store_file_state(
                            str(connection.id),
                            file_id,
                            etag=item.get("eTag"),
                            last_modified=normalized_event.get("timestamp"),
                        )

                normalized.append(normalized_event)
                event_ts = self._parse_timestamp(normalized_event.get("timestamp"))
                if event_ts and (latest_timestamp is None or event_ts > latest_timestamp):
                    latest_timestamp = event_ts

            # Check for deltaLink (for next incremental sync) or nextLink (for pagination)
            delta_link = data.get("@odata.deltaLink")
            if delta_link:
                delta_token = delta_link
                break  # Delta link means we're done with this sync

            next_link = data.get("@odata.nextLink")
            if not next_link:
                break  # No more pages

        return normalized, latest_timestamp, delta_token

    async def _fetch_folder_events_via_children(
        self,
        access_token: str,
        connection: OneDriveConnection,
        folder: OneDriveProtectedFolder,
    ) -> Tuple[List[Dict[str, Any]], Optional[datetime], Optional[str]]:
        """
        Fallback method: Use children endpoint to list files and detect changes by comparing timestamps.
        This is used when delta queries are not available (e.g., personal OneDrive accounts).
        """
        normalized: List[Dict[str, Any]] = []
        latest_timestamp: Optional[datetime] = None

        # Build children endpoint
        # For personal accounts, always use root children and filter client-side
        # Folder-specific endpoints may require SPO license
        endpoint = "https://graph.microsoft.com/v1.0/me/drive/root/children"

        logger.info(
            "OneDrive Graph API Children Request (fallback)",
            connection_id=str(connection.id),
            folder_id=folder.folder_id,
            folder_name=folder.folder_name,
        )

        try:
            async with httpx.AsyncClient() as client:
                # Get all children (files and folders)
                # Use smaller page size to avoid potential limits
                response = await client.get(
                    endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"$top": 200},  # Use smaller page size
                    timeout=30.0,
                )
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as e:
            error_text = e.response.text
            logger.error(
                "Graph API children query failed",
                status_code=e.response.status_code,
                error=error_text,
                folder_id=folder.folder_id,
            )
            # If root children also fails, log and return empty (personal account limitation)
            if "SPO license" in error_text or "BadRequest" in error_text:
                logger.warning(
                    "Root children endpoint also requires SPO license - personal account limitation",
                    folder_id=folder.folder_id,
                )
                return [], latest_timestamp, None
            raise

        items = data.get("value", [])
        baseline_timestamp = folder.last_seen_timestamp

        for item in items:
            # Filter to only include items from the protected folder
            if folder.folder_id != "root":
                parent_ref = item.get("parentReference", {})
                item_parent_id = parent_ref.get("id")
                
                # Match if parent ID matches folder_id (item is directly in the folder)
                # OR if the item itself is the folder
                if item_parent_id != folder.folder_id and item.get("id") != folder.folder_id:
                    # For nested items, check if the path contains our folder
                    item_path = parent_ref.get("path", "")
                    if not item_path or f"/{folder.folder_name}" not in item_path:
                        continue
            # Skip folders - we only track files
            if item.get("folder") and not item.get("file"):
                continue

            # Check if this file was modified after our baseline
            last_modified_str = item.get("lastModifiedDateTime")
            if not last_modified_str:
                continue

            try:
                last_modified = datetime.fromisoformat(last_modified_str.replace("Z", "+00:00"))
                last_modified_naive = self._as_naive_utc(last_modified)

                # If we have a baseline, only process files modified after it
                if baseline_timestamp and last_modified_naive <= baseline_timestamp:
                    continue

                # Determine change type: if createdDateTime and lastModifiedDateTime are close, it's a creation
                created_str = item.get("createdDateTime")
                change_type = "updated"  # Default to updated
                
                if created_str:
                    try:
                        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        time_diff = abs((last_modified - created).total_seconds())
                        if time_diff <= 60.0:
                            change_type = "created"
                    except (ValueError, AttributeError):
                        pass

                # Normalize the item to DLP event format
                normalized_event = normalize_delta_item(item, change_type, connection, folder)

                if normalized_event.get("event_subtype") not in TRACKED_EVENT_SUBTYPES:
                    continue

                normalized.append(normalized_event)
                if latest_timestamp is None or last_modified_naive > latest_timestamp:
                    latest_timestamp = last_modified_naive

            except (ValueError, AttributeError) as e:
                logger.warning(
                    "Failed to parse timestamp for item",
                    item_id=item.get("id"),
                    error=str(e),
                )
                continue

        # No delta token for children endpoint - return None
        return normalized, latest_timestamp, None

    async def _get_file_state(
        self, connection_id: str, file_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve stored file state from Redis.
        
        Returns:
            Dict with keys: etag, last_modified, version, or None if not found/unavailable
        """
        if not self.redis_client:
            return None
        
        try:
            key = f"onedrive:file_state:{connection_id}:{file_id}"
            value = await self.redis_client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.warning(
                "Failed to get file state from Redis",
                connection_id=connection_id,
                file_id=file_id,
                error=str(e),
            )
            return None

    async def _store_file_state(
        self,
        connection_id: str,
        file_id: str,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
        version: Optional[str] = None,
    ) -> bool:
        """
        Store file state in Redis.
        
        Args:
            connection_id: OneDrive connection ID
            file_id: File ID from Graph API
            etag: File ETag (changes when content changes)
            last_modified: Last modified timestamp
            version: File version (if available)
        
        Returns:
            True if stored successfully, False otherwise
        """
        if not self.redis_client:
            return False
        
        try:
            key = f"onedrive:file_state:{connection_id}:{file_id}"
            state = {
                "etag": etag,
                "last_modified": last_modified,
                "version": version,
            }
            # Store with 90 day TTL (7776000 seconds)
            await self.redis_client.setex(key, 7776000, json.dumps(state))
            return True
        except Exception as e:
            logger.warning(
                "Failed to store file state in Redis",
                connection_id=connection_id,
                file_id=file_id,
                error=str(e),
            )
            return False

    async def _fetch_file_metadata(
        self, access_token: str, file_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch current file metadata from Graph API.
        
        Args:
            access_token: OAuth access token
            file_id: File ID from Graph API
        
        Returns:
            Dict with file metadata (eTag, lastModifiedDateTime, version, etc.) or None on error
        """
        try:
            endpoint = f"https://graph.microsoft.com/v1.0/me/drive/items/{file_id}"
            params = {
                "$select": "id,name,eTag,lastModifiedDateTime,fileSystemInfo,createdDateTime"
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                    params=params,
                    timeout=10.0,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                # File not found - treat as deletion
                logger.debug("File not found in Graph API", file_id=file_id)
            else:
                logger.warning(
                    "Failed to fetch file metadata",
                    file_id=file_id,
                    status_code=e.response.status_code,
                    error=e.response.text[:200],
                )
            return None
        except Exception as e:
            logger.warning(
                "Error fetching file metadata",
                file_id=file_id,
                error=str(e),
            )
            return None

    async def _detect_file_modification(
        self,
        delta_item: Dict[str, Any],
        access_token: str,
        connection: OneDriveConnection,
        folder: OneDriveProtectedFolder,
    ) -> Optional[Dict[str, Any]]:
        """
        Detect if a file modification occurred by comparing current state with stored state.
        
        Args:
            delta_item: Delta item from Graph API
            access_token: OAuth access token
            connection: OneDriveConnection instance
            folder: OneDriveProtectedFolder instance
        
        Returns:
            Normalized event dict with event_subtype="file_modified" if modification detected,
            None otherwise
        """
        file_id = delta_item.get("id")
        if not file_id:
            return None
        
        # Fetch current file metadata
        current_metadata = await self._fetch_file_metadata(access_token, file_id)
        if not current_metadata:
            # File not found - might be a deletion, let delta handle it
            return None
        
        current_etag = current_metadata.get("eTag")
        current_last_modified = current_metadata.get("lastModifiedDateTime")
        
        # Get stored state
        stored_state = await self._get_file_state(str(connection.id), file_id)
        
        if stored_state:
            # File was seen before - check if ETag changed
            stored_etag = stored_state.get("etag")
            if current_etag and stored_etag and current_etag != stored_etag:
                # ETag changed - real modification
                logger.debug(
                    "File modification detected via ETag change",
                    file_id=file_id,
                    old_etag=stored_etag,
                    new_etag=current_etag,
                )
                # Update delta item with current metadata for accurate normalization
                delta_item["eTag"] = current_etag
                delta_item["lastModifiedDateTime"] = current_last_modified
                normalized_event = normalize_delta_item(
                    delta_item, "updated", connection, folder
                )
                # Ensure it's marked as modification
                normalized_event["event_subtype"] = "file_modified"
                normalized_event["change_type"] = "updated"
                # Store updated state
                await self._store_file_state(
                    str(connection.id),
                    file_id,
                    etag=current_etag,
                    last_modified=current_last_modified,
                )
                return normalized_event
            elif current_last_modified and stored_state.get("last_modified"):
                # ETag same but timestamp changed - metadata-only change, still log as modification
                stored_last_modified = stored_state.get("last_modified")
                if current_last_modified != stored_last_modified:
                    logger.debug(
                        "File metadata change detected",
                        file_id=file_id,
                        old_timestamp=stored_last_modified,
                        new_timestamp=current_last_modified,
                    )
                    delta_item["eTag"] = current_etag
                    delta_item["lastModifiedDateTime"] = current_last_modified
                    normalized_event = normalize_delta_item(
                        delta_item, "updated", connection, folder
                    )
                    normalized_event["event_subtype"] = "file_modified"
                    normalized_event["change_type"] = "updated"
                    await self._store_file_state(
                        str(connection.id),
                        file_id,
                        etag=current_etag,
                        last_modified=current_last_modified,
                    )
                    return normalized_event
        else:
            # File not in Redis - first time seeing it, but delta says "updated"
            # This might be a modification that happened before we started tracking
            # Store state and treat as modification
            logger.debug(
                "File not in Redis but delta reports update - treating as modification",
                file_id=file_id,
            )
            await self._store_file_state(
                str(connection.id),
                file_id,
                etag=current_etag,
                last_modified=current_last_modified,
            )
            delta_item["eTag"] = current_etag
            delta_item["lastModifiedDateTime"] = current_last_modified
            normalized_event = normalize_delta_item(
                delta_item, "updated", connection, folder
            )
            normalized_event["event_subtype"] = "file_modified"
            normalized_event["change_type"] = "updated"
            return normalized_event
        
        return None

    async def _persist_event(self, normalized_event: Dict[str, Any]) -> None:
        """
        Run event through EventProcessor and persist it to MongoDB.
        """
        if await self._is_duplicate(normalized_event["event_id"]):
            logger.debug("Skipping duplicate OneDrive event", event_id=normalized_event["event_id"])
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
            "OneDrive event matched policies",
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
                "id": f"onedrive-{event['connection_id']}",
                "name": "OneDrive Cloud",
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
                "ingest_source": "onedrive",
                "folder_id": event["folder_id"],
                "protected_folder_id": event.get("protected_folder_id"),
                "connection_id": event["connection_id"],
            },
            "tags": ["onedrive", "cloud"],
            "user": {"email": event.get("user_email", "unknown@onedrive")},
        }

        payload.setdefault("file", {})
        payload["file"]["path"] = event.get("folder_path")
        payload["file"]["name"] = event.get("file_name")
        payload["file"]["id"] = event.get("file_id")
        payload["file"]["size"] = event.get("file_size")
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
            "description": event.get("description", "OneDrive file activity"),
            "severity": processed.get("event", {}).get("severity", event["severity"]),
            "source": event["source"],
            "agent_id": f"onedrive-{event['connection_id']}",
            "user_email": event.get("user_email", "unknown@onedrive"),
            "classification_score": 0.0,
            "classification_labels": [],
            "action_taken": processed.get("event", {}).get("action", event.get("action", "logged")),
            "file_path": event.get("folder_path"),
            "file_name": event.get("file_name"),
            "file_id": event.get("file_id"),
            "file_size": event.get("file_size"),
            "mime_type": event.get("mime_type"),
            "folder_id": event.get("folder_id"),
            "protected_folder_id": event.get("protected_folder_id"),
            "folder_name": event.get("folder_name"),
            "folder_path": event.get("folder_path"),
            "blocked": False,
            "details": {
                "onedrive_event_id": event.get("onedrive_event_id"),
                "change_type": event.get("change_type"),
                "etag": event.get("etag"),
                "version": event.get("version"),
                "raw_delta_item": event.get("details"),
            },
            "matched_policies": processed.get("matched_policies", []),
            "policy_action_summaries": processed.get("policy_action_summaries", []),
            "metadata": metadata,
            "tags": processed.get("tags", ["onedrive"]),
            "policy_version": processed.get("policy_version"),
        }

