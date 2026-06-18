"""
Utilities for normalizing OneDrive Graph API delta events.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.models.onedrive import OneDriveConnection, OneDriveProtectedFolder

# Map Graph API change types to DLP event subtypes
# Graph API delta returns items with @microsoft.graph.changeType
ACTION_MAP: Dict[str, Tuple[str, str]] = {
    "created": ("file_created", "medium"),
    "updated": ("file_modified", "medium"),
    "deleted": ("file_deleted", "high"),
    "moved": ("file_moved", "high"),
    "renamed": ("file_moved", "high"),  # Graph API treats rename as move
    "copied": ("file_copied", "high"),  # If detectable
}

TRACKED_EVENT_SUBTYPES = {
    "file_created",
    "file_modified",
    "file_deleted",
    "file_moved",
    "file_copied",
    # Note: file_downloaded is NOT available without M365 subscription
}


def normalize_delta_item(
    delta_item: Dict[str, Any],
    change_type: str,
    connection: OneDriveConnection,
    folder: OneDriveProtectedFolder,
) -> Dict[str, Any]:
    """
    Convert a Graph API delta item into the internal event schema.
    
    Args:
        delta_item: The item from Graph API delta response
        change_type: The change type from @microsoft.graph.changeType
        connection: OneDriveConnection instance
        folder: OneDriveProtectedFolder instance
    """
    # If Graph marks the item as deleted, treat it as such regardless of changeType
    if delta_item.get("deleted") is not None:
        change_type = "deleted"

    # Improve change type detection: if createdDateTime and lastModifiedDateTime are close,
    # it's likely a file creation, not a modification
    normalized_change_type = _improve_change_type_detection(delta_item, change_type)
    event_subtype, severity = _determine_action(normalized_change_type)
    
    # Extract file metadata from delta item
    file_meta = _extract_file_metadata(delta_item)
    timestamp = _extract_timestamp(delta_item)
    
    # Extract user email (from createdBy or lastModifiedBy)
    user_email = _extract_user_email(delta_item)
    
    # Extract ETag and version for modification tracking
    etag = delta_item.get("eTag")
    file_info = delta_item.get("file", {})
    version = file_info.get("version") if file_info else None

    event_id = _build_event_id(
        item_id=delta_item.get("id"),
        connection_id=str(connection.id),
        folder_internal_id=str(folder.id),
        folder_drive_id=folder.folder_id or "",
        file_id=file_meta.get("file_id") or "",
        file_name=file_meta.get("file_name") or "",
        user_email=user_email or "",
        event_subtype=event_subtype or "",
        timestamp=timestamp or "",
        change_type=normalized_change_type,
    )

    # Build a descriptive message based on the action and file name
    file_name = file_meta.get("file_name") or "Unknown file"
    action_label = event_subtype.replace("_", " ").title() if event_subtype else "File activity"
    description = f"{action_label}: {file_name}"
    
    return {
        "event_id": event_id,
        "source": "onedrive_cloud",
        "event_type": "file",
        "event_subtype": event_subtype,
        "severity": severity,
        "action": "logged",
        "timestamp": timestamp,
        "user_email": user_email,
        "file_path": folder.folder_path or folder.folder_name or "OneDrive",
        "file_name": file_meta.get("file_name"),
        "file_id": file_meta.get("file_id"),
        "file_size": file_meta.get("file_size"),
        "mime_type": file_meta.get("mime_type"),
        "owner": file_meta.get("owner"),
        "connection_id": str(connection.id),
        "folder_id": folder.folder_id,
        "protected_folder_id": str(folder.id),
        "folder_name": folder.folder_name,
        "folder_path": folder.folder_path,
        "onedrive_event_id": delta_item.get("id"),
        "change_type": normalized_change_type,  # Use improved change type
        "description": description,  # Add descriptive message
        "etag": etag,  # ETag for modification detection
        "version": version,  # File version (if available)
        "details": delta_item,
    }


def _improve_change_type_detection(delta_item: Dict[str, Any], change_type: str) -> str:
    """
    Improve change type detection by comparing createdDateTime and lastModifiedDateTime.
    
    Graph API delta queries often return 'updated' for files that were actually just created,
    especially during initial sync. If createdDateTime and lastModifiedDateTime are within
    5 seconds of each other, treat it as a creation event.
    """
    if change_type.lower() != "updated":
        return change_type
    
    created_dt = delta_item.get("createdDateTime")
    modified_dt = delta_item.get("lastModifiedDateTime")
    
    if not created_dt or not modified_dt:
        return change_type
    
    try:
        from datetime import datetime
        created = datetime.fromisoformat(created_dt.replace("Z", "+00:00"))
        modified = datetime.fromisoformat(modified_dt.replace("Z", "+00:00"))
        
        # If created and modified times are within 60 seconds, it's likely a creation
        time_diff = abs((modified - created).total_seconds())
        if time_diff <= 60.0:
            return "created"
    except (ValueError, AttributeError):
        pass
    
    return change_type


def _determine_action(change_type: str) -> Tuple[str, str]:
    """Map Graph API change type to DLP event subtype and severity."""
    return ACTION_MAP.get(change_type.lower(), ("file_activity", "medium"))


def _extract_user_email(delta_item: Dict[str, Any]) -> str:
    """Extract user email from delta item (createdBy or lastModifiedBy)."""
    # Try lastModifiedBy first (most recent action)
    last_modified = delta_item.get("lastModifiedBy", {})
    if last_modified:
        user = last_modified.get("user", {})
        if user:
            return user.get("mail") or user.get("userPrincipalName") or "unknown@onedrive"
    
    # Fallback to createdBy
    created_by = delta_item.get("createdBy", {})
    if created_by:
        user = created_by.get("user", {})
        if user:
            return user.get("mail") or user.get("userPrincipalName") or "unknown@onedrive"
    
    return "unknown@onedrive"


def _extract_file_metadata(delta_item: Dict[str, Any]) -> Dict[str, Any]:
    """Extract file metadata from Graph API delta item."""
    file_info = delta_item.get("file", {})
    return {
        "file_name": delta_item.get("name"),
        "file_id": delta_item.get("id"),
        "file_size": delta_item.get("size"),
        "mime_type": file_info.get("mimeType") if file_info else None,
        "owner": _extract_owner(delta_item),
        "etag": delta_item.get("eTag"),
        "version": file_info.get("version") if file_info else None,
    }


def _extract_owner(delta_item: Dict[str, Any]) -> Optional[str]:
    """Extract file owner from delta item."""
    created_by = delta_item.get("createdBy", {})
    if created_by:
        user = created_by.get("user", {})
        if user:
            return user.get("displayName") or user.get("mail") or user.get("userPrincipalName")
    return None


def _extract_timestamp(delta_item: Dict[str, Any]) -> str:
    """Extract timestamp from delta item (lastModifiedDateTime or createdDateTime)."""
    # Prefer lastModifiedDateTime (when file was changed)
    timestamp = delta_item.get("lastModifiedDateTime")
    if timestamp:
        return _ensure_iso_z(timestamp)
    
    # Fallback to createdDateTime
    timestamp = delta_item.get("createdDateTime")
    if timestamp:
        return _ensure_iso_z(timestamp)
    
    # Default to current time
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _build_event_id(
    *,
    item_id: Optional[str],
    connection_id: str,
    folder_internal_id: str,
    folder_drive_id: str,
    file_id: str,
    file_name: str,
    user_email: str,
    event_subtype: str,
    timestamp: str,
    change_type: Optional[str] = None,
) -> str:
    """
    Build deterministic event ID for deduplication.
    
    IMPORTANT: Include change_type and timestamp in the ID to ensure modifications
    create unique event IDs (same file can be modified multiple times).
    """
    if item_id:
        # Include change_type and timestamp to make modifications unique
        # Format: onedrive-{item_id}-{change_type}-{timestamp_hash}
        # This ensures each modification creates a new event
        timestamp_hash = str(uuid.uuid5(uuid.NAMESPACE_URL, timestamp))[:8]
        change_suffix = change_type or event_subtype or "unknown"
        return f"onedrive-{item_id}-{change_suffix}-{timestamp_hash}"

    dedupe_key = "|".join(
        [
            connection_id,
            folder_internal_id,
            folder_drive_id,
            file_id,
            file_name,
            user_email,
            event_subtype,
            change_type or "unknown",
            timestamp,
        ]
    )
    derived = uuid.uuid5(uuid.NAMESPACE_URL, dedupe_key)
    return f"onedrive-{derived}"


def _ensure_iso_z(value: str) -> str:
    """Ensure timestamp is in ISO format with Z suffix."""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


