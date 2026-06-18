"""
Utilities for normalizing Google Drive Activity events.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.models.google_drive import GoogleDriveConnection, GoogleDriveProtectedFolder

ACTION_MAP: Dict[str, Tuple[str, str]] = {
    "create": ("file_created", "medium"),
    "upload": ("file_uploaded", "medium"),
    "move": ("file_moved", "high"),
    "copy": ("file_copied", "high"),
    "edit": ("file_modified", "medium"),
    "delete": ("file_deleted", "high"),
    "trash": ("file_trashed", "high"),
    "restore": ("file_restored", "low"),
    "comment": ("file_commented", "low"),
    "download": ("file_downloaded", "high"),
    "share": ("file_shared", "high"),
}

TRACKED_EVENT_SUBTYPES = {
    "file_created",
    "file_uploaded",
    "file_modified",
    "file_deleted",
    "file_trashed",
    "file_restored",
    "file_moved",
    "file_copied",
    "file_downloaded",
}


def normalize_drive_activity(
    activity: Dict[str, Any],
    connection: GoogleDriveConnection,
    folder: GoogleDriveProtectedFolder,
) -> Dict[str, Any]:
    """Convert a Drive Activity resource into the internal event schema."""

    event_subtype, severity = _determine_action(activity)
    actor_email = _extract_actor(activity)
    file_meta = _extract_file_metadata(activity)
    timestamp = _extract_timestamp(activity)

    event_id = _build_event_id(
        activity_id=activity.get("id"),
        connection_id=str(connection.id),
        folder_internal_id=str(folder.id),
        folder_drive_id=folder.folder_id or "",
        file_id=file_meta.get("file_id") or "",
        file_name=file_meta.get("file_name") or "",
        actor_email=actor_email or "",
        event_subtype=event_subtype or "",
        timestamp=timestamp or "",
    )

    return {
        "event_id": event_id,
        "source": "google_drive_cloud",
        "event_type": "file",
        "event_subtype": event_subtype,
        "severity": severity,
        "action": "logged",
        "timestamp": timestamp,
        "user_email": actor_email,
        "file_path": folder.folder_path or folder.folder_name or "Google Drive",
        "file_name": file_meta.get("file_name"),
        "file_id": file_meta.get("file_id"),
        "mime_type": file_meta.get("mime_type"),
        "owner": file_meta.get("owner"),
        "connection_id": str(connection.id),
        "folder_id": folder.folder_id,
        "protected_folder_id": str(folder.id),
        "folder_name": folder.folder_name,
        "folder_path": folder.folder_path,
        "google_event_id": activity.get("id"),
        "details": activity,
    }


def _determine_action(activity: Dict[str, Any]) -> Tuple[str, str]:
    detail = activity.get("primaryActionDetail", {}) or {}
    for key, value in detail.items():
        if key in ACTION_MAP:
            return ACTION_MAP[key]
        if isinstance(value, dict):
            for nested_key in value.keys():
                if nested_key in ACTION_MAP:
                    return ACTION_MAP[nested_key]
    return "file_activity", "medium"


def _extract_actor(activity: Dict[str, Any]) -> str:
    actors = activity.get("actors") or []
    if not actors:
        return "unknown@drive"
    actor = actors[0] or {}
    user = actor.get("user", {}) or {}
    known = user.get("knownUser", {}) or {}
    return (
        known.get("emailAddress")
        or known.get("personName")
        or user.get("emailAddress")
        or "unknown@drive"
    )


def _extract_file_metadata(activity: Dict[str, Any]) -> Dict[str, Any]:
    targets = activity.get("targets") or []
    if not targets:
        return {}
    drive_item = targets[0].get("driveItem") or {}
    return {
        "file_name": drive_item.get("title"),
        "file_id": drive_item.get("name"),
        "mime_type": drive_item.get("mimeType"),
        "owner": _extract_owner(drive_item),
    }


def _extract_owner(drive_item: Dict[str, Any]) -> Optional[str]:
    owner = drive_item.get("owner") or {}
    user = owner.get("user") or {}
    known = user.get("knownUser") or {}
    return known.get("personName")


def _extract_timestamp(activity: Dict[str, Any]) -> str:
    raw = activity.get("timestamp")
    if isinstance(raw, str) and raw:
        return _ensure_iso_z(raw)

    time_range = activity.get("timeRange") or {}
    for key in ("endTime", "startTime"):
        value = time_range.get(key)
        if isinstance(value, str) and value:
            return _ensure_iso_z(value)

    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _build_event_id(
    *,
    activity_id: Optional[str],
    connection_id: str,
    folder_internal_id: str,
    folder_drive_id: str,
    file_id: str,
    file_name: str,
    actor_email: str,
    event_subtype: str,
    timestamp: str,
) -> str:
    if activity_id:
        return f"gdrive-{activity_id}"

    dedupe_key = "|".join(
        [
            connection_id,
            folder_internal_id,
            folder_drive_id,
            file_id,
            file_name,
            actor_email,
            event_subtype,
            timestamp,
        ]
    )
    derived = uuid.uuid5(uuid.NAMESPACE_URL, dedupe_key)
    return f"gdrive-{derived}"


def _ensure_iso_z(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")
