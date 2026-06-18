"""
Unit tests for Google Drive event normalizer.
"""

import uuid
from datetime import datetime

from app.models.google_drive import GoogleDriveConnection, GoogleDriveProtectedFolder
from app.services.google_drive_event_normalizer import normalize_drive_activity


def build_connection():
    conn = GoogleDriveConnection(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        google_user_id="user-123",
        google_user_email="owner@example.com",
        refresh_token="token",
    )
    conn.set_refresh_token("refresh-token")
    return conn


def build_folder(connection):
    return GoogleDriveProtectedFolder(
        id=uuid.uuid4(),
        connection_id=connection.id,
        folder_id="abc123",
        folder_name="Finance",
        folder_path="My Drive/Finance",
    )


def test_normalize_drive_activity_basic():
    connection = build_connection()
    folder = build_folder(connection)
    activity = {
        "id": "act-1",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "primaryActionDetail": {
            "create": {}
        },
        "actors": [
            {"user": {"emailAddress": "user@example.com"}}
        ],
        "targets": [
            {"driveItem": {"title": "payroll.xlsx", "name": "files/1"}}
        ],
    }

    result = normalize_drive_activity(activity, connection, folder)
    assert result["event_id"] == "gdrive-act-1"
    assert result["severity"] == "medium"
    assert result["user_email"] == "user@example.com"
    assert result["file_name"] == "payroll.xlsx"
    assert result["folder_name"] == "Finance"
    assert result["folder_path"] == "My Drive/Finance"






























