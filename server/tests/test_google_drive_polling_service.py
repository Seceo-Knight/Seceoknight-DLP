"""
Tests for Google Drive polling service.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.models.google_drive import GoogleDriveConnection, GoogleDriveProtectedFolder
from app.models.user import User, UserRole
from app.services.google_drive_oauth import GoogleDriveOAuthService
from app.services.google_drive_polling import GoogleDrivePollingService


class FakeCollection:
    def __init__(self) -> None:
        self.docs = []

    async def find_one(self, query):
        for doc in self.docs:
            if doc["id"] == query.get("id"):
                return doc
        return None

    async def insert_one(self, doc):
        self.docs.append(doc)


class FakeProcessor:
    async def process_event(self, event):
        processed = dict(event)
        processed["matched_policies"] = [
            {
                "policy_id": "policy-1",
                "policy_name": "Test Policy",
                "severity": "medium",
                "priority": 100,
                "matched_rules": [],
            }
        ]
        processed["policy_action_summaries"] = []
        return processed


@pytest.mark.asyncio
async def test_poll_connection_inserts_events(monkeypatch, db_session):
    """Ensure polling inserts new events and updates cursors."""

    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "client")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", "https://example.com/callback")

    user = User(
        email="cloud@example.com",
        hashed_password="hashed",
        full_name="Cloud User",
        role=UserRole.ADMIN,
        organization="SeceoKnight",
    )
    db_session.add(user)
    await db_session.flush()

    connection = GoogleDriveConnection(
        user_id=user.id,
        google_user_id="google-user-1",
        google_user_email="cloud@example.com",
    )
    connection.set_refresh_token("refresh-token")
    connection.set_access_token("access-token")
    db_session.add(connection)
    await db_session.flush()

    folder = GoogleDriveProtectedFolder(
        connection_id=connection.id,
        folder_id="folder-1",
        folder_name="Finance",
        folder_path="My Drive/Finance",
    )
    db_session.add(folder)
    await db_session.commit()
    await db_session.refresh(connection)

    fake_collection = FakeCollection()
    fake_processor = FakeProcessor()

    async def fake_refresh(self, conn):
        return conn

    monkeypatch.setattr(GoogleDriveOAuthService, "refresh_access_token", fake_refresh)

    service = GoogleDrivePollingService(
        db_session,
        events_collection=fake_collection,
        event_processor=fake_processor,
    )

    event_timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    event_timestamp_iso = event_timestamp.isoformat().replace("+00:00", "Z")

    normalized_event = {
        "event_id": "gdrive-activity-1",
        "source": "google_drive_cloud",
        "event_type": "file",
        "event_subtype": "file_created",
        "severity": "medium",
        "action": "logged",
        "timestamp": event_timestamp_iso,
        "user_email": "actor@example.com",
        "file_path": "My Drive/Finance/payroll.xlsx",
        "file_name": "payroll.xlsx",
        "file_id": "files/123",
        "mime_type": "application/vnd.ms-excel",
        "connection_id": str(connection.id),
        "folder_id": folder.folder_id,
        "protected_folder_id": str(folder.id),
        "folder_name": folder.folder_name,
        "folder_path": folder.folder_path,
        "google_event_id": "act-1",
        "details": {"id": "act-1"},
    }

    async def fake_fetch(self, *_args, **_kwargs):
        return [normalized_event], event_timestamp

    monkeypatch.setattr(GoogleDrivePollingService, "_fetch_folder_events", fake_fetch)

    processed = await service.poll_connection(connection)
    assert processed == 1
    assert len(fake_collection.docs) == 1
    assert fake_collection.docs[0]["file_name"] == "payroll.xlsx"

    await db_session.refresh(connection)
    await db_session.refresh(folder)

    assert connection.last_activity_cursor == event_timestamp_iso
    assert folder.last_seen_timestamp == event_timestamp.replace(tzinfo=None)
