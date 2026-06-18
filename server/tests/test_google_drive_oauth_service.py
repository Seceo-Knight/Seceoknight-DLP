"""
Tests for Google Drive OAuth service.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.user import User, UserRole
from app.services.google_drive_oauth import GoogleDriveOAuthService


class MemoryStateStore:
    """Simple in-memory async store used for tests."""

    def __init__(self) -> None:
        self.store: Dict[str, Dict[str, Any]] = {}

    async def set(self, key: str, value: Dict[str, Any], expire: int | None = None) -> None:
        self.store[key] = value

    async def get(self, key: str) -> Dict[str, Any] | None:
        return self.store.get(key)

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)


class FakeFlow:
    """Minimal Flow stub used to bypass Google SDK network calls."""

    def __init__(self, auth_url: str, state: str) -> None:
        self._auth_url = auth_url
        self._state = state

    def authorization_url(self, **kwargs):
        return self._auth_url, self._state


class DummyCredentials:
    def __init__(self) -> None:
        self.token = "access-token"
        self.refresh_token = "refresh-token"
        self.expiry = datetime.utcnow() + timedelta(hours=1)
        self.scopes = list(GoogleDriveOAuthService.SCOPES)


@pytest.mark.asyncio
async def test_google_drive_oauth_flow(monkeypatch, db_session):
    """Ensure initiate/callback flow inserts a connection record."""
    # Seed a user
    user = User(
        email="driver@example.com",
        hashed_password="hashed",
        full_name="Drive User",
        role=UserRole.ADMIN,
        organization="SeceoKnight",
    )
    db_session.add(user)
    await db_session.commit()

    # Provide fake Google config
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "client-secret")
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", "https://example.com/callback")

    # Build service with memory state store
    state_store = MemoryStateStore()
    service = GoogleDriveOAuthService(db_session, state_store=state_store)

    fake_flow = FakeFlow("https://accounts.google.com/o/oauth2/auth?state=test-state", "test-state")
    monkeypatch.setattr(GoogleDriveOAuthService, "_build_flow", lambda self: fake_flow)

    async def fake_exchange(self, code: str):
        return DummyCredentials()

    async def fake_profile(self, creds):
        return {"id": "google-user-123", "email": "drive.user@example.com", "name": "Drive User"}

    monkeypatch.setattr(GoogleDriveOAuthService, "_exchange_code_for_credentials", fake_exchange)
    monkeypatch.setattr(GoogleDriveOAuthService, "_fetch_user_profile", fake_profile)

    connect_data = await service.initiate_oauth(user.id)
    assert connect_data["state"] == "test-state"
    assert "accounts.google.com" in connect_data["auth_url"]

    connection = await service.handle_oauth_callback(code="sample-code", state="test-state")
    assert connection.google_user_email == "drive.user@example.com"
    assert connection.status == "active"

    stmt = select(User).where(User.id == user.id)
    result = await db_session.execute(stmt)
    assert result.scalars().first() is not None






























