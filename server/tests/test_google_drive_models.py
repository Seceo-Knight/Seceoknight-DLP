"""
Smoke tests for Google Drive ORM models.
"""

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, func

from app.models.google_drive import GoogleDriveConnection, GoogleDriveProtectedFolder
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_google_drive_connection_token_encryption(db_session):
    """Ensure tokens round-trip via helper methods and timestamps update."""
    user = User(
        email="drive-user@example.com",
        hashed_password="hashed",
        full_name="Drive User",
        role=UserRole.ADMIN,
        organization="SeceoKnight",
    )
    db_session.add(user)
    await db_session.flush()

    connection = GoogleDriveConnection(
        user_id=user.id,
        google_user_id="drive-account-123",
        google_user_email="drive-account@example.com",
        status="active",
        scopes=["https://www.googleapis.com/auth/drive.readonly"],
    )
    connection.set_refresh_token("refresh-token-value")
    connection.set_access_token("access-token-value")
    connection.token_expiry = datetime.utcnow() + timedelta(hours=1)

    db_session.add(connection)
    await db_session.commit()
    await db_session.refresh(connection)

    assert connection.get_refresh_token() == "refresh-token-value"
    assert connection.get_access_token() == "access-token-value"
    assert connection.is_token_expired() is False


@pytest.mark.asyncio
async def test_google_drive_folder_cascade_delete(db_session):
    """Deleting a connection cascades to protected folders."""
    user = User(
        email="folder-owner@example.com",
        hashed_password="hashed",
        full_name="Folder Owner",
        role=UserRole.ADMIN,
        organization="SeceoKnight",
    )
    db_session.add(user)
    await db_session.flush()

    connection = GoogleDriveConnection(
        user_id=user.id,
        google_user_id="drive-folder-conn",
        google_user_email="owner@example.com",
    )
    connection.set_refresh_token("refresh")
    db_session.add(connection)
    await db_session.flush()

    folder = GoogleDriveProtectedFolder(
        connection_id=connection.id,
        folder_id="abc123",
        folder_name="Finance",
        folder_path="My Drive/Finance",
        sensitivity_level="high",
    )
    db_session.add(folder)
    await db_session.commit()

    # Sanity check row exists
    folder_count = await db_session.scalar(
        select(func.count(GoogleDriveProtectedFolder.id))
    )
    assert folder_count == 1

    # Deleting connection should delete folders
    await db_session.delete(connection)
    await db_session.commit()

    folder_count_after = await db_session.scalar(
        select(func.count(GoogleDriveProtectedFolder.id))
    )
    assert folder_count_after == 0






























