"""
Google Drive OAuth API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status, Body
from sqlalchemy import select, func
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.google_drive import GoogleDriveConnection, GoogleDriveProtectedFolder
from app.models.user import User
from app.services.google_drive_oauth import GoogleDriveOAuthService
from app.tasks.google_drive_polling_tasks import poll_google_drive_activity


router = APIRouter(prefix="/google-drive", tags=["Google Drive"])


class GoogleDriveConnectResponse(BaseModel):
    auth_url: str
    state: str


class GoogleDriveConnectionResponse(BaseModel):
    id: UUID
    connection_name: str | None = None
    google_user_email: str | None = None
    status: str
    last_polled_at: datetime | None = None
    last_activity_cursor: str | None = None
    scopes: List[str] | None = None
    monitoring_since: datetime | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class GoogleDriveConnectionStatusResponse(BaseModel):
    id: UUID
    status: str
    last_polled_at: datetime | None = None
    last_activity_cursor: str | None = None
    error_message: str | None = None

    class Config:
        from_attributes = True


class ProtectedFolderStatus(BaseModel):
    folder_id: str
    folder_name: str | None = None
    folder_path: str | None = None
    last_seen_timestamp: datetime | None = None

    class Config:
        from_attributes = True


class BaselineUpdateRequest(BaseModel):
    folder_ids: List[str] | None = None
    start_time: datetime | None = None


class GoogleDrivePollResponse(BaseModel):
    status: str
    task_id: str | None = None
    message: str | None = None


@router.post("/connect", response_model=GoogleDriveConnectResponse)
async def initiate_google_drive_connect(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("ANALYST")),
):
    """
    Generate Google OAuth URL for the authenticated analyst/admin user.
    """
    service = GoogleDriveOAuthService(db)
    return await service.initiate_oauth(current_user.id)


@router.get("/callback")
async def google_drive_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """
    OAuth callback endpoint invoked by Google. Completes account linking.
    """
    service = GoogleDriveOAuthService(db)
    connection = await service.handle_oauth_callback(code=code, state=state)
    return {
        "status": "success",
        "connection_id": str(connection.id),
        "google_user_email": connection.google_user_email,
    }


@router.get("/connections", response_model=List[GoogleDriveConnectionResponse])
async def list_google_drive_connections(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List Google Drive connections owned by the current user.
    """
    service = GoogleDriveOAuthService(db)
    connections = await service.list_connections(current_user.id)
    return connections


@router.get("/connections/{connection_id}/folders")
async def list_google_drive_folders(
    connection_id: UUID,
    parent_id: str = "root",
    page_token: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List folders within a specific Google Drive connection.
    Used for selecting protected folders.
    """
    service = GoogleDriveOAuthService(db)
    return await service.list_folders(
        user_id=current_user.id,
        connection_id=connection_id,
        parent_id=parent_id,
        page_token=page_token,
    )


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_google_drive_connection(
    connection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Remove a Google Drive connection and revoke stored tokens.
    """
    service = GoogleDriveOAuthService(db)
    await service.delete_connection(current_user.id, connection_id)
    return None


@router.get(
    "/connections/{connection_id}/status",
    response_model=GoogleDriveConnectionStatusResponse,
)
async def get_google_drive_connection_status(
    connection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve connection health info (status, last polled, cursor, errors).
    """
    service = GoogleDriveOAuthService(db)
    connection = await service.get_connection_status(current_user.id, connection_id)
    return connection


@router.get(
    "/connections/{connection_id}/protected-folders",
    response_model=List[ProtectedFolderStatus],
)
async def get_google_drive_protected_folders(
    connection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = GoogleDriveOAuthService(db)
    folders = await service.list_protected_folders(current_user.id, connection_id)
    return folders


@router.post("/connections/{connection_id}/baseline")
async def update_google_drive_baseline(
    connection_id: UUID,
    payload: BaselineUpdateRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = GoogleDriveOAuthService(db)
    updated, start_time = await service.update_folder_baseline(
        current_user.id,
        connection_id,
        folder_ids=payload.folder_ids,
        start_time=payload.start_time,
    )
    return {
        "status": "success",
        "updated": updated,
        "start_time": start_time,
    }


@router.post("/poll", response_model=GoogleDrivePollResponse)
async def trigger_google_drive_poll(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("ANALYST")),
):
    """
    Manually trigger Google Drive polling via Celery if folders are configured.
    """
    stmt = select(func.count(GoogleDriveProtectedFolder.id))
    result = await db.execute(stmt)
    folder_count = result.scalar() or 0
    if folder_count == 0:
        return GoogleDrivePollResponse(
            status="skipped",
            message="No Google Drive protected folders configured.",
        )

    task = poll_google_drive_activity.delay()
    return GoogleDrivePollResponse(
        status="queued",
        task_id=task.id,
        message="Google Drive polling task enqueued.",
    )

