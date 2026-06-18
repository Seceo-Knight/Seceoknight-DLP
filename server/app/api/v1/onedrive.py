"""
OneDrive OAuth API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status, Body
from fastapi.responses import HTMLResponse
from sqlalchemy import select, func
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.onedrive import OneDriveConnection, OneDriveProtectedFolder
from app.models.user import User
from app.services.onedrive_oauth import OneDriveOAuthService
from app.tasks.onedrive_polling_tasks import poll_onedrive_activity


router = APIRouter(prefix="/onedrive", tags=["OneDrive"])


class OneDriveConnectResponse(BaseModel):
    auth_url: str
    state: str


class OneDriveConnectionResponse(BaseModel):
    id: UUID
    connection_name: str | None = None
    microsoft_user_email: str | None = None
    status: str
    last_polled_at: datetime | None = None
    last_delta_token: str | None = None
    scopes: List[str] | None = None
    monitoring_since: datetime | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class OneDriveConnectionStatusResponse(BaseModel):
    id: UUID
    status: str
    last_polled_at: datetime | None = None
    last_delta_token: str | None = None
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


class OneDrivePollResponse(BaseModel):
    status: str
    task_id: str | None = None
    message: str | None = None


@router.post("/connect", response_model=OneDriveConnectResponse)
async def initiate_onedrive_connect(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("ANALYST")),
):
    """
    Generate Microsoft OAuth URL for the authenticated analyst/admin user.
    """
    service = OneDriveOAuthService(db)
    return await service.initiate_oauth(current_user.id)


@router.get("/callback", response_class=HTMLResponse)
async def onedrive_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """
    OAuth callback endpoint invoked by Microsoft. Completes account linking.
    """
    service = OneDriveOAuthService(db)
    connection = await service.handle_oauth_callback(code=code, state=state)

    # Simple success page so users know they can close the tab
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>OneDrive Connected</title>
      <style>
        body {{
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #020617;
          color: #e5e7eb;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          margin: 0;
        }}
        .card {{
          background: #020617;
          border: 1px solid #1f2937;
          border-radius: 0.75rem;
          padding: 2rem 2.5rem;
          max-width: 480px;
          text-align: center;
          box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }}
        h1 {{
          font-size: 1.5rem;
          margin-bottom: 0.75rem;
        }}
        p {{
          margin: 0.25rem 0;
          color: #9ca3af;
        }}
        .email {{
          color: #e5e7eb;
          font-weight: 600;
        }}
        .hint {{
          margin-top: 1rem;
          font-size: 0.9rem;
          color: #9ca3af;
        }}
      </style>
    </head>
    <body>
      <div class="card">
        <h1>OneDrive connection successful</h1>
        <p>Your account <span class="email">{connection.microsoft_user_email or ""}</span> is now linked.</p>
        <p class="hint">You can safely close this tab and return to the SeceoKnight dashboard.</p>
      </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=200)


@router.get("/connections", response_model=List[OneDriveConnectionResponse])
async def list_onedrive_connections(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List OneDrive connections owned by the current user.
    """
    service = OneDriveOAuthService(db)
    connections = await service.list_connections(current_user.id)
    return connections


@router.get("/connections/{connection_id}/folders")
async def list_onedrive_folders(
    connection_id: UUID,
    parent_id: str = "root",
    page_token: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List folders within a specific OneDrive connection.
    Used for selecting protected folders.
    """
    service = OneDriveOAuthService(db)
    return await service.list_folders(
        user_id=current_user.id,
        connection_id=connection_id,
        parent_id=parent_id,
        page_token=page_token,
    )


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_onedrive_connection(
    connection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Remove a OneDrive connection and revoke stored tokens.
    """
    service = OneDriveOAuthService(db)
    await service.delete_connection(current_user.id, connection_id)
    return None


@router.get(
    "/connections/{connection_id}/status",
    response_model=OneDriveConnectionStatusResponse,
)
async def get_onedrive_connection_status(
    connection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve connection health info (status, last polled, delta token, errors).
    """
    service = OneDriveOAuthService(db)
    connection = await service.get_connection_status(current_user.id, connection_id)
    return connection


@router.get(
    "/connections/{connection_id}/protected-folders",
    response_model=List[ProtectedFolderStatus],
)
async def get_onedrive_protected_folders(
    connection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = OneDriveOAuthService(db)
    folders = await service.list_protected_folders(current_user.id, connection_id)
    return folders


@router.post("/connections/{connection_id}/baseline")
async def update_onedrive_baseline(
    connection_id: UUID,
    payload: BaselineUpdateRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = OneDriveOAuthService(db)
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


@router.post("/poll", response_model=OneDrivePollResponse)
async def trigger_onedrive_poll(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("ANALYST")),
):
    """
    Manually trigger OneDrive polling via Celery if folders are configured.
    """
    stmt = select(func.count(OneDriveProtectedFolder.id))
    result = await db.execute(stmt)
    folder_count = result.scalar() or 0
    if folder_count == 0:
        return OneDrivePollResponse(
            status="skipped",
            message="No OneDrive protected folders configured.",
        )

    task = poll_onedrive_activity.delay()
    return OneDrivePollResponse(
        status="queued",
        task_id=task.id,
        message="OneDrive polling task enqueued.",
    )


