"""
Google Drive OAuth service for connecting user accounts.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from uuid import UUID
import json
import os

import structlog
from fastapi import HTTPException, status
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import CacheService, get_cache
from app.core.config import settings
from app.models.google_drive import GoogleDriveConnection, GoogleDriveProtectedFolder


logger = structlog.get_logger(__name__)


class GoogleDriveOAuthService:
    """
    Handles Google OAuth flow, token storage, and connection management.
    """

    AUTH_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    SCOPES: Sequence[str] = (
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        "https://www.googleapis.com/auth/drive.activity.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "openid",
    )
    STATE_CACHE_PREFIX = "gdrive:oauth:state:"
    STATE_TTL_SECONDS = 600

    def __init__(
        self,
        db: AsyncSession,
        state_store: Optional[Any] = None,
    ) -> None:
        self.db = db
        self.state_store = state_store or self._init_cache_store()
        self._fallback_state: Dict[str, Dict[str, Any]] = {} if self.state_store is None else {}
        self._client_config_cache: Optional[Dict[str, Any]] = None

    def _init_cache_store(self) -> Optional[CacheService]:
        try:
            return CacheService(get_cache())
        except RuntimeError:
            logger.warning("Redis cache not initialized; using in-memory OAuth state store")
            return None

    def _ensure_oauth_config(self) -> Dict[str, Any]:
        if self._client_config_cache:
            return self._client_config_cache

        config = self._load_client_config()
        if not config:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Google OAuth is not configured. Provide GOOGLE_CLIENT_* env vars or credentials.json",
            )

        if not config.get("redirect_uri"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Google OAuth redirect URI missing. Set GOOGLE_REDIRECT_URI or update credentials.json",
            )

        self._client_config_cache = config
        return config

    def get_client_config(self) -> Dict[str, Any]:
        """
        Expose resolved OAuth client config for other services (e.g., polling).
        """
        return self._ensure_oauth_config()

    def _load_client_config(self) -> Optional[Dict[str, Any]]:
        if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
            redirect_uri = settings.GOOGLE_REDIRECT_URI
            redirect_uris = [redirect_uri] if redirect_uri else []
            return {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "project_id": "seceoknight",
                "redirect_uri": redirect_uri,
                "redirect_uris": redirect_uris,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }

        file_config = self._load_config_from_file()
        if file_config:
            return file_config
        return None

    def _load_config_from_file(self) -> Optional[Dict[str, Any]]:
        path = settings.GOOGLE_OAUTH_CREDENTIALS_PATH
        if not path:
            return None

        resolved = path if os.path.isabs(path) else os.path.join(os.getcwd(), path)
        if not os.path.exists(resolved):
            return None

        try:
            with open(resolved, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception as exc:
            logger.error("Failed to read Google credentials file", path=resolved, error=str(exc))
            return None

        payload = raw.get("web") or raw.get("installed") or raw
        redirect_uris = payload.get("redirect_uris") or payload.get("redirectUris") or []
        redirect_uri = settings.GOOGLE_REDIRECT_URI or (redirect_uris[0] if redirect_uris else None)

        return {
            "client_id": payload.get("client_id"),
            "client_secret": payload.get("client_secret"),
            "project_id": payload.get("project_id", "seceoknight"),
            "redirect_uri": redirect_uri,
            "redirect_uris": redirect_uris,
            "auth_uri": payload.get("auth_uri", "https://accounts.google.com/o/oauth2/auth"),
            "token_uri": payload.get("token_uri", "https://oauth2.googleapis.com/token"),
        }

    def _state_key(self, state: str) -> str:
        return f"{self.STATE_CACHE_PREFIX}{state}"

    async def _store_state(self, state: str, payload: Dict[str, Any]) -> None:
        key = self._state_key(state)
        payload["created_at"] = datetime.utcnow().isoformat()
        if self.state_store:
            await self.state_store.set(key, payload, expire=self.STATE_TTL_SECONDS)
        else:
            self._fallback_state[key] = payload

    async def _pop_state(self, state: str) -> Optional[Dict[str, Any]]:
        key = self._state_key(state)
        if self.state_store:
            payload = await self.state_store.get(key)
            if payload:
                await self.state_store.delete(key)
            return payload
        return self._fallback_state.pop(key, None)

    def _build_flow(self) -> Flow:
        config = self._ensure_oauth_config()
        client_config = {
            "web": {
                "client_id": config["client_id"],
                "project_id": config.get("project_id", "seceoknight"),
                "auth_uri": config.get("auth_uri", "https://accounts.google.com/o/oauth2/auth"),
                "token_uri": config.get("token_uri", "https://oauth2.googleapis.com/token"),
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": config["client_secret"],
                "redirect_uris": config.get("redirect_uris") or [config["redirect_uri"]],
            }
        }
        flow = Flow.from_client_config(client_config, scopes=self.SCOPES)
        flow.redirect_uri = config["redirect_uri"]
        return flow

    async def initiate_oauth(self, user_id: UUID) -> Dict[str, str]:
        """
        Start OAuth flow and return authorization URL + state.
        """
        flow = self._build_flow()
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        await self._store_state(state, {"user_id": str(user_id)})
        return {"auth_url": auth_url, "state": state}

    async def handle_oauth_callback(self, code: str, state: str) -> GoogleDriveConnection:
        """
        Complete OAuth flow, store tokens, and upsert a connection.
        """
        stored_state = await self._pop_state(state)
        if not stored_state:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OAuth state")

        user_id = UUID(stored_state["user_id"])
        credentials = await self._exchange_code_for_credentials(code)
        profile = await self._fetch_user_profile(credentials)

        if not profile.get("id"):
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Unable to fetch Google profile")

        connection = await self._upsert_connection(user_id, profile, credentials)
        return connection

    async def _exchange_code_for_credentials(self, code: str) -> Credentials:
        """
        Exchange authorization code for Google credentials.
        """
        flow = self._build_flow()

        def _fetch() -> Credentials:
            flow.fetch_token(code=code)
            return flow.credentials

        return await asyncio.to_thread(_fetch)

    async def _fetch_user_profile(self, credentials: Credentials) -> Dict[str, Any]:
        """
        Fetch Google account profile using OAuth2 API.
        """

        def _call() -> Dict[str, Any]:
            service = build("oauth2", "v2", credentials=credentials, cache_discovery=False)
            return service.userinfo().get().execute()

        return await asyncio.to_thread(_call)

    async def _upsert_connection(
        self,
        user_id: UUID,
        profile: Dict[str, Any],
        credentials: Credentials,
    ) -> GoogleDriveConnection:
        """
        Insert or update GoogleDriveConnection record with encrypted tokens.
        """
        stmt = select(GoogleDriveConnection).where(
            GoogleDriveConnection.user_id == user_id,
            GoogleDriveConnection.google_user_id == profile["id"],
        )
        result = await self.db.execute(stmt)
        connection = result.scalars().first()

        if not connection:
            connection = GoogleDriveConnection(
                user_id=user_id,
                google_user_id=profile["id"],
                google_user_email=profile.get("email"),
                scopes=list(credentials.scopes or self.SCOPES),
                status="active",
            )
            self.db.add(connection)

        connection.connection_name = profile.get("name")
        connection.google_user_email = profile.get("email")
        connection.scopes = list(credentials.scopes or self.SCOPES)
        connection.status = "active"
        connection.error_message = None
        connection.token_expiry = credentials.expiry

        if credentials.token:
            connection.set_access_token(credentials.token)

        refresh_token = credentials.refresh_token or connection.get_refresh_token()
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google did not return a refresh token. Please re-authorize with 'prompt=consent'.",
            )
        connection.set_refresh_token(refresh_token)

        await self.db.commit()
        await self.db.refresh(connection)
        return connection

    async def list_connections(self, user_id: UUID) -> List[GoogleDriveConnection]:
        stmt = select(GoogleDriveConnection).where(GoogleDriveConnection.user_id == user_id).order_by(
            GoogleDriveConnection.created_at.desc()
        )
        result = await self.db.execute(stmt)
        connections = list(result.scalars().all())

        for connection in connections:
            monitoring_stmt = select(func.min(GoogleDriveProtectedFolder.last_seen_timestamp)).where(
                GoogleDriveProtectedFolder.connection_id == connection.id
            )
            monitoring_result = await self.db.execute(monitoring_stmt)
            connection.monitoring_since = monitoring_result.scalar()

        return connections

    async def delete_connection(self, user_id: UUID, connection_id: UUID) -> None:
        connection = await self._get_user_connection(user_id, connection_id)
        await self.db.delete(connection)
        await self.db.commit()

    async def get_connection_status(self, user_id: UUID, connection_id: UUID) -> GoogleDriveConnection:
        return await self._get_user_connection(user_id, connection_id)

    async def _get_user_connection(self, user_id: UUID, connection_id: UUID) -> GoogleDriveConnection:
        stmt = select(GoogleDriveConnection).where(
            GoogleDriveConnection.id == connection_id,
            GoogleDriveConnection.user_id == user_id,
        )
        result = await self.db.execute(stmt)
        connection = result.scalars().first()
        if not connection:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
        return connection

    async def list_protected_folders(self, user_id: UUID, connection_id: UUID) -> List[GoogleDriveProtectedFolder]:
        await self._get_user_connection(user_id, connection_id)
        stmt = select(GoogleDriveProtectedFolder).where(GoogleDriveProtectedFolder.connection_id == connection_id)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def update_folder_baseline(
        self,
        user_id: UUID,
        connection_id: UUID,
        folder_ids: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
    ) -> Tuple[int, datetime]:
        await self._get_user_connection(user_id, connection_id)

        stmt = select(GoogleDriveProtectedFolder).where(GoogleDriveProtectedFolder.connection_id == connection_id)
        if folder_ids:
            stmt = stmt.where(GoogleDriveProtectedFolder.folder_id.in_(folder_ids))

        result = await self.db.execute(stmt)
        folders = list(result.scalars().all())

        if not folders:
            return 0, self._normalize_baseline_time(start_time)

        baseline_time = self._normalize_baseline_time(start_time)
        updated = 0
        for folder in folders:
            folder.last_seen_timestamp = baseline_time
            folder.updated_at = datetime.utcnow()
            updated += 1

        await self.db.commit()
        return updated, baseline_time

    @staticmethod
    def _normalize_baseline_time(start_time: Optional[datetime]) -> datetime:
        if not start_time:
            return datetime.utcnow()
        if start_time.tzinfo is None:
            return start_time
        return start_time.astimezone(timezone.utc).replace(tzinfo=None)

    async def list_folders(
        self,
        user_id: UUID,
        connection_id: UUID,
        parent_id: str = "root",
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List folders in a Google Drive connection.
        """
        connection = await self._get_user_connection(user_id, connection_id)

        if connection.is_token_expired():
            connection = await self.refresh_access_token(connection)

        config = self._ensure_oauth_config()
        credentials = Credentials(
            token=connection.get_access_token(),
            refresh_token=connection.get_refresh_token(),
            token_uri=config.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            scopes=connection.scopes or list(self.SCOPES),
        )

        def _fetch_folders() -> Dict[str, Any]:
            service = build("drive", "v3", credentials=credentials, cache_discovery=False)
            query = f"mimeType = 'application/vnd.google-apps.folder' and '{parent_id}' in parents and trashed = false"
            
            results = service.files().list(
                q=query,
                pageSize=50,
                pageToken=page_token,
                fields="nextPageToken, files(id, name, mimeType, iconLink)",
                orderBy="name"
            ).execute()
            
            return results

        return await asyncio.to_thread(_fetch_folders)

    async def refresh_access_token(self, connection: GoogleDriveConnection) -> GoogleDriveConnection:
        """
        Refresh Google access token if expired.
        """
        refresh_token = connection.get_refresh_token()
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Connection lacks refresh token")

        config = self._ensure_oauth_config()
        credentials = Credentials(
            token=connection.get_access_token(),
            refresh_token=refresh_token,
            token_uri=config.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            scopes=connection.scopes or list(self.SCOPES),
        )
        request = Request()

        await asyncio.to_thread(credentials.refresh, request)

        if credentials.token:
            connection.set_access_token(credentials.token)
        if credentials.refresh_token:
            connection.set_refresh_token(credentials.refresh_token)
        connection.token_expiry = credentials.expiry
        connection.status = "active"
        connection.error_message = None

        await self.db.commit()
        await self.db.refresh(connection)
        return connection

