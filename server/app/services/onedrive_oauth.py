"""
OneDrive OAuth service for connecting user accounts.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from uuid import UUID
import secrets

import structlog
import httpx
from fastapi import HTTPException, status
from msal import ConfidentialClientApplication
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import CacheService, get_cache
from app.core.config import settings
from app.models.onedrive import OneDriveConnection, OneDriveProtectedFolder


logger = structlog.get_logger(__name__)


class OneDriveOAuthService:
    """
    Handles Microsoft OAuth flow, token storage, and connection management.
    """

    AUTHORITY_BASE = "https://login.microsoftonline.com"
    # Use Graph data scopes only; MSAL will automatically add OpenID scopes as needed.
    # Including reserved scopes like "offline_access" directly can cause
    # "API does not accept frozenset({'profile', 'openid', 'offline_access'})"
    # validation errors in some environments.
    SCOPES: Sequence[str] = (
        "Files.Read.All",
        "User.Read",
    )
    STATE_CACHE_PREFIX = "onedrive:oauth:state:"
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

        if not settings.ONEDRIVE_CLIENT_ID or not settings.ONEDRIVE_CLIENT_SECRET:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OneDrive OAuth is not configured. Provide ONEDRIVE_CLIENT_ID and ONEDRIVE_CLIENT_SECRET env vars",
            )

        if not settings.ONEDRIVE_REDIRECT_URI:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OneDrive OAuth redirect URI missing. Set ONEDRIVE_REDIRECT_URI",
            )

        # Use "consumers" for personal Microsoft accounts to avoid SPO license errors
        # "common" allows both work/school and personal, but personal accounts may hit SPO license issues
        # "consumers" specifically targets personal accounts
        tenant_id = settings.ONEDRIVE_TENANT_ID or "consumers"
        authority = f"{self.AUTHORITY_BASE}/{tenant_id}"

        self._client_config_cache = {
            "client_id": settings.ONEDRIVE_CLIENT_ID,
            "client_secret": settings.ONEDRIVE_CLIENT_SECRET,
            "redirect_uri": settings.ONEDRIVE_REDIRECT_URI,
            "authority": authority,
            "tenant_id": tenant_id,
        }
        return self._client_config_cache

    def get_client_config(self) -> Dict[str, Any]:
        """
        Expose resolved OAuth client config for other services (e.g., polling).
        """
        return self._ensure_oauth_config()

    def _build_msal_app(self) -> ConfidentialClientApplication:
        """Build MSAL ConfidentialClientApplication."""
        config = self._ensure_oauth_config()
        return ConfidentialClientApplication(
            client_id=config["client_id"],
            client_credential=config["client_secret"],
            authority=config["authority"],
        )

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

    async def initiate_oauth(self, user_id: UUID) -> Dict[str, str]:
        """
        Start OAuth flow and return authorization URL + state.
        """
        app = self._build_msal_app()
        config = self._ensure_oauth_config()

        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        await self._store_state(state, {"user_id": str(user_id)})

        # Build authorization URL with full Graph + offline_access scopes
        auth_url = app.get_authorization_request_url(
            scopes=list(self.SCOPES),
            redirect_uri=config["redirect_uri"],
            state=state,
        )

        return {"auth_url": auth_url, "state": state}

    async def handle_oauth_callback(self, code: str, state: str) -> OneDriveConnection:
        """
        Complete OAuth flow, store tokens, and upsert a connection.
        """
        stored_state = await self._pop_state(state)
        if not stored_state:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OAuth state")

        user_id = UUID(stored_state["user_id"])
        tokens = await self._exchange_code_for_tokens(code)
        profile = await self._fetch_user_profile(tokens["access_token"])

        if not profile.get("id"):
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Unable to fetch Microsoft profile")

        connection = await self._upsert_connection(user_id, profile, tokens)
        return connection

    async def _exchange_code_for_tokens(self, code: str) -> Dict[str, Any]:
        """
        Exchange authorization code for Microsoft tokens.
        """
        app = self._build_msal_app()
        config = self._ensure_oauth_config()

        def _fetch() -> Dict[str, Any]:
            result = app.acquire_token_by_authorization_code(
                code=code,
                scopes=list(self.SCOPES),
                redirect_uri=config["redirect_uri"],
            )
            if "error" in result:
                raise ValueError(f"Token acquisition failed: {result.get('error_description', result.get('error'))}")
            return result

        return await asyncio.to_thread(_fetch)

    async def _fetch_user_profile(self, access_token: str) -> Dict[str, Any]:
        """
        Fetch Microsoft account profile using Graph API.
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return response.json()

    async def _upsert_connection(
        self,
        user_id: UUID,
        profile: Dict[str, Any],
        tokens: Dict[str, Any],
    ) -> OneDriveConnection:
        """
        Insert or update OneDriveConnection record with encrypted tokens.
        """
        stmt = select(OneDriveConnection).where(
            OneDriveConnection.user_id == user_id,
            OneDriveConnection.microsoft_user_id == profile["id"],
        )
        result = await self.db.execute(stmt)
        connection = result.scalars().first()

        if not connection:
            connection = OneDriveConnection(
                user_id=user_id,
                microsoft_user_id=profile["id"],
                microsoft_user_email=profile.get("mail") or profile.get("userPrincipalName"),
                tenant_id=profile.get("tenantId"),
                scopes=list(self.SCOPES),
                status="active",
            )
            self.db.add(connection)

        connection.connection_name = profile.get("displayName")
        connection.microsoft_user_email = profile.get("mail") or profile.get("userPrincipalName")
        connection.scopes = list(self.SCOPES)
        connection.status = "active"
        connection.error_message = None

        # Parse token expiry
        expires_in = tokens.get("expires_in", 3600)
        if expires_in:
            connection.token_expiry = datetime.utcnow().replace(tzinfo=None) + timedelta(seconds=expires_in)
        else:
            connection.token_expiry = None

        if tokens.get("access_token"):
            connection.set_access_token(tokens["access_token"])

        refresh_token = tokens.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Microsoft did not return a refresh token. Please re-authorize.",
            )
        connection.set_refresh_token(refresh_token)

        await self.db.commit()
        await self.db.refresh(connection)
        return connection

    async def list_connections(self, user_id: UUID) -> List[OneDriveConnection]:
        stmt = select(OneDriveConnection).where(OneDriveConnection.user_id == user_id).order_by(
            OneDriveConnection.created_at.desc()
        )
        result = await self.db.execute(stmt)
        connections = list(result.scalars().all())

        for connection in connections:
            monitoring_stmt = select(func.min(OneDriveProtectedFolder.last_seen_timestamp)).where(
                OneDriveProtectedFolder.connection_id == connection.id
            )
            monitoring_result = await self.db.execute(monitoring_stmt)
            connection.monitoring_since = monitoring_result.scalar()

        return connections

    async def delete_connection(self, user_id: UUID, connection_id: UUID) -> None:
        connection = await self._get_user_connection(user_id, connection_id)
        await self.db.delete(connection)
        await self.db.commit()

    async def get_connection_status(self, user_id: UUID, connection_id: UUID) -> OneDriveConnection:
        return await self._get_user_connection(user_id, connection_id)

    async def _get_user_connection(self, user_id: UUID, connection_id: UUID) -> OneDriveConnection:
        stmt = select(OneDriveConnection).where(
            OneDriveConnection.id == connection_id,
            OneDriveConnection.user_id == user_id,
        )
        result = await self.db.execute(stmt)
        connection = result.scalars().first()
        if not connection:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
        return connection

    async def list_protected_folders(self, user_id: UUID, connection_id: UUID) -> List[OneDriveProtectedFolder]:
        await self._get_user_connection(user_id, connection_id)
        stmt = select(OneDriveProtectedFolder).where(OneDriveProtectedFolder.connection_id == connection_id)
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

        stmt = select(OneDriveProtectedFolder).where(OneDriveProtectedFolder.connection_id == connection_id)
        if folder_ids:
            stmt = stmt.where(OneDriveProtectedFolder.folder_id.in_(folder_ids))

        result = await self.db.execute(stmt)
        folders = list(result.scalars().all())

        if not folders:
            return 0, self._normalize_baseline_time(start_time)

        baseline_time = self._normalize_baseline_time(start_time)
        updated = 0
        for folder in folders:
            folder.last_seen_timestamp = baseline_time
            folder.delta_token = None  # Reset delta token when resetting baseline
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
        List folders in a OneDrive connection using Graph API.
        """
        connection = await self._get_user_connection(user_id, connection_id)

        if connection.is_token_expired():
            connection = await self.refresh_access_token(connection)

        access_token = connection.get_access_token()
        if not access_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No access token available")

        # Build Graph API endpoint
        if parent_id == "root":
            endpoint = "https://graph.microsoft.com/v1.0/me/drive/root/children"
        else:
            endpoint = f"https://graph.microsoft.com/v1.0/me/drive/items/{parent_id}/children"

        # Basic params for listing children. Some consumer accounts/endpoints
        # are picky about $filter/$orderby combinations, so we fetch a page
        # and filter client-side to avoid 400 errors from Graph.
        params = {
            "$top": 50,
        }
        if page_token:
            params["$skiptoken"] = page_token

        async def _fetch_folders() -> Dict[str, Any]:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                    params=params,
                )
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    # Log and surface a cleaner error up to the API layer
                    error_body = exc.response.text
                    logger.warning(
                        "OneDrive list folders failed",
                        status_code=exc.response.status_code,
                        url=str(exc.request.url),
                        body=error_body,
                    )
                    
                    # Check for specific Graph API errors
                    try:
                        error_json = exc.response.json()
                        error_msg = error_json.get("error", {}).get("message", "")
                        if "SPO license" in error_msg or "does not have a SPO license" in error_msg:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Your Microsoft account does not have OneDrive/SharePoint Online access. Personal OneDrive accounts may have limitations. Please ensure your account has OneDrive enabled.",
                            ) from exc
                    except (ValueError, KeyError):
                        pass  # Fall through to generic error
                    
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Failed to list OneDrive folders: {error_body[:200]}",
                    ) from exc

                data = response.json()

                # Transform to match Google Drive format for frontend compatibility
                files = []
                for item in data.get("value", []):
                    if item.get("folder"):  # Only folders
                        files.append({
                            "id": item["id"],
                            "name": item["name"],
                            "mimeType": "application/vnd.google-apps.folder",  # For compatibility
                            "iconLink": None,  # Graph API doesn't provide icon links
                        })

                return {
                    "files": files,
                    "nextPageToken": data.get("@odata.nextLink"),  # Use nextLink as page token
                }

        return await _fetch_folders()

    async def refresh_access_token(self, connection: OneDriveConnection) -> OneDriveConnection:
        """
        Refresh Microsoft access token if expired.
        """
        refresh_token = connection.get_refresh_token()
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Connection lacks refresh token")

        app = self._build_msal_app()

        def _refresh() -> Dict[str, Any]:
            result = app.acquire_token_by_refresh_token(
                refresh_token=refresh_token,
                scopes=list(self.SCOPES),
            )
            if "error" in result:
                raise ValueError(f"Token refresh failed: {result.get('error_description', result.get('error'))}")
            return result

        tokens = await asyncio.to_thread(_refresh)

        if tokens.get("access_token"):
            connection.set_access_token(tokens["access_token"])
        if tokens.get("refresh_token"):
            connection.set_refresh_token(tokens["refresh_token"])

        expires_in = tokens.get("expires_in", 3600)
        if expires_in:
            connection.token_expiry = datetime.utcnow().replace(tzinfo=None) + timedelta(seconds=expires_in)

        connection.status = "active"
        connection.error_message = None

        await self.db.commit()
        await self.db.refresh(connection)
        return connection

