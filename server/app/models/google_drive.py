"""
Google Drive cloud connector models.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional, ClassVar

from cryptography.fernet import Fernet
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    JSON,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.config import settings
from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


def _build_cipher() -> Fernet:
    key_source = settings.ENCRYPTION_KEY if settings.ENCRYPTION_KEY else settings.SECRET_KEY
    digest = hashlib.sha256(key_source.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


class GoogleDriveConnection(Base):
    __tablename__ = "google_drive_connections"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    connection_name = Column(String(255), nullable=True)
    google_user_id = Column(String(255), nullable=False)
    google_user_email = Column(String(255), nullable=True)
    refresh_token = Column(Text, nullable=False)
    access_token = Column(Text, nullable=True)
    token_expiry = Column(DateTime(timezone=True), nullable=True)
    scopes = Column(JSON, nullable=True, default=list)
    last_activity_cursor = Column(String(255), nullable=True)
    last_polled_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), nullable=False, default="active")
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    folders = relationship(
        "GoogleDriveProtectedFolder",
        cascade="all, delete-orphan",
        back_populates="connection",
    )

    __allow_unmapped__ = True

    _cipher: ClassVar[Optional[Fernet]] = None

    @classmethod
    def _get_cipher(cls) -> Fernet:
        if cls._cipher is None:
            cls._cipher = _build_cipher()
        return cls._cipher

    def set_refresh_token(self, token: str) -> None:
        if not token:
            raise ValueError("Refresh token cannot be empty")
        cipher = self._get_cipher()
        self.refresh_token = cipher.encrypt(token.encode("utf-8")).decode("utf-8")

    def get_refresh_token(self) -> Optional[str]:
        if not self.refresh_token:
            return None
        cipher = self._get_cipher()
        return cipher.decrypt(self.refresh_token.encode("utf-8")).decode("utf-8")

    def set_access_token(self, token: Optional[str]) -> None:
        if not token:
            self.access_token = None
            return
        cipher = self._get_cipher()
        self.access_token = cipher.encrypt(token.encode("utf-8")).decode("utf-8")

    def get_access_token(self) -> Optional[str]:
        if not self.access_token:
            return None
        cipher = self._get_cipher()
        return cipher.decrypt(self.access_token.encode("utf-8")).decode("utf-8")

    def is_token_expired(self) -> bool:
        if not self.token_expiry or not self.access_token:
            return True
        return datetime.now(timezone.utc) >= self.token_expiry

    def mark_error(self, message: str) -> None:
        self.status = "error"
        self.error_message = message
        self.updated_at = datetime.now(timezone.utc)

    def mark_polled(self, cursor: Optional[str], polled_at: Optional[datetime] = None) -> None:
        self.last_activity_cursor = cursor or self.last_activity_cursor
        self.last_polled_at = polled_at or datetime.now(timezone.utc)
        self.status = "active"
        self.error_message = None
        self.updated_at = datetime.now(timezone.utc)


class GoogleDriveProtectedFolder(Base):
    __tablename__ = "google_drive_protected_folders"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connection_id = Column(
        UUID(as_uuid=True),
        ForeignKey("google_drive_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    folder_id = Column(String(255), nullable=False)
    folder_name = Column(String(512), nullable=True)
    folder_path = Column(Text, nullable=True)
    sensitivity_level = Column(String(20), nullable=False, default="medium")
    last_seen_timestamp = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    connection = relationship("GoogleDriveConnection", back_populates="folders")

    def touch(self, timestamp: Optional[datetime] = None) -> None:
        ts = timestamp or datetime.now(timezone.utc)
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc)
        self.last_seen_timestamp = ts
        self.updated_at = datetime.now(timezone.utc)
