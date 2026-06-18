"""
File Fingerprint Service - Hash-based document identification
"""
import hashlib
from typing import Optional, List
from uuid import UUID
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.file_fingerprint import FileFingerprint

logger = structlog.get_logger()


class FingerprintService:
    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def compute_hash(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    async def add_fingerprint(self, hash_value: str, file_name: str = None, label_id: UUID = None) -> FileFingerprint:
        fp = FileFingerprint(hash=hash_value, file_name=file_name, label_id=label_id)
        self.db.add(fp)
        await self.db.flush()
        return fp

    async def get_by_hash(self, hash_value: str) -> Optional[FileFingerprint]:
        result = await self.db.execute(
            select(FileFingerprint).where(FileFingerprint.hash == hash_value)
        )
        return result.scalar_one_or_none()

    async def match_content(self, content: str) -> Optional[FileFingerprint]:
        content_hash = self.compute_hash(content)
        return await self.get_by_hash(content_hash)

    async def list_fingerprints(self, skip=0, limit=100, label_id=None) -> List[FileFingerprint]:
        query = select(FileFingerprint)
        if label_id:
            query = query.where(FileFingerprint.label_id == label_id)
        query = query.order_by(FileFingerprint.created_at.desc()).offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count(self, label_id=None) -> int:
        query = select(func.count(FileFingerprint.id))
        if label_id:
            query = query.where(FileFingerprint.label_id == label_id)
        result = await self.db.execute(query)
        return result.scalar() or 0

    async def delete_fingerprint(self, fingerprint_id: UUID) -> bool:
        result = await self.db.execute(
            select(FileFingerprint).where(FileFingerprint.id == fingerprint_id)
        )
        fp = result.scalar_one_or_none()
        if fp:
            await self.db.delete(fp)
            return True
        return False
