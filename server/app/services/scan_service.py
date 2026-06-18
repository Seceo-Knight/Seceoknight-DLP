"""
Data Discovery Scan Service
"""
from typing import Optional, List
from uuid import UUID
from datetime import datetime
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.scan_job import ScanJob
from app.models.scan_result import ScanResult

logger = structlog.get_logger()


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_job(self, target: str) -> ScanJob:
        job = ScanJob(target=target, status="pending")
        self.db.add(job)
        await self.db.flush()
        return job

    async def get_job(self, job_id: UUID) -> Optional[ScanJob]:
        result = await self.db.execute(select(ScanJob).where(ScanJob.id == job_id))
        return result.scalar_one_or_none()

    async def list_jobs(self, skip=0, limit=50, status=None) -> List[ScanJob]:
        query = select(ScanJob)
        if status:
            query = query.where(ScanJob.status == status)
        query = query.order_by(ScanJob.created_at.desc()).offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def update_job_status(self, job_id: UUID, status: str) -> Optional[ScanJob]:
        job = await self.get_job(job_id)
        if not job:
            return None
        job.status = status
        if status == "running":
            job.started_at = datetime.utcnow()
        elif status in ("completed", "failed"):
            job.completed_at = datetime.utcnow()
        await self.db.flush()
        return job

    async def add_result(self, job_id: UUID, file_path: str, label_id: UUID = None, matched_rule: UUID = None) -> ScanResult:
        result = ScanResult(job_id=job_id, file_path=file_path, label_id=label_id, matched_rule=matched_rule)
        self.db.add(result)
        await self.db.flush()
        return result

    async def get_results(self, job_id: UUID, skip=0, limit=100) -> List[ScanResult]:
        query = (
            select(ScanResult)
            .where(ScanResult.job_id == job_id)
            .order_by(ScanResult.created_at.desc())
            .offset(skip).limit(limit)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count_results(self, job_id: UUID) -> int:
        result = await self.db.execute(
            select(func.count(ScanResult.id)).where(ScanResult.job_id == job_id)
        )
        return result.scalar() or 0
