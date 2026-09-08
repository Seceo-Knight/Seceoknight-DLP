"""
Quarantine File Cleanup Tasks
Background tasks for automatic deletion of old quarantined-file blobs.

Quarantined file BYTES (uploaded to the server so the Dashboard can offer a
Download button -- see the "Synchronous... upload" flow in api/v1/events.py
and agent.cpp's UploadQuarantinedFile()) are stored in a GridFS bucket,
separately from the lightweight event record that describes them. This task
purges old GridFS blobs on a much shorter retention window than events
themselves (see Settings.QUARANTINE_RETENTION_DAYS's docstring for why) so
this feature doesn't grow the server's storage footprint without bound.

The event record is NOT deleted here -- only the quarantine_file_id/
quarantine_file_name/quarantine_file_size fields are cleared from it, so the
Dashboard naturally stops offering a Download button (the event itself still
shows it WAS quarantined, just that the retrievable copy has expired) rather
than leaving a broken link.
"""

import asyncio
from datetime import datetime, timedelta
from celery.utils.log import get_task_logger

from app.tasks.reporting_tasks import celery_app
from app.core.config import settings
from app.core.database import get_mongodb
import app.core.database as database
from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)
task_logger = get_task_logger(__name__)


@celery_app.task(name="app.tasks.quarantine_cleanup_tasks.cleanup_old_quarantine_files")
def cleanup_old_quarantine_files():
    """
    Delete quarantined-file blobs older than QUARANTINE_RETENTION_DAYS from
    GridFS, and clear the corresponding reference off each event doc.

    Scheduled to run daily at 2:30 AM UTC (30 minutes after the event
    cleanup task, so it isn't fighting the same task for DB connections).
    """
    task_logger.info("Starting quarantine file cleanup task")

    try:
        result = asyncio.run(run_cleanup())
        task_logger.info("Quarantine file cleanup task completed successfully", result=result)
        return result
    except Exception as e:
        task_logger.error(f"Quarantine file cleanup task failed: {str(e)}", exc_info=True)
        logger.log_error(e, {"task": "cleanup_old_quarantine_files"})
        raise


async def run_cleanup():
    """
    Async entry point for cleanup service.
    """
    await database.init_databases()

    try:
        from motor.motor_asyncio import AsyncIOMotorGridFSBucket
        from bson import ObjectId

        db = get_mongodb()
        events_collection = db["dlp_events"]
        bucket = AsyncIOMotorGridFSBucket(db, bucket_name="quarantine_files")

        retention_days = max(1, settings.QUARANTINE_RETENTION_DAYS)
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        logger.logger.info(
            "quarantine_cleanup_started",
            retention_days=retention_days,
            cutoff_date=cutoff_date.isoformat(),
        )

        # fs.files is GridFS's own metadata collection for this bucket --
        # uploadDate is stamped by GridFS itself at upload time.
        files_collection = db["quarantine_files.files"]
        old_files = await files_collection.find(
            {"uploadDate": {"$lt": cutoff_date}},
            projection={"_id": 1},
        ).to_list(None)

        if not old_files:
            logger.logger.info(
                "quarantine_cleanup_completed",
                retention_days=retention_days,
                cutoff_date=cutoff_date.isoformat(),
                deleted_count=0,
            )
            return {
                "status": "success",
                "retention_days": retention_days,
                "cutoff_date": cutoff_date.isoformat(),
                "deleted_count": 0,
                "message": "No quarantine files older than retention period found",
            }

        deleted_count = 0
        for doc in old_files:
            file_id: ObjectId = doc["_id"]
            try:
                await bucket.delete(file_id)
                deleted_count += 1
            except Exception as e:
                # A file's GridFS chunks can already be gone (partial upload,
                # earlier failed cleanup run) -- log and keep going rather
                # than letting one bad blob abort the whole day's cleanup.
                logger.logger.warning(
                    "quarantine_cleanup_delete_failed",
                    file_id=str(file_id),
                    error=str(e),
                )
            # Clear the event's reference regardless of whether the GridFS
            # delete itself succeeded -- either way there's nothing left to
            # download, and a dangling quarantine_file_id would just make
            # the Dashboard's Download button 404 forever.
            await events_collection.update_many(
                {"quarantine_file_id": str(file_id)},
                {"$unset": {
                    "quarantine_file_id": "",
                    "quarantine_file_name": "",
                    "quarantine_file_size": "",
                }},
            )

        logger.logger.info(
            "quarantine_cleanup_completed",
            retention_days=retention_days,
            cutoff_date=cutoff_date.isoformat(),
            deleted_count=deleted_count,
        )

        return {
            "status": "success",
            "retention_days": retention_days,
            "cutoff_date": cutoff_date.isoformat(),
            "deleted_count": deleted_count,
            "completed_at": datetime.utcnow().isoformat(),
        }

    finally:
        await database.close_databases()
