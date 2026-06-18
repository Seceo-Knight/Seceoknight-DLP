"""
Event Cleanup Tasks
Background tasks for automatic deletion of old events
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


@celery_app.task(name="app.tasks.event_cleanup_tasks.cleanup_old_events")
def cleanup_old_events():
    """
    Delete events older than the retention period from MongoDB.
    
    Scheduled to run daily at 2:00 AM UTC.
    Deletes events with timestamp older than EVENT_RETENTION_DAYS (default: 180 days).
    """
    task_logger.info("Starting event cleanup task")
    
    try:
        result = asyncio.run(run_cleanup())
        task_logger.info("Event cleanup task completed successfully", result=result)
        return result
    except Exception as e:
        task_logger.error(f"Event cleanup task failed: {str(e)}", exc_info=True)
        logger.log_error(e, {"task": "cleanup_old_events"})
        raise


async def run_cleanup():
    """
    Async entry point for cleanup service.
    """
    # Initialize database connections
    await database.init_databases()
    
    try:
        # Get MongoDB database
        db = get_mongodb()
        events_collection = db["dlp_events"]
        
        # Calculate cutoff date
        retention_days = settings.EVENT_RETENTION_DAYS
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        logger.logger.info(
            "event_cleanup_started",
            retention_days=retention_days,
            cutoff_date=cutoff_date.isoformat()
        )
        
        # Count events to be deleted (for logging)
        count_before = await events_collection.count_documents({})
        old_events_count = await events_collection.count_documents(
            {"timestamp": {"$lt": cutoff_date}}
        )
        
        if old_events_count == 0:
            logger.logger.info(
                "event_cleanup_completed",
                retention_days=retention_days,
                cutoff_date=cutoff_date.isoformat(),
                deleted_count=0,
                total_events=count_before
            )
            return {
                "status": "success",
                "retention_days": retention_days,
                "cutoff_date": cutoff_date.isoformat(),
                "deleted_count": 0,
                "total_events_before": count_before,
                "total_events_after": count_before,
                "message": "No events older than retention period found"
            }
        
        # Delete events older than cutoff date
        # MongoDB's delete_many() is efficient and handles batching internally
        delete_result = await events_collection.delete_many(
            {"timestamp": {"$lt": cutoff_date}}
        )
        
        deleted_count = delete_result.deleted_count
        
        # Count events after deletion
        count_after = await events_collection.count_documents({})
        
        logger.logger.info(
            "event_cleanup_completed",
            retention_days=retention_days,
            cutoff_date=cutoff_date.isoformat(),
            deleted_count=deleted_count,
            total_events_before=count_before,
            total_events_after=count_after
        )
        
        return {
            "status": "success",
            "retention_days": retention_days,
            "cutoff_date": cutoff_date.isoformat(),
            "deleted_count": deleted_count,
            "total_events_before": count_before,
            "total_events_after": count_after,
            "completed_at": datetime.utcnow().isoformat()
        }
        
    finally:
        # Close database connections
        await database.close_databases()

