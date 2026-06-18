"""
Google Drive Polling Tasks
Background tasks for polling Google Drive Activity API
"""

import asyncio
from celery.utils.log import get_task_logger

# Avoid circular import by importing celery_app locally or using shared_task
# using shared_task is safer if structure is complex, but here we follow the pattern
from app.tasks.reporting_tasks import celery_app
from app.services.google_drive_polling import GoogleDrivePollingService
import app.core.database as database

logger = get_task_logger(__name__)

@celery_app.task(name="app.tasks.google_drive_polling_tasks.poll_google_drive_activity")
def poll_google_drive_activity():
    """
    Periodically poll all configured Google Drive connections for new activity.
    """
    logger.info("Starting Google Drive polling task")
    
    try:
        asyncio.run(run_polling())
        logger.info("Google Drive polling task completed successfully")
        return "success"
    except Exception as e:
        logger.error(f"Google Drive polling task failed: {str(e)}")
        raise

async def run_polling():
    """
    Async entry point for polling service.
    """
    # Initialize DB (idempotent-ish)
    await database.init_databases()
    
    # Use the factory to get a session
    async with database.postgres_session_factory() as db:
        service = GoogleDrivePollingService(db)
        events_count = await service.poll_all_connections()
        logger.info(f"Polled {events_count} new events from Google Drive")
    
    # We should close databases to release connections, 
    # assuming this process is short-lived or forked per task.
    await database.close_databases()
