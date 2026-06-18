"""
Database Connection Management
PostgreSQL (SQLAlchemy) + MongoDB (Motor)
"""

from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import declarative_base
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
import structlog

from app.core.config import settings

logger = structlog.get_logger()

# SQLAlchemy Base for models
Base = declarative_base()

# Global database instances
postgres_engine: Optional[AsyncEngine] = None
postgres_session_factory: Optional[async_sessionmaker] = None
mongodb_client: Optional[AsyncIOMotorClient] = None
mongodb_database: Optional[AsyncIOMotorDatabase] = None


async def init_databases() -> None:
    """
    Initialize database connections
    """
    global postgres_engine, postgres_session_factory, mongodb_client, mongodb_database

    # Initialize PostgreSQL
    try:
        postgres_engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,
            pool_size=settings.POSTGRES_POOL_SIZE,
            max_overflow=settings.POSTGRES_MAX_OVERFLOW,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

        postgres_session_factory = async_sessionmaker(
            postgres_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        # Test connection
        async with postgres_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))

        logger.info(
            "PostgreSQL connection established",
            host=settings.POSTGRES_HOST,
            database=settings.POSTGRES_DB,
        )

    except Exception as e:
        logger.error("Failed to connect to PostgreSQL", error=str(e))
        raise

    # Initialize MongoDB
    try:
        mongodb_client = AsyncIOMotorClient(
            settings.MONGODB_URL,
            maxPoolSize=settings.MONGODB_MAX_POOL_SIZE,
            serverSelectionTimeoutMS=5000,
        )

        mongodb_database = mongodb_client[settings.MONGODB_DB]

        # Test connection
        await mongodb_client.admin.command('ping')

        logger.info(
            "MongoDB connection established",
            host=settings.MONGODB_HOST,
            database=settings.MONGODB_DB,
        )

        # Ensure unique index on event id for deduplication safety, plus
        # ABAC-support indexes so department-filtered queries don't scan
        # the whole collection. All are idempotent — re-creating an index
        # with the same key is a no-op.
        try:
            events_col = mongodb_database["dlp_events"]
            await events_col.create_index("id", unique=True, background=True, sparse=True)
            # ABAC hot path: equality on department + range on timestamp. The
            # leading-column lets the same index cover pure-department queries.
            await events_col.create_index(
                [("department", 1), ("timestamp", -1)],
                name="idx_dept_timestamp",
                background=True,
            )
            # Supports count queries scoped by dept (dashboard overview, etc.)
            await events_col.create_index(
                [("department", 1), ("severity", 1)],
                name="idx_dept_severity",
                background=True,
            )
            # Incidents collection: auto-incidents are now tagged with
            # department; this index supports ABAC-filtered listing.
            incidents_col = mongodb_database["incidents"]
            await incidents_col.create_index(
                [("department", 1), ("created_at", -1)],
                name="idx_dept_created",
                background=True,
            )
            logger.info("MongoDB indexes ensured (id, dept/timestamp, dept/severity, incidents dept/created)")
        except Exception as idx_err:
            # Duplicate key errors on existing data — log but don't crash
            logger.warning("MongoDB index creation issue (non-fatal)", error=str(idx_err))

    except Exception as e:
        logger.error("Failed to connect to MongoDB", error=str(e))
        raise


async def close_databases() -> None:
    """
    Close database connections
    """
    global postgres_engine, mongodb_client

    # Close PostgreSQL
    if postgres_engine is not None:
        await postgres_engine.dispose()
        logger.info("PostgreSQL connection closed")

    # Close MongoDB
    if mongodb_client is not None:
        mongodb_client.close()
        logger.info("MongoDB connection closed")


@asynccontextmanager
async def get_postgres_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get PostgreSQL session for dependency injection
    """
    if not postgres_session_factory:
        raise RuntimeError("Database not initialized")

    async with postgres_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_mongodb() -> AsyncIOMotorDatabase:
    """
    Get MongoDB database for dependency injection
    """
    if mongodb_database is None:
        raise RuntimeError("MongoDB not initialized")
    return mongodb_database


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for getting database session
    Alias for get_postgres_session for backward compatibility
    """
    if not postgres_session_factory:
        raise RuntimeError("Database not initialized")

    async with postgres_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Import text for raw SQL queries
from sqlalchemy import text

def get_db_session():
    """
    Legacy synchronous wrapper for getting database session.
    Used by Celery tasks that haven't been fully migrated to async.
    """
    if not postgres_session_factory:
        raise RuntimeError("Database not initialized")
    
    # Return a generator that yields a session
    # Note: The consumer is responsible for closing it
    session = postgres_session_factory()
    yield session

