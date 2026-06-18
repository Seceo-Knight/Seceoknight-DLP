"""
Redis Cache Management
"""

from typing import Optional, Any
import json
from datetime import timedelta

import redis.asyncio as aioredis
import structlog

from app.core.config import settings

logger = structlog.get_logger()

# Global Redis instance
redis_client: Optional[aioredis.Redis] = None


async def init_cache() -> None:
    """
    Initialize Redis connection
    """
    global redis_client

    try:
        redis_client = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=settings.REDIS_POOL_SIZE,
        )

        # Test connection
        await redis_client.ping()

        logger.info(
            "Redis connection established",
            host=settings.REDIS_HOST,
            db=settings.REDIS_DB,
        )

    except Exception as e:
        logger.error("Failed to connect to Redis", error=str(e))
        raise


async def close_cache() -> None:
    """
    Close Redis connection
    """
    global redis_client

    if redis_client is not None:
        await redis_client.close()
        logger.info("Redis connection closed")


def get_cache() -> aioredis.Redis:
    """
    Get Redis client for dependency injection
    """
    if redis_client is None:
        raise RuntimeError("Redis not initialized")
    return redis_client


class CacheService:
    """
    High-level cache service with common operations
    """

    def __init__(self, client: aioredis.Redis):
        self.client = client

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache
        """
        try:
            value = await self.client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.warning("Cache get failed", key=key, error=str(e))
            return None

    async def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None
    ) -> bool:
        """
        Set value in cache with optional expiration
        """
        try:
            serialized = json.dumps(value)
            if expire:
                await self.client.setex(key, expire, serialized)
            else:
                await self.client.set(key, serialized)
            return True
        except Exception as e:
            logger.warning("Cache set failed", key=key, error=str(e))
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache
        """
        try:
            await self.client.delete(key)
            return True
        except Exception as e:
            logger.warning("Cache delete failed", key=key, error=str(e))
            return False

    async def delete_prefix(self, prefix: str) -> int:
        """
        Delete all keys matching a given prefix.

        Returns number of keys deleted.
        """
        try:
            deleted = 0
            async for key in self.client.scan_iter(f"{prefix}*"):
                await self.client.delete(key)
                deleted += 1
            return deleted
        except Exception as e:
            logger.warning("Cache delete_prefix failed", prefix=prefix, error=str(e))
            return 0

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache
        """
        try:
            return await self.client.exists(key) > 0
        except Exception as e:
            logger.warning("Cache exists check failed", key=key, error=str(e))
            return False

    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Increment value in cache
        """
        try:
            return await self.client.incrby(key, amount)
        except Exception as e:
            logger.warning("Cache increment failed", key=key, error=str(e))
            return None

    async def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration on key
        """
        try:
            return await self.client.expire(key, seconds)
        except Exception as e:
            logger.warning("Cache expire failed", key=key, error=str(e))
            return False
