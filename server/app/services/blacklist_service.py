"""
Token Blacklist Service
Handles JWT token blacklisting using Redis
"""

from datetime import timedelta

from app.core.cache import redis_client
import structlog

logger = structlog.get_logger()


class TokenBlacklistService:
    """
    Service for blacklisting JWT tokens
    """

    def __init__(self, redis_client):
        self.redis = redis_client

    async def add_to_blacklist(self, token: str, expires_in: timedelta):
        """
        Add a token to the blacklist with an expiration time
        """
        try:
            jti = self._get_jti_from_token(token)
            await self.redis.setex(f"blacklist:{jti}", int(expires_in.total_seconds()), "blacklisted")
            logger.info("Token blacklisted", jti=jti)
        except Exception as e:
            logger.error("Failed to blacklist token", error=str(e))

    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is in the blacklist
        """
        try:
            if not self.redis:
                return False  # If Redis is not available, assume token is not blacklisted
            jti = self._get_jti_from_token(token)
            result = await self.redis.exists(f"blacklist:{jti}")
            return bool(result)
        except Exception as e:
            logger.error("Failed to check token blacklist", error=str(e))
            return False  # Fail safe - if we can't check, assume token is valid

    def _get_jti_from_token(self, token: str) -> str:
        """
        Get the JTI (JWT ID) from the token payload
        """
        from app.core.security import decode_token
        payload = decode_token(token)
        jti = payload.get("jti")
        if not jti:
            raise ValueError("Token does not contain a JTI")
        return jti
