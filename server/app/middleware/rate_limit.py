"""
Rate Limiting Middleware
Prevents API abuse by limiting requests per IP
"""

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.core.cache import get_cache

logger = structlog.get_logger()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce rate limiting per IP address
    """

    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def dispatch(self, request: Request, call_next) -> Response:
        # Get client IP
        client_ip = request.client.host
        path = request.url.path
        method = request.method

        # Skip rate limiting for health checks and for the dedicated
        # agent heartbeat / event-push endpoints (which legitimately
        # fire at high frequency from many clients).
        #
        # SECURITY NOTE: the previous version used
        #   `path in [...] or "/agents" in path and method in [...]`
        # which (a) had an operator-precedence trap between `or`/`and`
        # and (b) used unbounded substring matching, so paths like
        # `/api/v1/policies/agents-test` or `/api/v1/rules/tagents` got
        # a blanket bypass. The fix uses an anchored `startswith`
        # comparison against the API prefix, with explicit parentheses.
        AGENT_PREFIXES = (
            "/api/v1/agents/",   # heartbeat, registration, policy sync
            "/api/v1/events/",   # event ingestion
            "/api/v1/decision/", # real-time classification decisions
        )
        if path in ("/health", "/ready", "/metrics"):
            return await call_next(request)
        if method in ("POST", "PUT", "PATCH") and any(
            path.startswith(prefix) for prefix in AGENT_PREFIXES
        ):
            return await call_next(request)

        try:
            cache = get_cache()
            key = f"rate_limit:{client_ip}"
            current = await cache.incr(key)

            if current == 1:
                await cache.expire(key, self.window_seconds)
        except Exception as e:
            # If Redis fails, allow request to proceed once
            logger.error("Rate limiting error", error=str(e))
            return await call_next(request)

        if current > self.max_requests:
            logger.warning(
                "Rate limit exceeded",
                client_ip=client_ip,
                requests=current,
                limit=self.max_requests,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={
                    "Retry-After": str(self.window_seconds),
                    "X-RateLimit-Limit": str(self.max_requests),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)

        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, self.max_requests - current)
        )

        return response
