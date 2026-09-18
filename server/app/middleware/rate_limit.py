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

    # Endpoints under the exempted agent prefixes below that are NOT
    # lightweight (heartbeat/registration/event-push) -- they trigger real
    # document extraction + classification work, potentially on
    # attacker-controlled file_content_b64 payloads. Found in the September
    # 2026 security hardening audit: these were falling under the blanket
    # `AGENT_PREFIXES` exemption meant for cheap high-frequency traffic,
    # so they had NO rate limit at all, gated only by possession of an
    # agent key (and, until the same audit's other fix, an agent key was
    # free to obtain with one anonymous POST). Rather than exempt them
    # outright, they get their own higher-but-real, per-agent-key limit
    # below instead of the per-IP one (an agent's own IP may be shared /
    # NATed with many others, and keying by IP would either throttle a
    # whole site or be too loose to matter for a single abusive key).
    HEAVY_PATH_SUFFIXES = ("/policy/evaluate", "/web-activity/evaluate")
    HEAVY_PATH_PREFIX = "/api/v1/decision/"

    def _is_heavy_agent_endpoint(self, path: str) -> bool:
        if path.startswith(self.HEAVY_PATH_PREFIX):
            return True
        return any(path.endswith(suffix) for suffix in self.HEAVY_PATH_SUFFIXES)

    async def _enforce(
        self, request: Request, call_next, *, key: str, max_requests: int, window_seconds: int
    ) -> Response:
        """Shared incr/expire/429 logic, parameterized by cache key + limit."""
        try:
            cache = get_cache()
            current = await cache.incr(key)
            if current == 1:
                await cache.expire(key, window_seconds)
        except Exception as e:
            # If Redis fails, allow request to proceed once
            logger.error("Rate limiting error", error=str(e))
            return await call_next(request)

        if current > max_requests:
            logger.warning(
                "Rate limit exceeded",
                key=key,
                requests=current,
                limit=max_requests,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={
                    "Retry-After": str(window_seconds),
                    "X-RateLimit-Limit": str(max_requests),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, max_requests - current))
        return response

    async def dispatch(self, request: Request, call_next) -> Response:
        # Get client IP
        client_ip = request.client.host
        path = request.url.path
        method = request.method

        # Skip rate limiting for health checks and for the dedicated
        # agent heartbeat / event-push endpoints (which legitimately
        # fire at high frequency from many clients) -- EXCEPT the heavy
        # classification-triggering endpoints under the same prefixes,
        # which get their own limit below instead of a free pass.
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
            if self._is_heavy_agent_endpoint(path):
                from app.core.config import settings as _settings
                agent_key = request.headers.get("X-Agent-Key") or f"ip:{client_ip}"
                return await self._enforce(
                    request, call_next,
                    key=f"rate_limit:agent_heavy:{agent_key}",
                    max_requests=getattr(_settings, "RATE_LIMIT_AGENT_HEAVY_MAX_REQUESTS", 300),
                    window_seconds=getattr(_settings, "RATE_LIMIT_AGENT_HEAVY_WINDOW_SECONDS", 60),
                )
            return await call_next(request)

        return await self._enforce(
            request, call_next,
            key=f"rate_limit:{client_ip}",
            max_requests=self.max_requests,
            window_seconds=self.window_seconds,
        )
