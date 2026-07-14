"""
IP allowlist middleware — restrict the admin portal to authorized networks.

Rules:
  * The allowlist lives in the ``ip_allowlist`` table (managed by the Super
    Admin in Settings). It is cached for a few seconds to avoid a DB hit per
    request; management endpoints bump a generation to refresh immediately.
  * **Empty / all-disabled → fail-open** (the control is off).
  * **Loopback is always allowed** (health checks, local admin).
  * **Agent-ingestion + health endpoints are always exempt** so endpoints keep
    reporting from any network even while the portal is IP-restricted.
  * Any other request from an IP outside the allowlist gets **403**.

Real client IP: behind nginx we read ``X-Real-IP`` / the first ``X-Forwarded-For``
hop (nginx overwrites XFF with the real ``$remote_addr``, so it can't be spoofed
via that path). Falls back to the socket peer for direct hits.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import List, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import structlog

logger = structlog.get_logger()

_CACHE_TTL = 15  # seconds
_cache_nets: List[ipaddress._BaseNetwork] = []
_cache_time: float = 0.0
_cache_gen: int = 0
_current_gen: int = 0

_LOOPBACK = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]

# Agent machine-to-machine endpoints — always allowed regardless of source IP.
_AGENT_HEARTBEAT = re.compile(r"^/api/v1/agents/[^/]+/heartbeat/?$")
_AGENT_SYNC = re.compile(r"^/api/v1/agents/[^/]+/(policies/sync|policy/evaluate)/?$")
_AGENT_UNREG = re.compile(r"^/api/v1/agents/[^/]+/unregister/?$")


def bump_ip_allowlist_cache() -> None:
    """Force the middleware to reload on its next request (call after edits)."""
    global _current_gen
    _current_gen += 1


def get_client_ip(request: Request) -> str:
    """Best-effort real client IP (nginx forwards X-Real-IP / X-Forwarded-For)."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip()
    return request.client.host if request.client else ""


def _is_exempt(method: str, path: str) -> bool:
    if path in ("/health", "/api/v1/health"):
        return True
    # Agent enforcement / policy download API.
    if path.startswith("/api/v1/decision"):
        return True
    # TAXII 2.1 sharing server — partner vendors poll this from external IPs and
    # it has its own HTTP Basic auth, so it must not be gated by the portal
    # allowlist.
    if path.startswith("/api/v1/taxii2"):
        return True
    # Agent event ingestion (POST only; GET is human reporting).
    if method == "POST" and path.rstrip("/") == "/api/v1/events":
        return True
    # Agent registration.
    if method == "POST" and path.rstrip("/") == "/api/v1/agents":
        return True
    # Agent lifecycle (heartbeat / sync / evaluate / unregister).
    if method == "PUT" and _AGENT_HEARTBEAT.match(path):
        return True
    if method == "POST" and _AGENT_SYNC.match(path):
        return True
    if method == "DELETE" and _AGENT_UNREG.match(path):
        return True
    return False


async def _load_nets() -> List[ipaddress._BaseNetwork]:
    """Load enabled allowlist CIDRs, cached with a short TTL + generation bump."""
    global _cache_nets, _cache_time, _cache_gen
    now = time.monotonic()
    if _cache_gen == _current_gen and (now - _cache_time) < _CACHE_TTL:
        return _cache_nets

    nets: List[ipaddress._BaseNetwork] = []
    try:
        import app.core.database as db
        from sqlalchemy import text
        if db.postgres_session_factory is not None:
            async with db.postgres_session_factory() as session:
                rows = await session.execute(
                    text("SELECT cidr FROM ip_allowlist WHERE is_enabled = true")
                )
                for (cidr,) in rows.all():
                    try:
                        nets.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
                    except ValueError:
                        logger.warning("Invalid CIDR in ip_allowlist, skipping", cidr=cidr)
    except Exception as e:
        # DB unreachable → don't lock everyone out; fail-open this cycle.
        logger.warning("ip_allowlist load failed; failing open", error=str(e))
        return []

    _cache_nets = nets
    _cache_time = now
    _cache_gen = _current_gen
    return nets


class IPAllowlistMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        nets = await _load_nets()
        if not nets:
            return await call_next(request)  # feature off (empty allowlist)

        if _is_exempt(request.method, request.url.path):
            return await call_next(request)

        ip_str = get_client_ip(request)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            ip = None

        allowed = ip is not None and (
            any(ip in n for n in _LOOPBACK) or any(ip in n for n in nets)
        )
        if not allowed:
            logger.warning("IP blocked by allowlist", ip=ip_str, path=request.url.path)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "message": "Access to this portal is restricted to authorized IP addresses.",
                },
            )
        return await call_next(request)
