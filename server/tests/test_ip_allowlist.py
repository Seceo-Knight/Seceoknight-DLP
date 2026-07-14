"""
Tests for the IP allowlist middleware (app.middleware.ip_allowlist) and the
`ip_allowlist` API's CIDR handling.

Focused on the pure logic — client-IP resolution and the always-exempt
endpoint list — since the middleware's DB-backed cache path needs a live
Postgres connection. Ported alongside the IP allowlisting feature;
CyberSentinel DLP shipped this with zero tests.
"""
import types

import pytest

from app.middleware.ip_allowlist import get_client_ip, _is_exempt


def _request(headers=None, client_host=None):
    """Minimal Starlette-Request-shaped stand-in for get_client_ip()."""
    return types.SimpleNamespace(
        headers=headers or {},
        client=types.SimpleNamespace(host=client_host) if client_host else None,
    )


# ── get_client_ip ─────────────────────────────────────────────────────────────

def test_get_client_ip_prefers_x_forwarded_for_first_hop():
    req = _request(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1"}, client_host="10.0.0.2")
    assert get_client_ip(req) == "203.0.113.7"


def test_get_client_ip_falls_back_to_x_real_ip():
    req = _request(headers={"x-real-ip": "203.0.113.8"}, client_host="10.0.0.2")
    assert get_client_ip(req) == "203.0.113.8"


def test_get_client_ip_falls_back_to_socket_peer():
    req = _request(headers={}, client_host="10.0.0.2")
    assert get_client_ip(req) == "10.0.0.2"


def test_get_client_ip_no_client_returns_empty_string():
    req = _request(headers={})
    assert get_client_ip(req) == ""


def test_get_client_ip_strips_whitespace_in_xff():
    req = _request(headers={"x-forwarded-for": "  203.0.113.9  , 10.0.0.1"})
    assert get_client_ip(req) == "203.0.113.9"


# ── _is_exempt ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/health"),
        ("GET", "/api/v1/health"),
        ("POST", "/api/v1/events"),
        ("POST", "/api/v1/events/"),
        ("POST", "/api/v1/agents"),
        ("PUT", "/api/v1/agents/abc-123/heartbeat"),
        ("POST", "/api/v1/agents/abc-123/policies/sync"),
        ("POST", "/api/v1/agents/abc-123/policy/evaluate"),
        ("DELETE", "/api/v1/agents/abc-123/unregister"),
        ("GET", "/api/v1/decision/anything"),
        ("GET", "/api/v1/taxii2/api/collections/"),
    ],
)
def test_is_exempt_agent_and_infra_endpoints(method, path):
    assert _is_exempt(method, path) is True


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/v1/events"),          # GET is human dashboard traffic, not exempt
        ("GET", "/api/v1/policies"),
        ("POST", "/api/v1/policies"),
        ("GET", "/api/v1/threat-intel/iocs"),
        ("DELETE", "/api/v1/users/abc-123"),
    ],
)
def test_is_exempt_portal_endpoints_are_not_exempt(method, path):
    assert _is_exempt(method, path) is False


def test_ip_allowlist_entry_model_repr():
    from app.models.ip_allowlist import IPAllowlistEntry
    import uuid

    entry = IPAllowlistEntry(id=uuid.uuid4(), cidr="203.0.113.0/24", is_enabled=True)
    assert "203.0.113.0/24" in repr(entry)
    assert "enabled=True" in repr(entry)


@pytest.mark.asyncio
async def test_ip_allowlist_cidr_unique_constraint(db_session):
    from app.models.ip_allowlist import IPAllowlistEntry
    from sqlalchemy.exc import IntegrityError

    db_session.add(IPAllowlistEntry(cidr="203.0.113.0/24", label="office"))
    await db_session.commit()

    db_session.add(IPAllowlistEntry(cidr="203.0.113.0/24", label="dup"))
    with pytest.raises(IntegrityError):
        await db_session.commit()
