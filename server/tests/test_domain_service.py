"""
Tests for domain-scoped RBAC: app.core.domains + app.services.domain_service.

Ported (with real test coverage — CyberSentinel DLP shipped this feature
with zero tests) alongside the domain-scoped admin RBAC port.
"""
import pytest

from app.core.domains import (
    PolicyDomain,
    domain_for_policy_type,
    domain_for_event_type,
    domains_for_role,
    is_domain_admin,
)
from app.services.domain_service import (
    get_user_domains,
    user_is_domain_admin,
    user_can_access_domain,
    build_domain_mongo_filter,
    build_domain_sql_filter,
)


class _FakeUser:
    """Minimal stand-in for app.models.user.User — domain_service only reads
    `.role` (or falls back to dict-style access)."""

    def __init__(self, role):
        self.role = role


# ── app.core.domains ─────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "policy_type,expected",
    [
        ("usb_device_monitoring", PolicyDomain.THREAT.value),
        ("network_exfiltration", PolicyDomain.THREAT.value),
        ("screen_capture_monitoring", PolicyDomain.THREAT.value),
        ("print_monitoring", PolicyDomain.THREAT.value),
        ("clipboard_monitoring", PolicyDomain.DATA_PROTECTION.value),
        ("file_system_monitoring", PolicyDomain.DATA_PROTECTION.value),
        ("google_drive_cloud_monitoring", PolicyDomain.DATA_PROTECTION.value),
        ("onedrive_cloud_monitoring", PolicyDomain.DATA_PROTECTION.value),
        ("usb_device_authorization", PolicyDomain.ACCESS_CONTROL.value),
        ("device_access", PolicyDomain.ACCESS_CONTROL.value),
        ("some_unmapped_type", PolicyDomain.GENERAL.value),
        (None, PolicyDomain.GENERAL.value),
    ],
)
def test_domain_for_policy_type(policy_type, expected):
    assert domain_for_policy_type(policy_type) == expected


def test_domain_for_policy_type_is_case_insensitive():
    assert domain_for_policy_type("USB_DEVICE_MONITORING") == PolicyDomain.THREAT.value
    assert domain_for_policy_type("  clipboard  ") != PolicyDomain.THREAT.value  # untrimmed types don't match


@pytest.mark.parametrize(
    "event_type,expected",
    [
        ("usb", PolicyDomain.THREAT.value),
        ("network_exfil", PolicyDomain.THREAT.value),
        ("clipboard", PolicyDomain.DATA_PROTECTION.value),
        ("google_drive", PolicyDomain.DATA_PROTECTION.value),
        ("totally_unknown", PolicyDomain.GENERAL.value),
        (None, PolicyDomain.GENERAL.value),
    ],
)
def test_domain_for_event_type(event_type, expected):
    assert domain_for_event_type(event_type) == expected


def test_domains_for_role_admin_and_analyst_unrestricted():
    assert domains_for_role("ADMIN") is None
    assert domains_for_role("ANALYST") is None
    assert domains_for_role("MANAGER") is None
    assert domains_for_role("VIEWER") is None
    assert domains_for_role(None) is None


def test_domains_for_role_domain_admins_scoped():
    assert domains_for_role("THREAT_ADMIN") == {"threat"}
    assert domains_for_role("DATA_PROTECTION_ADMIN") == {"data_protection"}
    assert domains_for_role("ACCESS_CONTROL_ADMIN") == {"access_control"}
    # Case-insensitive on the role string.
    assert domains_for_role("threat_admin") == {"threat"}


def test_is_domain_admin():
    assert is_domain_admin("THREAT_ADMIN") is True
    assert is_domain_admin("ADMIN") is False
    assert is_domain_admin(None) is False


# ── app.services.domain_service ──────────────────────────────────────────────

def test_get_user_domains_and_is_domain_admin():
    admin = _FakeUser("ADMIN")
    threat_admin = _FakeUser("THREAT_ADMIN")

    assert get_user_domains(admin) is None
    assert user_is_domain_admin(admin) is False

    assert get_user_domains(threat_admin) == {"threat"}
    assert user_is_domain_admin(threat_admin) is True


def test_user_can_access_domain_super_admin_sees_everything():
    admin = _FakeUser("ADMIN")
    assert user_can_access_domain(admin, "threat") is True
    assert user_can_access_domain(admin, "data_protection") is True
    assert user_can_access_domain(admin, None) is True


def test_user_can_access_domain_scoped_admin_restricted():
    threat_admin = _FakeUser("THREAT_ADMIN")
    assert user_can_access_domain(threat_admin, "threat") is True
    assert user_can_access_domain(threat_admin, "data_protection") is False
    # A policy with no domain stamp falls back to "general", which a scoped
    # admin does NOT implicitly own.
    assert user_can_access_domain(threat_admin, None) is False


def test_user_can_access_domain_accepts_dict_shaped_user():
    # get_current_user's optional_auth path returns a dict, not a User model.
    assert user_can_access_domain({"role": "ACCESS_CONTROL_ADMIN"}, "access_control") is True
    assert user_can_access_domain({"role": "ACCESS_CONTROL_ADMIN"}, "threat") is False


def test_build_domain_mongo_filter_unrestricted_returns_none():
    assert build_domain_mongo_filter(_FakeUser("ADMIN")) is None
    assert build_domain_mongo_filter(_FakeUser("VIEWER")) is None


def test_build_domain_mongo_filter_scoped_admin():
    f = build_domain_mongo_filter(_FakeUser("THREAT_ADMIN"))
    assert f is not None
    assert "$or" in f
    # First clause matches the policy_domain stamp directly.
    assert {"policy_domain": {"$in": ["threat"]}} in f["$or"]
    # Second clause backstops pre-existing docs via event_type, and must not
    # include any data_protection event types.
    event_clause = next(c for c in f["$or"] if "event_type" in c)
    assert "clipboard" not in event_clause["event_type"]["$in"]
    assert "usb" in event_clause["event_type"]["$in"]


@pytest.mark.asyncio
async def test_build_domain_sql_filter(db_session):
    from app.models.policy import Policy
    import uuid

    threat_policy = Policy(
        id=uuid.uuid4(), name="usb-block", status="active", priority=100,
        type="usb", domain="threat", conditions={}, actions={},
        created_by=uuid.uuid4(),
    )
    dp_policy = Policy(
        id=uuid.uuid4(), name="clipboard-block", status="active", priority=100,
        type="clipboard", domain="data_protection", conditions={}, actions={},
        created_by=uuid.uuid4(),
    )
    db_session.add_all([threat_policy, dp_policy])
    await db_session.commit()

    from sqlalchemy import select

    # Unrestricted (ADMIN) → no filter clause, sees both.
    admin_filter = build_domain_sql_filter(_FakeUser("ADMIN"), Policy)
    assert admin_filter is None

    # THREAT_ADMIN → only the threat-domain policy.
    threat_filter = build_domain_sql_filter(_FakeUser("THREAT_ADMIN"), Policy)
    assert threat_filter is not None
    rows = (await db_session.execute(select(Policy).where(threat_filter))).scalars().all()
    assert [r.name for r in rows] == ["usb-block"]
