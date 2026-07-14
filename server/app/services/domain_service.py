"""
Domain-scoped RBAC — the policy-domain visibility layer.

Parallel to :mod:`app.services.abac_service` (which scopes by department /
clearance). This module scopes by *policy domain*: a domain-admin role
(THREAT_ADMIN / DATA_PROTECTION_ADMIN / ACCESS_CONTROL_ADMIN) may only see and
control the policies — and the events / alerts / incidents / dashboards
derived from them — within its domain. The global ADMIN and the read-only
ANALYST / MANAGER / VIEWER roles are unrestricted by domain (``None``).

Filter builders return ``None`` when the user is unrestricted, so callers do::

    dom = build_domain_mongo_filter(current_user)
    if dom is not None:
        query = merge_mongo_filter(query, dom)      # AND-merge
"""
from __future__ import annotations

from typing import Any, Optional, Set

from app.core.domains import domains_for_role, is_domain_admin, EVENT_TYPE_DOMAIN


def role_of(user: Any) -> Optional[str]:
    """Extract the role string from a User model or a dict."""
    if user is None:
        return None
    r = getattr(user, "role", None)
    if r is None and isinstance(user, dict):
        r = user.get("role")
    return getattr(r, "value", r)


def get_user_domains(user: Any) -> Optional[Set[str]]:
    """Allowed-domain set, or ``None`` when the user is unrestricted."""
    return domains_for_role(role_of(user))


def user_is_domain_admin(user: Any) -> bool:
    return is_domain_admin(role_of(user))


def user_can_access_domain(user: Any, domain: Optional[str]) -> bool:
    """True if the user may see/act on the given policy domain."""
    allowed = get_user_domains(user)
    if allowed is None:
        return True
    return (domain or "general") in allowed


def build_domain_mongo_filter(user: Any) -> Optional[dict]:
    """Mongo predicate scoping events / alerts / incidents to the user's
    domain(s), or ``None`` when unrestricted.

    Matches a document whose ``policy_domain`` is in the allowed set (new
    events are stamped at ingest) OR whose ``event_type`` maps to one of the
    allowed domains — so the filter works for pre-existing/derived docs that
    predate the ``policy_domain`` stamp (alerts, incidents, old events).
    """
    domains = get_user_domains(user)
    if domains is None:
        return None
    ev_types = sorted(et for et, d in EVENT_TYPE_DOMAIN.items() if d.value in domains)
    clauses: list = [{"policy_domain": {"$in": sorted(domains)}}]
    if ev_types:
        clauses.append({"event_type": {"$in": ev_types}})
    return {"$or": clauses}


def build_domain_sql_filter(user: Any, policy_model: Any):
    """SQLAlchemy predicate scoping ``policies`` to the user's domain(s), or
    ``None`` when unrestricted."""
    domains = get_user_domains(user)
    if domains is None:
        return None
    return policy_model.domain.in_(sorted(domains))
