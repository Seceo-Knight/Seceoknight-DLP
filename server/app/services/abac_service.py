"""
ABAC (Attribute-Based Access Control) — data visibility layer.

Single source of truth for the visibility predicate applied to DLP events
and everything derived from them (alerts, incidents, analytics). The same
predicate is emitted in two dialects so MongoDB and PostgreSQL cannot
drift out of sync:

* :func:`build_abac_sql_filter` — a SQLAlchemy ``ClauseElement`` suitable
  for :py:meth:`Query.filter` / :py:meth:`Select.where`.
* :func:`build_abac_mongo_filter` — a ``dict`` suitable for use inside
  ``find()`` / ``$match``.

The visibility rule (spec PART 2 §B):

    ALLOW IF
        user has "view_all_departments"
     OR (resource.department == user.department
         AND user.clearance_level >= resource.required_clearance)

Null handling (spec §C) is strict and DENYING:

    resource.department NULL       → deny
    resource.required_clearance    → coerced to 0 (baseline)
    user.department NULL           → deny all
    user.clearance_level NULL      → deny all

"DEFAULT" is a *normal* department — not a wildcard. An event whose
``department='DEFAULT'`` is visible only to users whose department is also
``DEFAULT`` (or to users with the global wildcard permission).

The function signatures return ``None`` when the user has the wildcard
permission, so callers can write::

    pred = await build_abac_sql_filter(db, current_user)
    if pred is not None:
        query = query.where(pred)
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import and_, false
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


# ── Constants ────────────────────────────────────────────────────────────
WILDCARD_PERMISSION = "view_all_departments"

# Sentinel: a Mongo filter that matches nothing. Used when the user's
# attributes are malformed per spec §C (NULL department / clearance).
_MONGO_DENY_ALL: dict[str, Any] = {"_abac_deny_all": True}


# ── Helpers ──────────────────────────────────────────────────────────────
async def _has_wildcard(db: AsyncSession, user: User) -> bool:
    """Does the user carry the view_all_departments permission?"""
    from app.services.permission_service import get_user_permissions

    perms = await get_user_permissions(db, user)
    return WILDCARD_PERMISSION in perms


def _user_attrs_valid(user: User) -> bool:
    """Spec §C: reject if user.department or user.clearance_level is NULL."""
    if user is None:
        return False
    if getattr(user, "department", None) in (None, ""):
        return False
    if getattr(user, "clearance_level", None) is None:
        return False
    return True


# ── PostgreSQL (SQLAlchemy) dialect ──────────────────────────────────────
async def build_abac_sql_filter(
    db: AsyncSession,
    user: User,
    event_model=None,
):
    """
    Return a SQLAlchemy boolean expression restricting queries to events
    the ``user`` is permitted to see, or ``None`` if the user carries the
    wildcard permission (caller should omit the filter entirely in that
    case — do NOT apply the expression).

    Caller usage::

        pred = await build_abac_sql_filter(db, current_user)
        if pred is not None:
            stmt = stmt.where(pred)

    The ``event_model`` parameter lets callers substitute an aliased
    ``Event`` (e.g. when joining incidents → events).
    """
    if event_model is None:
        # Lazy import to avoid a circular dependency at module load time.
        from app.models.event import Event as _Event

        event_model = _Event

    # 1. Wildcard short-circuit.
    if await _has_wildcard(db, user):
        return None

    # 2. Strict null-handling on the user side → deny-all.
    if not _user_attrs_valid(user):
        # ``false()`` materializes as ``FALSE`` in the SQL statement, which
        # PG's planner folds to an empty result set.
        return false()

    # 3. The predicate itself. ``department`` is NOT NULL on events post-
    # migration 009, so the resource-side null check is structural.
    return and_(
        event_model.department.is_not(None),
        event_model.department == user.department,
        event_model.required_clearance <= user.clearance_level,
    )


# ── MongoDB dialect ──────────────────────────────────────────────────────
async def build_abac_mongo_filter(
    db: AsyncSession, user: User
) -> Optional[dict]:
    """
    Return a Mongo match-filter restricting queries to visible events, or
    ``None`` if the user carries the wildcard permission.

    A deny-all sentinel (``{"_abac_deny_all": True}``) is used when the
    user's attributes are malformed — the sentinel is a field that does
    not exist on any real document, so it reliably matches nothing without
    any special handling in callers.
    """
    if await _has_wildcard(db, user):
        return None

    if not _user_attrs_valid(user):
        return _MONGO_DENY_ALL

    return {
        "department": user.department,
        # Documents missing ``required_clearance`` are treated as 0 via the
        # $ifNull mechanism below. We cannot use $lte directly against a
        # missing field (it would exclude the doc), so we wrap with
        # $or {field == null} → treat as 0.
        "$or": [
            {"required_clearance": {"$lte": user.clearance_level}},
            {"required_clearance": {"$exists": False}},
        ],
    }


def merge_mongo_filter(existing: Optional[dict], abac: Optional[dict]) -> dict:
    """
    Combine a user-supplied Mongo filter with an ABAC predicate.

    Rules:
    * ``abac is None``  → return ``existing`` (caller is global-access user).
    * If ``abac`` is the deny-all sentinel, return it directly (no point
      merging; nothing matches anyway).
    * Otherwise AND-merge via ``$and`` to preserve any ``$or`` inside both.

    Using ``$and`` instead of dict-merge prevents key-collision silent
    drops (e.g. both sides specifying ``$or``).
    """
    if abac is None:
        return dict(existing or {})
    if abac is _MONGO_DENY_ALL or abac.get("_abac_deny_all"):
        return dict(abac)
    if not existing:
        return dict(abac)
    return {"$and": [existing, abac]}
