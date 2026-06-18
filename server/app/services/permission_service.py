"""
Permission resolution.

Effective permission set for a user is the union of three sources, taken
in this order:

1. ADMIN wildcard. If the user's enum role is ADMIN, they implicitly get
   every seeded permission. This is a hard floor — it cannot be removed
   by clearing direct grants, and it sidesteps any accidental divergence
   between the role row's `role_permissions` and the canonical list.
2. Normalized ``role_permissions`` for the user's ``role_id`` FK.
3. Direct ``user_permissions`` grants (Phase-1.x addition).

Plus a fallback: if a user has a ``UserRole`` enum value but no ``role_id``
(pre-migration rows, or users created outside the admin UI), we fall back
to the hardcoded default set per enum role. This keeps behaviour stable
for legacy accounts without requiring a role-id backfill.

The service is read-only and safe to call on every request; it issues up
to three cheap SELECTs on the hot path and caches nothing.
"""

from __future__ import annotations

from typing import Iterable
from uuid import UUID

from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.permission import Permission, RolePermission, UserPermission


# Canonical full permission set. Must stay in sync with
# migration 006_rbac_permissions' seed list.
_ALL_PERMISSIONS: frozenset[str] = frozenset({
    "view_events", "view_alerts", "export_events",
    "create_policy", "update_policy", "delete_policy", "assign_policy",
    "manage_users", "view_users", "manage_roles",
    "view_dashboard", "create_dashboard", "edit_dashboard", "delete_dashboard",
    "view_all_departments",
})

# Fallback defaults for users with a UserRole enum value but no role_id FK.
_ROLE_DEFAULTS: dict[str, frozenset[str]] = {
    "ADMIN":   _ALL_PERMISSIONS,
    "ANALYST": frozenset({"view_events", "view_alerts", "view_dashboard", "view_users"}),
    "MANAGER": frozenset({"view_events", "export_events", "view_dashboard", "view_users"}),
    "VIEWER":  frozenset({"view_events", "view_dashboard"}),
    "AGENT":   frozenset(),
}


def _role_str(role) -> str:
    value = getattr(role, "value", role)
    return str(value).upper() if value else ""


async def get_user_permissions(db: AsyncSession, user: User) -> set[str]:
    """
    Resolve the full set of permission names granted to this user.
    Inactive users resolve to the empty set regardless of role.
    """
    if user is None or not getattr(user, "is_active", True):
        return set()

    # 1. ADMIN is a hard wildcard.
    if _role_str(user.role) == "ADMIN":
        return set(_ALL_PERMISSIONS)

    # 2. Normalized role grants (if any).
    role_perms: set[str] = set()
    if getattr(user, "role_id", None) is not None:
        stmt = (
            select(Permission.name)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == user.role_id)
        )
        rows = (await db.execute(stmt)).scalars().all()
        role_perms = {r for r in rows if r}

    # 3. Direct user grants (additive).
    stmt_u = (
        select(Permission.name)
        .join(UserPermission, UserPermission.permission_id == Permission.id)
        .where(UserPermission.user_id == user.id)
    )
    direct_perms = {r for r in (await db.execute(stmt_u)).scalars().all() if r}

    # 4. Enum fallback: only used when normalized source is empty.
    fallback = _ROLE_DEFAULTS.get(_role_str(user.role), frozenset())

    return role_perms | direct_perms | set(fallback if not role_perms else frozenset())


async def user_has_permission(
    db: AsyncSession, user: User, permission: str
) -> bool:
    perms = await get_user_permissions(db, user)
    return permission in perms


async def get_role_permissions(db: AsyncSession, role_id: UUID) -> set[str]:
    """Permissions attached to a role (admin UI use)."""
    stmt = (
        select(Permission.name)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role_id)
    )
    return {r for r in (await db.execute(stmt)).scalars().all() if r}


async def get_direct_user_permissions(
    db: AsyncSession, user_id: UUID
) -> set[str]:
    """Permissions granted directly to the user (bypassing role)."""
    stmt = (
        select(Permission.name)
        .join(UserPermission, UserPermission.permission_id == Permission.id)
        .where(UserPermission.user_id == user_id)
    )
    return {r for r in (await db.execute(stmt)).scalars().all() if r}


async def list_all_permissions(db: AsyncSession) -> list[dict]:
    """All seeded permissions, sorted by name. Used by the admin UI to
    render the permission-picker checklist."""
    stmt = select(Permission).order_by(Permission.name)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {"id": str(p.id), "name": p.name, "description": p.description or ""}
        for p in rows
    ]


async def set_user_direct_permissions(
    db: AsyncSession,
    user_id: UUID,
    permission_names: Iterable[str],
) -> set[str]:
    """
    Replace the set of direct grants for a user.

    Implemented as a DELETE-then-INSERT transaction so an empty list
    genuinely clears all direct grants (revocation semantics). Unknown
    permission names are ignored — the caller already validated them in
    the API layer, but we don't want a typo to crash the transaction.

    Does not modify the caller's session commit/rollback discipline.
    """
    names = {n.strip() for n in permission_names if n and n.strip()}

    # Look up IDs for the requested permissions (silently skip unknowns).
    id_stmt = select(Permission.id, Permission.name).where(
        Permission.name.in_(names)
    ) if names else select(Permission.id, Permission.name).where(False)
    rows = (await db.execute(id_stmt)).all()
    id_by_name = {name: pid for pid, name in rows}

    # Replace.
    await db.execute(
        delete(UserPermission).where(UserPermission.user_id == user_id)
    )
    for name in names:
        pid = id_by_name.get(name)
        if pid is None:
            continue
        await db.execute(
            insert(UserPermission).values(user_id=user_id, permission_id=pid)
        )

    return set(id_by_name.keys())
