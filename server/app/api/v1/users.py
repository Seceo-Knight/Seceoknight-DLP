"""
Users API Endpoints
User management and profile operations

Admin CRUD is gated by `require_permission("manage_users")`. Read endpoints
(list/get) retain the legacy `require_role("admin")` gate for backwards
compatibility with existing callers — admins always have manage_users, so
behavior is unchanged. New endpoints (POST /users) use the permission gate
directly.
"""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.security import (
    get_current_user,
    require_role,
    require_permission,
    validate_password_strength,
)
from app.core.config import settings
from app.core.database import get_db
from app.services.user_service import UserService

logger = structlog.get_logger()
router = APIRouter()


class UserOut(BaseModel):
    id: Optional[str] = None
    username: Optional[str] = None
    # NOTE: response uses `str` not `EmailStr`. Legacy rows (e.g. the bootstrap
    # `admin` account) store non-email values in the email column. The CREATE
    # endpoint still enforces EmailStr on input.
    email: str
    full_name: str
    role: str
    organization: str
    department: Optional[str] = None
    clearance_level: int = 1
    is_active: bool = True
    created_at: Optional[datetime] = None
    # Effective permission set (role defaults ∪ direct grants). Sorted.
    permissions: List[str] = []
    # Direct grants only (subset of `permissions`). Useful for the edit UI
    # to pre-tick the "extras" without losing the role-vs-direct distinction.
    direct_permissions: List[str] = []


class UserCreateRequest(BaseModel):
    """Admin create-user payload. Username and email are distinct fields —
    username is optional (used for display/login alias), email is the
    canonical identifier and must be unique."""

    email: EmailStr
    password: str
    full_name: str
    role: str = Field(default="VIEWER")
    organization: str = Field(default="SeceoKnight")
    username: Optional[str] = None
    department: Optional[str] = None
    clearance_level: int = Field(default=1, ge=0, le=10)
    # Optional direct-permission grants, unioned on top of the role defaults.
    permissions: Optional[List[str]] = None


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    department: Optional[str] = None
    clearance_level: Optional[int] = Field(default=None, ge=0, le=10)
    # When present (even empty list), replaces the user's direct grants.
    # `None` means "don't touch grants" — the edit UI can omit the field
    # when it only wants to change role/dept/etc.
    permissions: Optional[List[str]] = None


def _to_out(user, effective: Optional[set] = None, direct: Optional[set] = None) -> dict:
    role_val = getattr(user.role, "value", user.role)
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": str(role_val),
        "organization": user.organization or "SeceoKnight",
        "department": user.department,
        "clearance_level": getattr(user, "clearance_level", 1) or 1,
        "is_active": user.is_active,
        "mfa_enabled": getattr(user, "mfa_enabled", False) or False,
        "created_at": user.created_at,
        "permissions": sorted(effective) if effective is not None else [],
        "direct_permissions": sorted(direct) if direct is not None else [],
    }


async def _to_out_with_perms(db: AsyncSession, user) -> dict:
    """_to_out + resolve effective & direct permission sets for the row."""
    from app.services.permission_service import (
        get_user_permissions,
        get_direct_user_permissions,
    )
    effective = await get_user_permissions(db, user)
    direct = await get_direct_user_permissions(db, user.id)
    return _to_out(user, effective=effective, direct=direct)


@router.get("/me", response_model=UserOut)
async def get_current_user_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get current user's profile
    """
    user_service = UserService(db)
    user = await user_service.get_user_by_id(str(current_user.id))

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return await _to_out_with_perms(db, user)


@router.get("/", response_model=List[UserOut])
async def get_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    role: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    _: dict = Depends(require_permission("view_users")),
    db: AsyncSession = Depends(get_db),
):
    """
    List users. Requires the `view_users` permission (ADMIN, ANALYST, MANAGER).
    """
    user_service = UserService(db)
    users = await user_service.get_all_users(
        skip=skip,
        limit=limit,
        role=role,
        is_active=is_active,
    )
    return [await _to_out_with_perms(db, u) for u in users]


@router.post("/", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreateRequest,
    current_user=Depends(require_permission("manage_users")),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new user. Requires `manage_users` permission.

    Notes:
    * Email is the unique login identifier; username is an optional alias.
    * Password must satisfy the same complexity rules the auth flow enforces.
    * Role string is coerced to uppercase to match the UserRole enum.
    """
    if not validate_password_strength(payload.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {settings.PASSWORD_MIN_LENGTH} "
                   "characters and contain uppercase, lowercase, digit, and "
                   "special character",
        )

    # Coerce + whitelist role to match the enum.
    role_in = (payload.role or "VIEWER").strip().upper()
    allowed_roles = {"ADMIN", "ANALYST", "MANAGER", "VIEWER"}
    if role_in not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{payload.role}'. Allowed: {sorted(allowed_roles)}",
        )

    # Role escalation protection: only ADMIN can mint ADMIN accounts.
    caller_role = str(getattr(current_user.role, "value", current_user.role)).upper()
    if role_in == "ADMIN" and caller_role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can assign the ADMIN role.",
        )

    user_service = UserService(db)
    try:
        user = await user_service.create_user(
            email=payload.email,
            password=payload.password,
            full_name=payload.full_name,
            role=role_in,
            organization=payload.organization or "SeceoKnight",
            username=payload.username,
            department=payload.department,
            clearance_level=payload.clearance_level,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Apply direct permission grants, if any. Non-admins cannot grant the
    # `manage_roles` escalation permission (ADMIN-tier capability).
    if payload.permissions is not None:
        from app.services.permission_service import set_user_direct_permissions

        perms_to_set = [p for p in payload.permissions if isinstance(p, str)]
        if caller_role != "ADMIN" and "manage_roles" in perms_to_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can grant 'manage_roles'.",
            )
        await set_user_direct_permissions(db, user.id, perms_to_set)
        await db.commit()
        await db.refresh(user)

    logger.info(
        "User created via admin UI",
        creator_id=str(current_user.id),
        new_user_id=str(user.id),
        role=role_in,
        direct_perms=len(payload.permissions or []),
    )
    return await _to_out_with_perms(db, user)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: str,
    _: dict = Depends(require_permission("view_users")),
    db: AsyncSession = Depends(get_db),
):
    """
    Get specific user by ID. Requires `view_users` permission.
    """
    user_service = UserService(db)
    user = await user_service.get_user_by_id(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return _to_out(user)


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user=Depends(require_permission("manage_users")),
    db: AsyncSession = Depends(get_db),
):
    """
    Update a user. Requires `manage_users` permission.

    Role escalation protection: non-admins cannot promote a user to ADMIN,
    and non-admins cannot modify a user whose current role is ADMIN (you
    can't demote an admin unless you are one).
    """
    caller_role = str(getattr(current_user.role, "value", current_user.role)).upper()

    # Load target to evaluate escalation guards.
    user_service = UserService(db)
    existing = await user_service.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")

    target_role = str(getattr(existing.role, "value", existing.role)).upper()
    if caller_role != "ADMIN" and target_role == "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can modify admin accounts.",
        )

    if user_update.role is not None:
        new_role = user_update.role.strip().upper()
        allowed_roles = {"ADMIN", "ANALYST", "MANAGER", "VIEWER"}
        if new_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role '{user_update.role}'. Allowed: {sorted(allowed_roles)}",
            )
        if new_role == "ADMIN" and caller_role != "ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can assign the ADMIN role.",
            )
        user_update.role = new_role

    user = await user_service.update_user(
        user_id=user_id,
        full_name=user_update.full_name,
        role=user_update.role,
        is_active=user_update.is_active,
        department=user_update.department,
        clearance_level=user_update.clearance_level,
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Direct permission grants: if the field is provided (even as []), it
    # replaces the user's existing direct grants — this is the revocation
    # path. Non-admins cannot grant `manage_roles`.
    if user_update.permissions is not None:
        from app.services.permission_service import set_user_direct_permissions

        perms_to_set = [p for p in user_update.permissions if isinstance(p, str)]
        if caller_role != "ADMIN" and "manage_roles" in perms_to_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can grant 'manage_roles'.",
            )
        await set_user_direct_permissions(db, user.id, perms_to_set)
        await db.commit()
        await db.refresh(user)

    logger.info(
        "User updated",
        user_id=user_id,
        updated_by=str(current_user.id),
        direct_perms_touched=user_update.permissions is not None,
    )
    return await _to_out_with_perms(db, user)


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    hard: bool = Query(
        default=False,
        description="If true, permanently remove the row. Default is soft (is_active=false).",
    ),
    current_user=Depends(require_permission("manage_users")),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a user. Requires `manage_users`.

    Default: soft delete (is_active=false). Pass `?hard=true` to permanently
    remove the row from the database. Related rows in audit_logs / incidents
    have ON DELETE SET NULL semantics, so historical events are preserved
    but the actor reference is nulled.

    Self-delete prevention and admin-escalation guards apply to both modes.
    """
    if str(current_user.id) == str(user_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own account.",
        )

    user_service = UserService(db)

    caller_role = str(getattr(current_user.role, "value", current_user.role)).upper()
    target = await user_service.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target_role = str(getattr(target.role, "value", target.role)).upper()
    if caller_role != "ADMIN" and target_role == "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can remove admin accounts.",
        )

    if hard:
        success = await user_service.hard_delete_user(user_id)
        if not success:
            raise HTTPException(status_code=404, detail="User not found")
        logger.info(
            "User hard-deleted",
            user_id=user_id,
            deleted_by=str(current_user.id),
            target_role=target_role,
        )
        return {"message": "User permanently deleted", "hard": True}

    success = await user_service.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(
        "User deactivated",
        user_id=user_id,
        deactivated_by=str(current_user.id),
    )
    return {"message": "User deactivated successfully", "hard": False}


@router.post("/{user_id}/mfa/reset", status_code=200)
async def admin_reset_user_mfa(
    user_id: str,
    current_user: dict = Depends(require_role("ADMIN")),
    db: AsyncSession = Depends(get_db),
):
    """
    Admin endpoint: disable and clear MFA for any user account.

    Useful for account recovery when a user loses access to their
    authenticator app. The user can re-enable MFA themselves afterwards
    from Settings → Two-Factor Authentication.
    """
    user_service = UserService(db)
    target = await user_service.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Clear MFA fields directly on the model
    target.mfa_enabled = False
    target.mfa_secret = None
    db.add(target)
    await db.commit()

    logger.info(
        "Admin reset MFA for user",
        target_user_id=user_id,
        target_email=target.email,
        admin_id=str(current_user.id),
    )

    return {"message": f"MFA has been disabled for {target.email}"}
