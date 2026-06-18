"""
Authentication API Endpoints
User login, registration, token refresh, SSO exchange
"""

from datetime import datetime, timedelta
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt as jose_jwt, JWTError, ExpiredSignatureError
import structlog

from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    validate_password_strength,
    decode_token,
    get_current_user,
    require_role,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.cache import get_cache
from app.services.user_service import UserService
from app.services.blacklist_service import TokenBlacklistService
from app.services.audit_service import audit_log
from app.models.user import User

logger = structlog.get_logger()
router = APIRouter()


class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    organization: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    username: str
    current_password: str
    new_password: str
    new_password_confirm: str


@router.post("/register", response_model=Dict, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Register a new user (admin-only).

    SECURITY: Open self-registration is disabled. New accounts must be
    created by an existing admin. Without this guard, any anonymous
    attacker could register a VIEWER account and read every DLP event,
    policy, classification hit, clipboard capture, and file path in the
    system, since the authorization layer has no per-tenant scoping.
    """
    # Only admins can provision new accounts.
    # user.role is a UserRole enum instance; str(enum) returns
    # "ClassName.VALUE" not "VALUE", so extract .value first.
    role_val = getattr(current_user, "role", "")
    role_str = str(getattr(role_val, "value", role_val)).upper()
    if role_str != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can register new users.",
        )

    # Validate password strength
    if not validate_password_strength(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters "
                   "and contain uppercase, lowercase, digit, and special character",
        )

    # Create user service
    user_service = UserService(db)

    try:
        # Create user in database
        user = await user_service.create_user(
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name,
            organization=user_data.organization,
            role="VIEWER",  # Default role for new users
        )

        logger.info(
            "User registered by admin",
            admin_id=str(current_user.id),
            new_user_id=str(user.id),
            new_user_email=user.email,
        )

        return {
            "message": "User registered successfully",
            "email": user.email,
            "user_id": str(user.id),
        }

    except ValueError as e:
        # User already exists or other validation error
        logger.warning("Registration failed", email=user_data.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    User login with email and password
    Returns access and refresh tokens

    SECURITY: dedicated rate limiter bucketed by (client_ip + username)
    via Redis. 10 failed attempts in a 5-minute window (per key) triggers
    a 429 until the window expires. This is on TOP of the global
    RateLimitMiddleware and is specifically designed to blunt credential
    stuffing and slow-and-low brute force.
    """
    # ── Rate limit BEFORE touching the DB ─────────────────────────────
    client_ip = request.client.host if request.client else "unknown"
    username = (form_data.username or "").strip().lower()
    rl_key = f"login_fail:{client_ip}:{username}"
    try:
        cache = get_cache()
        failed = await cache.get(rl_key)
        if failed is not None:
            try:
                failed = int(failed)
            except (TypeError, ValueError):
                failed = 0
            if failed >= 10:
                logger.warning(
                    "Login rate limit hit",
                    ip=client_ip, username=username, failed=failed,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed login attempts. Try again in a few minutes.",
                    headers={"Retry-After": "300"},
                )
    except HTTPException:
        raise
    except Exception:
        # Redis unreachable → fail open on the limiter, the global
        # middleware still caps overall throughput.
        pass

    # Create user service
    user_service = UserService(db)

    # Authenticate user
    user = await user_service.authenticate_user(
        email=form_data.username,
        password=form_data.password,
    )

    if not user:
        logger.warning("Login failed - invalid credentials", email=form_data.username)
        # Increment the failed-attempts counter with a 5-minute TTL.
        try:
            cache = get_cache()
            current = await cache.incr(rl_key)
            if current == 1:
                await cache.expire(rl_key, 300)  # 5 minutes
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Successful login → clear the counter for this (ip, username).
    try:
        cache = get_cache()
        await cache.delete(rl_key)
    except Exception:
        pass

    # Check if password change is required
    if getattr(user, "must_change_password", False):
        logger.info("Login requires password change", email=user.email)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required. Use /api/v1/auth/change-password to set a new password before logging in.",
        )

    # Create tokens
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
        }
    )

    refresh_token = create_refresh_token(
        data={
            "sub": str(user.id),
            "email": user.email,
        }
    )

    logger.info("User logged in", user_id=str(user.id))

    await audit_log(user.id, "auth.login", {})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    Rejects tokens that have been blacklisted (e.g. after logout).
    """
    try:
        # Check blacklist BEFORE decoding — a logged-out refresh token must not
        # be able to mint new access tokens for its remaining 7-day lifetime.
        try:
            cache = get_cache()
            blacklist_service = TokenBlacklistService(cache)
            if await blacklist_service.is_blacklisted(request.refresh_token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token has been revoked",
                )
        except HTTPException:
            raise
        except Exception:
            # Redis unavailable — fail open in dev, fail closed in production
            if settings.ENVIRONMENT.lower() == "production":
                logger.error("Redis unavailable — cannot verify refresh token blacklist")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Authentication service temporarily unavailable",
                )

        payload = decode_token(request.refresh_token)

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        user_service = UserService(db)
        user = await user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )

        # Create new tokens
        access_token = create_access_token(
            data={
                "sub": str(user.id),
                "email": user.email,
                "role": user.role,
            }
        )

        new_refresh_token = create_refresh_token(
            data={
                "sub": str(user.id),
                "email": user.email,
            }
        )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
        }

    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Change the authenticated user's password.

    SECURITY: A valid JWT is required. The `username` field in the
    request body is IGNORED — the password is always rotated for the
    token bearer. This prevents unauthenticated brute-force of
    `current_password` against arbitrary accounts.
    """
    if request.new_password != request.new_password_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New passwords do not match",
        )

    if not validate_password_strength(request.new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters "
                   "and contain uppercase, lowercase, digit, and special character",
        )

    user_service = UserService(db)

    # Re-verify the current password for the authenticated user only.
    # The username from the request body is NOT trusted.
    user = await user_service.authenticate_user(
        email=current_user.email,
        password=request.current_password,
    )
    if not user or str(user.id) != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    # Update password
    success = await user_service.update_password(
        user_id=str(user.id),
        current_password=request.current_password,
        new_password=request.new_password,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password",
        )

    # Clear must_change_password flag if it was set
    if getattr(user, "must_change_password", False):
        from sqlalchemy import text as sa_text
        await db.execute(
            sa_text("UPDATE users SET must_change_password = FALSE WHERE id = :uid"),
            {"uid": user.id},
        )
        await db.commit()

    logger.info("Password changed", user_id=str(user.id))
    return {"message": "Password changed successfully"}


class LogoutRequest(BaseModel):
    refresh_token: str = ""


@router.post("/logout")
async def logout(
    request: Request,
    body: LogoutRequest = LogoutRequest(),
    current_user: User = Depends(get_current_user)
):
    """
    User logout — blacklists both the access token and the refresh token.

    Pass the refresh token in the request body so it cannot be used to mint
    new access tokens after logout:
        { "refresh_token": "<your-refresh-token>" }

    The refresh_token field is optional for backwards compatibility, but
    omitting it leaves the refresh token alive until it naturally expires
    (7 days), which is a security gap.
    """
    access_token = request.headers["authorization"].split(" ")[1]
    cache = get_cache()
    blacklist_service = TokenBlacklistService(cache)

    # Blacklist the access token
    access_expires_in = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    await blacklist_service.add_to_blacklist(access_token, access_expires_in)

    # Blacklist the refresh token if provided
    if body.refresh_token:
        try:
            refresh_expires_in = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            await blacklist_service.add_to_blacklist(body.refresh_token, refresh_expires_in)
            logger.info("Refresh token blacklisted on logout", email=current_user.email)
        except Exception as e:
            # Don't fail the logout if the refresh token is already expired/invalid
            logger.warning("Could not blacklist refresh token", error=str(e))
    else:
        logger.warning(
            "Logout without refresh_token — refresh token remains active until expiry",
            email=current_user.email,
        )

    logger.info("User logged out", email=current_user.email)
    await audit_log(current_user.id, "auth.logout")

    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict:
    """
    Return the authenticated user's identity + resolved permissions.

    This is the source of truth the frontend uses to drive UI gating.
    Never trust the role embedded in a JWT for authorization decisions —
    that's just a hint for optimistic UI; this endpoint is what actually
    backs show/hide logic, and the server re-checks on every protected call.
    """
    from app.services.permission_service import get_user_permissions

    permissions = sorted(await get_user_permissions(db, current_user))
    role_value = getattr(current_user.role, "value", str(current_user.role))

    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": role_value,
        "role_id": str(current_user.role_id) if current_user.role_id else None,
        "department": current_user.department,
        "organization": current_user.organization,
        "is_active": current_user.is_active,
        "permissions": permissions,
    }


@router.get("/users/check")
async def check_user_exists(
    email: EmailStr = Query(..., description="Email address to check"),
    _: User = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> Dict:
    """
    Admin-only probe: does a user with this email exist in the DLP system?

    Used by the SIEM to reconcile its local `dlpRegistered` flag when an
    admin deletes a DLP account directly from the admin panel. Without
    this, the SIEM would keep pushing stale SSO logins for a user that
    no longer exists, and the exchange at /sso/exchange would 401.
    """
    user_service = UserService(db)
    user = await user_service.get_user_by_email(email.strip().lower())
    return {"exists": user is not None}


# ── SSO Exchange ─────────────────────────────────────────────────────────
# The SIEM generates a short-lived JWT "exchange token" signed with
# DLP_SSO_SECRET. This endpoint verifies it, looks up the user in the
# DLP database, and issues standard DLP access+refresh tokens signed
# with SECRET_KEY. The exchange token is NOT the same as a DLP token.
#
# Two distinct secrets:
#   DLP_SSO_SECRET  →  verify exchange token from SIEM (never used to issue)
#   SECRET_KEY      →  issue DLP tokens (never used to verify SIEM tokens)


class SSOExchangeRequest(BaseModel):
    token: str


@router.post("/sso/exchange", response_model=TokenResponse)
async def sso_exchange(
    body: SSOExchangeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Exchange a SIEM-issued SSO token for DLP access + refresh tokens.

    Public endpoint — no Authorization header required. The exchange token
    itself serves as proof of authentication (signed by DLP_SSO_SECRET,
    30-second TTL, single-use nonce).
    """

    # ── Guard: SSO must be configured ────────────────────────────────
    if not settings.DLP_SSO_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO is not configured",
        )

    # ── Decode + verify exchange token ───────────────────────────────
    try:
        payload = jose_jwt.decode(
            body.token,
            settings.DLP_SSO_SECRET,
            algorithms=["HS256"],
        )
    except ExpiredSignatureError:
        logger.warning("SSO exchange: token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Exchange token has expired",
        )
    except JWTError as e:
        logger.warning("SSO exchange: invalid token", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid exchange token",
        )

    # ── Validate required claims ─────────────────────────────────────
    if payload.get("purpose") != "sso_exchange":
        logger.warning("SSO exchange: wrong purpose", purpose=payload.get("purpose"))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid exchange token: wrong purpose",
        )

    if payload.get("iss") != "seceoknight-siem":
        logger.warning("SSO exchange: wrong issuer", iss=payload.get("iss"))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid exchange token: wrong issuer",
        )

    nonce = payload.get("nonce")
    if not nonce:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid exchange token: missing nonce",
        )

    # ── Nonce replay protection ──────────────────────────────────────
    nonce_key = f"sso_nonce:{nonce}"
    try:
        cache = get_cache()
        existing = await cache.get(nonce_key)
        if existing is not None:
            logger.warning("SSO exchange: nonce already used", nonce=nonce)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Exchange token already used",
            )
        # Mark nonce as consumed. TTL = 60s (double the token's 30s lifetime
        # to account for clock skew).
        await cache.set(nonce_key, "1", ex=60)
    except HTTPException:
        raise
    except Exception:
        # Redis unavailable → fail open on nonce check (token signature +
        # expiry still protect us). Log so ops can investigate.
        logger.warning("SSO exchange: Redis unavailable for nonce check")

    # ── Look up user in DLP database ─────────────────────────────────
    email = payload.get("email", "").strip().lower()
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Exchange token missing email claim",
        )

    user_service = UserService(db)
    user = await user_service.get_user_by_email(email)

    if not user:
        logger.warning("SSO exchange: user not found", email=email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found in DLP system",
        )

    if not getattr(user, "is_active", True):
        logger.warning("SSO exchange: user inactive", email=email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )

    # ── Issue DLP tokens (signed with SECRET_KEY, not DLP_SSO_SECRET) ─
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
        }
    )

    refresh_token = create_refresh_token(
        data={
            "sub": str(user.id),
            "email": user.email,
        }
    )

    # Clear any login rate-limit counters for this user (same as normal login).
    client_ip = request.client.host if request.client else "unknown"
    try:
        cache = get_cache()
        await cache.delete(f"login_fail:{client_ip}:{email}")
    except Exception:
        pass

    logger.info(
        "SSO login successful",
        user_id=str(user.id),
        email=user.email,
        siem_user=payload.get("username"),
    )

    await audit_log(user.id, "auth.sso_login", {
        "siem_user": payload.get("username"),
        "siem_issuer": payload.get("iss"),
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
