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
    create_mfa_token,
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
from app.services import mfa_service
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


class LoginResponse(BaseModel):
    """
    Login can return either:
      - Full tokens (mfa_required=False) — MFA not enabled for this user
      - An mfa_token (mfa_required=True) — caller must complete /mfa/validate
    """
    access_token: str = ""
    refresh_token: str = ""
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: str = ""   # short-lived bridge token, only set when mfa_required=True


class MfaValidateRequest(BaseModel):
    mfa_token: str
    code: str  # 6-digit TOTP code


class MfaSetupResponse(BaseModel):
    qr_code: str   # base64 PNG — render as <img src="data:image/png;base64,{qr_code}">
    secret: str    # plaintext secret shown once for manual entry in authenticator apps


class MfaVerifySetupRequest(BaseModel):
    code: str      # first TOTP code the user enters to confirm setup


class MfaDisableRequest(BaseModel):
    password: str  # current password
    code: str      # current TOTP code


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


@router.post("/login", response_model=LoginResponse)
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

    # ── MFA gate ──────────────────────────────────────────────────────
    # If the user has MFA enabled, do NOT issue full tokens yet.
    # Return a short-lived mfa_token instead; the client must call
    # POST /auth/mfa/validate with the TOTP code to get real tokens.
    if getattr(user, "mfa_enabled", False):
        mfa_tok = create_mfa_token(str(user.id))
        logger.info("MFA challenge issued", user_id=str(user.id))
        await audit_log(user.id, "auth.mfa_challenge", {})
        return LoginResponse(mfa_required=True, mfa_token=mfa_tok)

    # No MFA — issue tokens immediately (existing behaviour).
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

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        mfa_required=False,
    )


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

        # Create new tokens. An SSO-vouched session stays SSO-vouched across
        # refreshes — dropping the claim here would silently re-gate the
        # session behind the IP allowlist mid-session (see
        # app/middleware/ip_allowlist.py's _is_sso_session).
        is_sso = bool(payload.get("sso"))
        access_token = create_access_token(
            data={
                "sub": str(user.id),
                "email": user.email,
                "role": user.role,
                **({"sso": True} if is_sso else {}),
            }
        )

        new_refresh_token = create_refresh_token(
            data={
                "sub": str(user.id),
                "email": user.email,
                **({"sso": True} if is_sso else {}),
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
        "mfa_enabled": getattr(current_user, "mfa_enabled", False) or False,
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
# The SIEM generates a short-lived JWT "exchange token". This endpoint
# verifies it, looks up (or, if SSO_JIT_PROVISION is on, provisions) the
# user in the DLP database, and issues standard DLP access+refresh tokens
# signed with SECRET_KEY. The exchange token is NOT the same as a DLP
# token.
#
# Hardened per gap-scan of CyberSentinel-DLP, August 26 2026 (commits
# ad46e71 role/ABAC mapping, 074266b RS256/JWKS verification). Key
# material — three roles, never interchangeable:
#   SIEM_JWKS_URL   →  the SIEM's PUBLIC keys, verify RS256 tokens
#                      (preferred: the DLP can then verify but not forge
#                      a SIEM token — see app/core/sso_jwks.py)
#   DLP_SSO_SECRET  →  shared secret, verify HS256 tokens (the original
#                      SeceoKnight scheme; kept as the migration fallback,
#                      clear it to retire symmetric signing)
#   SECRET_KEY      →  issue DLP tokens (never used to verify SIEM tokens)
#
# The token's own signed `alg` header routes which is used — see
# app/core/sso_verify.py for why that is safe here.
#
# Exchange token claim contract
# ──────────────────────────────
# Required : purpose="sso_exchange", iss="seceoknight-siem", nonce, exp
#            sub    the SIEM's immutable user id, if the SIEM sends one —
#                   the key an account is matched on in preference to
#                   email (app/models/user.py's siem_sub). email is
#                   accepted as a fallback key so a SIEM integration that
#                   only ever sent email keeps working unchanged.
#            aud    SSO_AUDIENCE ("seceoknight-dlp" by default). Mandatory
#                   on RS256; on HS256 checked only when present, so an
#                   already-integrated SIEM is not locked out the moment
#                   RS256 is turned on.
# Optional : username, full_name, organization, email
# Optional : role             "Administrator" | "L1" | "L2" | "L3"
#            access           "read-write" | "read-only"   (absent ⇒ read-only)
#            department       ABAC department
#            clearance_level  ABAC clearance (0-10)
#          → translated to a DLP role/attributes by app/core/sso_roles.py.
#            Every field above is optional; a SIEM sending none of them
#            gets exactly the pre-hardening behaviour (existing user found
#            by email, unchanged role).


class SSOExchangeRequest(BaseModel):
    token: str


def _nonce_ttl_seconds(payload: dict) -> int:
    """How long to remember a consumed nonce.

    Must outlive the token: retention shorter than the signature's
    validity leaves a gap in which a captured token is replayable.
    Derived from the token's own `exp` plus the clock leeway we granted
    it, floored at SSO_NONCE_TTL_SECONDS and capped so a token claiming a
    year-long expiry cannot pin an entry in Redis for a year.
    """
    floor = max(60, int(getattr(settings, "SSO_NONCE_TTL_SECONDS", 300) or 300))
    leeway = max(0, int(getattr(settings, "SSO_CLOCK_LEEWAY_SECONDS", 60) or 0))
    ttl = floor
    exp = payload.get("exp")
    if exp:
        try:
            remaining = int(exp) - int(datetime.utcnow().timestamp())
            ttl = max(ttl, remaining + leeway + 10)
        except (TypeError, ValueError):
            pass
    return min(ttl, 3600)


@router.post("/sso/exchange", response_model=TokenResponse)
async def sso_exchange(
    body: SSOExchangeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Exchange a SIEM-issued SSO token for DLP access + refresh tokens.

    Public endpoint — no Authorization header required. The exchange token
    itself serves as proof of authentication (RS256 via SIEM_JWKS_URL, or
    HS256 via DLP_SSO_SECRET as the migration fallback; ~30-second TTL,
    single-use nonce).
    """
    from app.core.sso_roles import resolve as resolve_sso_identity
    from app.core.sso_verify import (
        SSOTokenError,
        SSOUnavailable,
        sso_configured,
        verify_exchange_token,
    )

    # ── Guard: SSO must be configured ────────────────────────────────
    # Either signing scheme counts. During an RS256 cutover both are set;
    # afterwards DLP_SSO_SECRET is cleared and only the JWKS remains.
    if not sso_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO is not configured",
        )

    # ── Verify exchange token (RS256 via JWKS, or HS256 fallback) ────
    try:
        payload, token_alg = await verify_exchange_token(body.token)
    except SSOUnavailable as e:
        # We could not obtain the key material. That is our problem, not a
        # bad token, and 401 would send the SIEM chasing a signature fault
        # that does not exist.
        logger.error("SSO exchange: verification unavailable", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO verification is temporarily unavailable",
        )
    except SSOTokenError as e:
        logger.warning("SSO exchange: token rejected",
                       error=e.detail, expired=e.expired)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.detail,
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
        # Mark the nonce consumed for LONGER than the token can possibly
        # remain valid — derived from the token's own exp (see
        # _nonce_ttl_seconds above), not a flat guess. A flat TTL shorter
        # than (token TTL + clock leeway) reopens exactly the replay
        # window this exists to close.
        await cache.set(nonce_key, "1", ex=_nonce_ttl_seconds(payload))
    except HTTPException:
        raise
    except Exception:
        # Redis unavailable → fail open on nonce check (token signature +
        # expiry still protect us). Log so ops can investigate.
        logger.warning("SSO exchange: Redis unavailable for nonce check")

    # ── Identify the human ─────────────────────────────────────────────
    # Keyed on the SIEM's `sub` in preference to email — email is a
    # display attribute that changes (surname, domain migration, typo
    # fix); keyed on email alone, any of those orphans the DLP account and
    # the next login silently provisions a SECOND one. `sub` is accepted
    # only when the SIEM sends it; email remains the fallback so a SIEM
    # integration that predates this still works unchanged.
    siem_sub = str(payload.get("sub") or "").strip() or None
    email = str(payload.get("email") or "").strip().lower()
    if not siem_sub and not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Exchange token identifies no user (no sub, no email)",
        )

    # ── Translate the SIEM's role/access pair into a DLP role ─────────
    identity = resolve_sso_identity(payload)
    if identity.clamped_from:
        logger.warning("SSO exchange: role clamped by SSO_MAX_ROLE",
                       requested=identity.clamped_from, granted=identity.role)

    user_service = UserService(db)

    user = None
    matched_by = ""
    if siem_sub:
        user = await user_service.get_user_by_siem_sub(siem_sub)
        if user:
            matched_by = "siem_sub"
    if not user and email:
        user = await user_service.get_user_by_email(email)
        if user:
            matched_by = "email"

    # ── Reconcile the identity we matched with the one on the token ────
    if user:
        updates: Dict = {}
        if siem_sub and not getattr(user, "siem_sub", None):
            # Backfill: this account predates sub-keying, or was created
            # locally and is now claimed by its SIEM identity. From here
            # on it is found by sub and survives an email change.
            updates["siem_sub"] = siem_sub
        if matched_by == "siem_sub" and email and user.email != email:
            # The rename this exists to survive. Only trusted when the
            # match came from sub — an email-matched row tells us nothing
            # new about its own email.
            existing = await user_service.get_user_by_email(email)
            if existing is not None and str(existing.id) != str(user.id):
                logger.warning("SSO exchange: email already held by another account",
                               siem_sub=siem_sub, email=email)
            else:
                updates["email"] = email
        if updates:
            try:
                user = await user_service.update_user(str(user.id), **updates)
            except Exception as e:  # noqa: BLE001 — identity upkeep, never fatal
                logger.warning("SSO exchange: identity reconcile failed",
                               error=str(e), siem_sub=siem_sub)
            else:
                await audit_log(user.id, "auth.sso_identity_reconcile", {
                    "matched_by": matched_by, **updates,
                })

    # ── Just-in-time provisioning ────────────────────────────────────
    # Off by default (SeceoKnight's original contract): the SIEM is
    # expected to seed accounts itself via POST /api/v1/users using an
    # admin session obtained through this same endpoint. Turning it on
    # removes that round-trip but raises the stakes on token forgery,
    # which is why it is bounded by SSO_MAX_ROLE and by RS256 (above).
    if not user:
        if not settings.SSO_JIT_PROVISION:
            logger.warning("SSO exchange: user not found",
                           email=email, siem_sub=siem_sub)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found in DLP system",
            )
        if not email:
            # The DLP account is keyed on email everywhere else (unique
            # column, what ABAC/audit display) — a user can be FOUND by
            # sub alone, but not invented without an address.
            logger.warning("SSO exchange: cannot provision without an email",
                           siem_sub=siem_sub)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Exchange token missing email claim",
            )

        siem_username = (payload.get("username") or "").strip() or None
        # username is UNIQUE; a collision would abort the whole login, and a
        # provisioning login must not fail over a cosmetic display field.
        if siem_username:
            collision = await user_service.get_user_by_email(siem_username)
            if collision:
                siem_username = None

        import secrets as _secrets
        random_password = _secrets.token_urlsafe(32)  # never used to log in

        try:
            user = await user_service.create_user(
                email=email,
                password=random_password,
                full_name=(payload.get("full_name") or "").strip() or email.split("@")[0],
                role=identity.role,
                organization=(payload.get("organization") or "").strip() or "SeceoKnight",
                department=identity.department,
                clearance_level=identity.clearance_level,
                username=siem_username,
                sso_managed=True,
                sso_source_role=f"{identity.siem_role}:{identity.siem_access}"[:64],
                siem_sub=siem_sub,
            )
        except ValueError:
            # Lost a race with a concurrent SSO login for the same person.
            user = None
            if siem_sub:
                user = await user_service.get_user_by_siem_sub(siem_sub)
            if not user:
                user = await user_service.get_user_by_email(email)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found in DLP system",
                )

        logger.info("SSO exchange: JIT-provisioned new user",
                   email=user.email, role=identity.role, **identity.as_log())
        await audit_log(user.id, "auth.sso_provision", identity.as_log())

    if not getattr(user, "is_active", True):
        logger.warning("SSO exchange: user inactive", email=user.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )

    # ── Sync role/attributes on every login (SSO-owned accounts only) ─
    # Never touches a locally-owned account — see the ownership rules in
    # app/core/sso_roles.py's module docstring: only accounts this sync
    # itself provisioned are re-synced, and an admin editing such a
    # user's role by hand through PUT /users detaches it permanently
    # (sso_managed → false) rather than having the edit revert here.
    if (
        getattr(user, "sso_managed", False)
        and settings.SSO_SYNC_ON_LOGIN
        and identity.mapped
    ):
        changed = (
            str(getattr(user, "role", "")).upper() != identity.role
            or (identity.department is not None and user.department != identity.department)
            or (identity.clearance_level is not None and user.clearance_level != identity.clearance_level)
        )
        if changed:
            user = await user_service.update_user(
                str(user.id),
                role=identity.role,
                department=identity.department,
                clearance_level=identity.clearance_level,
                sso_source_role=f"{identity.siem_role}:{identity.siem_access}"[:64],
            )
            logger.info("SSO exchange: synced role/attributes from SIEM",
                       email=user.email, **identity.as_log())
            await audit_log(user.id, "auth.sso_sync", identity.as_log())

    # ── Issue DLP tokens (signed with SECRET_KEY, not the SSO key) ────
    # The `sso` claim marks the session as vouched for by the SIEM. The IP
    # allowlist honours it (SSO_ALLOWLIST_BYPASS, app/middleware/
    # ip_allowlist.py) so an off-network analyst does not get a successful
    # login attached to a console that 403s on every request. Password
    # sessions carry no such claim and stay gated.
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
            "sso": True,
        }
    )

    refresh_token = create_refresh_token(
        data={
            "sub": str(user.id),
            "email": user.email,
            "sso": True,
        }
    )

    # Clear any login rate-limit counters for this user (same as normal login).
    client_ip = request.client.host if request.client else "unknown"
    try:
        cache = get_cache()
        await cache.delete(f"login_fail:{client_ip}:{user.email}")
    except Exception:
        pass

    logger.info(
        "SSO login successful",
        user_id=str(user.id),
        email=user.email,
        siem_user=payload.get("username"),
        alg=token_alg,
        matched_by=matched_by or "provisioned",
    )

    await audit_log(user.id, "auth.sso_login", {
        "siem_user": payload.get("username"),
        "siem_issuer": payload.get("iss"),
        "alg": token_alg,
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


# ═══════════════════════════════════════════════════════════════════════════
# MFA Endpoints
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Begin MFA setup for the authenticated user.

    Generates a fresh TOTP secret, stores it encrypted in the DB
    (mfa_enabled stays False until /mfa/verify-setup succeeds), and
    returns the QR code + plaintext secret for the user to scan.

    If the user already has MFA enabled this endpoint returns 409 so
    the UI can redirect to /mfa/disable first.
    """
    if getattr(current_user, "mfa_enabled", False):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled. Disable it first to re-enroll.",
        )

    secret = mfa_service.generate_secret()
    encrypted = mfa_service.encrypt_secret(secret)

    user_service = UserService(db)
    user = await user_service.get_user_by_id(str(current_user.id))
    user.mfa_secret = encrypted
    await db.commit()

    qr = mfa_service.generate_qr_code_base64(secret, current_user.email)

    await audit_log(current_user.id, "auth.mfa_setup_started", {})
    logger.info("MFA setup started", user_id=str(current_user.id))

    return MfaSetupResponse(qr_code=qr, secret=secret)


@router.post("/mfa/verify-setup", response_model=TokenResponse)
async def mfa_verify_setup(
    body: MfaVerifySetupRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Complete MFA setup by verifying the first TOTP code.

    The user scans the QR code from /mfa/setup into their authenticator
    app, then enters the 6-digit code here. On success mfa_enabled is
    set to True and fresh tokens are returned (so the UI stays logged in).
    """
    if getattr(current_user, "mfa_enabled", False):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled.",
        )

    encrypted = getattr(current_user, "mfa_secret", None)
    if not encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No MFA setup in progress. Call /auth/mfa/setup first.",
        )

    try:
        secret = mfa_service.decrypt_secret(encrypted)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA secret could not be read. Please restart setup.",
        )

    if not mfa_service.verify_totp(secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid code. Check your authenticator app and try again.",
        )

    user_service = UserService(db)
    user = await user_service.get_user_by_id(str(current_user.id))
    user.mfa_enabled = True
    await db.commit()

    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role}
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.id), "email": user.email}
    )

    await audit_log(current_user.id, "auth.mfa_enabled", {})
    logger.info("MFA enabled", user_id=str(current_user.id))

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/mfa/validate", response_model=TokenResponse)
async def mfa_validate(
    body: MfaValidateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Second step of MFA login: validate the TOTP code and issue full tokens.

    Accepts the mfa_token returned by /auth/login (when mfa_required=True)
    plus the 6-digit code from the user's authenticator app.

    The mfa_token is single-use: it is consumed in Redis immediately so
    replay attacks cannot reuse a captured token within its 5-minute window.
    """
    from jose import jwt as jose_jwt, JWTError, ExpiredSignatureError

    # ── Decode & validate mfa_token ───────────────────────────────────
    try:
        payload = jose_jwt.decode(
            body.mfa_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA session expired. Please log in again.",
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token.",
        )

    if payload.get("type") != "mfa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
        )

    user_id = payload.get("sub")
    jti = payload.get("jti", "")

    # ── Single-use enforcement ────────────────────────────────────────
    used_key = f"mfa_used:{jti}"
    try:
        cache = get_cache()
        if await cache.get(used_key) is not None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA token already used. Please log in again.",
            )
        await cache.set(used_key, "1", ex=360)  # keep for 6 min (> 5 min TTL)
    except HTTPException:
        raise
    except Exception:
        pass  # Redis unavailable — fail open; expiry still enforced by JWT exp

    # ── Load user and verify TOTP ─────────────────────────────────────
    user_service = UserService(db)
    user = await user_service.get_user_by_id(user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )

    encrypted = getattr(user, "mfa_secret", None)
    if not encrypted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA secret missing. Contact an administrator.",
        )

    try:
        secret = mfa_service.decrypt_secret(encrypted)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA secret could not be read.",
        )

    if not mfa_service.verify_totp(secret, body.code):
        await audit_log(user.id, "auth.mfa_failed", {})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authenticator code.",
        )

    # ── Issue full tokens ─────────────────────────────────────────────
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role}
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.id), "email": user.email}
    )

    await audit_log(user.id, "auth.mfa_login", {})
    logger.info("MFA login successful", user_id=str(user.id))

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/mfa/disable")
async def mfa_disable(
    body: MfaDisableRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Self-service MFA disable is intentionally disabled.

    Only administrators can disable MFA for a user via
    POST /api/v1/users/{user_id}/mfa/reset. This prevents users from
    weakening their own account security.
    """
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Self-service MFA disable is not permitted. Contact your administrator.",
    )
