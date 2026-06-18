"""
Security and Authentication
JWT tokens, password hashing, OAuth2
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import uuid
import enum

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.cache import get_cache
from app.services.blacklist_service import TokenBlacklistService
from app.models.user import User
# UserService imported lazily to avoid circular imports

logger = structlog.get_logger()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Generate password hash
    """
    return pwd_context.hash(password)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create JWT access token
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),
        "type": "access"
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )

    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Create JWT refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),
        "type": "refresh"
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )

    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate JWT token
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError as e:
        logger.warning("Token decode failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current user from JWT token
    """
    # Lazy import to avoid circular dependency
    from app.services.user_service import UserService

    try:
        cache = get_cache()
        blacklist_service = TokenBlacklistService(cache)
        if await blacklist_service.is_blacklisted(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )
    except RuntimeError:
        if settings.ENVIRONMENT.lower() == "production":
            logger.error("Redis unavailable in production — token blacklist check failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        logger.warning("Redis not initialized, skipping token blacklist check (dev mode)")

    payload = decode_token(token)

    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    user_service = UserService(db)
    user = await user_service.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


async def optional_auth(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[Dict[str, Any]]:
    """
    Optional authentication for endpoints that can work with or without auth
    (e.g., agent endpoints that don't require authentication)

    Returns user dict if authenticated, None otherwise
    """
    # Lazy import to avoid circular dependency
    from app.services.user_service import UserService

    if not token:
        return None

    try:
        # Check blacklist
        try:
            cache = get_cache()
            blacklist_service = TokenBlacklistService(cache)
            if await blacklist_service.is_blacklisted(token):
                return None
        except RuntimeError:
            # Redis not initialized, skip blacklist check
            pass

        # Decode token
        payload = decode_token(token)
        user_id: str = payload.get("sub")

        if user_id is None:
            return None

        # Get user
        user_service = UserService(db)
        user = await user_service.get_user_by_id(user_id)

        if user is None:
            return None

        # Return user as dict
        return {
            "id": user.id,
            "email": user.email,
            "role": user.role
        }

    except Exception as e:
        # If any error occurs, just return None (no auth)
        logger.debug("Optional auth failed, continuing without auth", error=str(e))
        return None


def require_role(required_role: str):
    """
    Dependency factory to check user role
    """
    async def role_checker(current_user: User = Depends(get_current_user)):
        user_role = current_user.role

        # Role hierarchy: ADMIN > ANALYST ≈ MANAGER > VIEWER
        # MANAGER sits at ANALYST's level for backwards-compatible hierarchical checks.
        # Fine-grained gating should use require_permission instead of require_role.
        role_hierarchy = {"ADMIN": 3, "ANALYST": 2, "MANAGER": 2, "VIEWER": 1}
        
        # Convert role to string - handle enum properly
        # UserRole enum has .value attribute that returns the string value
        if isinstance(user_role, enum.Enum):
            user_role_str = user_role.value
        else:
            user_role_str = str(user_role)
        
        required_role_str = required_role.upper() if isinstance(required_role, str) else str(required_role)

        user_level = role_hierarchy.get(user_role_str, 0)
        required_level = role_hierarchy.get(required_role_str, 0)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return current_user

    return role_checker


def require_permission(permission: str):
    """
    Dependency factory for fine-grained RBAC.

    Resolves the current user's full permission set via permission_service
    and raises 403 if `permission` is not granted. Every denial is recorded
    in the audit log with result=DENIED so SOC can reconstruct attempts.

    Prefer this over require_role for new endpoints. require_role remains
    for legacy gates and for coarse ADMIN-only checks.
    """
    async def _checker(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        # Lazy import: permission_service -> models -> security -> cycle otherwise.
        from app.services.permission_service import get_user_permissions
        from app.services.audit_service import audit_log

        perms = await get_user_permissions(db, current_user)
        if permission not in perms:
            # Fire-and-forget audit of the denial. Do not let an audit write
            # failure leak into the authorization path.
            try:
                await audit_log(
                    current_user.id,
                    "authz.denied",
                    {
                        "required_permission": permission,
                        "user_role": getattr(
                            current_user.role, "value", str(current_user.role)
                        ),
                    },
                )
            except Exception:
                logger.warning(
                    "audit_log failed during 403 denial",
                    user_id=str(current_user.id),
                    permission=permission,
                )
            logger.info(
                "Permission denied",
                user_id=str(current_user.id),
                email=current_user.email,
                required=permission,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission}",
            )
        return current_user

    return _checker


def validate_password_strength(password: str) -> bool:
    """
    Validate password meets security requirements
    """
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    return has_upper and has_lower and has_digit and has_special
