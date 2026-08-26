"""
User Service - Business logic for user management
"""

from typing import Optional, List
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.role import Role
from app.core.security import get_password_hash, verify_password


class UserService:
    """Service for user-related operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """
        Fetch user by ID

        Args:
            user_id: UUID of the user

        Returns:
            User object or None if not found
        """
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Fetch user by email address

        Args:
            email: User's email address

        Returns:
            User object or None if not found
        """
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_user_by_siem_sub(self, siem_sub: str) -> Optional[User]:
        """
        Fetch the account belonging to a SIEM identity.

        This is the preferred SSO lookup key (over email) — see the
        siem_sub column comment in app/models/user.py. Email is a display
        attribute people change; `sub` is the SIEM's own id for the human
        and does not.
        """
        result = await self.db.execute(
            select(User).where(User.siem_sub == siem_sub)
        )
        return result.scalar_one_or_none()

    async def get_all_users(
        self,
        skip: int = 0,
        limit: int = 100,
        organization: Optional[str] = None,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> List[User]:
        """
        Fetch all users with optional filtering

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            organization: Filter by organization
            role: Filter by role
            is_active: Filter by active status

        Returns:
            List of User objects
        """
        query = select(User)

        if organization:
            query = query.where(User.organization == organization)
        if role:
            query = query.where(User.role == role)
        if is_active is not None:
            query = query.where(User.is_active == is_active)

        query = query.offset(skip).limit(limit).order_by(User.created_at.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def create_user(
        self,
        email: str,
        password: str,
        full_name: str,
        role: str = "VIEWER",
        organization: Optional[str] = None,
        department: Optional[str] = None,
        clearance_level: Optional[int] = None,
        username: Optional[str] = None,
        sso_managed: bool = False,
        sso_source_role: Optional[str] = None,
        siem_sub: Optional[str] = None,
    ) -> User:
        """
        Create a new user

        Args:
            email: User's email address
            password: Plain text password (will be hashed)
            full_name: User's full name
            role: User role (admin, analyst, viewer, agent)
            organization: Organization name
            sso_managed: True when this account is owned by SSO role sync
                (app/core/sso_roles.py) — role/department/clearance are
                re-applied from the SIEM on every login until an admin
                edits the role by hand and detaches it.
            sso_source_role: Last SIEM "role:access" pair seen, for tracing.
            siem_sub: The SIEM's immutable user id, if this account was
                provisioned via SSO.

        Returns:
            Created User object

        Raises:
            ValueError: If user with email already exists
        """
        # Check if user already exists
        existing_user = await self.get_user_by_email(email)
        if existing_user:
            raise ValueError(f"User with email {email} already exists")

        # Look up role_id from the roles table so the normalized
        # role_permissions path is used by get_user_permissions().
        # If the role row doesn't exist yet (e.g. test/migration runs),
        # fall back gracefully — _ROLE_DEFAULTS covers the NULL role_id case.
        role_row = await self.db.execute(
            select(Role).where(Role.name == role.upper())
        )
        role_obj = role_row.scalar_one_or_none()
        role_id = role_obj.id if role_obj else None

        # Create new user
        hashed_password = get_password_hash(password)
        user = User(
            email=email,
            username=username,
            hashed_password=hashed_password,
            full_name=full_name,
            role=role,
            role_id=role_id,
            organization=organization,
            department=department,
            clearance_level=clearance_level if clearance_level is not None else 1,
            is_active=True,
            is_verified=False,
            # SSO provenance — see app/core/sso_roles.py.
            sso_managed=sso_managed,
            sso_source_role=sso_source_role,
            siem_sub=siem_sub,
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def update_user(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        role: Optional[str] = None,
        organization: Optional[str] = None,
        is_active: Optional[bool] = None,
        department: Optional[str] = None,
        clearance_level: Optional[int] = None,
        sso_managed: Optional[bool] = None,
        sso_source_role: Optional[str] = None,
        siem_sub: Optional[str] = None,
        email: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Optional[User]:
        """
        Update user details

        Args:
            user_id: UUID of the user
            full_name: New full name
            role: New role
            organization: New organization
            is_active: New active status
            sso_managed: Set/clear SSO ownership of this account. See
                app/core/sso_roles.py — the SSO exchange endpoint sets this
                true on provisioning/sync; the admin UI's PUT /users sets
                it false when an admin edits the role by hand (detach).
            sso_source_role: Last SIEM "role:access" pair, for tracing.
            siem_sub: Backfill/update the SIEM identity key.
            email: Reconcile an email rename reported by the SIEM (only
                trusted when the account was matched by siem_sub, not by
                the email itself — see the SSO exchange endpoint).
            username: Update the login alias.

        Returns:
            Updated User object or None if not found
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return None

        if full_name is not None:
            user.full_name = full_name
        if role is not None:
            user.role = role
            # Keep role_id in sync so the normalized role_permissions path
            # stays correct after a role change.
            role_row = await self.db.execute(
                select(Role).where(Role.name == role.upper())
            )
            role_obj = role_row.scalar_one_or_none()
            user.role_id = role_obj.id if role_obj else None
        if organization is not None:
            user.organization = organization
        if is_active is not None:
            user.is_active = is_active
        if department is not None:
            user.department = department
        if clearance_level is not None:
            user.clearance_level = clearance_level
        if sso_managed is not None:
            user.sso_managed = sso_managed
        if sso_source_role is not None:
            user.sso_source_role = sso_source_role
        if siem_sub is not None:
            user.siem_sub = siem_sub
        if email is not None:
            user.email = email
        if username is not None:
            user.username = username

        user.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(user)

        # Invalidate the ingest-path user→department cache so subsequent
        # events for this user get tagged with the new attributes. Historical
        # events are intentionally not rewritten (immutability).
        try:
            from app.services.user_dept_cache import invalidate as _dept_invalidate

            await _dept_invalidate(user.email)
        except Exception:
            pass

        return user

    async def update_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> bool:
        """
        Update user password

        Args:
            user_id: UUID of the user
            current_password: Current password for verification
            new_password: New password (will be hashed)

        Returns:
            True if password was updated, False otherwise
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return False

        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            return False

        # Update password
        user.hashed_password = get_password_hash(new_password)
        user.updated_at = datetime.utcnow()

        await self.db.commit()
        return True

    async def delete_user(self, user_id: str) -> bool:
        """
        Delete a user (soft delete - sets is_active to False)
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return False

        email = user.email
        user.is_active = False
        user.updated_at = datetime.utcnow()

        await self.db.commit()

        # Invalidate ingest-path dept cache so new events for this email
        # don't reuse a stale department mapping during the TTL window.
        try:
            from app.services.user_dept_cache import invalidate as _dept_invalidate
            await _dept_invalidate(email)
        except Exception:
            pass

        return True

    async def hard_delete_user(self, user_id: str) -> bool:
        """
        Permanently delete a user from database
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return False

        email = user.email
        await self.db.delete(user)
        await self.db.commit()

        try:
            from app.services.user_dept_cache import invalidate as _dept_invalidate
            await _dept_invalidate(email)
        except Exception:
            pass

        return True

    async def update_last_login(self, user_id: str) -> None:
        """
        Update user's last login timestamp

        Args:
            user_id: UUID of the user
        """
        user = await self.get_user_by_id(user_id)
        if user:
            user.last_login = datetime.utcnow()
            await self.db.commit()

    async def verify_user(self, user_id: str) -> bool:
        """
        Verify user account

        Args:
            user_id: UUID of the user

        Returns:
            True if user was verified, False if not found
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return False

        user.is_verified = True
        user.updated_at = datetime.utcnow()

        await self.db.commit()
        return True

    async def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate user with email and password

        Args:
            email: User's email address
            password: User's password

        Returns:
            User object if authentication successful, None otherwise
        """
        user = await self.get_user_by_email(email)
        if not user:
            return None

        if not user.is_active:
            return None

        if not verify_password(password, user.hashed_password):
            return None

        # Update last login
        await self.update_last_login(str(user.id))

        return user

    async def get_user_count(self, role: Optional[str] = None) -> int:
        """
        Get total count of users

        Args:
            role: Optional role filter

        Returns:
            Number of users
        """
        from sqlalchemy import func

        query = select(func.count(User.id))

        if role:
            query = query.where(User.role == role)

        result = await self.db.execute(query)
        return result.scalar_one()
