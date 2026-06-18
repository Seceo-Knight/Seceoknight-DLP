"""
User Service - Business logic for user management
"""

from typing import Optional, List
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
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
    ) -> User:
        """
        Create a new user

        Args:
            email: User's email address
            password: Plain text password (will be hashed)
            full_name: User's full name
            role: User role (admin, analyst, viewer, agent)
            organization: Organization name

        Returns:
            Created User object

        Raises:
            ValueError: If user with email already exists
        """
        # Check if user already exists
        existing_user = await self.get_user_by_email(email)
        if existing_user:
            raise ValueError(f"User with email {email} already exists")

        # Create new user
        hashed_password = get_password_hash(password)
        user = User(
            email=email,
            username=username,
            hashed_password=hashed_password,
            full_name=full_name,
            role=role,
            organization=organization,
            department=department,
            clearance_level=clearance_level if clearance_level is not None else 1,
            is_active=True,
            is_verified=False,
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
    ) -> Optional[User]:
        """
        Update user details

        Args:
            user_id: UUID of the user
            full_name: New full name
            role: New role
            organization: New organization
            is_active: New active status

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
        if organization is not None:
            user.organization = organization
        if is_active is not None:
            user.is_active = is_active
        if department is not None:
            user.department = department
        if clearance_level is not None:
            user.clearance_level = clearance_level

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
