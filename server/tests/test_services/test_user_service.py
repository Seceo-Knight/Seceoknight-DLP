"""
Tests for UserService
"""

import pytest
from app.services.user_service import UserService


@pytest.mark.asyncio
@pytest.mark.unit
async def test_create_user(db_session, mock_user_data):
    """Test creating a new user"""
    service = UserService(db_session)

    user = await service.create_user(
        email=mock_user_data["email"],
        password=mock_user_data["password"],
        full_name=mock_user_data["full_name"],
        organization=mock_user_data["organization"],
        role=mock_user_data["role"],
    )

    assert user is not None
    assert user.email == mock_user_data["email"]
    assert user.full_name == mock_user_data["full_name"]
    assert user.is_active is True
    assert user.hashed_password != mock_user_data["password"]  # Password should be hashed


@pytest.mark.asyncio
@pytest.mark.unit
async def test_get_user_by_email(db_session, mock_user_data):
    """Test fetching user by email"""
    service = UserService(db_session)

    # Create user
    created_user = await service.create_user(
        email=mock_user_data["email"],
        password=mock_user_data["password"],
        full_name=mock_user_data["full_name"],
    )

    # Fetch user
    user = await service.get_user_by_email(mock_user_data["email"])

    assert user is not None
    assert user.id == created_user.id
    assert user.email == mock_user_data["email"]


@pytest.mark.asyncio
@pytest.mark.unit
async def test_authenticate_user_success(db_session, mock_user_data):
    """Test successful user authentication"""
    service = UserService(db_session)

    # Create user
    await service.create_user(
        email=mock_user_data["email"],
        password=mock_user_data["password"],
        full_name=mock_user_data["full_name"],
    )

    # Authenticate
    user = await service.authenticate_user(
        email=mock_user_data["email"],
        password=mock_user_data["password"],
    )

    assert user is not None
    assert user.email == mock_user_data["email"]


@pytest.mark.asyncio
@pytest.mark.unit
async def test_authenticate_user_wrong_password(db_session, mock_user_data):
    """Test authentication with wrong password"""
    service = UserService(db_session)

    # Create user
    await service.create_user(
        email=mock_user_data["email"],
        password=mock_user_data["password"],
        full_name=mock_user_data["full_name"],
    )

    # Authenticate with wrong password
    user = await service.authenticate_user(
        email=mock_user_data["email"],
        password="WrongPassword123!",
    )

    assert user is None


@pytest.mark.asyncio
@pytest.mark.unit
async def test_create_duplicate_user(db_session, mock_user_data):
    """Test creating user with duplicate email"""
    service = UserService(db_session)

    # Create first user
    await service.create_user(
        email=mock_user_data["email"],
        password=mock_user_data["password"],
        full_name=mock_user_data["full_name"],
    )

    # Try to create duplicate
    with pytest.raises(ValueError, match="already exists"):
        await service.create_user(
            email=mock_user_data["email"],
            password=mock_user_data["password"],
            full_name="Another User",
        )


@pytest.mark.asyncio
@pytest.mark.unit
async def test_update_user(db_session, mock_user_data):
    """Test updating user details"""
    service = UserService(db_session)

    # Create user
    user = await service.create_user(
        email=mock_user_data["email"],
        password=mock_user_data["password"],
        full_name=mock_user_data["full_name"],
    )

    # Update user
    updated_user = await service.update_user(
        user_id=str(user.id),
        full_name="Updated Name",
        role="admin",
    )

    assert updated_user is not None
    assert updated_user.full_name == "Updated Name"
    assert updated_user.role == "admin"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_delete_user(db_session, mock_user_data):
    """Test deleting user (soft delete)"""
    service = UserService(db_session)

    # Create user
    user = await service.create_user(
        email=mock_user_data["email"],
        password=mock_user_data["password"],
        full_name=mock_user_data["full_name"],
    )

    # Delete user
    success = await service.delete_user(str(user.id))

    assert success is True

    # Verify user is inactive
    deleted_user = await service.get_user_by_id(str(user.id))
    assert deleted_user.is_active is False
