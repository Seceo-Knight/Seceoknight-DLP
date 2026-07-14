"""
Pytest configuration and fixtures
"""

import pytest
import asyncio
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.types import CHAR

from app.core.database import Base
from app.core.config import settings


@compiles(postgresql.UUID, "sqlite")
def compile_uuid_sqlite(element, compiler, **kwargs):
    """Render PostgreSQL UUID columns as CHAR(36) for SQLite tests."""
    return "CHAR(36)"


@compiles(postgresql.INET, "sqlite")
def compile_inet_sqlite(element, compiler, **kwargs):
    """Render PostgreSQL INET columns as TEXT for SQLite tests."""
    return "TEXT"


@compiles(postgresql.JSONB, "sqlite")
def compile_jsonb_sqlite(element, compiler, **kwargs):
    """Render PostgreSQL JSONB columns as JSON for SQLite tests.

    Pre-existing gap: roles.permissions (and other JSONB columns added since)
    had no SQLite shim, so any test that triggers Base.metadata.create_all
    — which creates every table in metadata, not just the one under test —
    fails during fixture setup. Not something introduced by this change;
    confirmed by the same failure on the unmodified test_google_drive_models.py.
    """
    return "JSON"


from sqlalchemy import ARRAY  # noqa: E402


@compiles(ARRAY, "sqlite")
def compile_array_sqlite(element, compiler, **kwargs):
    """Render PostgreSQL ARRAY columns (e.g. rules.file_types) as TEXT for
    SQLite tests — same pre-existing-gap category as JSONB above; only
    affects DDL creation of unrelated tables pulled in by Base.metadata,
    not any assertions in this suite."""
    return "TEXT"


# Test database URL (in-memory SQLite for fast tests)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db_engine():
    """Create test database engine"""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=StaticPool,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session"""
    async_session = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session


@pytest.fixture
def mock_user_data():
    """Mock user data for testing"""
    return {
        "email": "test@example.com",
        "password": "Test123!@#",
        "full_name": "Test User",
        "organization": "Test Org",
        "role": "viewer",
    }


@pytest.fixture
def mock_policy_data():
    """Mock policy data for testing"""
    return {
        "name": "Test Policy",
        "description": "Test policy description",
        "conditions": {
            "match": "all",
            "rules": [
                {
                    "field": "classification.labels",
                    "operator": "contains",
                    "value": "PAN"
                }
            ]
        },
        "actions": {
            "alert": {"severity": "critical"},
            "block": None,
        },
        "enabled": True,
        "priority": 100,
        "compliance_tags": ["PCI-DSS"],
    }


@pytest.fixture
def mock_agent_data():
    """Mock agent data for testing"""
    return {
        "agent_id": "test-agent-001",
        "agent_name": "Test Agent",
        "hostname": "test-host",
        "os_type": "windows",
        "os_version": "Windows 10",
        "ip_address": "192.168.1.100",
        "agent_version": "1.0.0",
        "capabilities": {
            "file_monitoring": True,
            "clipboard_monitoring": True,
        },
    }
