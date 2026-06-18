"""
Database Initialization Script
Creates all tables and initial data for SeceoKnight DLP
"""

import asyncio
import sys
from pathlib import Path

# Add server directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "server"))

from sqlalchemy import text
from app.core.database import init_databases, close_databases, postgres_engine, mongodb_database, Base
from app.core.security import get_password_hash
from app.models import User, Policy, Agent, Event, Alert, ClassifiedFile


async def create_tables():
    """Create all database tables"""
    print("Creating PostgreSQL tables...")
    async with postgres_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✓ Tables created successfully")


async def create_default_user():
    """Create default admin user"""
    from sqlalchemy.ext.asyncio import AsyncSession
    from app.core.database import postgres_session_factory
    from app.models import UserRole
    import uuid

    print("Creating default admin user...")

    async with postgres_session_factory() as session:
        # Check if user already exists
        result = await session.execute(
            text("SELECT id FROM users WHERE email = 'admin@seceoknight.local'")
        )
        if result.scalar():
            print("  Admin user already exists")
            return

        # Create admin user
        admin_user = User(
            id=uuid.uuid4(),
            email="admin@seceoknight.local",
            hashed_password=get_password_hash("ChangeMe123!"),
            full_name="System Administrator",
            role=UserRole.ADMIN,
            organization="SeceoKnight",
            is_active=True,
            is_verified=True
        )

        session.add(admin_user)
        await session.commit()
        print("✓ Default admin user created")
        print("  Email: admin@seceoknight.local")
        print("  Password: ChangeMe123!")


async def create_mongodb_indexes():
    """Create MongoDB indexes"""
    print("Creating MongoDB indexes...")

    # Events collection indexes
    events_collection = mongodb_database["events"]
    await events_collection.create_index("event_id", unique=True)
    await events_collection.create_index("timestamp")
    await events_collection.create_index([("severity", 1), ("timestamp", -1)])
    await events_collection.create_index([("user_email", 1), ("timestamp", -1)])
    await events_collection.create_index([("agent_id", 1), ("timestamp", -1)])
    await events_collection.create_index([("event_type", 1)])

    # Audit logs collection indexes
    audit_collection = mongodb_database["audit_logs"]
    await audit_collection.create_index("timestamp")
    await audit_collection.create_index([("user_email", 1), ("timestamp", -1)])
    await audit_collection.create_index("action")

    print("✓ MongoDB indexes created")


async def create_default_policies():
    """Create default DLP policies"""
    from sqlalchemy.ext.asyncio import AsyncSession
    from app.core.database import postgres_session_factory
    import uuid

    print("Creating default policies...")

    async with postgres_session_factory() as session:
        # Check if policies already exist
        result = await session.execute(text("SELECT COUNT(*) FROM policies"))
        count = result.scalar()
        if count > 0:
            print("  Policies already exist")
            return

        # Get admin user ID
        result = await session.execute(
            text("SELECT id FROM users WHERE email = 'admin@seceoknight.local'")
        )
        admin_id = result.scalar()

        # PCI-DSS Credit Card Policy
        pci_policy = Policy(
            id=uuid.uuid4(),
            name="PCI-DSS Credit Card Protection",
            description="Detect and block credit card numbers (PAN) to prevent PCI-DSS violations",
            enabled=True,
            priority=100,
            conditions={
                "all": [
                    {"field": "classification.labels", "operator": "contains", "value": "PAN"}
                ]
            },
            actions=[
                {"type": "block", "message": "Credit card number detected"},
                {"type": "alert", "severity": "critical"},
                {"type": "log", "destination": "siem"}
            ],
            compliance_tags=["PCI-DSS", "Financial Data"],
            created_by=admin_id
        )

        # GDPR PII Policy
        gdpr_policy = Policy(
            id=uuid.uuid4(),
            name="GDPR PII Protection",
            description="Protect personally identifiable information under GDPR",
            enabled=True,
            priority=90,
            conditions={
                "any": [
                    {"field": "classification.labels", "operator": "contains", "value": "SSN"},
                    {"field": "classification.labels", "operator": "contains", "value": "PII"}
                ]
            },
            actions=[
                {"type": "alert", "severity": "high"},
                {"type": "quarantine"},
                {"type": "log", "destination": "siem"}
            ],
            compliance_tags=["GDPR", "PII"],
            created_by=admin_id
        )

        # HIPAA PHI Policy
        hipaa_policy = Policy(
            id=uuid.uuid4(),
            name="HIPAA PHI Protection",
            description="Protect Protected Health Information under HIPAA",
            enabled=True,
            priority=95,
            conditions={
                "all": [
                    {"field": "classification.labels", "operator": "contains", "value": "PHI"}
                ]
            },
            actions=[
                {"type": "block", "message": "Protected Health Information detected"},
                {"type": "alert", "severity": "critical"},
                {"type": "encrypt"},
                {"type": "log", "destination": "siem"}
            ],
            compliance_tags=["HIPAA", "PHI", "Healthcare"],
            created_by=admin_id
        )

        session.add_all([pci_policy, gdpr_policy, hipaa_policy])
        await session.commit()
        print("✓ Default policies created")


async def main():
    """Main initialization function"""
    print("=" * 60)
    print("SeceoKnight DLP - Database Initialization")
    print("=" * 60)
    print()

    try:
        # Initialize database connections
        print("Connecting to databases...")
        await init_databases()
        print("✓ Connected to databases")
        print()

        # Create tables
        await create_tables()
        print()

        # Create default user
        await create_default_user()
        print()

        # Create MongoDB indexes
        await create_mongodb_indexes()
        print()

        # Create default policies
        await create_default_policies()
        print()

        print("=" * 60)
        print("✓ Database initialization completed successfully!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("1. Start the server: cd server && uvicorn app.main:app --reload")
        print("2. Access dashboard: http://localhost:3000")
        print("3. Login with: admin@seceoknight.local / ChangeMe123!")
        print()

    except Exception as e:
        print(f"✗ Error during initialization: {e}")
        raise
    finally:
        await close_databases()


if __name__ == "__main__":
    asyncio.run(main())
