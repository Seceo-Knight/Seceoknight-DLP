#!/usr/bin/env python3
"""
Initialize database with tables and default admin user
"""
import asyncio
from sqlalchemy import text
from app.core import database
from app.core.security import get_password_hash
from datetime import datetime

async def main():
    print("Initializing database...")

    # Initialize connections
    await database.init_databases()

    print("Creating tables...")

    # Create users table
    create_users_table = """
    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        hashed_password VARCHAR(255) NOT NULL,
        full_name VARCHAR(255),
        role VARCHAR(50) DEFAULT 'VIEWER',
        organization VARCHAR(255),
        is_active BOOLEAN DEFAULT TRUE,
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );
    """

    async with database.postgres_engine.begin() as conn:
        await conn.execute(text(create_users_table))
        print("✓ Users table created")

        # Check if admin user exists
        result = await conn.execute(
            text("SELECT id FROM users WHERE email = 'admin'")
        )
        admin_exists = result.first() is not None

        if not admin_exists:
            # Create default admin user (username: admin, password: admin)
            hashed_password = get_password_hash("admin")
            insert_admin = """
            INSERT INTO users (email, hashed_password, full_name, role, is_active, is_verified)
            VALUES ('admin', :password, 'Administrator', 'ADMIN', TRUE, TRUE)
            """
            await conn.execute(
                text(insert_admin),
                {"password": hashed_password}
            )
            print("✓ Default admin user created (username: admin, password: admin)")
        else:
            print("✓ Admin user already exists")

    # Close connections
    await database.close_databases()

    print("\n✅ Database initialization complete!")
    print("\nYou can now log in to the dashboard with:")
    print("  Username: admin")
    print("  Password: admin")

if __name__ == "__main__":
    asyncio.run(main())
