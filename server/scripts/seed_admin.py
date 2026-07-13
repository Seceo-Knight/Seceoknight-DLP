"""Bootstrap the first admin account, if and only if no users exist yet.

BACKGROUND: nothing in the deployment pipeline (entrypoint.sh, install.sh,
or any Alembic migration) ever creates a first user. install.sh prints
"admin / Admin@1234" as if that account already exists, but no code path
actually provisions it. This script closes that gap.

Safe to run on every container start: it checks `SELECT COUNT(*) FROM
users` first and does nothing if the table is non-empty, so it will never
overwrite or duplicate an account an operator has already created or
changed.

The initial password is intentionally weak and well-known
(SEED_ADMIN_PASSWORD env var, default "Admin@1234") because it is meant to
be changed immediately after first login via Settings -> Profile -> Change
Password. This matches the message install.sh already prints.
"""
import asyncio
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text

from app.core import database as db
from app.core.security import get_password_hash


ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@seceoknight.local")
ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD", "Admin@1234")


async def main() -> None:
    await db.init_databases()
    async with db.postgres_session_factory() as session:
        count = (await session.execute(text("SELECT COUNT(*) FROM users"))).scalar_one()
        if count > 0:
            print(f"[seed_admin] {count} user(s) already exist — skipping.")
            return

        role_id = (
            await session.execute(text("SELECT id FROM roles WHERE name = 'ADMIN'"))
        ).scalar_one_or_none()
        if role_id is None:
            print("[seed_admin] No ADMIN role found (migrations not applied yet?) — skipping.")
            return

        await session.execute(
            text(
                """
                INSERT INTO users
                    (id, email, hashed_password, full_name, role, role_id,
                     organization, is_active, is_verified, created_at)
                VALUES
                    (:id, :email, :hashed_password, :full_name, 'ADMIN', :role_id,
                     :organization, true, true, now())
                """
            ),
            {
                "id": uuid.uuid4(),
                "email": ADMIN_EMAIL,
                "hashed_password": get_password_hash(ADMIN_PASSWORD),
                "full_name": "System Administrator",
                "role_id": role_id,
                "organization": "SeceoKnight",
            },
        )
        await session.commit()
        print(f"[seed_admin] Created first admin account: {ADMIN_EMAIL}")
        print("[seed_admin] Change this password immediately after first login.")


if __name__ == "__main__":
    asyncio.run(main())
