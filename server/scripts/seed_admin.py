"""Manual/standalone bootstrap of the first admin account.

NOT invoked automatically anymore. This used to be called from
entrypoint.sh on every manager container start, but that always ran
BEFORE app.main:app's own startup (lifespan) handler -- so its hardcoded
default password (originally "Admin@1234") always won the race and got
created first, silently defeating the random-per-deployment admin
password that app/main.py::_auto_init_schema_and_admin() generates. See
CHANGELOG.md ("Random Per-Deployment Admin Password" / the entrypoint.sh
fix that removed the call to this script) for the full story.

app/main.py::_auto_init_schema_and_admin() already does this job on every
normal startup -- correctly (CSPRNG-random password or DLP_ADMIN_PASSWORD
if pinned, ON-CONFLICT-safe against concurrent workers) -- so this script
is redundant for the standard Docker deployment path. It's kept only for
a non-standard setup that runs the app some other way and needs to seed
the first admin manually; if you do run it by hand, don't rely on the
env-var default below being safe to leave unset in anything but a
throwaway/local environment.

Safe to run on every container start: it checks `SELECT COUNT(*) FROM
users` first and does nothing if the table is non-empty, so it will never
overwrite or duplicate an account an operator has already created or
changed.
"""
import asyncio
import os
import secrets as _secrets
import string as _string
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text

from app.core import database as db
from app.core.security import get_password_hash


def _random_password(length: int = 20) -> str:
    """Same construction as app/main.py::_generate_admin_password() --
    guarantees upper/lower/digit/symbol coverage instead of hoping a flat
    random draw happens to include all four classes, then CSPRNG-shuffles
    so the guaranteed characters aren't always in the same position."""
    upper, lower, digits = _string.ascii_uppercase, _string.ascii_lowercase, _string.digits
    symbols = "!@#$%^&*-_=+"
    pool = upper + lower + digits + symbols
    required = [_secrets.choice(upper), _secrets.choice(lower), _secrets.choice(digits), _secrets.choice(symbols)]
    rest = [_secrets.choice(pool) for _ in range(length - len(required))]
    chars = required + rest
    for i in range(len(chars) - 1, 0, -1):
        j = _secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


ADMIN_EMAIL = os.environ.get("SEED_ADMIN_EMAIL", "admin@seceoknight.local")
# Only use SEED_ADMIN_PASSWORD if explicitly set; otherwise generate a
# random one instead of falling back to a hardcoded, publicly-known default.
_ENV_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD")
ADMIN_PASSWORD = _ENV_PASSWORD if _ENV_PASSWORD else _random_password()
_PASSWORD_WAS_GENERATED = not _ENV_PASSWORD


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
        if _PASSWORD_WAS_GENERATED:
            print(f"[seed_admin] Generated password (only shown once): {ADMIN_PASSWORD}")
        print("[seed_admin] Change this password immediately after first login.")


if __name__ == "__main__":
    asyncio.run(main())
