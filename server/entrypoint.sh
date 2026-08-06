#!/bin/sh
# Entrypoint for SeceoKnight DLP containers.
#
# Runs Alembic migrations first (idempotent — already-applied migrations are
# skipped), then starts the process specified by CMD/command.
#
# - manager:       no command override → defaults to uvicorn
# - celery-worker: command = celery -A app.tasks worker ...
# - celery-beat:   command = celery -A app.tasks beat ...

set -e

echo "[entrypoint] Running database migrations..."
alembic upgrade head
echo "[entrypoint] Migrations complete."

# If arguments were passed via docker-compose `command:`, use them.
# Otherwise fall back to uvicorn (the manager default).
if [ "$#" -gt 0 ]; then
    echo "[entrypoint] Starting: $*"
    exec "$@"
else
    # NOTE: first-admin seeding is intentionally NOT done here anymore.
    # scripts/seed_admin.py used to run at this point and create the admin
    # account with a hardcoded default password (Admin@1234). Because it ran
    # here -- before uvicorn, and therefore before app.main:app's own
    # lifespan startup handler -- it always won the race against
    # _auto_init_schema_and_admin() in app/main.py, which does the exact
    # same job correctly (random CSPRNG password per deployment, or
    # DLP_ADMIN_PASSWORD if pinned; see CHANGELOG.md). The result was that
    # the random-password fix never actually took effect in a real Docker
    # deployment: seed_admin.py's weak hardcoded password always got created
    # first. Removing the call here lets app.main:app's lifespan handler be
    # the single, already-correct source of first-admin seeding. The script
    # itself is left in place (unused by this entrypoint) only in case an
    # operator wants to run it manually for a non-standard setup.
    echo "[entrypoint] Starting uvicorn..."
    exec uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "${PORT:-55000}" \
        --workers "${UVICORN_WORKERS:-4}"
fi
