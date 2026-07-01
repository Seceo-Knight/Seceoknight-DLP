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
    echo "[entrypoint] Starting uvicorn..."
    exec uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "${PORT:-55000}" \
        --workers "${UVICORN_WORKERS:-4}"
fi
