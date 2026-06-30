#!/bin/sh
# Entrypoint for the SeceoKnight DLP manager container.
# Runs Alembic migrations on every startup (idempotent — already-applied
# migrations are skipped). This guarantees the DB schema and seed data are
# always in sync with the deployed code without manual intervention.

set -e

echo "[entrypoint] Running database migrations..."
alembic upgrade head
echo "[entrypoint] Migrations complete."

echo "[entrypoint] Starting application..."
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "${PORT:-55000}" \
    --workers "${UVICORN_WORKERS:-4}"
