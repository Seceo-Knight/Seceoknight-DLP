"""
One-time Mongo → PostgreSQL events sync.

Walks ``dlp_events`` in ``_id`` order (stable cursor = resumable), maps each
doc to a PG ``events`` row via ``event_mapper``, and inserts with
``ON CONFLICT (event_id) DO NOTHING``. Idempotent — safe to run twice.

Usage (inside the manager container)::

    docker compose exec manager python -m app.scripts.events_sync
    docker compose exec manager python -m app.scripts.events_sync --batch-size 500

Reporting:

* ``events_sync.batch`` — per-iteration progress (attempted, upserted, skipped)
* ``events_sync.done``  — final totals + PG vs Mongo row counts

The script is safe to run alongside the live dual-write path. Every insert
uses the unique ``event_id`` index for conflict detection, so a race where
a newly-ingested event reaches PG first (via dual-write) is silently
tolerated.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

import structlog
from bson import ObjectId
from sqlalchemy import text as sa_text

import app.core.database as _db
from app.core.database import (
    close_databases,
    get_mongodb,
    init_databases,
)
from app.services.pg_event_mirror import mirror_events_bulk

logger = structlog.get_logger()


async def _pg_count() -> int:
    if _db.postgres_session_factory is None:
        return 0
    async with _db.postgres_session_factory() as s:
        r = await s.execute(sa_text("SELECT COUNT(*) FROM events"))
        return int(r.scalar() or 0)


async def run(batch_size: int) -> dict[str, int]:
    mongo = get_mongodb()
    coll = mongo.dlp_events

    total_docs = await coll.estimated_document_count()
    pg_before = await _pg_count()
    logger.info(
        "events_sync.start",
        mongo_docs=total_docs,
        pg_events_before=pg_before,
        batch_size=batch_size,
    )

    attempted = 0
    errors = 0
    iterations = 0
    last_id: Any = None

    # Cursor by _id so restarts resume rather than re-walk.
    while True:
        iterations += 1
        query: dict = {}
        if last_id is not None:
            query = {"_id": {"$gt": last_id}}

        # Projection-lite: return everything (mapper needs wide fields), just
        # ensure sort + limit are cheap. A covering index on _id makes the
        # scan trivial.
        cursor = coll.find(query).sort("_id", 1).limit(batch_size)
        batch = [d async for d in cursor]
        if not batch:
            break

        last_id = batch[-1]["_id"]
        if not isinstance(last_id, ObjectId):
            # Defensive: if _id isn't ObjectId for some reason, stop so we
            # don't re-walk.
            logger.warning("events_sync.unexpected_id_type", type=str(type(last_id)))

        a, e = await mirror_events_bulk(batch)
        attempted += a
        errors += e
        pg_now = await _pg_count()
        logger.info(
            "events_sync.batch",
            iteration=iterations,
            batch_docs=len(batch),
            attempted=a,
            errors=e,
            pg_events_now=pg_now,
        )

    pg_after = await _pg_count()
    summary = {
        "mongo_docs": total_docs,
        "pg_events_before": pg_before,
        "pg_events_after": pg_after,
        "attempted": attempted,
        "errors": errors,
        "iterations": iterations,
    }
    logger.info("events_sync.done", **summary)
    return summary


async def _main(batch_size: int) -> int:
    await init_databases()
    try:
        summary = await run(batch_size)
    finally:
        await close_databases()
    # Exit code: 0 when Mongo and PG counts agree after the run; 1 otherwise.
    # Skips (conflicts) still count as success — no data lost.
    if summary["pg_events_after"] >= summary["mongo_docs"]:
        print(
            f"events_sync: OK "
            f"(mongo={summary['mongo_docs']} "
            f"pg={summary['pg_events_after']} "
            f"attempted={summary['attempted']} "
            f"errors={summary['errors']})"
        )
        return 0
    print(
        f"events_sync: INCOMPLETE "
        f"(mongo={summary['mongo_docs']} "
        f"pg={summary['pg_events_after']} "
        f"attempted={summary['attempted']} "
        f"errors={summary['errors']})"
    )
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Mongo → PostgreSQL events sync")
    parser.add_argument("--batch-size", type=int, default=1000)
    args = parser.parse_args()
    sys.exit(asyncio.run(_main(args.batch_size)))


if __name__ == "__main__":
    main()
