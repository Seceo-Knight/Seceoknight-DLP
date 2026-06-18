"""
Mongo → PostgreSQL event mirror (dual-write companion).

Agents write to MongoDB (the authoritative store for raw DLP events); this
module mirrors each write into the PostgreSQL ``events`` table so the
analytics/export stack has something to aggregate.

Failure isolation (per Phase 3 spec):
* Mongo write is primary. This mirror runs AFTER Mongo has already accepted
  the doc.
* Any exception here is logged at WARNING level and swallowed — the agent
  has already received 201 from the POST path, so a PG hiccup must not
  crash the response or retry.
* Idempotency via PG's unique index on ``events.event_id``; ON CONFLICT
  DO NOTHING lets us retry / re-run backfill without duplicates.
"""

from __future__ import annotations

from typing import Iterable, Sequence

import structlog
from sqlalchemy.dialects.postgresql import insert as pg_insert

# NOTE: dereference the session factory at call time, not import time.
# app.core.database._db.postgres_session_factory is None at module-load and gets
# populated by init_databases() during app startup; an ``import from`` would
# freeze the None reference and silently no-op every write.
import app.core.database as _db
from app.models.event import Event
from app.services.event_mapper import mongo_doc_to_pg_event

logger = structlog.get_logger()


async def mirror_event_to_pg(mongo_doc: dict) -> None:
    """Mirror a single Mongo doc to PG. Never raises; always best-effort."""
    if _db.postgres_session_factory is None:
        return
    row = mongo_doc_to_pg_event(mongo_doc)
    if not row.get("event_id"):
        logger.debug("pg_mirror: skipping doc without event_id")
        return
    try:
        async with _db.postgres_session_factory() as session:
            stmt = (
                pg_insert(Event)
                .values(**row)
                .on_conflict_do_nothing(index_elements=["event_id"])
            )
            await session.execute(stmt)
            await session.commit()
    except Exception as e:
        logger.warning(
            "pg_mirror.write_failed",
            event_id=row.get("event_id"),
            error=str(e),
        )


async def mirror_events_bulk(mongo_docs: Iterable[dict]) -> tuple[int, int]:
    """
    Mirror a batch of Mongo docs to PG.

    Returns ``(attempted, errors)``. The function chunks internally: asyncpg
    caps a single query at 32 767 bind parameters, and the Event insert uses
    ~42 columns per row, so we stay well under the limit with 500 rows per
    chunk. Each chunk runs in its own transaction. If a chunk's bulk insert
    fails (e.g. one row has a bad INET value), that chunk falls back to
    per-row writes so the rest of the batch still lands.
    """
    docs = [d for d in mongo_docs if d]
    if not docs or _db.postgres_session_factory is None:
        return 0, 0

    rows = [mongo_doc_to_pg_event(d) for d in docs]
    rows = [r for r in rows if r.get("event_id")]
    if not rows:
        return 0, 0

    # Conservative chunk size: 500 rows * ~42 cols ≈ 21 000 params.
    # Also keeps each transaction short so concurrent ingest isn't blocked.
    CHUNK = 500
    total_attempted = 0
    total_errors = 0

    for i in range(0, len(rows), CHUNK):
        chunk = rows[i : i + CHUNK]
        try:
            async with _db.postgres_session_factory() as session:
                stmt = (
                    pg_insert(Event)
                    .values(chunk)
                    .on_conflict_do_nothing(index_elements=["event_id"])
                )
                await session.execute(stmt)
                await session.commit()
            total_attempted += len(chunk)
            continue
        except Exception as e:
            logger.warning(
                "pg_mirror.chunk_failed_falling_back_per_row",
                chunk_size=len(chunk),
                error=str(e),
            )

        # Per-row fallback for this chunk only.
        for row in chunk:
            try:
                async with _db.postgres_session_factory() as session:
                    stmt = (
                        pg_insert(Event)
                        .values(**row)
                        .on_conflict_do_nothing(index_elements=["event_id"])
                    )
                    await session.execute(stmt)
                    await session.commit()
                total_attempted += 1
            except Exception as e:
                total_errors += 1
                logger.warning(
                    "pg_mirror.row_failed",
                    event_id=row.get("event_id"),
                    error=str(e),
                )

    return total_attempted, total_errors
