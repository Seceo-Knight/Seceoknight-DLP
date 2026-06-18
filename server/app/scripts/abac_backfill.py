"""
ABAC backfill: stamp ``department='DEFAULT'`` and ``required_clearance=0``
onto existing MongoDB ``dlp_events`` documents that predate migration 009.

Properties (per spec PART 2 §5):

* **Batched**   — processes up to ``--batch-size`` docs per iteration (default 1000).
* **Resumable** — the selector ``{department: {$exists: false}}`` means that
                  re-running the script picks up exactly where it left off.
                  Each completed batch is independently committed by Mongo.
* **Logged**    — emits `backfill_progress` logs every batch with counts of
                  total / processed / remaining, plus a final summary.
* **No partial state** — each doc either ends up with both new fields or
                  neither; Mongo applies the ``$set`` atomically per-doc.

Usage (from inside the manager container)::

    docker compose exec manager python -m app.scripts.abac_backfill
    docker compose exec manager python -m app.scripts.abac_backfill --batch-size 500

The script is safe to run in parallel with live ingest: new events written
after migration 009 already carry the fields (see events.py / decision.py),
so they won't match the selector. Running twice is a no-op.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import structlog

from app.core.config import settings  # noqa: F401 — force settings load
from app.core.database import get_mongodb, init_databases, close_databases

logger = structlog.get_logger()


async def _backfill_collection(
    coll, collection_name: str, batch_size: int
) -> int:
    """Generic backfiller used for both dlp_events and incidents.

    For incidents, we copy ``department`` / ``required_clearance`` from the
    linked event row when available; otherwise we fall back to the same
    ``DEFAULT`` / ``0`` baseline we use for dlp_events. This keeps the rule
    "incident visibility follows underlying event" intact.
    """
    db = get_mongodb()
    events_coll = db.dlp_events
    is_incidents = collection_name == "incidents"

    total_docs = await coll.estimated_document_count()
    remaining = await coll.count_documents({"department": {"$exists": False}})
    logger.info(
        "abac_backfill.start",
        collection=collection_name,
        total_docs=total_docs,
        pending=remaining,
        batch_size=batch_size,
    )

    total_modified = 0
    iteration = 0

    while True:
        iteration += 1

        projection = (
            {"_id": 1, "event_id": 1}
            if is_incidents
            else {"_id": 1}
        )
        cursor = coll.find(
            {"department": {"$exists": False}}, projection=projection
        ).limit(batch_size)
        docs = [doc async for doc in cursor]
        if not docs:
            break

        if is_incidents:
            # Resolve per-doc from source event; fall back to DEFAULT/0.
            modified_this_batch = 0
            for inc in docs:
                dept = "DEFAULT"
                req_clr = 0
                event_id = inc.get("event_id")
                if event_id:
                    ev = await events_coll.find_one(
                        {"id": event_id},
                        projection={"department": 1, "required_clearance": 1, "_id": 0},
                    )
                    if ev:
                        dept = ev.get("department") or "DEFAULT"
                        req_clr = int(ev.get("required_clearance") or 0)
                res = await coll.update_one(
                    {"_id": inc["_id"], "department": {"$exists": False}},
                    {"$set": {"department": dept, "required_clearance": req_clr}},
                )
                modified_this_batch += res.modified_count
        else:
            ids = [d["_id"] for d in docs]
            res = await coll.update_many(
                {"_id": {"$in": ids}, "department": {"$exists": False}},
                {"$set": {"department": "DEFAULT", "required_clearance": 0}},
            )
            modified_this_batch = res.modified_count

        total_modified += modified_this_batch
        remaining = await coll.count_documents({"department": {"$exists": False}})
        logger.info(
            "abac_backfill.batch",
            collection=collection_name,
            iteration=iteration,
            batch_size=len(docs),
            modified_this_batch=modified_this_batch,
            total_modified=total_modified,
            remaining=remaining,
        )

        if modified_this_batch == 0 and remaining > 0:
            logger.error(
                "abac_backfill.stuck",
                collection=collection_name,
                remaining=remaining,
            )
            raise RuntimeError(f"abac_backfill stuck on {collection_name}")

    logger.info(
        "abac_backfill.done",
        collection=collection_name,
        total_modified=total_modified,
    )
    return total_modified


async def backfill_mongo(batch_size: int) -> int:
    """
    Backfill ABAC fields on ``dlp_events`` and ``incidents`` collections.
    Returns total documents modified across both.
    """
    db = get_mongodb()
    total = 0
    total += await _backfill_collection(db.dlp_events, "dlp_events", batch_size)
    total += await _backfill_collection(db.incidents, "incidents", batch_size)
    return total


async def _run(batch_size: int) -> int:
    await init_databases()
    try:
        return await backfill_mongo(batch_size)
    finally:
        await close_databases()


def main() -> None:
    parser = argparse.ArgumentParser(description="ABAC Phase 2 MongoDB backfill")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Number of documents per batch (default: 1000)",
    )
    args = parser.parse_args()

    modified = asyncio.run(_run(args.batch_size))
    print(f"abac_backfill: modified {modified} dlp_events documents")
    # Exit 0 whether modified was 0 (already-backfilled) or positive.
    sys.exit(0)


if __name__ == "__main__":
    main()
