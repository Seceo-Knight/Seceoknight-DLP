"""Reassign agent_code values in chronological registration order.

The original lazy-backfill in ``agents._ensure_agent_code`` ran in Mongo
cursor order, which for ``/agents/all`` is ``last_seen DESC`` — so codes
ended up sorted by recency, not by creation time. This script fixes
existing deployments by:

  1. Clearing every ``agent_code`` on the Mongo ``agents`` collection.
  2. Restarting the Postgres ``agent_code_seq`` at 1.
  3. Walking the Mongo agents in deterministic ``(created_at ASC, _id ASC)``
     order and allocating a fresh ``nextval`` for each.

Idempotent: re-running the script always rebuilds codes from the same
deterministic ordering, so values never drift. Safe to run while the
manager is up — concurrent registrations during the run could win a
sequence value, but the UNIQUE constraint and ``$exists:false`` guard in
``_ensure_agent_code`` mean nothing collides.

Usage::

    docker compose exec manager python -m scripts.reorder_agent_codes
"""
from __future__ import annotations

import asyncio
import sys
import os

# Make the script runnable both as `python -m scripts.reorder_agent_codes`
# and as `python scripts/reorder_agent_codes.py` from the server dir.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import text  # noqa: E402

from app.core.database import (  # noqa: E402
    init_databases,
    close_databases,
    get_mongodb,
)
import app.core.database as _db  # noqa: E402


async def main() -> None:
    await init_databases()

    mongo = get_mongodb()
    agents = mongo["agents"]

    # Step 1 — clear codes so every doc takes part in the reassignment.
    cleared = await agents.update_many(
        {"agent_code": {"$exists": True}},
        {"$unset": {"agent_code": ""}},
    )
    print(f"cleared agent_code on {cleared.modified_count} docs")

    # Step 2 — reset the Postgres sequence so allocation begins at 1.
    if not _db.postgres_session_factory:
        raise RuntimeError("Postgres session factory not initialised")

    async with _db.postgres_session_factory() as session:
        await session.execute(text("ALTER SEQUENCE agent_code_seq RESTART WITH 1"))
        await session.commit()
    print("agent_code_seq reset to 1")

    # Step 3 — walk agents in (created_at ASC, _id ASC) order and assign.
    cursor = agents.find({}, {"_id": 1, "agent_id": 1, "name": 1, "created_at": 1}).sort(
        [("created_at", 1), ("_id", 1)]
    )
    docs = await cursor.to_list(length=None)
    print(f"reassigning codes for {len(docs)} agents")

    for doc in docs:
        async with _db.postgres_session_factory() as session:
            row = await session.execute(text("SELECT nextval('agent_code_seq')"))
            await session.commit()
            code = int(row.scalar())
        await agents.update_one({"_id": doc["_id"]}, {"$set": {"agent_code": code}})
        print(
            f"  {code:>4}  agent_id={doc.get('agent_id')!r}  "
            f"name={doc.get('name')!r}  created_at={doc.get('created_at')}"
        )

    await close_databases()
    print("done")


if __name__ == "__main__":
    asyncio.run(main())
