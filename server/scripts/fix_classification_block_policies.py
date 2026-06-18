"""Repair classification-aware USB blocking policies.

Backfills two known gaps that prevent the realtime evaluator from
returning ``action=block`` on USB transfers of sensitive files:

  1. Inserts ``Block Sensitive Files on USB`` when it does not yet
     exist. This is the policy the realtime evaluator at
     ``server/app/api/v1/agents.py:evaluate_policy_realtime`` needs
     in order to return a block decision when the agent reports
     ``classification_level in (Confidential, Restricted)`` and
     ``destination_type=removable_drive``. Without it, every policy
     match falls through to ``allow`` even when classification
     correctly tags content as sensitive.

  2. Repairs ``Block Sensitive Data`` when its conditions are stuck
     in the impossibly-conjunctive shape
     ``{"match": "all", "rules": [{equals Restricted}, {equals
     Confidential}]}`` — a single classification level cannot equal
     both strings simultaneously, so the policy never matches.
     Collapses the two ``equals`` rules into one ``in`` rule.

Idempotent: re-running is a no-op once the fixes are present.

Usage::

    docker compose exec manager python -m scripts.fix_classification_block_policies
    docker compose restart manager     # or wait ~5 min for cache TTL
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import text  # noqa: E402

from app.core.database import init_databases, close_databases  # noqa: E402
import app.core.database as _db  # noqa: E402


BLOCK_SENSITIVE_DATA_NAME = "Block Sensitive Data"
BLOCK_SENSITIVE_USB_NAME = "Block Sensitive Files on USB"

REPAIRED_BLOCK_SENSITIVE_DATA_CONDITIONS = {
    "match": "all",
    "rules": [
        {
            "field": "classification_level",
            "operator": "in",
            "value": ["Confidential", "Restricted"],
        }
    ],
}

BLOCK_SENSITIVE_USB_POLICY = {
    "name": BLOCK_SENSITIVE_USB_NAME,
    "description": "Blocks Confidential/Restricted files going to removable drives",
    "enabled": True,
    "priority": 100,
    "type": "usb_file_transfer_monitoring",
    "severity": "critical",
    "config": {
        "description": "Block sensitive data from leaving on USB",
    },
    "conditions": {
        "match": "all",
        "rules": [
            {
                "field": "classification_level",
                "operator": "in",
                "value": ["Confidential", "Restricted"],
            },
            {
                "field": "destination_type",
                "operator": "equals",
                "value": "removable_drive",
            },
        ],
    },
    "actions": {
        "block": {},
        "alert": {"severity": "critical"},
    },
}


def _is_broken_block_sensitive_data(conditions) -> bool:
    """True iff conditions still encode the impossible AND of two equals rules."""
    if not isinstance(conditions, dict):
        return False
    if conditions.get("match", "all").lower() != "all":
        return False
    rules = conditions.get("rules") or []
    if len(rules) < 2:
        return False
    levels_seen = set()
    for rule in rules:
        if not isinstance(rule, dict):
            return False
        if rule.get("field") != "classification_level":
            return False
        if rule.get("operator") != "equals":
            return False
        levels_seen.add(rule.get("value"))
    return len(levels_seen) >= 2  # multiple distinct equals = impossible AND


async def _repair_block_sensitive_data(session) -> str:
    row = (
        await session.execute(
            text(
                "SELECT id, conditions FROM policies "
                "WHERE name = :name AND deleted_at IS NULL"
            ),
            {"name": BLOCK_SENSITIVE_DATA_NAME},
        )
    ).first()
    if row is None:
        return f"skip   {BLOCK_SENSITIVE_DATA_NAME!r} — not present"

    policy_id, conditions = row
    if not _is_broken_block_sensitive_data(conditions):
        return f"ok     {BLOCK_SENSITIVE_DATA_NAME!r} — conditions already healthy"

    await session.execute(
        text(
            "UPDATE policies SET conditions = :c, updated_at = NOW() "
            "WHERE id = :id"
        ),
        {
            "c": json.dumps(REPAIRED_BLOCK_SENSITIVE_DATA_CONDITIONS),
            "id": policy_id,
        },
    )
    return (
        f"fixed  {BLOCK_SENSITIVE_DATA_NAME!r} — collapsed two equals rules "
        f"into a single 'in' rule"
    )


async def _ensure_block_sensitive_files_on_usb(session) -> str:
    # Unique constraint on `name` includes soft-deleted rows, so we look for
    # any row with this name (deleted or not) and resurrect/refresh it
    # rather than failing with a duplicate-key error.
    existing = (
        await session.execute(
            text("SELECT id, deleted_at FROM policies WHERE name = :name"),
            {"name": BLOCK_SENSITIVE_USB_NAME},
        )
    ).first()

    p = BLOCK_SENSITIVE_USB_POLICY

    if existing is not None:
        policy_id, deleted_at = existing
        if deleted_at is None:
            return f"ok     {BLOCK_SENSITIVE_USB_NAME!r} — already present"
        # Soft-deleted instance exists — resurrect with canonical config.
        await session.execute(
            text(
                "UPDATE policies SET deleted_at = NULL, enabled = :enabled, "
                "status = 'active', priority = :priority, type = :type, "
                "severity = :severity, description = :description, "
                "config = :config, conditions = :conditions, "
                "actions = :actions, updated_at = NOW() WHERE id = :id"
            ),
            {
                "id": policy_id,
                "description": p["description"],
                "enabled": p["enabled"],
                "priority": p["priority"],
                "type": p["type"],
                "severity": p["severity"],
                "config": json.dumps(p["config"]),
                "conditions": json.dumps(p["conditions"]),
                "actions": json.dumps(p["actions"]),
            },
        )
        return f"restored  {BLOCK_SENSITIVE_USB_NAME!r} — was soft-deleted"

    admin_row = (
        await session.execute(
            text(
                "SELECT id FROM users WHERE role = 'ADMIN' "
                "AND deleted_at IS NULL ORDER BY created_at LIMIT 1"
            )
        )
    ).first()
    if admin_row is None:
        return (
            f"skip   {BLOCK_SENSITIVE_USB_NAME!r} — no admin user found, "
            f"cannot set created_by"
        )
    admin_id = admin_row[0]

    await session.execute(
        text(
            "INSERT INTO policies (id, name, description, enabled, status, "
            "priority, type, severity, config, conditions, actions, "
            "compliance_tags, agent_ids, created_by, created_at, updated_at) "
            "VALUES (gen_random_uuid(), :name, :description, :enabled, "
            "'active', :priority, :type, :severity, :config, :conditions, "
            ":actions, NULL, NULL, :created_by, NOW(), NOW())"
        ),
        {
            "name": p["name"],
            "description": p["description"],
            "enabled": p["enabled"],
            "priority": p["priority"],
            "type": p["type"],
            "severity": p["severity"],
            "config": json.dumps(p["config"]),
            "conditions": json.dumps(p["conditions"]),
            "actions": json.dumps(p["actions"]),
            "created_by": admin_id,
        },
    )
    return f"added  {BLOCK_SENSITIVE_USB_NAME!r}"


async def main() -> None:
    await init_databases()

    if not _db.postgres_session_factory:
        raise RuntimeError("Postgres session factory not initialised")

    async with _db.postgres_session_factory() as session:
        msg1 = await _repair_block_sensitive_data(session)
        msg2 = await _ensure_block_sensitive_files_on_usb(session)
        await session.commit()

    print(msg1)
    print(msg2)
    print()
    print("Restart the manager (or wait ~5 min for cache TTL) so the")
    print("evaluator picks up the new state:")
    print("    docker compose restart manager")

    await close_databases()


if __name__ == "__main__":
    asyncio.run(main())
