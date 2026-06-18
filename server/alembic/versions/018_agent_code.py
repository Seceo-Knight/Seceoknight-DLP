"""Add agents.agent_code — short, human-readable numeric ID.

Keeps UUID (agents.id) and the freeform agents.agent_id string as the
internal identifiers; agent_code is purely for display ("001", "012",
"123" once zero-padded in the UI).

Design constraints (per spec):
  * Sequence-driven assignment, never computed in app code.
  * Stored as INTEGER UNIQUE — formatting is a UI concern.
  * Existing rows backfilled in created_at order so the oldest agent
    becomes 1, the next 2, etc.

Revision ID: 018_agent_code
Revises: 017_drop_dashboards
"""
from alembic import op


revision = "018_agent_code"
down_revision = "017_drop_dashboards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) Sequence first so the column DEFAULT can reference it.
    op.execute("CREATE SEQUENCE IF NOT EXISTS agent_code_seq START 1")

    # 2) Add column nullable so we can backfill deterministically by
    #    created_at before flipping it to NOT NULL. The DEFAULT applies
    #    to any row inserted from this point forward.
    op.execute(
        "ALTER TABLE agents "
        "ADD COLUMN IF NOT EXISTS agent_code INTEGER "
        "DEFAULT nextval('agent_code_seq')"
    )

    # 3) Backfill: oldest registered agent → smallest code. We do this in
    #    a single statement using a CTE so the ordering is deterministic
    #    even when multiple rows share a created_at second.
    op.execute(
        """
        WITH ordered AS (
            SELECT id,
                   nextval('agent_code_seq') AS code
            FROM (
                SELECT id
                FROM agents
                WHERE agent_code IS NULL
                ORDER BY created_at NULLS LAST, id
            ) s
        )
        UPDATE agents a
           SET agent_code = ordered.code
          FROM ordered
         WHERE a.id = ordered.id
        """
    )

    # 4) Lock down: NOT NULL + UNIQUE. After backfill every row has a
    #    code, and the sequence guarantees future inserts won't collide.
    op.execute("ALTER TABLE agents ALTER COLUMN agent_code SET NOT NULL")
    op.execute(
        "ALTER TABLE agents "
        "ADD CONSTRAINT agents_agent_code_key UNIQUE (agent_code)"
    )

    # 5) Tie the sequence to the column so pg_dump round-trips correctly
    #    and DROP COLUMN cleans up the sequence too.
    op.execute("ALTER SEQUENCE agent_code_seq OWNED BY agents.agent_code")


def downgrade() -> None:
    op.execute("ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_agent_code_key")
    op.execute("ALTER TABLE agents DROP COLUMN IF EXISTS agent_code")
    op.execute("DROP SEQUENCE IF EXISTS agent_code_seq")
