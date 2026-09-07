"""Scope policy name uniqueness to non-deleted rows only.

Problem: policies use a soft delete (``deleted_at`` timestamp, see
app/services/policy_service.py delete_policy -- rows are kept for audit
trail rather than removed). But the ``policies.name`` column has a plain
table-wide UNIQUE constraint (``policies_name_key``, from the original
``sa.UniqueConstraint('name')`` in 001_initial_schema.py), which Postgres
enforces across ALL rows regardless of ``deleted_at``.

Effect: once a policy named e.g. "Clipboard Monitoring" is deleted, its
row still occupies that name at the DB level. Trying to create a new
policy re-using that name -- exactly what an admin does after clearing
out a policy list and rebuilding it -- fails with a uniqueness error,
surfaced to the user as "Policy with name '...' already exists" even
though nothing with that name is visible anywhere in the UI.

(The application-level pre-check in PolicyService.get_policy_by_name()
had the same bug -- not filtering deleted_at -- fixed alongside this
migration in the same commit.)

Fix: drop the table-wide unique constraint and replace it with a partial
unique index that only applies to non-deleted rows
(``WHERE deleted_at IS NULL``), so a policy name becomes reusable again
as soon as the row that held it is soft-deleted.

Idempotent (IF EXISTS / IF NOT EXISTS), safe to re-run.

Revision ID: 043_policy_name_unique_active_only
Revises: 042_sso_role_provenance
"""
from alembic import op
import sqlalchemy as sa


revision = "043_policy_name_unique_active_only"
down_revision = "042_sso_role_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_name_key"))
    bind.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_policies_name_active "
        "ON policies (name) WHERE deleted_at IS NULL"
    ))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DROP INDEX IF EXISTS ix_policies_name_active"))
    # NOTE: this will fail if any soft-deleted rows currently share a name
    # with another row (active or deleted) -- that's an expected trade-off
    # of downgrading past a partial-uniqueness fix, not a migration bug.
    bind.execute(sa.text(
        "ALTER TABLE policies ADD CONSTRAINT policies_name_key UNIQUE (name)"
    ))
