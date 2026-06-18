"""Drop the stale ck_incident_severity CHECK constraint.

Migration 004 converted ``incidents.severity`` from VARCHAR to INTEGER, but
did not drop the associated CHECK constraint which still enforces the old
string values ('low','medium','high','critical','info'). The result is
that every INSERT into ``incidents`` with a numeric severity is rejected
with a CheckViolationError, breaking the /incidents POST endpoint entirely.

This migration drops that constraint. The column definition (INTEGER) and
application logic are unchanged; severity is already range-bounded at the
API layer (``Field(ge=0, le=4)``), so removing the DB-level string check
does not reduce validation.

Revision ID: 010_drop_incident_sev_check
Revises: 009_abac_event_columns
"""
from alembic import op


revision = "010_drop_incident_sev_check"
down_revision = "009_abac_event_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF EXISTS keeps the migration re-runnable and forward-compatible with
    # environments where the constraint was manually cleaned up already.
    op.execute(
        "ALTER TABLE incidents DROP CONSTRAINT IF EXISTS ck_incident_severity"
    )


def downgrade() -> None:
    # Intentional no-op: re-adding the old VARCHAR-based CHECK would fail on
    # any row whose severity is numeric, which is every row post-004. The
    # downgrade simply leaves the table without the stale constraint.
    pass
