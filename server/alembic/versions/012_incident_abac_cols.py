"""Add optional ABAC columns to the PostgreSQL ``incidents`` table.

Phase 3 prep. The columns are purely additive and nullable — existing rows
stay valid, and the current ABAC query logic (which joins
``incidents.event_id → events.department``) continues to work unchanged.

Phase 3 code can start populating ``incidents.department`` and
``incidents.required_clearance`` at incident creation, enabling per-row
ABAC on manual incidents that have no underlying event. Until that
populate logic ships, these columns stay NULL.

Revision ID: 012_incident_abac_cols
Revises: 011_incident_sev_to_int
"""
from alembic import op
import sqlalchemy as sa


revision = "012_incident_abac_cols"
down_revision = "011_incident_sev_to_int"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("department", sa.String(255), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column("required_clearance", sa.Integer(), nullable=True),
    )
    # Index department so ABAC-scoped incident queries (which Phase 3 may
    # add) don't sequential-scan.
    op.create_index(
        "idx_incidents_department",
        "incidents",
        ["department"],
    )


def downgrade() -> None:
    op.drop_index("idx_incidents_department", table_name="incidents")
    op.drop_column("incidents", "required_clearance")
    op.drop_column("incidents", "department")
