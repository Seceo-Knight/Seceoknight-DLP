"""Convert incidents.severity VARCHAR → INTEGER with bounded CHECK.

Brings the DB in line with the pydantic API (int 0–4) and with how events
already encode severity (integer-ish via string in Event).

NOTE: migration 004 already converted incidents.severity from VARCHAR to
INTEGER (see "incidents: severity String→Integer" in 004), and 010 confirms
this in its own docstring. By the time this migration runs, severity is
already an INTEGER column (1=low..4=critical), so there is no string-based
data left to convert here — attempting a CASE-based string→int backfield
against an already-integer column raises "invalid input syntax for type
integer" on every fresh install. All that's left to do is (re-)establish
the bounded CHECK constraint that 010 dropped, this time permitting 0
(info) alongside the existing 1-4 range so the scale matches events and
the pydantic API.

Mapping (matches IncidentCreate docstring: "0=info..4=critical"):
    'info' → 0
    'low' → 1
    'medium' → 2
    'high' → 3
    'critical' → 4

Revision ID: 011_incident_sev_to_int
Revises: 010_drop_incident_sev_check
"""
from alembic import op
import sqlalchemy as sa


revision = "011_incident_sev_to_int"
down_revision = "010_drop_incident_sev_check"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_incident_severity",
        "incidents",
        "severity BETWEEN 0 AND 4",
    )


def downgrade() -> None:
    # Reverse-map ints back to the legacy strings. Best-effort: any value
    # outside 0–4 becomes 'low' (the pre-migration default).
    op.drop_constraint("ck_incident_severity", "incidents", type_="check")
    op.add_column(
        "incidents",
        sa.Column("severity_str", sa.String(20), nullable=True),
    )
    op.execute(
        """
        UPDATE incidents SET severity_str = CASE severity
            WHEN 0 THEN 'info'
            WHEN 1 THEN 'low'
            WHEN 2 THEN 'medium'
            WHEN 3 THEN 'high'
            WHEN 4 THEN 'critical'
            ELSE 'low'
        END
        """
    )
    op.alter_column("incidents", "severity_str", nullable=False)
    op.drop_column("incidents", "severity")
    op.alter_column("incidents", "severity_str", new_column_name="severity")
