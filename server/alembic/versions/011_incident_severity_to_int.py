"""Convert incidents.severity VARCHAR → INTEGER with bounded CHECK.

Brings the DB in line with the pydantic API (int 0–4) and with how events
already encode severity (integer-ish via string in Event). No existing rows
today, but the UPDATE step is included to make the migration safe to apply
in environments where string values were inserted.

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
    # 1. Add a new INT column; backfill from the string column.
    op.add_column(
        "incidents",
        sa.Column("severity_int", sa.Integer(), nullable=True),
    )
    op.execute(
        """
        UPDATE incidents SET severity_int = CASE severity
            WHEN 'info'     THEN 0
            WHEN 'low'      THEN 1
            WHEN 'medium'   THEN 2
            WHEN 'high'     THEN 3
            WHEN 'critical' THEN 4
            ELSE 1
        END
        """
    )
    # 2. NOT NULL + default 1 (= 'low'; matches pydantic default=2 but the DB
    #    default is conservative for direct SQL inserts that omit the column).
    op.alter_column(
        "incidents",
        "severity_int",
        nullable=False,
        server_default=sa.text("1"),
    )

    # 3. Drop the old string column and rename.
    op.drop_column("incidents", "severity")
    op.alter_column("incidents", "severity_int", new_column_name="severity")

    # 4. Re-create the CHECK with the new int-based rule. Re-uses the
    #    constraint name ck_incident_severity that was dropped in 010.
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
