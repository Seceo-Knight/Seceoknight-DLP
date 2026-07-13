"""Fix remaining model/migration drift, found via a full audit of every
SQLAlchemy model's columns against actual migration coverage:

  * agents.deleted_at            — on the model, never migrated
  * file_fingerprints.updated_at — on the model, never migrated
  * policies.deleted_at          — on the model, never migrated
  * incidents.deleted_at         — on the model, never migrated
  * rules.deleted_at             — on the model, never migrated (this is
                                    the column behind "Failed to load
                                    Policies and Rules" in the dashboard)
  * policy_agents (whole table)  — app/models/policy_agent.py has no
                                    corresponding CREATE TABLE anywhere;
                                    any code path touching policy-agent
                                    assignments (Policy.agent_assignments
                                    backref, or a dedicated endpoint) would
                                    crash with UndefinedTable.

Revision ID: 025_fix_remaining_drift
Revises: 024_must_change_password
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "025_fix_remaining_drift"
down_revision = "024_must_change_password"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("file_fingerprints", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("policies", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("rules", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "policy_agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_id", "agent_id", name="uq_policy_agent"),
    )
    op.create_index("ix_policy_agents_policy_id", "policy_agents", ["policy_id"])
    op.create_index("ix_policy_agents_agent_id", "policy_agents", ["agent_id"])


def downgrade() -> None:
    op.drop_index("ix_policy_agents_agent_id", table_name="policy_agents")
    op.drop_index("ix_policy_agents_policy_id", table_name="policy_agents")
    op.drop_table("policy_agents")
    op.drop_column("rules", "deleted_at")
    op.drop_column("incidents", "deleted_at")
    op.drop_column("policies", "deleted_at")
    op.drop_column("file_fingerprints", "updated_at")
    op.drop_column("agents", "deleted_at")
