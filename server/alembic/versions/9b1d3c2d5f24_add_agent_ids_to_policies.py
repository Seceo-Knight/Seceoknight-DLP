"""add agent_ids column to policies

Revision ID: 9b1d3c2d5f24
Revises: caa6530e7d81
Create Date: 2025-12-08 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "9b1d3c2d5f24"
down_revision = "caa6530e7d81"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("policies", sa.Column("agent_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("policies", "agent_ids")












