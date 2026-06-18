"""Add type, severity, config columns to policies table

Revision ID: 4a08eecdb2f5
Revises: 001_initial
Create Date: 2025-11-18 11:34:43.702095

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '4a08eecdb2f5'
down_revision = '001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add new columns to policies table for frontend format (Option B: Extend Database)
    op.add_column('policies', sa.Column('type', sa.String(length=50), nullable=True))
    op.add_column('policies', sa.Column('severity', sa.String(length=20), nullable=True))
    op.add_column('policies', sa.Column('config', sa.JSON(), nullable=True))


def downgrade() -> None:
    # Remove columns from policies table
    op.drop_column('policies', 'config')
    op.drop_column('policies', 'severity')
    op.drop_column('policies', 'type')
