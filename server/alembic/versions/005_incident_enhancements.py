"""Add title, description, policy_id to incidents table

Revision ID: 005_incidents
Revises: 004_schema_overhaul
Create Date: 2026-03-30 09:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '005_incidents'
down_revision = '004_schema_overhaul'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('incidents', sa.Column('title', sa.String(500), nullable=True))
    op.add_column('incidents', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('incidents', sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key('fk_incidents_policy_id', 'incidents', 'policies', ['policy_id'], ['id'], ondelete='SET NULL')
    op.create_index('ix_incidents_policy_id', 'incidents', ['policy_id'])


def downgrade() -> None:
    op.drop_index('ix_incidents_policy_id', table_name='incidents')
    op.drop_constraint('fk_incidents_policy_id', 'incidents', type_='foreignkey')
    op.drop_column('incidents', 'policy_id')
    op.drop_column('incidents', 'description')
    op.drop_column('incidents', 'title')
