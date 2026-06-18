"""add rules table

Revision ID: 002
Revises: 001
Create Date: 2025-01-15 10:00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_add_rules'
down_revision = 'add_onedrive_tables'
branch_labels = None
depends_on = None


def upgrade():
    # Create rules table
    op.create_table(
        'rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('type', sa.String(20), nullable=False),
        sa.Column('pattern', sa.Text(), nullable=True),
        sa.Column('regex_flags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('keywords', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('case_sensitive', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('dictionary_path', sa.String(500), nullable=True),
        sa.Column('dictionary_hash', sa.String(64), nullable=True),
        sa.Column('threshold', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('weight', sa.Float(), nullable=False, server_default='0.5'),
        sa.Column('classification_labels', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('severity', sa.String(20), nullable=True),
        sa.Column('category', sa.String(100), nullable=True),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('match_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_matched_at', sa.DateTime(), nullable=True),
    )

    # Create indexes
    op.create_index('ix_rules_enabled', 'rules', ['enabled'])
    op.create_index('ix_rules_type', 'rules', ['type'])
    op.create_index('ix_rules_category', 'rules', ['category'])
    op.create_index('ix_rules_severity', 'rules', ['severity'])


def downgrade():
    op.drop_index('ix_rules_severity')
    op.drop_index('ix_rules_category')
    op.drop_index('ix_rules_type')
    op.drop_index('ix_rules_enabled')
    op.drop_table('rules')
