"""add core tables: devices, data_labels, policy_conditions, policy_actions, incidents
and add columns to users, rules, events

Revision ID: 003_core_tables
Revises: 002_add_rules
Create Date: 2026-03-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003_core_tables'
down_revision = '002_add_rules'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Add columns to users ---
    op.add_column('users', sa.Column('username', sa.String(150), nullable=True))
    op.add_column('users', sa.Column('department', sa.String(255), nullable=True))
    op.create_index('ix_users_username', 'users', ['username'], unique=True)

    # --- Create devices table ---
    op.create_table('devices',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('hostname', sa.String(255), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('os', sa.String(100), nullable=False),
        sa.Column('agent_version', sa.String(50), nullable=True),
        sa.Column('status', sa.String(30), nullable=False, server_default='inactive'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_devices_hostname', 'devices', ['hostname'])
    op.create_index('ix_devices_user_id', 'devices', ['user_id'])

    # --- Create data_labels table ---
    op.create_table('data_labels',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('color', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index('ix_data_labels_name', 'data_labels', ['name'])

    # --- Add columns to rules (classification_rules) ---
    op.add_column('rules', sa.Column('priority', sa.Integer(), nullable=True, server_default='100'))
    op.add_column('rules', sa.Column('label_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key('fk_rules_label_id', 'rules', 'data_labels', ['label_id'], ['id'], ondelete='SET NULL')
    op.create_index('ix_rules_label_id', 'rules', ['label_id'])

    # --- Create policy_conditions table ---
    op.create_table('policy_conditions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('value', sa.String(500), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_policy_conditions_policy_id', 'policy_conditions', ['policy_id'])

    # --- Create policy_actions table ---
    op.create_table('policy_actions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action_type', sa.String(50), nullable=False),
        sa.Column('value', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_policy_actions_policy_id', 'policy_actions', ['policy_id'])

    # --- Add columns to events ---
    op.add_column('events', sa.Column('device_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('events', sa.Column('channel', sa.String(50), nullable=True))
    op.add_column('events', sa.Column('decision', sa.String(30), nullable=True))
    op.create_foreign_key('fk_events_device_id', 'events', 'devices', ['device_id'], ['id'], ondelete='SET NULL')
    op.create_index('ix_events_device_id', 'events', ['device_id'])

    # --- Create incidents table ---
    op.create_table('incidents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_id', sa.String(64), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('status', sa.String(30), nullable=False, server_default='open'),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['event_id'], ['events.event_id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_incidents_event_id', 'incidents', ['event_id'])
    op.create_index('ix_incidents_assigned_to', 'incidents', ['assigned_to'])


def downgrade() -> None:
    # --- Drop incidents ---
    op.drop_index('ix_incidents_assigned_to', table_name='incidents')
    op.drop_index('ix_incidents_event_id', table_name='incidents')
    op.drop_table('incidents')

    # --- Drop event columns ---
    op.drop_index('ix_events_device_id', table_name='events')
    op.drop_constraint('fk_events_device_id', 'events', type_='foreignkey')
    op.drop_column('events', 'decision')
    op.drop_column('events', 'channel')
    op.drop_column('events', 'device_id')

    # --- Drop policy_actions ---
    op.drop_index('ix_policy_actions_policy_id', table_name='policy_actions')
    op.drop_table('policy_actions')

    # --- Drop policy_conditions ---
    op.drop_index('ix_policy_conditions_policy_id', table_name='policy_conditions')
    op.drop_table('policy_conditions')

    # --- Drop rule columns ---
    op.drop_index('ix_rules_label_id', table_name='rules')
    op.drop_constraint('fk_rules_label_id', 'rules', type_='foreignkey')
    op.drop_column('rules', 'label_id')
    op.drop_column('rules', 'priority')

    # --- Drop data_labels ---
    op.drop_index('ix_data_labels_name', table_name='data_labels')
    op.drop_table('data_labels')

    # --- Drop devices ---
    op.drop_index('ix_devices_user_id', table_name='devices')
    op.drop_index('ix_devices_hostname', table_name='devices')
    op.drop_table('devices')

    # --- Drop user columns ---
    op.drop_index('ix_users_username', table_name='users')
    op.drop_column('users', 'department')
    op.drop_column('users', 'username')
