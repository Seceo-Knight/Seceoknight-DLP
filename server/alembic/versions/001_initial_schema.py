"""Initial schema - All tables

Revision ID: 001_initial
Revises:
Create Date: 2025-01-02 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=False),
        sa.Column('role', sa.Enum('ADMIN', 'ANALYST', 'VIEWER', name='userrole'), nullable=False),
        sa.Column('organization', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_verified', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Create policies table
    op.create_table('policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('conditions', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('actions', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('compliance_tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create agents table
    op.create_table('agents',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('os', sa.String(length=50), nullable=False),
        sa.Column('os_version', sa.String(length=100), nullable=True),
        sa.Column('ip_address', postgresql.INET(), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('config', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('capabilities', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('total_events', sa.Integer(), nullable=False),
        sa.Column('total_violations', sa.Integer(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('last_heartbeat', sa.DateTime(), nullable=True),
        sa.Column('health_status', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('registered_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_agents_agent_id'), 'agents', ['agent_id'], unique=True)

    # Create events table
    op.create_table('events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('event_subtype', sa.String(length=50), nullable=True),
        sa.Column('agent_id', sa.String(length=64), nullable=True),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('source_id', sa.String(length=64), nullable=True),
        sa.Column('user_email', sa.String(length=255), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('file_path', sa.Text(), nullable=True),
        sa.Column('file_name', sa.String(length=255), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('file_hash', sa.String(length=64), nullable=True),
        sa.Column('classification', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('policy_name', sa.String(length=255), nullable=True),
        sa.Column('policy_violated', sa.String(length=255), nullable=True),
        sa.Column('destination', sa.String(length=255), nullable=True),
        sa.Column('destination_details', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('destination_ip', sa.String(length=45), nullable=True),
        sa.Column('protocol', sa.String(length=20), nullable=True),
        sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('reviewed', sa.String(length=20), nullable=False),
        sa.Column('reviewed_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_events_event_id'), 'events', ['event_id'], unique=True)
    op.create_index(op.f('ix_events_event_type'), 'events', ['event_type'], unique=False)
    op.create_index(op.f('ix_events_severity'), 'events', ['severity'], unique=False)
    op.create_index(op.f('ix_events_user_email'), 'events', ['user_email'], unique=False)
    op.create_index(op.f('ix_events_user_id'), 'events', ['user_id'], unique=False)
    op.create_index(op.f('ix_events_agent_id'), 'events', ['agent_id'], unique=False)
    op.create_index(op.f('ix_events_policy_id'), 'events', ['policy_id'], unique=False)
    op.create_index(op.f('ix_events_timestamp'), 'events', ['timestamp'], unique=False)
    op.create_index('idx_event_severity_timestamp', 'events', ['severity', 'timestamp'])
    op.create_index('idx_event_user_timestamp', 'events', ['user_email', 'timestamp'])
    op.create_index('idx_event_type_timestamp', 'events', ['event_type', 'timestamp'])
    op.create_index('idx_event_agent_timestamp', 'events', ['agent_id', 'timestamp'])

    # Create alerts table
    op.create_table('alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('alert_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('source_id', sa.String(length=64), nullable=True),
        sa.Column('event_id', sa.String(length=64), nullable=True),
        sa.Column('agent_id', sa.String(length=64), nullable=True),
        sa.Column('user_email', sa.String(length=255), nullable=True),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('assigned_at', sa.DateTime(), nullable=True),
        sa.Column('resolved', sa.Boolean(), nullable=False),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('notifications_sent', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('notification_history', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('escalated', sa.Boolean(), nullable=False),
        sa.Column('escalated_at', sa.DateTime(), nullable=True),
        sa.Column('escalation_level', sa.Integer(), nullable=False),
        sa.Column('triggered_at', sa.DateTime(), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_alert_id'), 'alerts', ['alert_id'], unique=True)
    op.create_index(op.f('ix_alerts_alert_type'), 'alerts', ['alert_type'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_index(op.f('ix_alerts_event_id'), 'alerts', ['event_id'], unique=False)
    op.create_index(op.f('ix_alerts_agent_id'), 'alerts', ['agent_id'], unique=False)
    op.create_index(op.f('ix_alerts_user_email'), 'alerts', ['user_email'], unique=False)
    op.create_index(op.f('ix_alerts_triggered_at'), 'alerts', ['triggered_at'], unique=False)
    op.create_index('idx_alert_severity_status', 'alerts', ['severity', 'status'])
    op.create_index('idx_alert_type_triggered', 'alerts', ['alert_type', 'triggered_at'])
    op.create_index('idx_alert_user_triggered', 'alerts', ['user_email', 'triggered_at'])
    op.create_index('idx_alert_resolved_triggered', 'alerts', ['resolved', 'triggered_at'])

    # Create classified_files table
    op.create_table('classified_files',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('file_id', sa.String(length=64), nullable=False),
        sa.Column('file_name', sa.String(length=255), nullable=False),
        sa.Column('file_path', sa.Text(), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('file_type', sa.String(length=100), nullable=True),
        sa.Column('mime_type', sa.String(length=100), nullable=True),
        sa.Column('file_hash', sa.String(length=64), nullable=False),
        sa.Column('md5_hash', sa.String(length=32), nullable=True),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('source_id', sa.String(length=64), nullable=True),
        sa.Column('agent_id', sa.String(length=64), nullable=True),
        sa.Column('location', sa.Text(), nullable=True),
        sa.Column('storage_type', sa.String(length=50), nullable=True),
        sa.Column('storage_location', sa.String(length=255), nullable=True),
        sa.Column('owner_email', sa.String(length=255), nullable=True),
        sa.Column('owner_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('owner_username', sa.String(length=255), nullable=True),
        sa.Column('classification', sa.String(length=50), nullable=False),
        sa.Column('classification_labels', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('classification_method', sa.String(length=50), nullable=True),
        sa.Column('sensitive_patterns', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('sensitive_data_count', sa.Integer(), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('risk_level', sa.String(length=20), nullable=True),
        sa.Column('content_preview', sa.Text(), nullable=True),
        sa.Column('content_length', sa.Integer(), nullable=True),
        sa.Column('language', sa.String(length=10), nullable=True),
        sa.Column('entropy_score', sa.Float(), nullable=True),
        sa.Column('is_encrypted', sa.Boolean(), nullable=False),
        sa.Column('is_compressed', sa.Boolean(), nullable=False),
        sa.Column('policy_matches', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('policies_violated', sa.Integer(), nullable=False),
        sa.Column('compliance_tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('quarantined', sa.Boolean(), nullable=False),
        sa.Column('quarantine_path', sa.Text(), nullable=True),
        sa.Column('quarantine_reason', sa.Text(), nullable=True),
        sa.Column('quarantined_at', sa.DateTime(), nullable=True),
        sa.Column('access_restricted', sa.Boolean(), nullable=False),
        sa.Column('access_restrictions', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('reviewed', sa.Boolean(), nullable=False),
        sa.Column('reviewed_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(), nullable=True),
        sa.Column('review_notes', sa.Text(), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('scan_status', sa.String(length=20), nullable=False),
        sa.Column('scan_duration_ms', sa.Integer(), nullable=True),
        sa.Column('last_scanned_at', sa.DateTime(), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_modified', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_classified_files_file_id'), 'classified_files', ['file_id'], unique=True)
    op.create_index(op.f('ix_classified_files_file_hash'), 'classified_files', ['file_hash'], unique=False)
    op.create_index(op.f('ix_classified_files_agent_id'), 'classified_files', ['agent_id'], unique=False)
    op.create_index(op.f('ix_classified_files_owner_email'), 'classified_files', ['owner_email'], unique=False)
    op.create_index(op.f('ix_classified_files_classification'), 'classified_files', ['classification'], unique=False)
    op.create_index('idx_file_classification_risk', 'classified_files', ['classification', 'risk_level'])
    op.create_index('idx_file_owner_classification', 'classified_files', ['owner_email', 'classification'])
    op.create_index('idx_file_source_scanned', 'classified_files', ['source_type', 'last_scanned_at'])
    op.create_index('idx_file_quarantined', 'classified_files', ['quarantined', 'quarantined_at'])
    op.create_index('idx_file_hash_classification', 'classified_files', ['file_hash', 'classification'])


def downgrade() -> None:
    op.drop_table('classified_files')
    op.drop_table('alerts')
    op.drop_table('events')
    op.drop_table('agents')
    op.drop_table('policies')
    op.drop_table('users')
