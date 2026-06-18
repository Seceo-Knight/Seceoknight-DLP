"""Schema overhaul: roles, endpoints, agent_logs, file_fingerprints, incident_comments,
scan_jobs, scan_results, audit_logs. Update users, data_labels, rules, policies,
policy_conditions, policy_actions, events, incidents.

Revision ID: 004_schema_overhaul
Revises: 003_core_tables
Create Date: 2026-03-30 08:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '004_schema_overhaul'
down_revision = '003_core_tables'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── 1. roles table ──
    op.create_table('roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(50), nullable=False),
        sa.Column('permissions', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index('ix_roles_name', 'roles', ['name'])

    # ── 2. users: add role_id FK ──
    op.add_column('users', sa.Column('role_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key('fk_users_role_id', 'users', 'roles', ['role_id'], ['id'], ondelete='SET NULL')
    op.create_index('ix_users_role_id', 'users', ['role_id'])

    # ── 3. endpoints table ──
    op.create_table('endpoints',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('hostname', sa.String(255), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('os', sa.String(100), nullable=False),
        sa.Column('agent_version', sa.String(50), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, server_default='offline'),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_endpoints_hostname', 'endpoints', ['hostname'])
    op.create_index('ix_endpoints_user_id', 'endpoints', ['user_id'])
    op.create_index('idx_endpoints_status_last_seen', 'endpoints', ['status', 'last_seen'])

    # ── 4. agent_logs table ──
    op.create_table('agent_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('endpoint_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('raw_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_agent_logs_endpoint_id', 'agent_logs', ['endpoint_id'])
    op.create_index('ix_agent_logs_event_type', 'agent_logs', ['event_type'])
    op.create_index('ix_agent_logs_created_at', 'agent_logs', ['created_at'])
    op.create_index('idx_agent_logs_endpoint_created', 'agent_logs', ['endpoint_id', 'created_at'])

    # ── 5. data_labels: severity String→Integer, add description ──
    # Add new INT column, migrate, drop old
    op.add_column('data_labels', sa.Column('severity_int', sa.Integer(), nullable=True))
    op.execute("""
        UPDATE data_labels SET severity_int = CASE
            WHEN severity = 'low' THEN 0
            WHEN severity = 'medium' THEN 1
            WHEN severity = 'high' THEN 2
            WHEN severity = 'critical' THEN 3
            ELSE 0
        END
    """)
    op.alter_column('data_labels', 'severity_int', nullable=False)
    op.drop_column('data_labels', 'severity')
    op.alter_column('data_labels', 'severity_int', new_column_name='severity')
    op.add_column('data_labels', sa.Column('description', sa.Text(), nullable=True))

    # ── 6. rules: add file_types ARRAY ──
    op.add_column('rules', sa.Column('file_types', postgresql.ARRAY(sa.String()), nullable=True))

    # ── 7. file_fingerprints table ──
    op.create_table('file_fingerprints',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('hash', sa.String(128), nullable=False),
        sa.Column('file_name', sa.String(500), nullable=True),
        sa.Column('label_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('hash'),
        sa.ForeignKeyConstraint(['label_id'], ['data_labels.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_file_fingerprints_hash', 'file_fingerprints', ['hash'])
    op.create_index('ix_file_fingerprints_label_id', 'file_fingerprints', ['label_id'])

    # ── 8. policies: add status column ──
    op.add_column('policies', sa.Column('status', sa.String(20), nullable=True, server_default='active'))
    op.execute("UPDATE policies SET status = CASE WHEN enabled THEN 'active' ELSE 'inactive' END")

    # ── 9. policy_conditions: rename type→condition_type, add operator ──
    op.alter_column('policy_conditions', 'type', new_column_name='condition_type')
    op.add_column('policy_conditions', sa.Column('operator', sa.String(20), nullable=True))

    # ── 10. policy_actions: add parameters JSONB ──
    op.add_column('policy_actions', sa.Column('parameters', postgresql.JSONB(), nullable=True))

    # ── 11. events: add endpoint_id FK, classification_label FK ──
    op.add_column('events', sa.Column('endpoint_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key('fk_events_endpoint_id', 'events', 'endpoints', ['endpoint_id'], ['id'], ondelete='SET NULL')
    op.create_index('ix_events_endpoint_id', 'events', ['endpoint_id'])

    op.add_column('events', sa.Column('classification_label', postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key('fk_events_classification_label', 'events', 'data_labels', ['classification_label'], ['id'], ondelete='SET NULL')
    op.create_index('ix_events_classification_label', 'events', ['classification_label'])

    # ── 12. incidents: severity String→Integer, add status index ──
    op.add_column('incidents', sa.Column('severity_int', sa.Integer(), nullable=True))
    op.execute("""
        UPDATE incidents SET severity_int = CASE
            WHEN severity = 'low' THEN 1
            WHEN severity = 'medium' THEN 2
            WHEN severity = 'high' THEN 3
            WHEN severity = 'critical' THEN 4
            ELSE 1
        END
    """)
    op.alter_column('incidents', 'severity_int', nullable=False)
    op.drop_column('incidents', 'severity')
    op.alter_column('incidents', 'severity_int', new_column_name='severity')
    op.create_index('ix_incidents_status', 'incidents', ['status'])
    op.create_index('idx_incidents_severity_status', 'incidents', ['severity', 'status'])

    # ── 13. incident_comments table ──
    op.create_table('incident_comments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('incident_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('comment', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_incident_comments_incident_id', 'incident_comments', ['incident_id'])
    op.create_index('ix_incident_comments_user_id', 'incident_comments', ['user_id'])

    # ── 14. scan_jobs table ──
    op.create_table('scan_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('status', sa.String(30), nullable=False, server_default='pending'),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scan_jobs_status', 'scan_jobs', ['status'])
    op.create_index('idx_scan_jobs_status_created', 'scan_jobs', ['status', 'created_at'])

    # ── 15. scan_results table ──
    op.create_table('scan_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('file_path', sa.Text(), nullable=False),
        sa.Column('label_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('matched_rule', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['label_id'], ['data_labels.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['matched_rule'], ['rules.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_scan_results_job_id', 'scan_results', ['job_id'])
    op.create_index('ix_scan_results_label_id', 'scan_results', ['label_id'])
    op.create_index('ix_scan_results_matched_rule', 'scan_results', ['matched_rule'])

    # ── 16. audit_logs table ──
    op.create_table('audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('details', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])
    op.create_index('idx_audit_logs_user_created', 'audit_logs', ['user_id', 'created_at'])
    op.create_index('idx_audit_logs_action_created', 'audit_logs', ['action', 'created_at'])


def downgrade() -> None:
    # Drop new tables in reverse dependency order
    op.drop_table('audit_logs')
    op.drop_table('scan_results')
    op.drop_table('scan_jobs')
    op.drop_table('incident_comments')

    # incidents: severity INT→String
    op.add_column('incidents', sa.Column('severity_str', sa.String(20), nullable=True))
    op.execute("""
        UPDATE incidents SET severity_str = CASE
            WHEN severity = 1 THEN 'low'
            WHEN severity = 2 THEN 'medium'
            WHEN severity = 3 THEN 'high'
            WHEN severity = 4 THEN 'critical'
            ELSE 'low'
        END
    """)
    op.drop_index('idx_incidents_severity_status', table_name='incidents')
    op.drop_index('ix_incidents_status', table_name='incidents')
    op.drop_column('incidents', 'severity')
    op.alter_column('incidents', 'severity_str', new_column_name='severity')

    # events: drop new columns
    op.drop_index('ix_events_classification_label', table_name='events')
    op.drop_constraint('fk_events_classification_label', 'events', type_='foreignkey')
    op.drop_column('events', 'classification_label')
    op.drop_index('ix_events_endpoint_id', table_name='events')
    op.drop_constraint('fk_events_endpoint_id', 'events', type_='foreignkey')
    op.drop_column('events', 'endpoint_id')

    # policy_actions: drop parameters
    op.drop_column('policy_actions', 'parameters')

    # policy_conditions: undo rename, drop operator
    op.drop_column('policy_conditions', 'operator')
    op.alter_column('policy_conditions', 'condition_type', new_column_name='type')

    # policies: drop status
    op.drop_column('policies', 'status')

    # file_fingerprints
    op.drop_table('file_fingerprints')

    # rules: drop file_types
    op.drop_column('rules', 'file_types')

    # data_labels: severity INT→String, drop description
    op.drop_column('data_labels', 'description')
    op.add_column('data_labels', sa.Column('severity_str', sa.String(20), nullable=True))
    op.execute("""
        UPDATE data_labels SET severity_str = CASE
            WHEN severity = 0 THEN 'low'
            WHEN severity = 1 THEN 'medium'
            WHEN severity = 2 THEN 'high'
            WHEN severity = 3 THEN 'critical'
            ELSE 'low'
        END
    """)
    op.drop_column('data_labels', 'severity')
    op.alter_column('data_labels', 'severity_str', new_column_name='severity')

    # agent_logs
    op.drop_table('agent_logs')

    # endpoints
    op.drop_table('endpoints')

    # users: drop role_id
    op.drop_index('ix_users_role_id', table_name='users')
    op.drop_constraint('fk_users_role_id', 'users', type_='foreignkey')
    op.drop_column('users', 'role_id')

    # roles
    op.drop_table('roles')
