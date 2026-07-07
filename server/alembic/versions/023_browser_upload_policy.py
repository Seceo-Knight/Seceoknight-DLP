"""Seed 'Detect Browser Upload' policy for browser file-dialog monitoring.

This migration upserts the browser_upload_monitoring policy that was previously
created manually on existing deployments.  Using ON CONFLICT (name) DO UPDATE
makes it safe to run even if the policy already exists (it will fix the type
and conditions if they were misconfigured).

Revision ID: 023_browser_upload_policy
Revises: 022_reports_table
Create Date: 2026-07-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
import json

revision = '023_browser_upload_policy'
down_revision = '022_reports_table'
branch_labels = None
depends_on = None


_CONDITIONS = json.dumps({
    "match": "any",
    "rules": [
        {
            "field": "event_subtype",
            "operator": "equals",
            "value": "browser_file_selection"
        },
        {
            "field": "channel",
            "operator": "equals",
            "value": "BROWSER"
        }
    ]
})

_ACTIONS = json.dumps({
    "alert": {
        "severity": "medium"
    }
})

_CONFIG = json.dumps({
    "description": "Monitor browser file uploads and alert on all file selections"
})


def upgrade() -> None:
    conn = op.get_bind()

    # Find any admin user to use as created_by (required NOT NULL FK).
    row = conn.execute(
        sa.text("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1")
    ).first()
    admin_id = str(row[0]) if row else None

    if admin_id is None:
        # Fallback: use any existing user
        row = conn.execute(sa.text("SELECT id FROM users LIMIT 1")).first()
        admin_id = str(row[0]) if row else None

    if admin_id is None:
        # No users at all — skip (init_db hasn't run yet; the seed in main.py
        # will pick this up from default_policies.json on first boot).
        return

    conn.execute(
        sa.text("""
            INSERT INTO policies
                (id, name, description, enabled, priority, type, severity,
                 config, conditions, actions, compliance_tags, agent_ids,
                 created_by, created_at, updated_at)
            VALUES
                (gen_random_uuid(),
                 'Detect Browser Upload',
                 'Alerts when any file is selected in a browser file-upload dialog '
                 '(Chrome, Edge, Firefox). Matches on event_subtype=browser_file_selection '
                 'or channel=BROWSER.',
                 TRUE,
                 70,
                 'browser_upload_monitoring',
                 'medium',
                 CAST(:config     AS JSON),
                 CAST(:conditions AS JSON),
                 CAST(:actions    AS JSON),
                 NULL,
                 NULL,
                 CAST(:created_by AS UUID),
                 NOW(),
                 NOW())
            ON CONFLICT (name) DO UPDATE
                SET type       = 'browser_upload_monitoring',
                    conditions = CAST(:conditions AS JSON),
                    actions    = CAST(:actions    AS JSON),
                    severity   = 'medium',
                    priority   = 70,
                    updated_at = NOW()
        """),
        {
            "config":     _CONFIG,
            "conditions": _CONDITIONS,
            "actions":    _ACTIONS,
            "created_by": admin_id,
        }
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM policies WHERE name = 'Detect Browser Upload'")
    )
