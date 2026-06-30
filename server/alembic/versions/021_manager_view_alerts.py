"""Grant view_alerts to MANAGER role.

MANAGER users need to see Alerts and Incidents to do their job.
Previously only view_events was granted which hid both nav items.

Revision ID: 021_manager_view_alerts
Revises: 020_mfa_fields
"""
from alembic import op
import sqlalchemy as sa

revision = "021_manager_view_alerts"
down_revision = "020_mfa_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text("""
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id
            FROM roles r, permissions p
            WHERE r.name = 'MANAGER' AND p.name = 'view_alerts'
            ON CONFLICT DO NOTHING
        """)
    )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text("""
            DELETE FROM role_permissions
            WHERE role_id = (SELECT id FROM roles WHERE name = 'MANAGER')
              AND permission_id = (SELECT id FROM permissions WHERE name = 'view_alerts')
        """)
    )
