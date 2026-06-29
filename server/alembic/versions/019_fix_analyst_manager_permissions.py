"""Fix ANALYST and MANAGER role permissions: add view_all_departments.

Problem:
  ANALYST and MANAGER roles were missing the view_all_departments permission.
  When a user with either role has a NULL department (which is the default for
  newly created users), the ABAC filter applies a deny-all sentinel and returns
  zero for all event-derived dashboard metrics (Total Events, Critical Alerts,
  Blocked Events). Only Active Agents showed correctly because agent counts
  are not ABAC-gated.

Fix:
  1. Add view_all_departments to the ANALYST role → analysts bypass ABAC and
     can see all events across all departments (required to do their job).
  2. Add view_all_departments + policy management perms to the MANAGER role →
     managers have full operational visibility and policy assignment rights.

No data is destroyed. This migration only inserts rows into role_permissions.
It is idempotent — rows with the same (role_id, permission_id) composite PK
will conflict and be skipped (ON CONFLICT DO NOTHING).

Revision ID: 019_fix_analyst_manager_permissions
Revises: 018_agent_code
"""

from alembic import op
import sqlalchemy as sa

revision = "019_fix_analyst_manager_permissions"
down_revision = "018_agent_code"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # Grant view_all_departments to ANALYST
    bind.execute(sa.text("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r, permissions p
        WHERE r.name = 'ANALYST'
          AND p.name = 'view_all_departments'
        ON CONFLICT DO NOTHING
    """))

    # Grant view_all_departments + policy perms to MANAGER
    bind.execute(sa.text("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r, permissions p
        WHERE r.name = 'MANAGER'
          AND p.name IN ('view_all_departments', 'create_policy', 'update_policy', 'assign_policy')
        ON CONFLICT DO NOTHING
    """))


def downgrade() -> None:
    bind = op.get_bind()

    # Remove view_all_departments from ANALYST
    bind.execute(sa.text("""
        DELETE FROM role_permissions
        WHERE role_id = (SELECT id FROM roles WHERE name = 'ANALYST')
          AND permission_id = (SELECT id FROM permissions WHERE name = 'view_all_departments')
    """))

    # Remove view_all_departments + added perms from MANAGER
    bind.execute(sa.text("""
        DELETE FROM role_permissions
        WHERE role_id = (SELECT id FROM roles WHERE name = 'MANAGER')
          AND permission_id IN (
            SELECT id FROM permissions
            WHERE name IN ('view_all_departments', 'create_policy', 'update_policy', 'assign_policy')
          )
    """))
