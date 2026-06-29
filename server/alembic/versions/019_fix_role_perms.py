"""Fix ANALYST/MANAGER permissions + widen alembic_version column.

Two things in one migration:

1. Widen alembic_version.version_num from VARCHAR(32) to VARCHAR(64).
   The default Alembic column is VARCHAR(32) which is too short for
   descriptive revision IDs like the one this migration replaces.
   Widening it is safe — it is a pure metadata column with no FK refs.

2. Grant view_all_departments to ANALYST and MANAGER roles.
   Without this permission both roles hit the ABAC deny-all sentinel
   whenever a user's department column is NULL (the default for newly
   created users), causing Total Events / Critical Alerts / Blocked
   Events to show as zero on the dashboard while Active Agents still
   shows correctly (agent counts skip ABAC).

   Role visibility after this migration:
     ADMIN   -> view_all_departments -> sees all events  (unchanged)
     MANAGER -> view_all_departments -> sees all events  (fixed)
     ANALYST -> view_all_departments -> sees all events  (fixed)
     VIEWER  -> ABAC-restricted to their department      (unchanged)

Revision ID: 019_fix_role_perms
Revises: 018_agent_code
"""

from alembic import op
import sqlalchemy as sa

revision = "019_fix_role_perms"
down_revision = "018_agent_code"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Widen alembic_version.version_num so long revision IDs never fail.
    bind.execute(sa.text(
        "ALTER TABLE alembic_version "
        "ALTER COLUMN version_num TYPE VARCHAR(64)"
    ))

    # 2. Grant view_all_departments to ANALYST.
    bind.execute(sa.text("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r, permissions p
        WHERE r.name = 'ANALYST'
          AND p.name = 'view_all_departments'
        ON CONFLICT DO NOTHING
    """))

    # 3. Grant view_all_departments + policy perms to MANAGER.
    bind.execute(sa.text("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r, permissions p
        WHERE r.name = 'MANAGER'
          AND p.name IN (
              'view_all_departments',
              'create_policy',
              'update_policy',
              'assign_policy'
          )
        ON CONFLICT DO NOTHING
    """))


def downgrade() -> None:
    bind = op.get_bind()

    bind.execute(sa.text("""
        DELETE FROM role_permissions
        WHERE role_id = (SELECT id FROM roles WHERE name = 'ANALYST')
          AND permission_id = (
              SELECT id FROM permissions WHERE name = 'view_all_departments'
          )
    """))

    bind.execute(sa.text("""
        DELETE FROM role_permissions
        WHERE role_id = (SELECT id FROM roles WHERE name = 'MANAGER')
          AND permission_id IN (
              SELECT id FROM permissions
              WHERE name IN (
                  'view_all_departments',
                  'create_policy',
                  'update_policy',
                  'assign_policy'
              )
          )
    """))

    # Note: we intentionally do NOT shrink version_num back to VARCHAR(32)
    # as that would risk breaking whatever is currently stored there.
