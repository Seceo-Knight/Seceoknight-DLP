"""RBAC Phase 1: normalize permissions, seed system roles, add MANAGER.

What this migration does (all inside the Alembic transaction):

1. Adds ``MANAGER`` to the ``userrole`` Postgres enum.
2. Creates the normalized ``permissions`` and ``role_permissions`` tables.
3. Seeds the 15 canonical permission names.
4. Ensures the 4 system roles (ADMIN, ANALYST, MANAGER, VIEWER) exist in
   the ``roles`` table. ADMIN and ANALYST may already be present from the
   004 migration / prior seeding — we upsert by name and do not overwrite.
5. Inserts ``role_permissions`` rows for each system role per spec.
6. Opportunistically migrates any pre-existing ``roles.permissions`` JSONB
   keys (where the value is truthy) into ``role_permissions`` rows, mapping
   permission names that exist. Unknown JSONB keys are logged-and-skipped.

Intentional non-actions (per ops plan):

* The ``roles.permissions`` JSONB column is **NOT** dropped. It remains as a
  read-only fallback until the normalized path is verified in production.
* Existing users are not reassigned — their ``role`` enum + ``role_id`` FK
  continue to work unchanged.
* ABAC columns (department on events, clearance_level on users) are Phase 2.

Revision ID: 006_rbac_permissions
Revises: 005_incidents
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "006_rbac_permissions"
down_revision = "005_incidents"
branch_labels = None
depends_on = None


# ── Canonical permission set (spec PART 1 §C) ────────────────────────────
PERMISSIONS: list[tuple[str, str]] = [
    ("view_events",             "Read DLP events"),
    ("view_alerts",             "Read DLP alerts"),
    ("export_events",           "Export events to CSV/JSON"),
    ("create_policy",           "Create new DLP policies"),
    ("update_policy",           "Modify existing DLP policies"),
    ("delete_policy",           "Remove DLP policies"),
    ("assign_policy",           "Attach policies to agents/groups"),
    ("manage_users",            "Create, update, disable users"),
    ("view_users",              "List users (no mutation)"),
    ("manage_roles",            "Create, update, delete roles and bindings"),
    ("view_dashboard",          "Load the dashboard UI and its tiles"),
    ("create_dashboard",        "Create custom dashboards"),
    ("edit_dashboard",          "Edit dashboards owned by the user"),
    ("delete_dashboard",        "Delete dashboards owned by the user"),
    ("view_all_departments",    "ABAC override: bypass per-department visibility"),
]

# ── System role → permission name assignments (spec PART 1 §D) ───────────
# ADMIN gets everything (including view_all_departments → full ABAC bypass).
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "ADMIN":   [p[0] for p in PERMISSIONS],
    "ANALYST": ["view_events", "view_alerts", "view_dashboard", "view_users"],
    "MANAGER": ["view_events", "export_events", "view_dashboard", "view_users"],
    # VIEWER is kept for backwards-compat (existing default for new users).
    # Spec did not call it out; grant the minimum that lets a VIEWER see the
    # dashboard without surfacing admin-only actions.
    "VIEWER":  ["view_events", "view_dashboard"],
}


def upgrade() -> None:
    bind = op.get_bind()

    # ── 1. Extend userrole enum with MANAGER (idempotent) ────────────
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction block on some
    # Postgres versions; Alembic runs on autocommit block, but IF NOT EXISTS
    # is critical to keep this migration re-runnable.
    with op.get_context().autocommit_block():
        bind.execute(sa.text("ALTER TYPE userrole ADD VALUE IF NOT EXISTS 'MANAGER'"))

    # ── 2. Create normalized tables ──────────────────────────────────
    op.create_table(
        "permissions",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_permissions_name", "permissions", ["name"])

    op.create_table(
        "role_permissions",
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.PrimaryKeyConstraint("role_id", "permission_id"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["permission_id"], ["permissions.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_role_permissions_role_id", "role_permissions", ["role_id"]
    )
    op.create_index(
        "ix_role_permissions_permission_id", "role_permissions", ["permission_id"]
    )

    # ── 3. Seed permissions (idempotent) ─────────────────────────────
    for name, desc in PERMISSIONS:
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (id, name, description, created_at)
                VALUES (gen_random_uuid(), :name, :description, now())
                ON CONFLICT (name) DO NOTHING
                """
            ),
            {"name": name, "description": desc},
        )

    # ── 4. Ensure system roles exist (idempotent) ────────────────────
    for role_name in ROLE_PERMISSIONS.keys():
        bind.execute(
            sa.text(
                """
                INSERT INTO roles (id, name, permissions, created_at, updated_at)
                VALUES (gen_random_uuid(), :name, NULL, now(), now())
                ON CONFLICT (name) DO NOTHING
                """
            ),
            {"name": role_name},
        )

    # ── 5. Bind system role → permissions (idempotent) ───────────────
    for role_name, perm_names in ROLE_PERMISSIONS.items():
        for perm_name in perm_names:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO role_permissions (role_id, permission_id)
                    SELECT r.id, p.id
                    FROM roles r, permissions p
                    WHERE r.name = :role AND p.name = :perm
                    ON CONFLICT DO NOTHING
                    """
                ),
                {"role": role_name, "perm": perm_name},
            )

    # ── 6. Migrate pre-existing JSONB permissions into normalized form
    # Best-effort: for every role with a JSONB permissions object, each
    # truthy top-level key is treated as a permission name. Keys that
    # don't match a seeded permission are ignored. No JSONB column is
    # dropped — the column stays as a read-only fallback until Phase 1
    # is validated in production.
    bind.execute(
        sa.text(
            """
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id
            FROM roles r,
                 LATERAL jsonb_each(
                     CASE
                         WHEN jsonb_typeof(r.permissions) = 'object'
                         THEN r.permissions
                         ELSE '{}'::jsonb
                     END
                 ) AS kv(key, value)
                 JOIN permissions p ON p.name = kv.key
            WHERE (kv.value::text = 'true' OR kv.value::text = '1')
            ON CONFLICT DO NOTHING
            """
        )
    )


def downgrade() -> None:
    op.drop_index("ix_role_permissions_permission_id", table_name="role_permissions")
    op.drop_index("ix_role_permissions_role_id", table_name="role_permissions")
    op.drop_table("role_permissions")

    op.drop_index("ix_permissions_name", table_name="permissions")
    op.drop_table("permissions")

    # Note: ALTER TYPE ... DROP VALUE is not supported by Postgres. The
    # 'MANAGER' enum member persists after downgrade. This is fine: no rows
    # will reference it since the application code path is gone, and
    # re-applying upgrade is a no-op (IF NOT EXISTS).
