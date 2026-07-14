"""Domain-scoped RBAC: add policy.domain, three domain-admin roles + perms.

Ported from CyberSentinel DLP's threat-intel/RBAC branch, adapted onto
SeceoKnight's own migration chain (head was 026_drop_policies_enabled).

1. Adds ``THREAT_ADMIN`` / ``DATA_PROTECTION_ADMIN`` / ``ACCESS_CONTROL_ADMIN``
   to the ``userrole`` enum.
2. Adds ``policies.domain`` (threat|data_protection|access_control|general),
   defaulting to ``general``, and backfills existing rows from ``type``.
3. Seeds the three roles in ``roles`` and binds their permissions in
   ``role_permissions`` (names match SeceoKnight's own 006_rbac_permissions
   canonical permission set — verified present before writing this).

All idempotent. ``ALTER TYPE ... DROP VALUE`` isn't supported by Postgres, so
downgrade only removes the column + role bindings.

Revision ID: 027_domain_scoped_rbac
Revises: 026_drop_policies_enabled
"""
from alembic import op
import sqlalchemy as sa


revision = "027_domain_scoped_rbac"
down_revision = "026_drop_policies_enabled"
branch_labels = None
depends_on = None


NEW_ROLES = ["THREAT_ADMIN", "DATA_PROTECTION_ADMIN", "ACCESS_CONTROL_ADMIN"]

# Operational perms every domain admin needs (scoped at query time by domain).
_OPS = [
    "view_events", "view_alerts", "view_dashboard", "export_events",
    "create_policy", "update_policy", "delete_policy", "assign_policy",
    # Domain admins see their whole domain across departments.
    "view_all_departments",
]

NEW_ROLE_PERMISSIONS = {
    "THREAT_ADMIN": list(_OPS),
    "DATA_PROTECTION_ADMIN": list(_OPS),
    # Access Control governs identity + device access.
    "ACCESS_CONTROL_ADMIN": list(_OPS) + ["manage_users", "view_users", "manage_roles"],
}

# type (lowercased) → domain, for backfilling existing policies.
_THREAT = [
    "usb_device_monitoring", "usb_file_transfer_monitoring", "usb",
    "network_exfil", "network_exfiltration",
    "screen_capture", "screen_capture_monitoring", "print", "print_monitoring",
]
_DP = [
    "clipboard_monitoring", "clipboard", "file_system_monitoring",
    "file_transfer_monitoring", "file", "google_drive_local_monitoring",
    "google_drive_cloud_monitoring", "onedrive_cloud_monitoring",
    "classification_aware_policy",
]
_AC = ["usb_device_authorization", "device_access"]


def upgrade() -> None:
    bind = op.get_bind()

    # ── 1. Extend userrole enum (idempotent) ─────────────────────────
    with op.get_context().autocommit_block():
        for r in NEW_ROLES:
            bind.execute(sa.text(f"ALTER TYPE userrole ADD VALUE IF NOT EXISTS '{r}'"))

    # ── 2. Add policies.domain + index (idempotent) ──────────────────
    bind.execute(sa.text(
        "ALTER TABLE policies ADD COLUMN IF NOT EXISTS domain "
        "VARCHAR(30) NOT NULL DEFAULT 'general'"
    ))
    bind.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_policies_domain ON policies (domain)"
    ))

    # ── 3. Backfill domain from type ─────────────────────────────────
    def _fill(domain, types):
        bind.execute(
            sa.text(
                "UPDATE policies SET domain = :d WHERE lower(type) = ANY(:types) "
                "AND domain = 'general'"
            ),
            {"d": domain, "types": types},
        )
    _fill("threat", _THREAT)
    _fill("data_protection", _DP)
    _fill("access_control", _AC)

    # ── 4. Ensure the three roles exist (idempotent) ─────────────────
    for role_name in NEW_ROLES:
        bind.execute(
            sa.text(
                "INSERT INTO roles (id, name, permissions, created_at, updated_at) "
                "VALUES (gen_random_uuid(), :name, NULL, now(), now()) "
                "ON CONFLICT (name) DO NOTHING"
            ),
            {"name": role_name},
        )

    # ── 5. Bind role → permissions (idempotent; skips unknown perm names) ──
    for role_name, perm_names in NEW_ROLE_PERMISSIONS.items():
        for perm_name in perm_names:
            bind.execute(
                sa.text(
                    "INSERT INTO role_permissions (role_id, permission_id) "
                    "SELECT r.id, p.id FROM roles r, permissions p "
                    "WHERE r.name = :role AND p.name = :perm "
                    "ON CONFLICT DO NOTHING"
                ),
                {"role": role_name, "perm": perm_name},
            )


def downgrade() -> None:
    bind = op.get_bind()
    # Remove role bindings + role rows for the three domain roles.
    for role_name in NEW_ROLES:
        bind.execute(
            sa.text(
                "DELETE FROM role_permissions WHERE role_id IN "
                "(SELECT id FROM roles WHERE name = :name)"
            ),
            {"name": role_name},
        )
        bind.execute(sa.text("DELETE FROM roles WHERE name = :name"), {"name": role_name})
    bind.execute(sa.text("DROP INDEX IF EXISTS ix_policies_domain"))
    bind.execute(sa.text("ALTER TABLE policies DROP COLUMN IF EXISTS domain"))
    # Note: ALTER TYPE ... DROP VALUE is unsupported; enum members persist.
