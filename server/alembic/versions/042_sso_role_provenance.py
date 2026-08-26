"""SSO/SIEM hardening: role provenance + SIEM identity keying on users.

Ported from CyberSentinel-DLP (commits ad46e71 and 074266b, gap-scan of
August 26 2026), combined into a single migration since SeceoKnight is
adopting the whole SSO hardening pass at once.

Adds three columns to `users`:

  sso_managed       bool, default false. Marks an account as owned by the
                     SIEM role/attribute sync (app/core/sso_roles.py):
                     role/department/clearance are re-applied from the
                     exchange token on every login. An admin editing such a
                     user's role by hand through the normal admin UI
                     detaches it (sets this back to false) rather than
                     having the edit silently revert at the next login.

  sso_source_role    varchar(64), nullable. The last SIEM role:access pair
                     seen (e.g. "L3:ro"), purely for tracing — so an
                     unexpected DLP role can be traced back to what the
                     SIEM actually sent.

  siem_sub           varchar(255), nullable, UNIQUE. The SIEM's own
                     immutable user id (the exchange token's `sub` claim).
                     An SSO login is matched on this in preference to
                     email — email is a display attribute people change,
                     and keyed on email alone a rename orphans the DLP
                     account: the next login finds nothing, provisions a
                     SECOND account, and the original's history and role
                     are attached to a user who can no longer reach them.
                     Nullable because locally-created accounts have no SIEM
                     identity at all, and existing SSO accounts backfill
                     their sub lazily on the first login that presents one
                     (see /auth/sso/exchange) — nothing has to be migrated
                     ahead of time.

All three are idempotent (IF NOT EXISTS / IF NOT EXISTS index), safe to
re-run, and match the same DDL applied at startup in main.py's
_auto_init_schema_and_admin — SeceoKnight deployments upgrade by pulling a
new image and restarting, and an SSO login against a database missing these
columns fails at the lookup, which is a hard outage of the only way some
tenants log in at all.

Revision ID: 042_sso_role_provenance
Revises: 041_dismissed_usb_devices
"""
from alembic import op


revision = "042_sso_role_provenance"
down_revision = "041_dismissed_usb_devices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_managed BOOLEAN "
        "NOT NULL DEFAULT false"
    )
    op.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_source_role VARCHAR(64)"
    )
    op.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS siem_sub VARCHAR(255)"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_siem_sub "
        "ON users (siem_sub) WHERE siem_sub IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_users_siem_sub")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS siem_sub")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS sso_source_role")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS sso_managed")
