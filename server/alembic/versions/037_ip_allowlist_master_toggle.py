"""IP allowlist master enable/disable toggle (task #154).

Ported from CyberSentinel DLP (commit 0003851, "Added Whitelist Toggle").

Problem: SeceoKnight's ``ip_allowlist`` enforcement state was purely derived
from "at least one entry has is_enabled=true" (see server/app/middleware/
ip_allowlist.py). There was no way to pause enforcement without disabling or
deleting every configured CIDR one at a time -- an admin who wants to
temporarily open the portal (e.g. troubleshooting from a new location) had
no single switch and risked losing track of which entries to re-enable.

Fix: a tiny singleton settings table holding one master boolean. When
``enabled = false`` the middleware treats the control as off regardless of
how many CIDR entries exist, without touching the entries themselves.
Defaults to enabled=true so existing enforcement behavior is unchanged for
anyone who hasn't touched the new toggle yet.

Idempotent (IF NOT EXISTS / ON CONFLICT DO NOTHING), safe to re-run.

Revision ID: 037_ip_allowlist_master_toggle
Revises: 036_user_risk_scores
"""
from alembic import op
import sqlalchemy as sa


revision = "037_ip_allowlist_master_toggle"
down_revision = "036_user_risk_scores"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS ip_allowlist_settings (
            id          SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            enabled     BOOLEAN NOT NULL DEFAULT true,
            updated_by  UUID,
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    ))
    # Seed the single row so the API can always UPDATE rather than
    # insert-or-update on first toggle.
    bind.execute(sa.text(
        "INSERT INTO ip_allowlist_settings (id, enabled) VALUES (1, true) "
        "ON CONFLICT (id) DO NOTHING"
    ))


def downgrade() -> None:
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS ip_allowlist_settings"))
