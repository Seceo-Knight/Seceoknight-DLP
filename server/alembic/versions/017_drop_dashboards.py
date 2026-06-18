"""Permanently remove the custom-dashboards feature.

Drops the ``dashboards`` and ``dashboard_widgets`` tables. CASCADE
removes everything migrations 013-016 added to those two tables —
including ``dashboard_widgets.{group_by, query_type, query_key,
config_v2}`` and ``dashboards.{description, tags, abac_roles}``.

Intentionally KEPT (out of scope for this removal):
  * ``events.classification_level`` and ``idx_events_classification_level``
    (added in 014). The column is denormalized DLP data used by /events
    search and ABAC outside the dashboards surface.
  * ``users.clearance_level`` (007) and the ABAC permission columns —
    unrelated to dashboards.

Downgrade: explicit no-op. The product decision is permanent removal.
If you ever need to re-introduce custom dashboards, write a fresh
forward migration with the schema you want at that time — don't try to
reconstruct the historical 013-016 chain from this point.

Revision ID: 017_drop_dashboards
Revises: 016_dashboard_meta
"""
from alembic import op


revision = "017_drop_dashboards"
down_revision = "016_dashboard_meta"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CASCADE drops the FK from dashboard_widgets → dashboards and any
    # other dependent objects. Use IF EXISTS so the migration is safe to
    # re-run on a database where the tables were already removed manually.
    op.execute("DROP TABLE IF EXISTS dashboard_widgets CASCADE")
    op.execute("DROP TABLE IF EXISTS dashboards CASCADE")


def downgrade() -> None:
    raise NotImplementedError(
        "Permanent removal of custom dashboards. "
        "Write a new forward migration if you want them back."
    )
