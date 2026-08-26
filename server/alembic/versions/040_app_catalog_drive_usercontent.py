"""App catalog fix — Google Drive's real download CDN host was missing.

Found live on a real endpoint (August 26, 2026): a genuine Google Drive
download (user downloading a file they'd been sent) resolved to
`drive.usercontent.google.com`, not `drive.google.com` or
`googleusercontent.com` -- two similar-looking but textually distinct
domains that Google actually uses. `googleusercontent.com` (seeded in 039)
does NOT cover it, since `drive.usercontent.google.com` does not end with
`.googleusercontent.com` (it ends with `.usercontent.google.com`, a
different string). background.js's downloads-hook host-match is a strict
`host === d || host.endsWith("." + d)` suffix check, so this was a silent
miss: the download completed normally (as intended -- the hook never
blocks), but was never recognized as "from a catalogued app" and so never
got its best-effort content inspection/alert.

Confirmed via dlp-host.log on the test endpoint:
  downloads.onCreated fired: url=https://drive.usercontent.google.com/download?...  referrer=
  downloads: resolved host=drive.usercontent.google.com watched=false

Adding `usercontent.google.com` as its own catalog entry closes this gap via
the existing suffix-match logic, no extension code change needed.

Idempotent (ON CONFLICT DO NOTHING), safe to re-run.

Revision ID: 040_app_catalog_drive_usercontent
Revises: 039_app_catalog
"""
from alembic import op
import sqlalchemy as sa


revision = "040_app_catalog_drive_usercontent"
down_revision = "039_app_catalog"
branch_labels = None
depends_on = None


_SEED = [
    ("usercontent.google.com", "file_sharing", "Google Drive (download CDN)"),
]


def upgrade() -> None:
    bind = op.get_bind()
    for domain, category, vendor_name in _SEED:
        bind.execute(
            sa.text(
                """
                INSERT INTO app_catalog (domain, category, vendor_name, is_builtin)
                VALUES (:domain, :category, :vendor_name, true)
                ON CONFLICT (domain) DO NOTHING
                """
            ),
            {"domain": domain, "category": category, "vendor_name": vendor_name},
        )


def downgrade() -> None:
    bind = op.get_bind()
    for domain, _category, _vendor_name in _SEED:
        bind.execute(
            sa.text("DELETE FROM app_catalog WHERE domain = :domain AND is_builtin = true"),
            {"domain": domain},
        )
