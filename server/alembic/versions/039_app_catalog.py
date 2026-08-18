"""App catalog — classify web destinations into activity-control categories.

New capability (GenAI / web-activity control), ported in spirit from
CyberSentinel-DLP commit f435920 ("control what users do in web apps, not
just where they go") — adapted to SeceoKnight's own architecture rather than
copied file-for-file.

Problem this unblocks: SeceoKnight's browser extension previously had one
flat destination list (CLOUD_HOSTS in inject.js) and one activity concept
("a file is being uploaded"). There was no way to express "block Attach and
Send on webmail but allow Download" or to single out generative-AI vendors
(ChatGPT, Copilot, Gemini, Claude, ...) as their own category at all — a
repo-wide search for any GenAI vendor previously returned nothing.

``app_catalog`` classifies a hostname into one of: webmail | file_sharing |
collaboration | genai | other. Seeded with SeceoKnight's existing
CLOUD_HOSTS baseline (re-categorized) plus the major GenAI vendors, which
were entirely absent before. Admins can add more via the dashboard/API on
top of this seed, same additive pattern as cloud_upload_hosts.

Idempotent (IF NOT EXISTS / ON CONFLICT DO NOTHING), safe to re-run.

Revision ID: 039_app_catalog
Revises: 038_printer_deny
"""
from alembic import op
import sqlalchemy as sa


revision = "039_app_catalog"
down_revision = "038_printer_deny"
branch_labels = None
depends_on = None


# (domain, category, vendor_name)
_SEED = [
    # -- webmail --
    ("gmail.com", "webmail", "Gmail"),
    ("mail.google.com", "webmail", "Gmail"),
    ("outlook.com", "webmail", "Outlook"),
    ("outlook.office.com", "webmail", "Outlook Web"),
    ("outlook.office365.com", "webmail", "Outlook Web"),
    ("outlook.cloud.microsoft", "webmail", "Outlook Web"),
    ("live.com", "webmail", "Outlook/Live Mail"),

    # -- file sharing / cloud storage --
    ("drive.google.com", "file_sharing", "Google Drive"),
    ("docs.google.com", "file_sharing", "Google Docs"),
    ("googleusercontent.com", "file_sharing", "Google (content)"),
    ("googleapis.com", "file_sharing", "Google APIs"),
    ("dropbox.com", "file_sharing", "Dropbox"),
    ("dropboxapi.com", "file_sharing", "Dropbox"),
    ("dropboxusercontent.com", "file_sharing", "Dropbox"),
    ("onedrive.live.com", "file_sharing", "OneDrive"),
    ("1drv.ms", "file_sharing", "OneDrive"),
    ("sharepoint.com", "file_sharing", "SharePoint"),
    ("office.com", "file_sharing", "Microsoft 365"),
    ("microsoftonline.com", "file_sharing", "Microsoft 365"),
    ("box.com", "file_sharing", "Box"),
    ("boxcloud.com", "file_sharing", "Box"),
    ("app.box.com", "file_sharing", "Box"),
    ("wetransfer.com", "file_sharing", "WeTransfer"),
    ("mega.nz", "file_sharing", "MEGA"),
    ("mediafire.com", "file_sharing", "MediaFire"),
    ("icloud.com", "file_sharing", "iCloud"),
    ("amazonaws.com", "file_sharing", "Amazon S3"),
    ("s3.amazonaws.com", "file_sharing", "Amazon S3"),
    ("wasabisys.com", "file_sharing", "Wasabi"),

    # -- collaboration --
    ("slack.com", "collaboration", "Slack"),
    ("files.slack.com", "collaboration", "Slack"),
    ("teams.microsoft.com", "collaboration", "Microsoft Teams"),
    ("teams.live.com", "collaboration", "Microsoft Teams"),
    ("discord.com", "collaboration", "Discord"),
    ("telegram.org", "collaboration", "Telegram Web"),
    ("web.telegram.org", "collaboration", "Telegram Web"),
    ("web.whatsapp.com", "collaboration", "WhatsApp Web"),

    # -- generative AI (previously entirely absent from SeceoKnight) --
    ("chat.openai.com", "genai", "ChatGPT"),
    ("chatgpt.com", "genai", "ChatGPT"),
    ("copilot.microsoft.com", "genai", "Microsoft Copilot"),
    ("gemini.google.com", "genai", "Google Gemini"),
    ("bard.google.com", "genai", "Google Gemini (Bard)"),
    ("claude.ai", "genai", "Claude"),
    ("poe.com", "genai", "Poe"),
    ("perplexity.ai", "genai", "Perplexity"),
    ("character.ai", "genai", "Character.AI"),
    ("huggingface.co", "genai", "Hugging Face"),
]


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        """
        CREATE TABLE IF NOT EXISTS app_catalog (
            id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            domain       VARCHAR(255) NOT NULL UNIQUE,
            category     VARCHAR(20) NOT NULL,
            vendor_name  VARCHAR(255),
            is_builtin   BOOLEAN NOT NULL DEFAULT false,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    ))
    bind.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_app_catalog_category ON app_catalog (category)"
    ))
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
    op.get_bind().execute(sa.text("DROP TABLE IF EXISTS app_catalog"))
