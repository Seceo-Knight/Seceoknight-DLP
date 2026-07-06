"""
Email Alert Settings API
Manage SMTP configuration and alert notification recipients.
Settings are stored in MongoDB (system_settings collection) and override
the defaults from config.py / env vars at runtime.
"""

from typing import List, Optional
from datetime import datetime, timezone
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import asyncio

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
import structlog

from app.core.security import get_current_user, require_role
from app.core.database import get_mongodb
from app.core.config import settings

logger = structlog.get_logger()
router = APIRouter()

SETTINGS_COLLECTION = "system_settings"
EMAIL_SETTINGS_KEY = "email_alert_settings"


# ── Pydantic models ──────────────────────────────────────────────────────────

class EmailAlertSettings(BaseModel):
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_tls: bool = True
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None   # write-only; returned as None on GET
    smtp_from_name: str = "SeceoKnight DLP"
    smtp_from_email: str = "noreply@seceoknight.com"
    alert_recipients: List[str] = []
    min_severity: str = "high"            # critical | high | medium | low
    enabled: bool = True


class EmailAlertSettingsResponse(BaseModel):
    smtp_host: str
    smtp_port: int
    smtp_tls: bool
    smtp_user: Optional[str]
    smtp_password: Optional[str]          # always None in response
    smtp_from_name: str
    smtp_from_email: str
    alert_recipients: List[str]
    min_severity: str
    enabled: bool
    updated_at: Optional[str] = None


class TestEmailRequest(BaseModel):
    recipient: str


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _load_settings(mongo_db) -> dict:
    """Load settings from MongoDB, falling back to config.py defaults."""
    col = mongo_db.get_collection(SETTINGS_COLLECTION)
    doc = await col.find_one({"key": EMAIL_SETTINGS_KEY})
    if doc:
        doc.pop("_id", None)
        doc.pop("key", None)
        return doc
    # Fall back to config defaults
    return {
        "smtp_host": settings.SMTP_HOST,
        "smtp_port": settings.SMTP_PORT,
        "smtp_tls": settings.SMTP_TLS,
        "smtp_user": settings.SMTP_USER,
        "smtp_password": None,            # never expose stored password on first load
        "smtp_from_name": settings.SMTP_FROM_NAME,
        "smtp_from_email": settings.SMTP_FROM_EMAIL,
        "alert_recipients": list(getattr(settings, "ALERT_EMAIL_RECIPIENTS", [])),
        "min_severity": getattr(settings, "ALERT_EMAIL_MIN_SEVERITY", "high"),
        "enabled": True,
    }


def _smtp_send_test(host, port, tls, user, password, from_email, from_name, recipient):
    """Blocking test-send — run via executor."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "[SeceoKnight DLP] Test Email — SMTP configuration verified"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = recipient

    plain = (
        "This is a test email from SeceoKnight DLP.\n\n"
        "Your SMTP configuration is working correctly.\n"
        "Email alerts will be sent to this address when policy violations occur.\n"
    )
    html = """<!DOCTYPE html><html><body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:32px 0">
<tr><td align="center"><table width="520" cellpadding="0" cellspacing="0"
  style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)">
  <tr><td style="background:#2563eb;padding:20px 28px">
    <p style="margin:0;color:#fff;font-size:11px;letter-spacing:.1em;text-transform:uppercase">SeceoKnight DLP</p>
    <h1 style="margin:4px 0 0;color:#fff;font-size:20px;font-weight:700">Test Email</h1>
  </td></tr>
  <tr><td style="padding:24px 28px">
    <p style="margin:0;font-size:15px;color:#111827">Your SMTP configuration is working correctly.</p>
    <p style="margin:12px 0 0;font-size:14px;color:#6b7280">
      Email alerts will be delivered to this address when DLP policy violations are detected.</p>
    <p style="margin:20px 0 0;font-size:12px;color:#9ca3af">SeceoKnight DLP Security Platform</p>
  </td></tr>
</table></td></tr></table></body></html>"""

    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))

    if tls:
        server = smtplib.SMTP(host, port, timeout=10)
        server.ehlo()
        server.starttls()
    else:
        server = smtplib.SMTP_SSL(host, port, timeout=10)
    try:
        if user and password:
            server.login(user, password)
        server.sendmail(from_email, [recipient], msg.as_string())
    finally:
        server.quit()


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("/email", response_model=EmailAlertSettingsResponse)
async def get_email_settings(
    mongo_db=Depends(get_mongodb),
    current_user=Depends(get_current_user),
):
    """Return current email alert settings (password field is always redacted)."""
    data = await _load_settings(mongo_db)
    data["smtp_password"] = None          # never expose password
    return EmailAlertSettingsResponse(**data)


@router.put("/email", response_model=EmailAlertSettingsResponse)
async def update_email_settings(
    payload: EmailAlertSettings,
    mongo_db=Depends(get_mongodb),
    current_user=Depends(require_role(["admin", "superadmin"])),
):
    """Save email alert settings to MongoDB. Pass smtp_password=null to keep existing."""
    col = mongo_db.get_collection(SETTINGS_COLLECTION)
    existing = await col.find_one({"key": EMAIL_SETTINGS_KEY})

    update_data = payload.dict()
    # Preserve existing password if the caller sent null (they don't want to change it)
    if update_data["smtp_password"] is None and existing:
        update_data["smtp_password"] = existing.get("smtp_password")

    update_data["key"] = EMAIL_SETTINGS_KEY
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()

    await col.update_one(
        {"key": EMAIL_SETTINGS_KEY},
        {"$set": update_data},
        upsert=True,
    )

    logger.info("email_settings_updated", updated_by=current_user.get("email"))

    # Also patch live settings object so new alerts use updated values immediately
    settings.SMTP_HOST = update_data["smtp_host"]
    settings.SMTP_PORT = update_data["smtp_port"]
    settings.SMTP_TLS = update_data["smtp_tls"]
    settings.SMTP_USER = update_data["smtp_user"]
    if update_data["smtp_password"]:
        settings.SMTP_PASSWORD = update_data["smtp_password"]
    settings.SMTP_FROM_EMAIL = update_data["smtp_from_email"]
    settings.SMTP_FROM_NAME = update_data["smtp_from_name"]
    settings.ALERT_EMAIL_RECIPIENTS = update_data["alert_recipients"]
    settings.ALERT_EMAIL_MIN_SEVERITY = update_data["min_severity"]

    response = EmailAlertSettingsResponse(**update_data)
    response.smtp_password = None
    return response


@router.post("/email/test")
async def test_email_settings(
    payload: TestEmailRequest,
    mongo_db=Depends(get_mongodb),
    current_user=Depends(require_role(["admin", "superadmin"])),
):
    """Send a test email using the currently saved SMTP settings."""
    data = await _load_settings(mongo_db)

    # Re-read live password from MongoDB (GET redacts it)
    col = mongo_db.get_collection(SETTINGS_COLLECTION)
    doc = await col.find_one({"key": EMAIL_SETTINGS_KEY})
    stored_password = doc.get("smtp_password") if doc else data.get("smtp_password")

    host = data.get("smtp_host", settings.SMTP_HOST)
    port = data.get("smtp_port", settings.SMTP_PORT)
    tls = data.get("smtp_tls", settings.SMTP_TLS)
    user = data.get("smtp_user", settings.SMTP_USER)
    password = stored_password or settings.SMTP_PASSWORD
    from_email = data.get("smtp_from_email", settings.SMTP_FROM_EMAIL)
    from_name = data.get("smtp_from_name", settings.SMTP_FROM_NAME)

    if not user or not password:
        raise HTTPException(
            status_code=400,
            detail="SMTP credentials are not configured. Save your settings first."
        )

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, _smtp_send_test,
            host, port, tls, user, password, from_email, from_name, payload.recipient
        )
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(status_code=400, detail="SMTP authentication failed. Check your username and password.")
    except smtplib.SMTPConnectError:
        raise HTTPException(status_code=400, detail=f"Could not connect to {host}:{port}. Check host and port.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send test email: {str(e)}")

    return {"success": True, "message": f"Test email sent to {payload.recipient}"}
