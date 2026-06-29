"""
MFA Service — TOTP-based multi-factor authentication.

Flow:
  Setup:
    1. POST /auth/mfa/setup      → generate secret, return QR code (base64 PNG)
    2. POST /auth/mfa/verify-setup → user enters first code → MFA enabled

  Login (when mfa_enabled=True):
    1. POST /auth/login          → credentials OK → return {mfa_required, mfa_token}
    2. POST /auth/mfa/validate   → mfa_token + TOTP code → return full tokens

  Disable:
    POST /auth/mfa/disable       → current password + TOTP code → MFA disabled

Security:
  - TOTP secret stored Fernet-encrypted in the DB (never plaintext)
  - mfa_token is a short-lived (5 min) JWT with type="mfa_pending"
  - mfa_token is single-use: consumed in Redis on first validate call
  - TOTP window=1 (±30 s clock drift allowed)
"""

from __future__ import annotations

import base64
import io
import os

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

APP_NAME = "SeceoKnight DLP"

# ── Fernet key ────────────────────────────────────────────────────────────────
# Derive a 32-byte URL-safe base64 key from the application secret.
# We pad/truncate to exactly 32 bytes then base64-encode so Fernet accepts it.
def _fernet() -> Fernet:
    raw = (settings.SECRET_KEY or "").encode()
    # Pad or truncate to 32 bytes
    key_bytes = (raw * 8)[:32]
    b64_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(b64_key)


# ── Secret management ─────────────────────────────────────────────────────────

def generate_secret() -> str:
    """Generate a fresh base32 TOTP secret (160-bit / 32 chars)."""
    return pyotp.random_base32()


def encrypt_secret(secret: str) -> str:
    """Encrypt the plaintext TOTP secret for DB storage."""
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(encrypted: str) -> str:
    """Decrypt the stored TOTP secret. Raises ValueError on tamper."""
    try:
        return _fernet().decrypt(encrypted.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("MFA secret could not be decrypted — possible tampering") from exc


# ── QR code ──────────────────────────────────────────────────────────────────

def build_provisioning_uri(secret: str, email: str) -> str:
    """Return the otpauth:// URI that authenticator apps scan."""
    return pyotp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=APP_NAME,
    )


def generate_qr_code_base64(secret: str, email: str) -> str:
    """
    Return a base64-encoded PNG of the QR code for the given secret/email.
    The frontend can render it as: <img src="data:image/png;base64,{result}" />
    """
    uri = build_provisioning_uri(secret, email)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ── Verification ──────────────────────────────────────────────────────────────

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code against the given secret.

    window=1 allows ±30 s clock drift (one period before/after current).
    Returns True on match, False otherwise. Never raises.
    """
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(str(code).strip(), valid_window=window)
    except Exception:
        return False
