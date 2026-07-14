"""
Shared symmetric encryption for secrets stored at rest (e.g. TOTP MFA secrets).

Mirrors the per-model cipher already used for Google Drive / OneDrive OAuth
tokens: derive a stable Fernet key from ``ENCRYPTION_KEY`` (falling back to
``SECRET_KEY`` when unset, which matches the current Docker deployment).
"""
import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet

from app.core.config import settings


@lru_cache(maxsize=1)
def _cipher() -> Fernet:
    key_source = settings.ENCRYPTION_KEY or settings.SECRET_KEY
    digest = hashlib.sha256(key_source.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_str(plaintext: str) -> str:
    """Encrypt a string → URL-safe token stored in the DB."""
    return _cipher().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_str(token: str) -> str:
    """Decrypt a token produced by :func:`encrypt_str`."""
    return _cipher().decrypt(token.encode("utf-8")).decode("utf-8")
