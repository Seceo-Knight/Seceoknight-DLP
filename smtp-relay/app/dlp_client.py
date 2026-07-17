"""
Client for the SeceoKnight DLP server.

The relay owns no classification logic of its own — it extracts text and asks
the existing server (`/agents/{id}/policy/evaluate`) for the decision, then
records events via `/events/`. That keeps one source of truth for
classification + policy across every channel (email, cloud upload, USB).
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional, Tuple

import httpx

from .config import config

log = logging.getLogger(__name__)


class Decision(Tuple):
    pass


async def evaluate(file_name: str, text: str, recipients: str,
                   skipped: Optional[str] = None) -> Tuple[str, Optional[str], str]:
    """Ask the DLP server to classify `text`. Returns (action, level, reason)
    where action is one of block | alert | allow.

    `skipped` ("too_large" / "unreadable") is passed when we could NOT read the
    attachment — the server then marks it uninspectable and its policy decides,
    keeping email consistent with USB/cloud instead of each channel inventing
    its own answer for content it can't see.
    """
    if not config.DLP_AGENT_KEY:
        log.warning("no DLP_AGENT_KEY configured — cannot evaluate")
        return ("block" if config.BLOCK_ON_DLP_ERROR else "allow"), None, "relay-unconfigured"
    url = f"{config.DLP_SERVER_URL.rstrip('/')}/agents/{config.DLP_AGENT_ID}/policy/evaluate"
    try:
        async with httpx.AsyncClient(timeout=config.DLP_TIMEOUT, follow_redirects=True) as c:
            r = await c.post(
                url,
                headers={"X-Agent-Key": config.DLP_AGENT_KEY},
                json={
                    "file_name": file_name,
                    "file_content": text,
                    "event_type": "email_send",
                    "destination_type": "email",
                    "destination_path": recipients,
                    **({"inspection_skipped": skipped} if skipped else {}),
                },
            )
            r.raise_for_status()
            body = r.json()
        level = (body.get("classification") or {}).get("level")
        if body.get("action") == "block":
            return "block", level, body.get("reason") or ""
        if body.get("alert_severity"):
            return "alert", level, body.get("reason") or ""
        return "allow", level, body.get("reason") or ""
    except Exception as e:  # noqa: BLE001 — a DLP outage must not silently mangle mail
        log.error("evaluate failed for %s: %s", file_name, e)
        return ("block" if config.BLOCK_ON_DLP_ERROR else "allow"), None, f"evaluate-error: {e}"


async def emit_event(*, subtype: str, action: str, severity: str, blocked: bool,
                     level: Optional[str], file_name: Optional[str],
                     sender: str, recipients: str, description: str) -> None:
    """Record one DLP event. Field names must match the server's EventCreate
    schema — undeclared fields are silently dropped."""
    if not config.DLP_AGENT_KEY:
        return
    url = f"{config.DLP_SERVER_URL.rstrip('/')}/events/"
    try:
        async with httpx.AsyncClient(timeout=config.DLP_TIMEOUT, follow_redirects=True) as c:
            await c.post(
                url,
                headers={"X-Agent-Key": config.DLP_AGENT_KEY},
                json={
                    "event_id": "email-" + uuid.uuid4().hex,
                    "agent_id": config.DLP_AGENT_ID,
                    "event_type": "email",
                    "event_subtype": subtype,
                    "severity": severity,
                    "action": action,               # logged | alerted | blocked
                    "blocked": blocked,
                    "destination": recipients,
                    "destination_type": "email",
                    "file_path": file_name,
                    "classification_level": level,
                    "user_email": sender,
                    "description": description,
                },
            )
    except Exception as e:  # noqa: BLE001
        log.error("emit_event failed (%s): %s", subtype, e)
