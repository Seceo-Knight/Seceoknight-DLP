"""Relay configuration (env-driven)."""
import os


def _bool(name: str, default: bool = False) -> bool:
    return (os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on"))


class Config:
    # --- where we listen (Google Workspace / your MTA routes outbound mail here)
    LISTEN_HOST = os.environ.get("RELAY_LISTEN_HOST", "0.0.0.0")
    LISTEN_PORT = int(os.environ.get("RELAY_LISTEN_PORT", "10025"))
    MAX_MESSAGE_BYTES = int(os.environ.get("RELAY_MAX_MESSAGE_BYTES", str(50 * 1024 * 1024)))

    # --- where clean mail goes next (e.g. smtp-relay.gmail.com:587, or your smarthost)
    NEXT_HOP_HOST = os.environ.get("RELAY_NEXT_HOP_HOST", "")
    NEXT_HOP_PORT = int(os.environ.get("RELAY_NEXT_HOP_PORT", "25"))
    NEXT_HOP_USER = os.environ.get("RELAY_NEXT_HOP_USER", "")
    NEXT_HOP_PASS = os.environ.get("RELAY_NEXT_HOP_PASS", "")
    NEXT_HOP_STARTTLS = _bool("RELAY_NEXT_HOP_STARTTLS", True)

    # --- DLP server (reuses the existing classifier/policy/event pipeline)
    DLP_SERVER_URL = os.environ.get("DLP_SERVER_URL", "http://manager:55000/api/v1")
    DLP_AGENT_ID = os.environ.get("DLP_AGENT_ID", "smtp-relay")
    DLP_AGENT_KEY = os.environ.get("DLP_AGENT_KEY", "")
    DLP_TIMEOUT = float(os.environ.get("DLP_TIMEOUT", "20"))

    # --- behaviour
    # What to do when an attachment can't be read (encrypted zip, scanned image
    # PDF, legacy .doc). Default allows it — flipping this to true makes the
    # relay fail CLOSED on unreadable content, which is safer but will bounce
    # legitimate mail, so it's opt-in.
    BLOCK_UNEXTRACTABLE = _bool("RELAY_BLOCK_UNEXTRACTABLE", False)
    # If the DLP server is unreachable we allow (fail-open) by default so a DLP
    # outage never stops company mail. Set true to fail closed.
    BLOCK_ON_DLP_ERROR = _bool("RELAY_BLOCK_ON_DLP_ERROR", False)
    # Also scan the message body text itself, not just attachments.
    SCAN_BODY = _bool("RELAY_SCAN_BODY", True)

    REJECT_MESSAGE = os.environ.get(
        "RELAY_REJECT_MESSAGE",
        "550 5.7.1 Message blocked by SeceoKnight DLP: sensitive data detected",
    )


config = Config()
