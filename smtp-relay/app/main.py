"""
SeceoKnight DLP — SMTP relay entrypoint.

Listens for outbound mail (routed here by Google Workspace's outbound gateway
or your MTA's smarthost), inspects every attachment + body, and rejects any
message carrying Confidential/Restricted content before it can leave.
"""
import asyncio
import logging
import signal
import ssl

from aiosmtpd.controller import Controller

from .config import config
from .handler import DLPHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("skdlp.relay")


def _build_tls_context() -> "ssl.SSLContext | None":
    """Build the STARTTLS context from RELAY_TLS_CERT_FILE/RELAY_TLS_KEY_FILE,
    or None if either is unset (listener stays plaintext-only, unchanged from
    before this existed). aiosmtpd's SMTP class forwards this straight to
    Python's stdlib STARTTLS handling — this only builds the context; no
    protocol-level trust decisions happen here."""
    if not config.TLS_CERT_FILE or not config.TLS_KEY_FILE:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=config.TLS_CERT_FILE, keyfile=config.TLS_KEY_FILE)
    return ctx


def main() -> None:
    tls_context = _build_tls_context()
    controller_kwargs = {}
    if tls_context is not None:
        controller_kwargs["tls_context"] = tls_context
        controller_kwargs["require_starttls"] = config.REQUIRE_STARTTLS

    controller = Controller(
        DLPHandler(),
        hostname=config.LISTEN_HOST,
        port=config.LISTEN_PORT,
        data_size_limit=config.MAX_MESSAGE_BYTES,
        enable_SMTPUTF8=True,
        **controller_kwargs,
    )
    controller.start()
    log.info("DLP SMTP relay listening on %s:%s", config.LISTEN_HOST, config.LISTEN_PORT)
    if tls_context is not None:
        log.info("STARTTLS enabled (cert=%s, required=%s)", config.TLS_CERT_FILE, config.REQUIRE_STARTTLS)
    else:
        log.warning("STARTTLS not configured — listener is plaintext-only. "
                     "Set RELAY_TLS_CERT_FILE/RELAY_TLS_KEY_FILE before exposing this relay "
                     "to the public internet (e.g. Google Workspace's outbound gateway).")
    log.info("DLP server: %s (agent=%s, keyed=%s)",
             config.DLP_SERVER_URL, config.DLP_AGENT_ID, bool(config.DLP_AGENT_KEY))
    if config.NEXT_HOP_HOST:
        log.info("next hop: %s:%s (starttls=%s)",
                 config.NEXT_HOP_HOST, config.NEXT_HOP_PORT, config.NEXT_HOP_STARTTLS)
    else:
        log.warning("NO NEXT HOP configured — clean mail is accepted but NOT delivered (test mode)")

    loop = asyncio.new_event_loop()
    stop = loop.create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: stop.done() or stop.set_result(None))
        except NotImplementedError:
            pass
    try:
        loop.run_until_complete(stop)
    finally:
        controller.stop()
        log.info("relay stopped")


if __name__ == "__main__":
    main()
