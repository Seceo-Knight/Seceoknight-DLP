"""
SeceoKnight DLP — SMTP relay entrypoint.

Listens for outbound mail (routed here by Google Workspace's outbound gateway
or your MTA's smarthost), inspects every attachment + body, and rejects any
message carrying Confidential/Restricted content before it can leave.
"""
import asyncio
import logging
import signal

from aiosmtpd.controller import Controller

from .config import config
from .handler import DLPHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("csdlp.relay")


def main() -> None:
    controller = Controller(
        DLPHandler(),
        hostname=config.LISTEN_HOST,
        port=config.LISTEN_PORT,
        data_size_limit=config.MAX_MESSAGE_BYTES,
        enable_SMTPUTF8=True,
    )
    controller.start()
    log.info("DLP SMTP relay listening on %s:%s", config.LISTEN_HOST, config.LISTEN_PORT)
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
