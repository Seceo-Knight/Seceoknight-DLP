"""
The DLP SMTP handler.

Outbound mail is routed here (Google Workspace outbound gateway / smarthost).
For each message we pull apart the MIME tree, turn every attachment and the
body into text, ask the DLP server for a decision, and then either reject the
whole message (so it never leaves) or forward it to the next hop.

Decision matrix (driven by the `email_send_prevention` policies on the server):
  Public                    -> forward, log
  Internal                  -> forward, alert
  Confidential / Restricted -> REJECT 550 + attempt & prevention alerts

Reject-at-DATA is a real block: the sending MTA never gets a 250, so the mail
is not delivered and the sender is told why.
"""
from __future__ import annotations

import email
import email.policy
import logging
from typing import List, Tuple

import aiosmtplib

from .config import config
from .dlp_client import emit_event, evaluate
from .extract import extract_text

log = logging.getLogger(__name__)


class DLPHandler:
    async def handle_DATA(self, server, session, envelope):  # noqa: N802 (aiosmtpd API)
        sender = envelope.mail_from or "(unknown)"
        recipients = ", ".join(envelope.rcpt_tos or [])

        if len(envelope.content or b"") > config.MAX_MESSAGE_BYTES:
            log.warning("message from %s exceeds size cap — rejecting", sender)
            return "552 5.3.4 Message too large for DLP inspection"

        msg = None
        parts: List[Tuple[str, bytes, bool]] = []
        try:
            msg = email.message_from_bytes(envelope.content, policy=email.policy.default)
            parts = self._collect_parts(msg)
        except Exception as e:  # noqa: BLE001 — unparseable MIME
            log.error("MIME parse failed from %s: %s", sender, e)
            if config.BLOCK_ON_DLP_ERROR:
                return "451 4.7.1 Message could not be inspected by DLP"

        subject = (msg.get("Subject") if msg is not None else "") or ""
        worst_action, worst_level, worst_name = "allow", None, None

        for name, data, is_body in parts:
            ex = extract_text("body.txt" if is_body else name, data)

            if not ex.ok and not is_body:
                # Couldn't read it (encrypted archive, scanned image, legacy
                # .doc, oversized, opaque binary). Never treat that as clean —
                # ask the server so the same policy that governs USB/cloud
                # decides here too. RELAY_BLOCK_UNEXTRACTABLE remains a local
                # override for sites that want to reject without consulting policy.
                log.info("uninspectable attachment %s (%s: %s)", name, ex.kind, ex.reason)
                if config.BLOCK_UNEXTRACTABLE:
                    await self._record_block(sender, recipients, name, None,
                                             f"Uninspectable attachment blocked ({ex.reason})")
                    return config.REJECT_MESSAGE
                skipped = "too_large" if ex.kind == "too_large" else "unreadable"
                action, level, reason = await evaluate(name, "", recipients, skipped=skipped)
                if action == "block":
                    await self._record_block(
                        sender, recipients, name, level,
                        f"Uninspectable attachment ({ex.reason}) blocked by policy"[:480])
                    return config.REJECT_MESSAGE
                continue
            if not ex.text.strip():
                continue

            action, level, reason = await evaluate(name if not is_body else "(message body)",
                                                   ex.text, recipients)
            log.info("part=%s kind=%s level=%s action=%s truncated=%s",
                     name, ex.kind, level, action, ex.truncated)

            if action != "block" and ex.truncated and not is_body:
                # We only read part of this attachment (it outran the scan budget,
                # or an archive hit its safety limits) and what we read looked
                # clean — but "clean so far" is not clean. Re-ask as uninspectable
                # so the same policy that governs an unopenable attachment decides,
                # rather than letting filler in front of a secret buy a pass.
                log.info("partially inspected attachment %s (%s) — consulting policy",
                         name, ex.reason)
                action, level, reason = await evaluate(name, "", recipients, skipped="too_large")
                if action == "block":
                    await self._record_block(
                        sender, recipients, name, level,
                        f"Partially inspected attachment ({ex.reason}) blocked by policy"[:480])
                    return config.REJECT_MESSAGE

            if action == "block":
                await self._record_block(
                    sender, recipients, name, level,
                    f"Sensitive data ({level}) blocked in outbound email to {recipients}: {reason}"[:480],
                )
                return config.REJECT_MESSAGE
            if action == "alert" and worst_action == "allow":
                worst_action, worst_level, worst_name = "alert", level, name

        # Nothing sensitive enough to block — forward it on.
        try:
            await self._forward(envelope)
        except Exception as e:  # noqa: BLE001
            log.error("forward to next hop failed: %s", e)
            return "451 4.4.1 Temporary failure relaying message"

        if worst_action == "alert":
            await emit_event(subtype="email_send_internal", action="alerted", severity="medium",
                             blocked=False, level=worst_level, file_name=worst_name,
                             sender=sender, recipients=recipients,
                             description=f"Internal data emailed to {recipients} (subject: {subject})"[:480])
        else:
            await emit_event(subtype="email_send_allowed", action="logged", severity="info",
                             blocked=False, level=worst_level or "Public", file_name=None,
                             sender=sender, recipients=recipients,
                             description=f"Email sent to {recipients} (subject: {subject})"[:480])
        return "250 Message accepted for delivery"

    # ---- helpers ----------------------------------------------------------
    @staticmethod
    def _collect_parts(msg) -> List[Tuple[str, bytes, bool]]:
        """Flatten the MIME tree into (name, bytes, is_body) tuples."""
        parts: List[Tuple[str, bytes, bool]] = []
        for part in msg.walk():
            if part.is_multipart():
                continue
            payload = part.get_payload(decode=True) or b""
            if not payload:
                continue
            filename = part.get_filename()
            if filename:
                parts.append((filename, payload, False))
            elif config.SCAN_BODY and part.get_content_type() in ("text/plain", "text/html"):
                parts.append(("(message body)", payload, True))
        return parts

    @staticmethod
    async def _record_block(sender, recipients, name, level, description) -> None:
        """Emit the attempt + prevention pair for a blocked message."""
        await emit_event(subtype="email_send_attempt", action="alerted", severity="high",
                         blocked=False, level=level, file_name=name,
                         sender=sender, recipients=recipients,
                         description=f"Attempt: {description}"[:480])
        await emit_event(subtype="email_send_prevented", action="blocked", severity="critical",
                         blocked=True, level=level, file_name=name,
                         sender=sender, recipients=recipients,
                         description=description)

    @staticmethod
    async def _forward(envelope) -> None:
        if not config.NEXT_HOP_HOST:
            # Test mode: accept and drop. Never use in production — set
            # RELAY_NEXT_HOP_HOST so clean mail actually gets delivered.
            log.warning("no next hop configured; message accepted but NOT forwarded")
            return
        await aiosmtplib.send(
            envelope.content,
            sender=envelope.mail_from,
            recipients=envelope.rcpt_tos,
            hostname=config.NEXT_HOP_HOST,
            port=config.NEXT_HOP_PORT,
            start_tls=True if config.NEXT_HOP_STARTTLS else None,
            username=config.NEXT_HOP_USER or None,
            password=config.NEXT_HOP_PASS or None,
        )
