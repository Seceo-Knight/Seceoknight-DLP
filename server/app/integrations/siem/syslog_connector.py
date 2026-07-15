"""
Generic Syslog SIEM connector.

Forwards DLP events to any on-prem or cloud SIEM that accepts syslog:
QRadar, ArcSight, LogRhythm, Wazuh, rsyslog/syslog-ng, Graylog, etc.

Transport:
  * UDP            — fire-and-forget (RFC 5426)
  * TCP            — LF-framed stream (RFC 6587 non-transparent framing)
  * TCP + TLS      — same, wrapped in TLS

Wire format (the syslog MSG payload):
  * CEF   — ArcSight Common Event Format (also ingested by QRadar, Splunk, …)
  * LEEF  — IBM QRadar Log Event Extended Format (LEEF 2.0)

The full line is an RFC 5424 syslog frame whose MSG is the CEF/LEEF record:
    <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD  CEF:0|...|...

This connector is write-only: query_events / create_alert are not supported.
Socket I/O is blocking, so every send runs in a thread via asyncio.to_thread
to avoid stalling the event loop.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.observability import StructuredLogger
from app.integrations.siem.base import SIEMConnector, SIEMType, EventSeverity

logger = StructuredLogger(__name__)


# ── severity maps ────────────────────────────────────────────────────────────
# DLP severity → syslog severity (RFC 5424: 2=crit 3=err 4=warning 5=notice 6=info)
_SYSLOG_SEVERITY = {
    "critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6,
}
# DLP severity → CEF severity (0–10)
_CEF_SEVERITY = {
    "critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1,
}
# Syslog facilities (local0–local7 → 16–23); default local0.
_FACILITIES = {f"local{i}": 16 + i for i in range(8)}
_FACILITIES.update({"user": 1, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10})


def _dlp_sev(event: Dict[str, Any]) -> str:
    sev = str(event.get("severity", "medium")).lower()
    return sev if sev in _SYSLOG_SEVERITY else "medium"


class SyslogConnector(SIEMConnector):
    """RFC 5424 syslog forwarder with CEF/LEEF payloads over UDP/TCP/TLS."""

    def __init__(
        self,
        name: str,
        host: str,
        port: int = 514,
        protocol: str = "udp",          # udp | tcp | tls
        log_format: str = "cef",        # cef | leef
        facility: str = "local0",
        verify_certs: bool = True,
        min_severity: str = "low",
        **kwargs,
    ):
        use_ssl = protocol.lower() == "tls"
        super().__init__(
            name=name,
            siem_type=SIEMType.SYSLOG,
            host=host,
            port=port,
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            **kwargs,
        )
        self.protocol = protocol.lower()
        self.log_format = log_format.lower()
        self.facility = _FACILITIES.get(facility.lower(), 16)
        self.min_severity = str(min_severity).lower()
        self._sock: Optional[socket.socket] = None

        if self.protocol not in ("udp", "tcp", "tls"):
            raise ValueError(f"Unsupported syslog protocol: {protocol}")
        if self.log_format not in ("cef", "leef"):
            raise ValueError(f"Unsupported syslog format: {log_format}")

    # ── lifecycle ────────────────────────────────────────────────────────────
    async def connect(self) -> bool:
        try:
            await asyncio.to_thread(self._open_socket)
            self.connected = True
            return True
        except Exception as e:
            logger.log_error(e, {"operation": "syslog_connect", "siem": self.name})
            self.connected = False
            return False

    async def disconnect(self) -> bool:
        await asyncio.to_thread(self._close_socket)
        self.connected = False
        return True

    async def test_connection(self) -> Dict[str, Any]:
        """Open the socket (and for TCP/TLS complete the handshake) and send a
        single informational test record."""
        try:
            probe = self._syslog_frame(
                self._format_record({
                    "event_type": "connectivity_test",
                    "severity": "info",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metadata": {"message": "SeceoKnight DLP syslog connectivity test"},
                }),
                "info",
            )
            await asyncio.to_thread(self._send_raw, probe)
            return {
                "success": True,
                "message": f"Sent test record via {self.protocol.upper()} to {self.host}:{self.port}",
                "protocol": self.protocol,
                "format": self.log_format,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── sending ──────────────────────────────────────────────────────────────
    async def send_event(self, event: Dict[str, Any], index: Optional[str] = None) -> bool:
        try:
            record = self._format_record(event)
            frame = self._syslog_frame(record, _dlp_sev(event))
            await asyncio.to_thread(self._send_raw, frame)
            return True
        except Exception as e:
            logger.log_error(e, {"operation": "syslog_send_event", "siem": self.name})
            # Drop the (possibly dead) TCP socket so the next send reconnects.
            await asyncio.to_thread(self._close_socket)
            return False

    async def send_batch(self, events: List[Dict[str, Any]], index: Optional[str] = None) -> Dict[str, Any]:
        sent, failed = 0, 0
        for ev in events:
            if await self.send_event(ev, index):
                sent += 1
            else:
                failed += 1
        return {"success": failed == 0, "sent": sent, "failed": failed, "total": len(events)}

    async def query_events(self, query, start_time, end_time, limit: int = 100):
        raise NotImplementedError("Syslog is write-only; querying is not supported.")

    async def create_alert(self, alert_name, description, severity, query, **kwargs):
        raise NotImplementedError("Syslog is write-only; alert creation is not supported.")

    # ── socket plumbing (blocking; always called via asyncio.to_thread) ──────
    def _open_socket(self) -> None:
        self._close_socket()
        if self.protocol == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return
        raw = socket.create_connection((self.host, self.port), timeout=10)
        if self.protocol == "tls":
            ctx = ssl.create_default_context()
            if not self.verify_certs:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
        self._sock = raw

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _send_raw(self, frame: str) -> None:
        data = frame.encode("utf-8", errors="replace")
        if self.protocol == "udp":
            if self._sock is None:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.sendto(data, (self.host, self.port))
            return
        # TCP / TLS — LF-framed (RFC 6587 non-transparent framing). Reconnect
        # once if the stream was never opened or was torn down.
        if self._sock is None:
            self._open_socket()
        assert self._sock is not None
        self._sock.sendall(data + b"\n")

    # ── framing + formatters ─────────────────────────────────────────────────
    def _syslog_frame(self, msg: str, dlp_severity: str) -> str:
        pri = self.facility * 8 + _SYSLOG_SEVERITY.get(dlp_severity, 4)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        host = (self.config.get("device_host") or socket.gethostname() or "-").split(".")[0]
        # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
        return f"<{pri}>1 {ts} {host} SeceoKnightDLP - DLP - {msg}"

    def _format_record(self, event: Dict[str, Any]) -> str:
        f = self.format_dlp_event(event)
        return self._to_leef(f) if self.log_format == "leef" else self._to_cef(f)

    # -- CEF -------------------------------------------------------------------
    @staticmethod
    def _cef_hdr_escape(v: str) -> str:
        return str(v).replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _cef_ext_escape(v: str) -> str:
        return (str(v).replace("\\", "\\\\").replace("=", "\\=")
                .replace("\n", " ").replace("\r", " "))

    def _to_cef(self, f: Dict[str, Any]) -> str:
        dlp = f.get("dlp", {})
        agent = f.get("agent", {})
        user = f.get("user", {})
        net = f.get("network", {})
        fil = f.get("file", {})
        sev_word = str(f.get("severity", "medium")).lower()

        sig = str(dlp.get("classification_type") or f.get("event_type") or "dlp_event")
        name = self._event_name(f)
        header = "|".join([
            "CEF:0",
            "SeceoKnight",
            "DLP",
            "2.0.0",
            self._cef_hdr_escape(sig),
            self._cef_hdr_escape(name),
            str(_CEF_SEVERITY.get(sev_word, 5)),
        ])

        # CEF extension — prefer standard CEF keys, fall back to labelled customs.
        ext_pairs = [
            ("rt", self._epoch_ms(f.get("timestamp"))),
            ("externalId", f.get("event_id")),
            ("src", net.get("source_ip")),
            ("dst", net.get("destination_ip")),
            ("dhost", net.get("destination_host")),
            ("shost", agent.get("hostname")),
            ("suser", user.get("username")),
            ("duser", user.get("email")),
            ("fname", fil.get("name")),
            ("filePath", fil.get("path")),
            ("fsize", fil.get("size")),
            ("fileHash", fil.get("hash")),
            ("act", self._action(f, dlp)),
            ("outcome", "blocked" if dlp.get("blocked") else "allowed"),
            ("cs1", dlp.get("policy_name")), ("cs1Label", "PolicyName"),
            ("cs2", dlp.get("confidence")), ("cs2Label", "Confidence"),
            ("cs3", net.get("destination_country")), ("cs3Label", "DestCountry"),
            ("cn1", agent.get("id")), ("cn1Label", "AgentId"),
            ("msg", (f.get("metadata") or {}).get("message")),
        ]
        ext = " ".join(
            f"{k}={self._cef_ext_escape(v)}"
            for k, v in ext_pairs if v is not None and v != ""
        )
        return f"{header}|{ext}"

    # -- LEEF (2.0) ------------------------------------------------------------
    def _to_leef(self, f: Dict[str, Any]) -> str:
        dlp = f.get("dlp", {})
        agent = f.get("agent", {})
        user = f.get("user", {})
        net = f.get("network", {})
        fil = f.get("file", {})

        event_id = str(dlp.get("classification_type") or f.get("event_type") or "dlp_event")
        # LEEF 2.0 header with explicit tab delimiter marker: LEEF:2.0|...|<TAB>
        header = "|".join(["LEEF:2.0", "SeceoKnight", "DLP", "2.0.0",
                           event_id.replace("|", "_"), "0x09"])

        attrs = [
            ("devTime", f.get("timestamp")),
            ("devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'" if f.get("timestamp") else None),
            ("cat", f.get("event_type")),
            ("sev", str(_CEF_SEVERITY.get(str(f.get("severity", "medium")).lower(), 5))),
            ("src", net.get("source_ip")),
            ("dst", net.get("destination_ip")),
            ("dstHost", net.get("destination_host")),
            ("identSrc", agent.get("ip")),
            ("identHostName", agent.get("hostname")),
            ("usrName", user.get("username")),
            ("fileName", fil.get("name")),
            ("filePath", fil.get("path")),
            ("fileHash", fil.get("hash")),
            ("action", self._action(f, dlp)),
            ("blocked", dlp.get("blocked")),
            ("policyName", dlp.get("policy_name")),
            ("confidence", dlp.get("confidence")),
            ("agentId", agent.get("id")),
            ("externalId", f.get("event_id")),
        ]
        body = "\t".join(
            f"{k}={self._leef_escape(v)}"
            for k, v in attrs if v is not None and v != ""
        )
        return f"{header}\t{body}"

    @staticmethod
    def _leef_escape(v: Any) -> str:
        return str(v).replace("\t", " ").replace("\n", " ").replace("\r", " ")

    # -- shared helpers --------------------------------------------------------
    @staticmethod
    def _epoch_ms(ts: Optional[str]) -> Optional[int]:
        if not ts:
            return None
        try:
            s = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _action(f: Dict[str, Any], dlp: Dict[str, Any]) -> Optional[str]:
        actions = f.get("actions")
        if actions:
            return ",".join(str(a) for a in actions) if isinstance(actions, list) else str(actions)
        if dlp.get("blocked"):
            return "block"
        return None

    @staticmethod
    def _event_name(f: Dict[str, Any]) -> str:
        dlp = f.get("dlp", {})
        etype = str(f.get("event_type") or "DLP event").replace("_", " ")
        verb = "blocked" if dlp.get("blocked") else "detected"
        ctype = dlp.get("classification_type")
        base = f"{ctype} {verb}" if ctype else f"{etype} {verb}"
        return base.strip().capitalize()
