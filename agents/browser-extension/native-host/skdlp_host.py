#!/usr/bin/env python3
"""
SeceoKnight DLP — browser native-messaging host.

The browser launches this per the host manifest (com.seceoknightdlp.dlp) and
speaks the Chrome Native Messaging protocol over stdio: each message is a
little-endian uint32 length followed by that many UTF-8 JSON bytes.

For each "classify" request from the extension it:
  1. calls the DLP server  POST /agents/{agent_id}/policy/evaluate
     (event_type=cloud_upload) using the agent's X-Agent-Key,
  2. maps the response to an action  (block | alert | allow),
  3. emits the endpoint event(s) to /events — on a BLOCK it emits BOTH an
     "attempt" and a "prevented" event, an "alert" event for Internal, and a
     normal "allow" log for Public,
  4. replies to the extension with {requestId, action, level, reason}.

Fail-open: any error yields action=allow so a DLP hiccup never bricks uploads.
Config (first found wins):
  - env SKDLP_HOST_CONFIG  → path to a JSON file
  - %ProgramData%\\SeceoKnight\\dlp-host.json  (Windows)
  - /etc/seceoknightdlp/dlp-host.json             (Linux/macOS)
JSON keys: server_url, agent_id, agent_key.  (env overrides:
  SKDLP_SERVER_URL, SKDLP_AGENT_ID, SKDLP_AGENT_KEY)

This is the reference implementation. It can run as-is (Python 3.8+, requires
`requests`) or be frozen to an .exe (PyInstaller) for managed deployment; a
C++ port can later live inside the agent.
"""
import json
import os
import struct
import sys
import time
import uuid

try:
    import requests
except Exception:  # requests missing → still speak the protocol, fail open
    requests = None

LOG_PATH = os.environ.get(
    "SKDLP_HOST_LOG",
    os.path.join(os.environ.get("ProgramData", "/tmp"), "SeceoKnight", "dlp-host.log"),
)


def log(msg):
    # Native-messaging hosts must NEVER write to stdout (that's the protocol
    # channel). Log to a file instead; best-effort.
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write("%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg))
    except Exception:
        pass


def load_config():
    cfg = {}
    path = os.environ.get("SKDLP_HOST_CONFIG")
    candidates = [path] if path else []
    candidates += [
        os.path.join(os.environ.get("ProgramData", ""), "SeceoKnight", "dlp-host.json"),
        "/etc/seceoknightdlp/dlp-host.json",
    ]
    for p in candidates:
        if p and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    cfg = json.load(fh)
                break
            except Exception as e:
                log("config read failed %s: %s" % (p, e))
    return {
        "server_url": os.environ.get("SKDLP_SERVER_URL") or cfg.get("server_url") or "http://localhost:55000/api/v1",
        "agent_id": os.environ.get("SKDLP_AGENT_ID") or cfg.get("agent_id") or "browser-guard",
        "agent_key": os.environ.get("SKDLP_AGENT_KEY") or cfg.get("agent_key") or "",
    }


CFG = load_config()


# ---- Native Messaging stdio framing ----
def read_message():
    raw_len = sys.stdin.buffer.read(4)
    if len(raw_len) < 4:
        return None
    (length,) = struct.unpack("<I", raw_len)
    data = sys.stdin.buffer.read(length)
    return json.loads(data.decode("utf-8"))


def send_message(obj):
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


# ---- DLP server calls ----
def evaluate(meta):
    """Return (action, level, reason). action in {block, alert, allow}."""
    if requests is None or not CFG["agent_key"]:
        return "allow", None, "host-unconfigured"
    try:
        # CRITICAL: send the raw bytes as file_content_b64, NOT decoded to
        # UTF-8 text. inject.js already base64-encodes the real file bytes
        # (contentB64) — decoding them as text here and sending file_content
        # would turn any binary upload (docx/pdf/xlsx/pptx) into garbage
        # replacement characters before it ever reached the classifier, the
        # same bypass that was found and fixed for USB file transfer. The
        # server's document_extract.py does the real pdf/docx/xlsx/pptx
        # parsing when file_content_b64 is sent instead.
        content_b64 = meta.get("contentB64", "") or ""
        r = requests.post(
            "%s/agents/%s/policy/evaluate" % (CFG["server_url"].rstrip("/"), CFG["agent_id"]),
            headers={"X-Agent-Key": CFG["agent_key"], "Content-Type": "application/json"},
            json={
                "file_name": meta.get("fileName", "upload.bin"),
                "file_content_b64": content_b64,
                "file_size": meta.get("fileSize"),
                "event_type": "cloud_upload",
                "destination_type": "cloud",
                "destination_path": meta.get("host") or meta.get("url"),
            },
            timeout=6,
        )
        r.raise_for_status()
        body = r.json()
        level = (body.get("classification") or {}).get("level")
        if body.get("action") == "block":
            return "block", level, body.get("reason")
        if body.get("alert_severity"):
            return "alert", level, body.get("reason")
        return "allow", level, body.get("reason")
    except Exception as e:
        log("evaluate failed: %s" % e)
        return "allow", None, "evaluate-error"


def emit_event(meta, action_taken, severity, level, subtype, blocked):
    """Emit one DLP event. Field names match the server's EventCreate schema
    (undeclared fields are silently dropped), so we map the browser upload onto
    event_id/agent_id/action/destination/blocked/event_subtype/etc."""
    if requests is None or not CFG["agent_key"]:
        return
    try:
        requests.post(
            "%s/events/" % CFG["server_url"].rstrip("/"),
            headers={"X-Agent-Key": CFG["agent_key"], "Content-Type": "application/json"},
            json={
                "event_id": "clupload-" + uuid.uuid4().hex,
                "agent_id": CFG["agent_id"],
                "event_type": "network_exfil",
                "event_subtype": subtype,
                "severity": severity,
                "action": action_taken,               # logged | alerted | blocked
                "blocked": bool(blocked),
                "destination": meta.get("host") or meta.get("url"),
                "destination_type": "cloud",
                "file_path": meta.get("fileName"),
                "classification_level": level,
                "description": "Cloud upload %s (%s) to %s" % (subtype, level or "Unknown", meta.get("host")),
            },
            timeout=5,
        )
    except Exception as e:
        log("emit_event failed: %s" % e)


def handle(meta):
    action, level, reason = evaluate(meta)
    if action == "block":
        # Explicit attempt + prevention pair, per the policy requirement.
        emit_event(meta, "alerted", "high", level, "cloud_upload_attempt", blocked=False)
        emit_event(meta, "blocked", "critical", level, "cloud_upload_prevented", blocked=True)
    elif action == "alert":
        emit_event(meta, "alerted", "medium", level, "cloud_upload_internal", blocked=False)
    else:
        emit_event(meta, "logged", "info", level, "cloud_upload_allowed", blocked=False)
    return action, level, reason


def main():
    log("host started (server=%s agent=%s keyed=%s)" % (CFG["server_url"], CFG["agent_id"], bool(CFG["agent_key"])))
    while True:
        try:
            msg = read_message()
        except Exception as e:
            log("read error: %s" % e)
            break
        if msg is None:
            break
        if msg.get("type") == "ping":
            # Self-test from the extension: confirm the host is reachable.
            log("ping received -> pong")
            send_message({"type": "pong", "ok": True, "keyed": bool(CFG["agent_key"]),
                          "server": CFG["server_url"]})
            continue
        if msg.get("type") != "classify":
            continue
        req_id = msg.get("requestId")
        meta = {k: msg.get(k) for k in ("host", "url", "fileName", "fileSize", "mimeType", "contentB64")}
        try:
            action, level, reason = handle(meta)
        except Exception as e:
            log("handle error: %s" % e)
            action, level, reason = "allow", None, "host-error"
        send_message({"requestId": req_id, "action": action, "level": level, "reason": reason})


if __name__ == "__main__":
    main()
