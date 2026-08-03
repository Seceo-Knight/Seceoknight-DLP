"""
Linux Clipboard Monitor (X11 + Wayland)

The hardest part of clipboard monitoring on Linux isn't reading the
clipboard -- it's *whose* clipboard. seceoknight-agent.service runs as
root (required for cross-user file monitoring, same reason the whole
agent isn't user-scoped), but the clipboard is a property of a specific
logged-in user's X11 or Wayland session, not something root has direct
access to: root has no $DISPLAY/$WAYLAND_DISPLAY of its own, and X11
servers generally refuse a connection from a different user's UID than
the one that owns the session unless explicitly permitted (xhost).

This mirrors the same "which user is actually interactively logged in"
problem CyberSentinel's Linux agent solves for file-owner attribution via
`who`/`loginctl` -- the fix here is the same idea applied to clipboard
access: find the active graphical session's owning user via
`loginctl`/`who`, then read the clipboard *as that user* (sudo -u with
the session's DISPLAY/WAYLAND_DISPLAY/XAUTHORITY/XDG_RUNTIME_DIR env vars
set), rather than trying to access it as root directly.

Backends:
- X11: polls `xclip -selection clipboard -o` (no watch/blocking-read
  primitive exists for X11 selections short of writing a native X11
  event-loop client, which is a much larger dependency footprint for a
  polling-tolerant DLP use case).
- Wayland: uses `wl-paste --watch cat`, which blocks and prints on each
  clipboard change -- true event-driven capture, no polling needed, where
  the compositor supports it (most modern ones do via wlr-data-control).

Requires `xclip` and/or `wl-clipboard` (system packages) depending on
which display server is in use. Degrades to a logged no-op if neither
tool nor any active graphical session is found (e.g. a headless server),
consistent with print/USB monitoring's degrade-gracefully design.
"""

import hashlib
import logging
import os
import re
import subprocess
import threading
import time
from typing import Callable, Dict, Optional

logger = logging.getLogger("dlp-agent.clipboard")


class GraphicalSession:
    __slots__ = ("username", "uid", "session_type", "display", "xdg_runtime_dir")

    def __init__(self, username: str, uid: str, session_type: str, display: str, xdg_runtime_dir: str):
        self.username = username
        self.uid = uid
        self.session_type = session_type  # "x11" or "wayland"
        self.display = display
        self.xdg_runtime_dir = xdg_runtime_dir


def find_active_graphical_session() -> Optional[GraphicalSession]:
    """Find the active local graphical (X11 or Wayland) login session and
    its owning user, via loginctl -- the same systemd-logind session
    database `who`/`loginctl` themselves read from, and the standard way
    to answer "who's actually sitting at this machine" on modern Linux
    (works whether they logged in via a display manager or a text
    console + startx)."""
    try:
        result = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            session_id = line.split()[0]
            props = _get_session_properties(session_id)
            if not props:
                continue
            if props.get("Type") not in ("x11", "wayland"):
                continue
            if props.get("State") != "active":
                continue
            if props.get("Remote") == "yes":
                continue  # Skip SSH/remote sessions -- no local clipboard to read

            username = props.get("Name", "")
            uid = props.get("User", "")
            session_type = props.get("Type")
            display = props.get("Display", "")
            if not username or not uid:
                continue

            xdg_runtime_dir = f"/run/user/{uid}"
            return GraphicalSession(username, uid, session_type, display, xdg_runtime_dir)
    except FileNotFoundError:
        logger.debug("loginctl not available -- cannot detect graphical sessions")
    except Exception as exc:
        logger.debug(f"Failed to enumerate graphical sessions: {exc}")
    return None


def _get_session_properties(session_id: str) -> Optional[Dict[str, str]]:
    try:
        result = subprocess.run(
            ["loginctl", "show-session", session_id, "-p", "Type", "-p", "State",
             "-p", "Name", "-p", "User", "-p", "Display", "-p", "Remote"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        props = {}
        for line in result.stdout.strip().split("\n"):
            if "=" in line:
                key, _, value = line.partition("=")
                props[key] = value
        return props
    except Exception:
        return None


class ClipboardMonitor:
    """Monitors clipboard content changes for the active graphical
    session's user, classifying and reporting the same way file events
    are (via the callback -> agent.py's own classification pipeline)."""

    def __init__(self, callback: Optional[Callable[[str, str], None]] = None,
                 poll_interval: float = 2.0, max_content_bytes: int = 100_000):
        self.callback = callback
        self.poll_interval = poll_interval
        self.max_content_bytes = max_content_bytes
        self._running = False
        self._thread = None
        self._wayland_watch_proc = None
        self._last_hash: Optional[str] = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Clipboard monitor started")

    def stop(self):
        self._running = False
        if self._wayland_watch_proc:
            try:
                self._wayland_watch_proc.terminate()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Clipboard monitor stopped")

    def _run_loop(self):
        # Re-resolve the active session periodically rather than once --
        # the interactively logged-in user can change (fast user
        # switching, someone locks/unlocks, a different user logs in on
        # the console) over an agent's long uptime.
        session = None
        backend = None
        last_session_check = 0.0
        session_recheck_interval = 30.0

        while self._running:
            now = time.time()
            if session is None or (now - last_session_check) > session_recheck_interval:
                session = find_active_graphical_session()
                last_session_check = now
                if session is None:
                    logger.debug("No active graphical session found -- clipboard monitoring idle")
                    time.sleep(self.poll_interval)
                    continue
                backend = self._pick_backend(session)
                if backend is None:
                    logger.warning(
                        f"No clipboard tool available for {session.session_type} session "
                        f"({'xclip' if session.session_type == 'x11' else 'wl-clipboard'} not installed) "
                        "-- clipboard monitoring idle"
                    )
                    time.sleep(self.poll_interval)
                    continue

            if backend == "wayland-watch":
                self._run_wayland_watch(session)
                # _run_wayland_watch blocks until the watch process exits
                # (compositor restart, session end, etc.) -- loop back to
                # re-resolve the session afterward instead of busy-spinning.
                session = None
                continue

            # X11 (or Wayland without a working --watch): poll.
            self._poll_once(session, backend)
            time.sleep(self.poll_interval)

    def _pick_backend(self, session: GraphicalSession) -> Optional[str]:
        if session.session_type == "wayland":
            if _tool_exists("wl-paste"):
                return "wayland-watch"
            return None
        if session.session_type == "x11":
            if _tool_exists("xclip"):
                return "x11-poll"
            return None
        return None

    def _session_env(self, session: GraphicalSession) -> Dict[str, str]:
        env = dict(os.environ)
        env["XDG_RUNTIME_DIR"] = session.xdg_runtime_dir
        if session.session_type == "x11":
            env["DISPLAY"] = session.display or ":0"
            # XAUTHORITY isn't exposed by loginctl directly; $HOME/.Xauthority
            # is the standard location for it under almost every display
            # manager (gdm/lightdm/sddm all write it there for the user).
            env["XAUTHORITY"] = f"/home/{session.username}/.Xauthority"
        else:
            env["WAYLAND_DISPLAY"] = session.display or "wayland-0"
        return env

    def _run_as_session_user(self, session: GraphicalSession, command: list, timeout: Optional[float] = None):
        env = self._session_env(session)
        env_args = [f"{k}={v}" for k, v in env.items() if k in
                    ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR")]
        full_cmd = ["sudo", "-u", session.username, "env"] + env_args + command
        return subprocess.run(full_cmd, capture_output=True, timeout=timeout)

    def _poll_once(self, session: GraphicalSession, backend: str):
        try:
            if backend == "x11-poll":
                result = self._run_as_session_user(
                    session, ["xclip", "-selection", "clipboard", "-o"], timeout=5
                )
            else:
                result = self._run_as_session_user(
                    session, ["wl-paste", "--no-newline"], timeout=5
                )
            if result.returncode != 0:
                return  # Empty clipboard, or transient access error -- not worth logging every poll
            content = result.stdout.decode("utf-8", errors="ignore")
            self._handle_content(content, session.username)
        except subprocess.TimeoutExpired:
            logger.debug("Clipboard read timed out")
        except Exception as exc:
            logger.debug(f"Clipboard poll error: {exc}")

    def _run_wayland_watch(self, session: GraphicalSession):
        """wl-paste --watch blocks and invokes its argument (here, `cat`)
        each time the clipboard changes -- genuinely event-driven, unlike
        X11's polling path. Runs until the process exits (session end,
        compositor restart) or stop() is called."""
        env = self._session_env(session)
        env_args = [f"{k}={v}" for k, v in env.items() if k in
                    ("WAYLAND_DISPLAY", "XDG_RUNTIME_DIR")]
        cmd = ["sudo", "-u", session.username, "env"] + env_args + ["wl-paste", "--watch", "cat"]
        try:
            self._wayland_watch_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            while self._running:
                line = self._wayland_watch_proc.stdout.readline()
                if not line:
                    break  # Process exited
                content = line.decode("utf-8", errors="ignore")
                self._handle_content(content, session.username)
        except Exception as exc:
            logger.debug(f"wl-paste --watch error: {exc}")
        finally:
            if self._wayland_watch_proc:
                try:
                    self._wayland_watch_proc.terminate()
                except Exception:
                    pass
                self._wayland_watch_proc = None

    def _handle_content(self, content: str, username: str):
        if not content or not content.strip():
            return
        content = content[: self.max_content_bytes]
        content_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
        if content_hash == self._last_hash:
            return  # No change since last read
        self._last_hash = content_hash

        if self.callback:
            self.callback(content, username)


def _tool_exists(name: str) -> bool:
    try:
        result = subprocess.run(["which", name], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False
