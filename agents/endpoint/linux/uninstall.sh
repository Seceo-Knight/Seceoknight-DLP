#!/usr/bin/env bash
#
# SeceoKnight DLP - Linux Endpoint Agent uninstaller.
#
# By default this removes the service and the code but KEEPS the config
# (agent identity) and the quarantine directory, so a reinstall re-attaches to
# the same agent record on the manager. Pass --purge to remove everything.
#
# Ported from a comparable script in CyberSentinel-DLP (a competitor product)
# after finding SeceoKnight's Linux agent had no scripted uninstall at all --
# the server-side uninstall.sh at the repo root is a different thing (tears
# down the manager stack, not an endpoint).

set -euo pipefail

INSTALL_DIR="/opt/seceoknight/agent"
# Left over from installs that predate the single-executable build (install.sh
# now falls back to a python3 source install under this same directory when
# no binary can be downloaded, but nothing separate needs cleaning up there --
# unlike CyberSentinel, SK's source fallback shares INSTALL_DIR, not a
# standalone venv path, so there is no separate legacy-venv directory here).
CONFIG_DIR="/etc/seceoknight"
LOG_FILE="/var/log/seceoknight_agent.log"
QUARANTINE_DIR="/opt/seceoknight/quarantine"
# Last-known-good policy bundle cache (task #95/#117), written by
# _save_policy_bundle_to_cache() so a restart while the server is
# unreachable still enforces the last confirmed policy. Treated the same
# as CONFIG_DIR: kept by default so a reinstall starts enforcing
# immediately from cache instead of wide-open until the first sync.
CACHE_DIR="/var/lib/seceoknight"
SERVICE_NAME="seceoknight-agent"
PURGE=0

usage() {
  cat <<EOF
Usage: sudo ./uninstall.sh [--purge] [--service-name NAME]

  --purge            Also remove config (agent identity), logs, quarantine
                      and the cached policy bundle.
  --service-name     systemd unit name (default: $SERVICE_NAME)

Without --purge, $CONFIG_DIR, $QUARANTINE_DIR and $CACHE_DIR are left in
place so that reinstalling reuses the same agent identity on the manager
and resumes enforcing the last known policy immediately.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --purge)        PURGE=1; shift ;;
    --service-name) SERVICE_NAME="${2:-}"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *)              usage >&2; echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "ERROR: must run as root (sudo)." >&2; exit 1; }

echo "Stopping and disabling $SERVICE_NAME..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
echo "  service removed"

rm -rf "$INSTALL_DIR"
echo "  executable / installed agent files removed"

if [ "$PURGE" -eq 1 ]; then
  # Quarantine can hold the only remaining copy of a file the agent pulled out
  # of a user's directory. Say so rather than deleting it silently.
  if [ -d "$QUARANTINE_DIR" ] && [ -n "$(ls -A "$QUARANTINE_DIR" 2>/dev/null)" ]; then
    echo
    echo "  WARNING: $QUARANTINE_DIR is not empty. Quarantined files may be the"
    echo "           only copy of the data they contain. Deleting in 10s —"
    echo "           press Ctrl-C to abort and back them up first."
    sleep 10
  fi
  rm -rf "$CONFIG_DIR" "$QUARANTINE_DIR" "$CACHE_DIR"
  rm -f "$LOG_FILE"
  echo "  config, log, quarantine and policy cache removed (--purge)"
  echo
  echo "Fully removed. The agent record remains on the manager — delete it there too."
else
  echo "  config kept:        $CONFIG_DIR"
  echo "  log kept:           $LOG_FILE"
  echo "  quarantine kept:    $QUARANTINE_DIR"
  echo "  policy cache kept:  $CACHE_DIR"
  echo
  echo "Uninstalled. Re-running install.sh will reuse the existing agent identity."
fi
