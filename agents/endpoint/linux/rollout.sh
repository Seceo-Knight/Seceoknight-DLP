#!/usr/bin/env bash
#
# SeceoKnight DLP - fleet rollout helper.
#
# Pushes this directory to a list of endpoints over SSH and runs install.sh on
# each. Intended for small/medium fleets where you already have SSH key access;
# for larger estates drive install.sh from Ansible/Salt instead.
#
#   ./rollout.sh --server-url https://10.0.0.5/api/v1 \
#                --hosts alice@10.0.0.11,bob@10.0.0.12
#
#   ./rollout.sh --server-url https://10.0.0.5/api/v1 --hosts-file fleet.txt
#
# By default install.sh downloads the pre-built, checksummed agent binary
# straight from GitHub on each target (no build toolchain needed there at
# all) -- so unlike a from-source deploy, this script does not need to ship a
# binary payload itself. Pass --from-source only if a target has no network
# path to GitHub and must build from the local .py source instead.
#
# Ported from a comparable script in CyberSentinel-DLP (a competitor
# product), adapted for SeceoKnight's install.sh, which self-downloads its
# binary rather than needing one shipped to it -- so the payload list here is
# shorter than the source it was ported from.
#
# Requires passwordless sudo on the targets, or run as root there.

set -euo pipefail

SERVER_URL=""
HOSTS=""
HOSTS_FILE=""
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=15"
PARALLEL=4
EXTRA_ARGS=""
FROM_SOURCE=0

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: ./rollout.sh --server-url URL (--hosts LIST | --hosts-file PATH) [options]

  --server-url URL     Manager API base URL (e.g. https://dlp.corp.local/api/v1),
                        passed through to install.sh --server-url
  --hosts LIST         Comma-separated [user@]host entries
  --hosts-file PATH    File with one [user@]host per line (# comments allowed)
  --parallel N         Concurrent installs (default: $PARALLEL)
  --ssh-opts "..."     Extra ssh options
  --extra "..."        Extra flags forwarded to install.sh
  --from-source         Ship and build from local .py source instead of
                        letting each target download the prebuilt binary
                        (only needed if a target can't reach GitHub)
  -h, --help           Show this help

Each host registers as its own agent: install.sh never copies an agent_id --
agent.py generates a fresh one per machine on first run.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="${2:-}"; shift 2 ;;
    --hosts)      HOSTS="${2:-}";      shift 2 ;;
    --hosts-file) HOSTS_FILE="${2:-}"; shift 2 ;;
    --parallel)   PARALLEL="${2:-}";   shift 2 ;;
    --ssh-opts)   SSH_OPTS="${2:-}";   shift 2 ;;
    --extra)      EXTRA_ARGS="${2:-}"; shift 2 ;;
    --from-source) FROM_SOURCE=1;      shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            usage >&2; echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

[ -n "$SERVER_URL" ] || { usage >&2; echo "ERROR: --server-url is required." >&2; exit 1; }

# install.sh always needs agent_config.json (it does a plain `cp` from the
# same directory it's run from) and uninstall.sh is worth having on every
# target for later teardown. --from-source additionally needs the actual
# source + requirements.txt, since the target won't download a binary.
PAYLOAD=("$SRC_DIR/install.sh" "$SRC_DIR/uninstall.sh" "$SRC_DIR/agent_config.json")
REMOTE_INSTALL_ARGS=""
if [ "$FROM_SOURCE" -eq 1 ]; then
  PAYLOAD+=("$SRC_DIR/agent.py" "$SRC_DIR/policy_cache.py" "$SRC_DIR/print_monitor.py"
            "$SRC_DIR/usb_monitor.py" "$SRC_DIR/clipboard_monitor.py" "$SRC_DIR/requirements.txt")
  REMOTE_INSTALL_ARGS="--from-source"
fi

for f in "${PAYLOAD[@]}"; do
  [ -f "$f" ] || { echo "ERROR: missing file needed for rollout: $f" >&2; exit 1; }
done

TARGETS=()
if [ -n "$HOSTS" ]; then
  IFS=',' read -r -a TARGETS <<< "$HOSTS"
fi
if [ -n "$HOSTS_FILE" ]; then
  [ -f "$HOSTS_FILE" ] || { echo "ERROR: no such file: $HOSTS_FILE" >&2; exit 1; }
  while read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | tr -d '[:space:]')"
    [ -n "$line" ] && TARGETS+=("$line")
  done < "$HOSTS_FILE"
fi

[ "${#TARGETS[@]}" -gt 0 ] || { echo "ERROR: no targets given." >&2; exit 1; }

RESULT_DIR="$(mktemp -d)"
trap 'rm -rf "$RESULT_DIR"' EXIT

deploy_one() {
  local target="$1"
  local safe="${target//[^A-Za-z0-9]/_}"
  local log="$RESULT_DIR/$safe.log"

  {
    echo "=== $target ==="
    # shellcheck disable=SC2086
    ssh $SSH_OPTS "$target" "rm -rf ~/.seceoknight-deploy && mkdir -p ~/.seceoknight-deploy" || return 1
    # shellcheck disable=SC2086
    scp $SSH_OPTS -q "${PAYLOAD[@]}" "$target:~/.seceoknight-deploy/" || return 1
    # shellcheck disable=SC2086
    ssh $SSH_OPTS "$target" \
      "cd ~/.seceoknight-deploy && chmod +x install.sh uninstall.sh && sudo ./install.sh --server-url '$SERVER_URL' $REMOTE_INSTALL_ARGS $EXTRA_ARGS" || return 1
  } >"$log" 2>&1

  return $?
}

echo "Rolling out to ${#TARGETS[@]} host(s), ${PARALLEL} at a time..."
echo

pids=()
for target in "${TARGETS[@]}"; do
  deploy_one "$target" &
  pids+=("$!:$target")

  # Simple concurrency gate: drain the oldest job once the window is full.
  if [ "${#pids[@]}" -ge "$PARALLEL" ]; then
    entry="${pids[0]}"; pids=("${pids[@]:1}")
    wait "${entry%%:*}" || true
  fi
done
for entry in "${pids[@]}"; do wait "${entry%%:*}" || true; done

OK=0; FAILED=0; FAILED_HOSTS=()
for target in "${TARGETS[@]}"; do
  safe="${target//[^A-Za-z0-9]/_}"
  if grep -q "Installation complete" "$RESULT_DIR/$safe.log" 2>/dev/null; then
    printf '  \033[32m✓\033[0m %s\n' "$target"
    OK=$((OK + 1))
  else
    printf '  \033[31m✗\033[0m %s\n' "$target"
    FAILED=$((FAILED + 1)); FAILED_HOSTS+=("$target")
  fi
done

echo
echo "Succeeded: $OK    Failed: $FAILED"

# A rollout that quietly half-worked is worse than one that failed loudly:
# print the actual errors for every host that did not finish.
if [ "$FAILED" -gt 0 ]; then
  for target in "${FAILED_HOSTS[@]}"; do
    safe="${target//[^A-Za-z0-9]/_}"
    echo
    echo "--- $target (last 20 lines) ---"
    tail -20 "$RESULT_DIR/$safe.log" 2>/dev/null || echo "  no output captured"
  done
  exit 1
fi
