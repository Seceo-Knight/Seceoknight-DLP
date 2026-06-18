#!/usr/bin/env bash
set -euo pipefail

# SeceoKnight DLP - Linux agent installer
# Flow: clone -> venv -> deps -> config -> systemd service (boot autostart)

MANAGER_URL="${MANAGER_URL:-http://localhost:55000/api/v1}"
INSTALL_DIR="${INSTALL_DIR:-/opt/seceoknight/agent}"
CONFIG_DIR="${CONFIG_DIR:-/etc/seceoknight}"
VENV_DIR="${VENV_DIR:-}"
REPO_URL="${REPO_URL:-https://github.com/seceoknight-06/Data-Loss-Prevention.git}"
BRANCH="${BRANCH:-main}"
REF="${REF:-}"
SERVICE_NAME="${SERVICE_NAME:-seceoknight-agent}"
LOG_PATH="${LOG_PATH:-}"
NO_START=0
FORCE=0

usage() {
  cat <<'EOF'
Usage: install_linux_agent.sh [options]
  --manager-url URL         Manager API base (default: http://localhost:55000/api/v1)
  --install-dir PATH        Agent install dir (default: /opt/seceoknight/agent)
  --config-dir PATH         Config dir (default: /etc/seceoknight)
  --venv-dir PATH           Virtualenv dir (default: <install-dir>/.venv)
  --repo-url URL            Git repo URL (default: https://github.com/YOUR_ORG/Data-Loss-Prevention.git)
  --branch NAME             Git branch (default: main)
  --ref REF                 Optional commit/tag
  --service-name NAME       Systemd service name (default: seceoknight-agent)
  --log-path PATH           Optional log path (default: <install-dir>/seceoknight_agent.log)
  --no-start                Register service but do not start
  --force                   Re-clone and overwrite config/venv
  -h, --help                Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager-url) MANAGER_URL="$2"; shift 2;;
    --install-dir) INSTALL_DIR="$2"; shift 2;;
    --config-dir) CONFIG_DIR="$2"; shift 2;;
    --venv-dir) VENV_DIR="$2"; shift 2;;
    --repo-url) REPO_URL="$2"; shift 2;;
    --branch) BRANCH="$2"; shift 2;;
    --ref) REF="$2"; shift 2;;
    --service-name) SERVICE_NAME="$2"; shift 2;;
    --log-path) LOG_PATH="$2"; shift 2;;
    --no-start) NO_START=1; shift;;
    --force) FORCE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

if [[ -z "$VENV_DIR" ]]; then
  VENV_DIR="${INSTALL_DIR}/.venv"
fi
if [[ -z "$LOG_PATH" ]]; then
  LOG_PATH="${INSTALL_DIR}/seceoknight_agent.log"
fi

# Prefer env-provided manager URL when caller did not override
if [[ "$MANAGER_URL" == "http://localhost:55000/api/v1" && -n "${SECEOKNIGHT_SERVER_URL:-}" ]]; then
  MANAGER_URL="$SECEOKNIGHT_SERVER_URL"
fi

log() { echo "[INFO] $*"; }
ok() { echo "[ OK ] $*"; }
warn() { echo "[WARN] $*"; }
err() { echo "[ERROR] $*" >&2; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Run as root (sudo)."
    exit 1
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
}

require_root
require_cmd git
require_cmd python3
require_cmd systemctl

log "ManagerUrl:   $MANAGER_URL"
log "InstallDir:   $INSTALL_DIR"
log "ConfigDir:    $CONFIG_DIR"
log "VenvDir:      $VENV_DIR"
log "RepoUrl:      $REPO_URL"
log "Branch/Ref:   $BRANCH $REF"
log "ServiceName:  $SERVICE_NAME"
log "LogPath:      $LOG_PATH"
echo

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

log "Cloning repository..."
git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$tmpdir" >/dev/null
if [[ -n "$REF" ]]; then
  (cd "$tmpdir" && git checkout "$REF" >/dev/null)
fi

agent_src="$tmpdir/agents/endpoint/linux"
if [[ ! -d "$agent_src" ]]; then
  err "Agent source not found at $agent_src"
  exit 1
fi

if [[ $FORCE -eq 1 && -d "$INSTALL_DIR" ]]; then
  warn "Force requested: clearing install dir $INSTALL_DIR"
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
fi

log "Copying agent files..."
rsync -a --delete "$agent_src/" "$INSTALL_DIR/"
ok "Agent files copied to $INSTALL_DIR"

# Python version check
pyver="$(python3 - <<'PY'
import sys
print(".".join(map(str, sys.version_info[:3])))
PY
)"
major="${pyver%%.*}"
minor="$(echo "$pyver" | cut -d. -f2)"
if (( major < 3 || (major == 3 && minor < 10) )); then
  err "Python 3.10+ required (found $pyver)"
  exit 1
fi
ok "Python $pyver detected"

# Virtualenv
if [[ $FORCE -eq 1 && -d "$VENV_DIR" ]]; then
  warn "Force requested: removing venv $VENV_DIR"
  rm -rf "$VENV_DIR"
fi
if [[ ! -d "$VENV_DIR" ]]; then
  log "Creating virtual environment..."
  python3 -m venv "$VENV_DIR"
fi
VENV_PY="$VENV_DIR/bin/python"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install -r "$INSTALL_DIR/requirements.txt"
ok "Dependencies installed"

# Config
config_path="${CONFIG_DIR}/agent_config.json"
default_config="${INSTALL_DIR}/agent_config.json"
if [[ -s "$config_path" && $FORCE -eq 0 ]]; then
  log "Using existing config at $config_path"
  cfg="$(cat "$config_path")"
elif [[ -s "$default_config" ]]; then
  log "Loaded template config from $default_config"
  cfg="$(cat "$default_config")"
else
  warn "Template config not found; using defaults"
  cfg='{
  "server_url": "",
  "agent_name": "",
  "monitoring": {
    "file_system": true,
    "clipboard": true,
    "usb_devices": true,
    "monitored_paths": [
      "/home",
      "/tmp"
    ],
    "file_extensions": [".pdf",".docx",".xlsx",".txt",".csv",".json",".xml"],
    "transfer_blocking": {
      "enabled": false,
      "block_removable_drives": true,
      "poll_interval_seconds": 5
    }
  },
  "quarantine": {
    "enabled": true,
    "folder": "/quarantine"
  },
  "heartbeat_interval": 30,
  "policy_sync_interval": 60
}'
fi

cfg="$(printf '%s' "$cfg" | CS_MANAGER_URL="$MANAGER_URL" python3 -c 'import json,sys,os; data=json.load(sys.stdin); data["server_url"]=os.environ["CS_MANAGER_URL"]; data.setdefault("agent_name", os.uname().nodename); data.setdefault("quarantine", {"enabled": True, "folder": "/quarantine"}); mon=data.setdefault("monitoring", {}); mon.setdefault("monitored_paths", ["/home", "/tmp"]); print(json.dumps(data, indent=2))')"
printf '%s\n' "$cfg" > "$config_path"
ok "Config written to $config_path"

# Systemd unit
unit_path="/etc/systemd/system/${SERVICE_NAME}.service"
cat > "$unit_path" <<EOF
[Unit]
Description=SeceoKnight DLP Agent
After=network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=SECEOKNIGHT_SERVER_URL=$MANAGER_URL
ExecStart=$VENV_PY $INSTALL_DIR/agent.py
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
if [[ $NO_START -eq 0 ]]; then
  systemctl restart "$SERVICE_NAME"
fi
ok "Systemd service '$SERVICE_NAME' installed (enable=yes, start=$((NO_START==0)))"

if [[ $NO_START -eq 0 ]]; then
  systemctl status --no-pager "$SERVICE_NAME" || true
  log "Tail log (if present): tail -n 50 $LOG_PATH"
fi

log "Done. Config: $config_path"





