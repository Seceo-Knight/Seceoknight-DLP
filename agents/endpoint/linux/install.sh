#!/bin/bash
# SeceoKnight DLP - Linux Agent Installer
#
# Default: downloads the pre-built, self-contained binary (frozen via
# PyInstaller by .github/workflows/build-linux-agent.yml and committed
# alongside this script) -- no python3/pip/pyudev compile toolchain
# needed on the target machine at all, matching how the Windows agent
# ships as a single .exe with no separate runtime dependency.
#
# Falls back to installing from the local .py source in this directory
# (requires python3/pip on the target) if the binary can't be fetched --
# e.g. no network access to GitHub -- or if --from-source is passed
# explicitly.

set -e

RAW_BASE="https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/agents/endpoint/linux"
BINARY_NAME="seceoknight_linux_agent"
FROM_SOURCE=false
SERVER_URL=""

# Simple positional-ish parsing: --server-url takes the next argument, every
# other recognized flag is a standalone switch.
while [ $# -gt 0 ]; do
    case "$1" in
        --from-source) FROM_SOURCE=true; shift ;;
        --server-url) SERVER_URL="${2:-}"; shift 2 ;;
        *) shift ;;
    esac
done

echo "============================================"
echo "SeceoKnight DLP - Linux Agent Installer"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo)"
    exit 1
fi

# Create installation directory (seceoknight-agent.service's
# WorkingDirectory/ExecStart point at /opt/seceoknight/agent/, not
# /opt/seceoknight/ directly -- see the comment on the layout mismatch
# fixed here previously)
echo "[1/5] Creating installation directory..."
mkdir -p /opt/seceoknight/agent
mkdir -p /etc/seceoknight
mkdir -p /var/log

# System dependency for print-job monitoring (lpstat/cancel are external
# CUPS binaries, not something PyInstaller can freeze into the agent
# binary). USB monitoring needs libudev, which is present on essentially
# every Linux install already (it's how the kernel/systemd itself does
# hotplug) and is bundled into the frozen binary at build time via
# --collect-all pyudev, so it needs no separate install step here.
echo "[2/5] Installing system dependencies (cups-client for print monitoring, xclip/wl-clipboard for clipboard monitoring)..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y --no-install-recommends cups-client xclip wl-clipboard sudo -qq || \
        echo "  Warning: could not install one or more of cups-client/xclip/wl-clipboard -- the corresponding monitor will log a no-op instead of failing agent startup"
else
    echo "  Skipping (no apt-get found) -- install your distro's CUPS client and xclip/wl-clipboard packages manually for print/clipboard monitoring"
fi

install_binary() {
    echo "[3/5] Downloading pre-built agent binary..."
    local tmp_bin tmp_sum expected_sum actual_sum
    tmp_bin="$(mktemp)"
    tmp_sum="$(mktemp)"

    if ! curl -fsSL "$RAW_BASE/$BINARY_NAME" -o "$tmp_bin"; then
        echo "  Failed to download binary from $RAW_BASE/$BINARY_NAME"
        rm -f "$tmp_bin" "$tmp_sum"
        return 1
    fi
    if ! curl -fsSL "$RAW_BASE/$BINARY_NAME.sha256" -o "$tmp_sum"; then
        echo "  Failed to download checksum"
        rm -f "$tmp_bin" "$tmp_sum"
        return 1
    fi

    expected_sum="$(awk '{print $1}' "$tmp_sum")"
    actual_sum="$(sha256sum "$tmp_bin" | awk '{print $1}')"
    if [ "$expected_sum" != "$actual_sum" ]; then
        echo "  Checksum mismatch (expected $expected_sum, got $actual_sum) -- refusing to install a binary that doesn't match its published checksum"
        rm -f "$tmp_bin" "$tmp_sum"
        return 1
    fi

    mv "$tmp_bin" "/opt/seceoknight/agent/$BINARY_NAME"
    chmod +x "/opt/seceoknight/agent/$BINARY_NAME"
    rm -f "$tmp_sum"
    echo "  Binary installed and checksum verified"
    return 0
}

install_from_source() {
    echo "[3/5] Installing from local Python source (requires python3/pip on this machine)..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y python3 python3-pip -qq || true
    fi
    pip3 install -r requirements.txt -q
    cp agent.py policy_cache.py print_monitor.py usb_monitor.py clipboard_monitor.py /opt/seceoknight/agent/
    chmod +x /opt/seceoknight/agent/agent.py
    INSTALLED_FROM_SOURCE=true
}

INSTALLED_FROM_SOURCE=false
if [ "$FROM_SOURCE" = true ]; then
    install_from_source
elif install_binary; then
    :
else
    echo "  Binary install failed -- falling back to source install"
    install_from_source
fi

cp agent_config.json /etc/seceoknight/

# --server-url lets a scripted/fleet install (see rollout.sh) point the agent
# at the real manager instead of leaving the "YOUR_SERVER_IP" placeholder in
# place, which would otherwise need a manual edit on every single machine.
# Uses sed rather than a Python/JSON edit so this works on the prebuilt-binary
# install path too, which is deliberately designed to need no Python on the
# target at all. Only the one known line (with its known quoting) is touched.
# Does NOT touch agent_id -- that field is intentionally absent from the
# shipped template so agent.py generates a fresh, unique one per machine on
# first run (a shared hardcoded agent_id here previously caused every
# fleet-installed endpoint to collide as the same agent record on the server).
if [ -n "$SERVER_URL" ]; then
    sed -i "s|\"server_url\": *\"[^\"]*\"|\"server_url\": \"${SERVER_URL}\"|" /etc/seceoknight/agent_config.json
    echo "  server_url set to $SERVER_URL"
fi

# Install systemd service. Generated here (rather than copying the static
# seceoknight-agent.service file) because ExecStart differs depending on
# which install path above actually succeeded: the frozen binary runs
# directly, the source fallback needs "python3 agent.py".
echo "[4/5] Installing systemd service..."
if [ "$INSTALLED_FROM_SOURCE" = true ]; then
    EXEC_START="/usr/bin/python3 /opt/seceoknight/agent/agent.py"
else
    EXEC_START="/opt/seceoknight/agent/$BINARY_NAME"
fi

cat > /etc/systemd/system/seceoknight-agent.service << EOF
[Unit]
Description=SeceoKnight DLP Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/seceoknight/agent
ExecStart=$EXEC_START
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=seceoknight-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Enable and start service
echo "[5/5] Starting agent..."
systemctl enable seceoknight-agent
systemctl start seceoknight-agent

echo ""
echo "============================================"
echo "✓ Installation complete!"
echo "============================================"
echo ""
echo "Agent Status:"
systemctl status seceoknight-agent --no-pager -l
echo ""
echo "Useful Commands:"
echo "  View logs:    journalctl -u seceoknight-agent -f"
echo "  Stop agent:   sudo systemctl stop seceoknight-agent"
echo "  Start agent:  sudo systemctl start seceoknight-agent"
echo "  Agent status: sudo systemctl status seceoknight-agent"
echo ""
echo "Configuration: /etc/seceoknight/agent_config.json"
echo "Logs: /var/log/seceoknight_agent.log"
echo ""
