#!/bin/bash
# SeceoKnight DLP - Linux Agent Installer

set -e

echo "============================================"
echo "SeceoKnight DLP - Linux Agent Installer"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo)"
    exit 1
fi

# Install Python dependencies
echo "[1/5] Installing Python dependencies..."
apt-get update -qq
apt-get install -y python3 python3-pip -qq
pip3 install -r requirements.txt -q

# Create installation directory
echo "[2/5] Creating installation directory..."
mkdir -p /opt/seceoknight
mkdir -p /etc/seceoknight
mkdir -p /var/log

# Copy files
echo "[3/5] Installing agent..."
cp agent.py /opt/seceoknight/
cp agent_config.json /etc/seceoknight/
chmod +x /opt/seceoknight/agent.py

# Install systemd service
echo "[4/5] Installing systemd service..."
cp seceoknight-agent.service /etc/systemd/system/
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
