# SeceoKnight DLP - Linux Agent

Enterprise endpoint DLP agent for Linux systems.

## Features

- ✅ **File System Monitoring** - Real-time inotify-based monitoring
- ✅ **Automatic Classification** - Pattern-based sensitive data detection
- ✅ **Real-time Reporting** - Sends events to central server
- ✅ **Systemd Integration** - Runs as system service
- ✅ **Low Resource Usage** - Optimized for servers

## Requirements

- Ubuntu 20.04+ / CentOS 8+ / Debian 11+
- Python 3.8+
- Root privileges (for installation)

## Quick Installation

```bash
# Clone or download agent files
cd agents/endpoint/linux

# Make installer executable
chmod +x install.sh

# Run installer
sudo ./install.sh
```

## Manual Installation

```bash
# Install dependencies
sudo apt-get install python3 python3-pip
pip3 install -r requirements.txt

# Create directories
sudo mkdir -p /opt/seceoknight
sudo mkdir -p /etc/seceoknight

# Copy files
sudo cp agent.py /opt/seceoknight/
sudo cp agent_config.json /etc/seceoknight/
sudo cp seceoknight-agent.service /etc/systemd/system/

# Start service
sudo systemctl daemon-reload
sudo systemctl enable seceoknight-agent
sudo systemctl start seceoknight-agent
```

## Configuration

Edit `/etc/seceoknight/agent_config.json`:

```json
{
  "server_url": "http://YOUR-SERVER-IP:8000/api/v1",
  "agent_name": "YOUR-AGENT-NAME",
  "monitoring": {
    "monitored_paths": [
      "/home",
      "/var/www"
    ]
  }
}
```

After editing, restart the agent:
```bash
sudo systemctl restart seceoknight-agent
```

## Usage

### Start Agent
```bash
sudo systemctl start seceoknight-agent
```

### Stop Agent
```bash
sudo systemctl stop seceoknight-agent
```

### Check Status
```bash
sudo systemctl status seceoknight-agent
```

### View Logs
```bash
# Real-time logs
sudo journalctl -u seceoknight-agent -f

# Last 100 lines
sudo journalctl -u seceoknight-agent -n 100

# Log file
sudo tail -f /var/log/seceoknight_agent.log
```

## Monitored Events

| Event Type | Description |
|------------|-------------|
| **File Created** | New file created in monitored directories |
| **File Modified** | File content changed |
| **File Moved** | File moved or renamed |

## Sensitive Data Detection

The agent detects:
- Credit Card Numbers (PAN)
- Social Security Numbers (SSN)
- Email Addresses
- API Keys and Secrets
- Private Keys (RSA, DSA, EC)
- Passwords in configuration files

## Troubleshooting

### Check if agent is running
```bash
sudo systemctl status seceoknight-agent
ps aux | grep agent.py
```

### Agent won't start
```bash
# Check logs
sudo journalctl -u seceoknight-agent -n 50

# Check configuration
sudo cat /etc/seceoknight/agent_config.json

# Test connectivity
curl http://YOUR-SERVER-IP:8000/health
```

### Permission errors
```bash
# Ensure proper permissions
sudo chown -R root:root /opt/seceoknight
sudo chmod +x /opt/seceoknight/agent.py
```

### High CPU usage
- Reduce monitored paths
- Exclude cache directories
- Increase file size limit in config

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop seceoknight-agent
sudo systemctl disable seceoknight-agent

# Remove files
sudo rm /etc/systemd/system/seceoknight-agent.service
sudo rm -rf /opt/seceoknight
sudo rm -rf /etc/seceoknight

# Reload systemd
sudo systemctl daemon-reload
```

## Performance

- **CPU Usage**: <1% idle, 2-5% during activity
- **Memory**: ~50-100MB RAM
- **Disk I/O**: Minimal (event-driven)
- **Network**: <1KB/s average

## Security

- Agent runs as root (required for file monitoring)
- All events sent over HTTPS (if configured)
- Configuration file protected (600 permissions)
- No sensitive data stored locally

## Support

For issues or questions:
- Check logs: `/var/log/seceoknight_agent.log`
- System logs: `sudo journalctl -u seceoknight-agent`
- Review server logs

## Version

**Version**: 1.0.0
**Platform**: Linux (Ubuntu, Debian, CentOS, RHEL)
**Last Updated**: January 2025
