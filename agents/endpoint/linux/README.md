# SeceoKnight DLP - Linux Agent

Enterprise endpoint DLP agent for Linux systems.

## Features

- ✅ **File System Monitoring** - Real-time inotify-based monitoring
- ✅ **Automatic Classification** - Pattern-based sensitive data detection
- ✅ **Print Job Monitoring** - CUPS print jobs classified and blocked/logged, matching the Windows agent
- ✅ **USB Storage Monitoring** - udev-based connect/disconnect detection with allowlist enforcement (unmount), same allowlist as Windows
- ✅ **Clipboard Monitoring** - X11 (xclip) and Wayland (wl-clipboard) content classified and reported, same content rules as Windows
- ✅ **Real-time Reporting** - Sends events to central server
- ✅ **Systemd Integration** - Runs as system service
- ✅ **Low Resource Usage** - Optimized for servers

## Requirements

- Ubuntu 20.04+ / CentOS 8+ / Debian 11+ (frozen binary needs glibc 2.31+, i.e. anything Debian 11/bullseye or newer)
- Root privileges (for installation)
- `libudev` (present on essentially every modern Linux install already) for USB storage monitoring
- `cups-client` (`lpstat`/`cancel`) for print job monitoring
- `xclip` (X11) and/or `wl-clipboard` (Wayland) for clipboard monitoring -- reads the logged-in user's clipboard by re-executing as that user via `sudo -u`, since the agent itself runs as root and root has no session of its own to read a clipboard from
- All three of the above degrade to a logged no-op if their system dependency is missing, rather than blocking agent startup
- Python 3.8+ is **only** needed for `--from-source` installs (see below) -- the default install downloads a self-contained binary with everything already bundled in, no Python toolchain required on the target machine

## Quick Installation

Default install downloads the pre-built binary (see `.github/workflows/build-linux-agent.yml`) -- no python3/pip needed on the target machine:

```bash
# Clone or download agent files
cd agents/endpoint/linux

# Make installer executable
chmod +x install.sh

# Run installer
sudo ./install.sh
```

Prefer installing from the local `.py` source instead (e.g. for local development, or a target with no network access to GitHub)?

```bash
sudo ./install.sh --from-source
```

## Manual Installation

Binary (recommended, no python3/pip needed on the target):

```bash
sudo mkdir -p /opt/seceoknight/agent /etc/seceoknight
curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/agents/endpoint/linux/seceoknight_linux_agent \
  -o /opt/seceoknight/agent/seceoknight_linux_agent
sudo chmod +x /opt/seceoknight/agent/seceoknight_linux_agent
sudo cp agent_config.json /etc/seceoknight/
# Edit ExecStart in seceoknight-agent.service to point at the binary path
# above (see the comment in that file), then:
sudo cp seceoknight-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now seceoknight-agent
```

From source (requires python3/pip on the target machine):

```bash
# Install dependencies
sudo apt-get install python3 python3-pip
pip3 install -r requirements.txt

# Create directories (seceoknight-agent.service expects agent.py under
# /opt/seceoknight/agent/, not directly in /opt/seceoknight/)
sudo mkdir -p /opt/seceoknight/agent
sudo mkdir -p /etc/seceoknight

# Copy files
sudo cp agent.py policy_cache.py print_monitor.py usb_monitor.py /opt/seceoknight/agent/
sudo cp agent_config.json /etc/seceoknight/
sudo cp seceoknight-agent.service /etc/systemd/system/
# seceoknight-agent.service defaults to the python3 agent.py ExecStart already

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
| **Print Job** | Document sent to a CUPS printer -- classified by filename, blocked (job cancelled) if Restricted |
| **USB Connect/Disconnect** | USB storage device attached/removed -- checked against the same allowlist as the Windows agent; non-allowlisted devices are unmounted when enforcement is on |
| **Clipboard Copy** | Clipboard content changed for the active graphical session's user -- classified with the same rules as file content; reported only, not cleared (see clipboard_monitor.py for why) |

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
sudo chmod +x /opt/seceoknight/agent/seceoknight_linux_agent /opt/seceoknight/agent/agent.py 2>/dev/null
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
