# SeceoKnight DLP

SeceoKnight DLP is an enterprise Data Loss Prevention platform. It monitors your endpoints (Windows and Linux computers), detects sensitive data (credit card numbers, SSNs, passwords, confidential documents), and blocks or alerts when that data is about to leave your organization.

**What it does:**
- Monitors file access, USB transfers, clipboard, screen capture, and print jobs on Windows
- Monitors file system activity on Linux
- Classifies sensitive content automatically using 20+ detection rules
- Enforces policies: block, quarantine, encrypt, or alert
- Provides a web dashboard to view events, manage policies, and monitor agents
- Generates 7 report types: Executive Summary, Policy Violations, Incident Trends, Top Violators, Policy Effectiveness, Compliance Overview, and Incident Detail Report

---

## Requirements

### Server (Ubuntu Linux)
- Ubuntu 20.04, 22.04, or 24.04 LTS
- 8 GB RAM minimum (16 GB recommended)
- 50 GB free disk space
- Ports 80 and 443 open in your firewall

### Windows Agent
- Windows 10 or Windows 11 (64-bit)
- PowerShell (already installed on all Windows machines)
- Must be run as Administrator

### Linux Agent
- Python 3.8 or newer
- `pip` package manager

---

## Step 1 — Deploy the Server

Run this single command on your Ubuntu server. It installs Docker automatically if needed, generates all passwords, detects your server IP, and starts everything:

```bash
curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install.sh | sudo bash
```

**What happens automatically:**
- Docker Engine is installed if not already present
- All database passwords and secret keys are randomly generated — you do not need to set them
- Your server IP is detected automatically for the CORS and allowed hosts configuration
- A self-signed SSL certificate is created so the dashboard uses HTTPS
- All services start (database, search engine, dashboard, API)

**At the end you will see:**

```
================================================================
  Installation Complete
================================================================

Endpoints:
  Dashboard (HTTPS) : https://192.168.1.50
  API Docs          : https://192.168.1.50/api/v1/docs

First-login credentials:
  Username : admin
  Password : Admin@1234
```

Open the Dashboard URL in your browser. Your browser will show a **security warning** about the certificate — this is normal for a self-signed certificate. Click **"Advanced"** then **"Proceed"** to continue.

> **Important:** Change the admin password immediately after first login.
> Go to: **Settings → Profile → Change Password**

---

## Step 2 — Install the Windows Agent

Run this on each Windows computer you want to monitor. Open **PowerShell as Administrator** and run:

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install-agent.ps1 | iex"
```

The script will ask you three questions:

1. **Server IP or hostname** — Enter the IP address of your Ubuntu server (e.g. `192.168.1.50`)
2. **Agent Name** — Press Enter to use your computer name (recommended), or type a custom name
3. **Confirm** — Type `Y` and press Enter

The agent installs as a background scheduled task and starts monitoring immediately. You will see it appear in the dashboard under **Agents**.

**To stop the agent:**
```powershell
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

**To start it again:**
```powershell
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

---

## Step 3 — Install the Linux Agent

Run these commands on each Linux machine you want to monitor:

```bash
git clone https://github.com/Seceo-Knight/Seceoknight-DLP.git
cd Seceoknight-DLP/agents/endpoint/linux

pip3 install -r requirements.txt

export SECEOKNIGHT_SERVER_URL=https://YOUR_SERVER_IP/api/v1
python3 agent.py
```

**To run as a permanent background service (recommended):**

```bash
sudo mkdir -p /opt/seceoknight/agent
sudo cp -r agents/endpoint/linux/* /opt/seceoknight/agent/

# Edit the service file — set your server IP
sudo nano systemd/seceoknight-agent.service
# Find: Environment="SECEOKNIGHT_SERVER_URL=https://YOUR_SERVER_IP/api/v1"
# Replace YOUR_SERVER_IP with your actual IP, then save

sudo cp systemd/seceoknight-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable seceoknight-agent
sudo systemctl start seceoknight-agent

# Verify it is running
sudo systemctl status seceoknight-agent
```

---

## Updating to a New Version

```bash
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

This pulls the latest pre-built images from GHCR and restarts all services with zero downtime.

---

## Getting a Trusted SSL Certificate (Optional)

The self-signed certificate installed by default causes browser warnings. To get a free trusted certificate from Let's Encrypt you need a **domain name** pointed at your server.

```bash
sudo bash /opt/seceoknight/scripts/generate-certs.sh \
  --domain dlp.yourcompany.com \
  --email admin@yourcompany.com
```

Then edit `/opt/seceoknight/.env`:
```
CORS_ORIGINS=["https://dlp.yourcompany.com"]
ALLOWED_HOSTS=dlp.yourcompany.com
```

Restart nginx:
```bash
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml restart nginx
```

---

## Troubleshooting

**Site does not load / "Connection refused"**
```bash
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml ps
# All containers should show "healthy" or "running"
```

**Login fails**
- Default credentials: `admin` / `Admin@1234`

**Container shows "unhealthy" — check its logs**
```bash
docker compose -f /opt/seceoknight/docker-compose.prod.yml logs manager
docker compose -f /opt/seceoknight/docker-compose.prod.yml logs celery-worker
```

**Disk full — containers fail to start**
```bash
docker system prune -f
```

**Agent not appearing in dashboard**
```bash
# Test from the agent machine — must return {"status":"healthy"}
curl -k https://YOUR_SERVER_IP/api/v1/health
# If it fails, check port 443 is open in the server firewall
```

**Always run docker compose from the install directory**

The `.env` file lives in `/opt/seceoknight`. Running `docker compose` from any other directory will fail with "no configuration file provided".

```bash
# Correct
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml restart manager

# Wrong — will error
cd /opt/seceoknight/app-src
docker compose restart manager
```

**Restart everything**
```bash
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml restart
```

**Stop everything**
```bash
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml down
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Classification System](CLASSIFICATION_SYSTEM.md) | How sensitive data is detected |
| [Classification Policies Guide](CLASSIFICATION_POLICIES_GUIDE.md) | How to configure detection policies |
| [OneDrive Setup](ONEDRIVE_SETUP_GUIDE.md) | Connecting OneDrive cloud monitoring |
| [Security Policy](SECURITY.md) | Reporting vulnerabilities |
| [Changelog](CHANGELOG.md) | Version history |

---

## Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/Seceo-Knight">
        <img src="https://github.com/Seceo-Knight.png" width="80px;" alt=""/>
        <br />
        <sub><b>Seceo-Knight</b></sub>
      </a>
    </td>
  </tr>
</table>

## License

MIT
