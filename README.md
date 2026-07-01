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
- Docker Engine 24+ with Docker Compose v2
- Git
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

### Install Docker (if not already installed)

```bash
curl -fsSL https://get.docker.com | sudo bash
sudo systemctl enable docker
sudo systemctl start docker
```

Verify:
```bash
docker --version
docker compose version
```

### Clone the Repository

```bash
git clone https://github.com/Seceo-Knight/Seceoknight-DLP.git /opt/seceoknight/app-src
cd /opt/seceoknight/app-src
```

### Configure Environment

```bash
cp .env.example /opt/seceoknight/.env
```

Edit the file and set all required values:
```bash
nano /opt/seceoknight/.env
```

At minimum, replace every placeholder value — the required fields are:

```
SECRET_KEY=          # random string, min 32 characters
JWT_SECRET=          # random string, min 32 characters
POSTGRES_PASSWORD=   # strong password
MONGODB_PASSWORD=    # strong password
REDIS_PASSWORD=      # strong password
OPENSEARCH_PASSWORD= # strong password (must contain uppercase, number, special char)
CORS_ORIGINS=["http://YOUR_SERVER_IP","https://YOUR_SERVER_IP"]
```

Generate secure random values with:
```bash
openssl rand -base64 48 | tr -d '/+='
```

### Generate TLS Certificates

```bash
mkdir -p /opt/seceoknight/certs
chmod 700 /opt/seceoknight/certs

# Replace YOUR_SERVER_IP with your actual server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

openssl req -x509 -nodes -newkey rsa:4096 -days 825 \
  -keyout /opt/seceoknight/certs/privkey.pem \
  -out /opt/seceoknight/certs/fullchain.pem \
  -subj "/CN=seceoknight.local/O=SeceoKnight DLP" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${SERVER_IP}"

chmod 600 /opt/seceoknight/certs/privkey.pem
chmod 644 /opt/seceoknight/certs/fullchain.pem
```

### Copy the Compose File

```bash
cp /opt/seceoknight/app-src/docker-compose.prod.yml /opt/seceoknight/docker-compose.prod.yml
mkdir -p /opt/seceoknight/nginx
cp /opt/seceoknight/app-src/nginx/nginx.conf /opt/seceoknight/nginx/nginx.conf
```

### Build and Start

```bash
cd /opt/seceoknight

# Build images from source
docker compose -f docker-compose.prod.yml build

# Start all services
docker compose -f docker-compose.prod.yml up -d
```

### Verify Everything is Running

```bash
docker compose -f /opt/seceoknight/docker-compose.prod.yml ps
```

All containers should show **healthy** or **running**. This takes about 2–3 minutes on first start.

```bash
# Test the API is up
curl -k https://localhost/api/v1/health
```

**At the end you will see:**

```
Dashboard (HTTPS) : https://YOUR_SERVER_IP
API Docs          : https://YOUR_SERVER_IP/api/v1/docs

First-login credentials:
  Username : admin
  Password : Admin@1234
```

Open the Dashboard URL in your browser. Your browser will show a **security warning** — this is normal for a self-signed certificate. Click **"Advanced"** then **"Proceed"** to continue.

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
2. **Agent Name** — Press Enter to use your computer name, or type a custom name
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

When new code is pushed to the repo, update the server with:

```bash
# 1. Pull latest code
cd /opt/seceoknight/app-src
git pull origin main

# 2. Copy changed files into running containers
docker cp server/app/services/export_service.py seceoknight-manager:/app/app/services/export_service.py
docker cp server/app/services/analytics_service.py seceoknight-manager:/app/app/services/analytics_service.py
docker cp server/app/services/analytics_service.py seceoknight-celery-worker:/app/app/services/analytics_service.py
docker cp server/app/tasks/reporting_tasks.py seceoknight-celery-worker:/app/app/tasks/reporting_tasks.py
docker cp server/app/api/v1/reports.py seceoknight-manager:/app/app/api/v1/reports.py
docker cp dashboard/dist/. seceoknight-dashboard:/usr/share/nginx/html/

# 3. Restart to pick up changes
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml restart manager celery-worker
```

For a **full rebuild** (e.g. after dependency or Dockerfile changes):

```bash
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```

---

## Getting a Trusted SSL Certificate (Optional)

The self-signed certificate installed by default causes browser warnings. To get a free trusted certificate from Let's Encrypt you need a **domain name** pointed at your server.

```bash
sudo bash /opt/seceoknight/app-src/scripts/generate-certs.sh \
  --domain dlp.yourcompany.com \
  --email admin@yourcompany.com
```

Then update `/opt/seceoknight/.env`:
```
CORS_ORIGINS=["https://dlp.yourcompany.com"]
ALLOWED_HOSTS=dlp.yourcompany.com
```

Restart:
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

**Container shows "unhealthy"**
```bash
# Check logs for the unhealthy container (e.g. manager)
docker compose -f /opt/seceoknight/docker-compose.prod.yml logs manager
```

**Disk full — containers fail to start**
```bash
# Free up unused Docker resources
docker system prune -f
```

**Agent not appearing in dashboard**
```bash
# Test from the agent machine
curl -k https://YOUR_SERVER_IP/api/v1/health
# Must return {"status":"healthy"}
# If it fails, check port 443 is open in the server firewall
```

**View live server logs**
```bash
docker compose -f /opt/seceoknight/docker-compose.prod.yml logs -f manager
docker compose -f /opt/seceoknight/docker-compose.prod.yml logs -f celery-worker
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

**Run from the wrong directory (common error)**

Always run `docker compose` from `/opt/seceoknight` where the `.env` file lives. Running from `/opt/seceoknight/app-src` will fail with "no configuration file provided" because the `.env` is not there.

```bash
# Correct
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml restart manager

# Wrong — will error
cd /opt/seceoknight/app-src
docker compose restart manager
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
