# SeceoKnight DLP

SeceoKnight DLP is an enterprise Data Loss Prevention platform. It monitors your endpoints (Windows and Linux computers), detects sensitive data (credit card numbers, SSNs, passwords, confidential documents), and blocks or alerts when that data is about to leave your organization.

**What it does:**
- Monitors file access, USB transfers, clipboard, screen capture, and print jobs on Windows
- Monitors file system activity on Linux
- Classifies sensitive content automatically using 20+ detection rules, including inside binary documents (PDF/DOCX/XLSX/PPTX) — not just plain text
- Enforces policies: block, quarantine, encrypt, or alert
- Blocks sensitive **cloud uploads** (Drive, Gmail, Dropbox, OneDrive, Box, …) straight from the browser via the Cloud Upload Guard extension (see Step 4)
- Blocks sensitive **outbound email** at the mail-flow level via the SMTP relay — works with both Google Workspace and Microsoft 365 (see Step 5)
- Provides a web dashboard to view events, manage policies, and monitor agents, including a full admin **Audit Trail** of who changed what
- Generates 7 report types: Executive Summary, Policy Violations, Incident Trends, Top Violators, Policy Effectiveness, Compliance Overview, and Incident Detail Report
- Ingests and shares threat-intelligence indicators (IOCs) via STIX 2.1 / TAXII 2.1 — poll external feeds, add IOCs manually or via CSV/STIX import, and optionally publish your own DLP-derived indicators to partner vendors
- Supports domain-scoped admin roles (Threat, Data Protection, Access Control) alongside the global Super Admin, so each admin sees and manages only the policies, events, and incidents in their own domain
- Restricts the admin portal to authorized IP ranges via an admin-managed allowlist (fail-open when empty; agent and health endpoints always exempt)
- Enforces a dashboard-managed log-retention policy (event + index retention) with a hard 90-day compliance floor

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

## Step 4 — Enable the SMTP Relay (Email DLP) — Optional

Blocks outbound email carrying sensitive data (attachments + body) before it
leaves your organization, whether your org uses **Gmail (Google Workspace)**
or **Outlook (Microsoft 365 / Exchange Online)** — the relay is a plain SMTP
server that doesn't care which platform routes mail to it.

1. **Register an agent identity for the relay** — run this once from anywhere
   that can reach the server (it authenticates to the DLP server like any
   endpoint agent):
   ```bash
   curl -k -X POST https://YOUR_SERVER_IP/api/v1/agents/ \
     -H "Content-Type: application/json" \
     -d '{"name": "smtp-relay", "os": "linux", "ip_address": "127.0.0.1"}'
   ```
   The response contains `agent_id` and a one-time `api_key` — **copy both now**,
   the key is never shown again (re-register to get a fresh one if you lose it).

2. **Add the relay's config to `/opt/seceoknight/.env`** on the server:
   ```
   RELAY_AGENT_ID=<agent_id from step 1>
   RELAY_AGENT_KEY=<api_key from step 1>
   RELAY_NEXT_HOP_HOST=<see step 3>
   RELAY_NEXT_HOP_PORT=587
   ```

3. **Point your mail platform's outbound routing at the relay**, and get the
   right `RELAY_NEXT_HOP_HOST` for your platform:
   - **Google Workspace** — Admin console → Gmail → Hosts/Routing → outbound
     gateway. Full walkthrough: [`smtp-relay/README.md` § Google Workspace
     routing](smtp-relay/README.md#google-workspace-routing-the-deployment-step).
   - **Microsoft 365 / Exchange Online** — Exchange admin center → Mail flow →
     Connectors → smart host. Full walkthrough: [`smtp-relay/README.md` §
     Microsoft 365 / Exchange Online
     routing](smtp-relay/README.md#microsoft-365--exchange-online-routing-the-deployment-step).

4. **Start the relay:**
   ```bash
   cd /opt/seceoknight
   docker compose -f docker-compose.prod.yml up -d smtp-relay
   ```

5. **Test it** — send a message containing a fake credit-card/SSN number
   through your normal mail client. It should bounce with a `550` rejection;
   clean mail goes through normally. See [`smtp-relay/README.md` §
   Test](smtp-relay/README.md#test) for a ready-made test script.

Full reference (env vars, limitations, diagram): [`smtp-relay/README.md`](smtp-relay/README.md).

---

## Step 5 — Install the Browser Extension (Cloud Upload Guard) — Optional

Blocks uploads of Confidential/Restricted files to cloud apps (Google Drive,
Gmail, Dropbox, OneDrive, Box, …) straight from Chrome/Edge on a managed
Windows endpoint.

1. **Get the extension + native host onto the PC** — copy
   `agents/browser-extension/` from this repo to the endpoint (e.g.
   `C:\SeceoKnight\browser-extension\`).
2. **Load the extension** — `chrome://extensions` (or `edge://extensions`) →
   Developer mode → Load unpacked → select that folder. Copy the **extension
   ID** it's assigned (for a managed fleet, push it instead via the
   `ExtensionInstallForcelist` group policy).
3. **Build/register the native host** — from an elevated PowerShell:
   ```powershell
   cd C:\SeceoKnight\browser-extension\native-host
   pip install pyinstaller requests
   pyinstaller --onefile skdlp_host.py
   mkdir "C:\Program Files\SeceoKnight" -Force
   copy dist\skdlp_host.exe "C:\Program Files\SeceoKnight\skdlp_host.exe"

   .\install.ps1 `
     -ExtensionId  <EXTENSION_ID_FROM_STEP_2> `
     -ServerUrl    https://YOUR_SERVER_IP/api/v1 `
     -AgentId      <this PC's agent id> `
     -AgentKey     <this PC's agent API key> `
     -HostCommand  "C:\Program Files\SeceoKnight\skdlp_host.exe"
   ```
   (Reuse this PC's existing endpoint-agent id/key from the Agents page — or
   register a dedicated one the same way as Step 4.1.)
4. **Restart the browser fully** and verify the bridge before testing uploads:
   `chrome://extensions` → the extension → **service worker** → Console →
   look for `native host reachable (pong)`.
5. **Test** — upload a plain text file (allowed) and a file with fake PII/credit-card
   numbers (blocked, red banner + `cloud_upload_prevented` event in the dashboard).

Full step-by-step (with troubleshooting):
[`agents/browser-extension/INSTALL_WINDOWS.md`](agents/browser-extension/INSTALL_WINDOWS.md).

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
| [SMTP Relay (Email DLP)](smtp-relay/README.md) | Full setup for Google Workspace **and** Microsoft 365, config vars, limitations |
| [Browser Extension — Windows Install](agents/browser-extension/INSTALL_WINDOWS.md) | Complete step-by-step Cloud Upload Guard install + troubleshooting |
| [Browser Extension — Overview](agents/browser-extension/README.md) | How it works, components, test steps |
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
