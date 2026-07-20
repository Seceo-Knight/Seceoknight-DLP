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

In plain terms: your mail platform (Google or Microsoft) will be told
"before sending any outgoing email, send it to this relay first." The relay
checks it for sensitive data. If it's clean, the relay forwards it on and it
sends normally. If it contains something sensitive (credit card numbers,
SSNs, confidential documents, etc.), the relay bounces it back to the sender
— the email never leaves your organization.

### 4.1 — Is your DLP server reachable from the internet?

This is the single most important thing to figure out **before** doing
anything else, because it decides how much extra setup you need. Google's or
Microsoft's mail servers need to be able to connect *to* your relay over the
public internet — an internal-only server will not work for this step.

- **Server is a cloud VM** (AWS, GCP, Azure, DigitalOcean, a rented VPS, etc.)
  — it very likely already has a public IP. You mostly just need to open one
  port for it (see 4.2).
- **Server is on-prem / in your office**, behind a router or firewall (e.g. a
  FortiGate) — you'll need three things before continuing:
  1. **A static public IP address** from your internet provider (ask them if
     you don't know — if your IP changes periodically, you'll need a Dynamic
     DNS service instead of a fixed domain name).
  2. **Admin access to your firewall/router**, to forward one external port
     through to your DLP server. On a FortiGate this is called a **Virtual
     IP (VIP)**: go to *Policy & Objects → Virtual IPs → Create New*, and map
     `your-public-ip : <a port you choose>` → `your-server's-internal-ip :
     10025`. Then create a **firewall policy** (*Policy & Objects → Firewall
     Policy*) allowing that traffic in from your WAN interface to your
     internal network, SMTP service only.
     - ⚠️ Many internet providers **block incoming port 25** by default (a
       common anti-spam measure) — check with your provider, or test with a
       tool like [mxtoolbox.com/SuperTool.aspx](https://mxtoolbox.com/SuperTool.aspx)
       from *outside* your network. If port 25 is blocked, that's fine —
       just pick a different external port instead (e.g. `2525`). Both
       Google and Microsoft let you specify any port when you set up
       routing in Step 4.3, so this isn't a blocker, just something to know
       up front.
  3. **A domain name pointing at that public IP** (e.g. `relay.yourcompany.com`)
     — you'll need this for the TLS certificate in the next step and for the
     mail platform configuration in Step 4.3. If you don't already have a
     domain, your company's existing website domain works fine — just add a
     new DNS "A record" for a subdomain like `relay.yourcompany.com`
     pointing at your public IP (your domain registrar's dashboard, e.g.
     GoDaddy/Namecheap/Cloudflare, has an option to add DNS records).

### 4.2 — Get a security certificate (TLS) for the relay

Since mail is going to travel over the public internet to reach your relay,
it needs to be encrypted in transit — otherwise anyone between the sender
and your relay could read the (sensitive!) email contents. This step gets a
free certificate and turns encryption on.

1. On the server, install `certbot` (the standard free-certificate tool) if
   it isn't already there:
   ```bash
   sudo apt-get update && sudo apt-get install -y certbot
   ```
2. Get the certificate for your domain name from Step 4.1 (replace
   `relay.yourcompany.com` with your actual domain):
   ```bash
   sudo certbot certonly --standalone -d relay.yourcompany.com
   ```
   This briefly needs port 80 reachable from the internet to prove you own
   the domain. If that's genuinely not possible on your network, ask
   whoever manages your DNS about certbot's DNS-based verification instead
   (`--dns-<provider>` — doesn't need any port open at all).
   You'll end up with two files at
   `/etc/letsencrypt/live/relay.yourcompany.com/fullchain.pem` and `privkey.pem`.
3. Add these lines to `/opt/seceoknight/.env`
   (`sudo nano /opt/seceoknight/.env`, add at the bottom, save with `Ctrl+O`,
   `Enter`, `Ctrl+X`):
   ```
   RELAY_TLS_CERT_DIR=/etc/letsencrypt/live/relay.yourcompany.com
   RELAY_TLS_CERT_FILE=/certs/fullchain.pem
   RELAY_TLS_KEY_FILE=/certs/privkey.pem
   RELAY_REQUIRE_STARTTLS=true
   ```
   > Certificates from Let's Encrypt expire every 90 days. Set up a
   > reminder (or a cron job running `sudo certbot renew`) to renew it —
   > after renewing, restart the relay (Step 4.5) to pick up the new cert.

### 4.3 — Register an agent identity for the relay

The relay is not a Windows/Linux endpoint — you do **not** need to install
the agent from Step 2 or Step 3 anywhere for this. It just needs its own
identity (an `agent_id` + `api_key`) so it can call the DLP API the same way
an endpoint agent does. **You also can't reuse an already-installed agent's
key** — the dashboard's Agents page shows an agent's `agent_id`, but never
its `api_key` (it's only ever returned once, at registration). So register a
fresh one dedicated to the relay.

Run this **on the server itself** (SSH into it first):
```bash
curl -k -X POST https://localhost/api/v1/agents/ \
  -H "Content-Type: application/json" \
  -d '{"name": "smtp-relay", "os": "linux", "ip_address": "127.0.0.1"}'
```
You'll get back JSON that looks like this:
```json
{
  "agent_id": "LINUX-smtp-relay",
  "name": "smtp-relay",
  "api_key": "csak_9f2K7pQ...(long random string)...xYz",
  "os": "linux",
  "...": "..."
}
```
**Copy two values from that response now** — the `api_key` is shown this one
time only; if you lose it, just run the same curl command again to get a
fresh one (re-registering rotates the key):
- `agent_id` → this becomes `RELAY_AGENT_ID`
- `api_key` → this becomes `RELAY_AGENT_KEY`

Add those two values to `/opt/seceoknight/.env` the same way as Step 4.2
above:
```
RELAY_AGENT_ID=LINUX-smtp-relay        # the agent_id you just copied
RELAY_AGENT_KEY=csak_9f2K7pQ...xYz     # the api_key you just copied
RELAY_NEXT_HOP_HOST=smtp-relay.gmail.com   # see step 4.4 for where this comes from
RELAY_NEXT_HOP_PORT=587
```
(Replace the example values above with your own — don't paste the literal
`LINUX-smtp-relay` / `csak_9f2K7pQ...xYz` from this guide.)

### 4.4 — Point your mail platform's outbound routing at the relay

Use the domain name + port you set up in Step 4.1 (e.g.
`relay.yourcompany.com:2525`) here.

- **Google Workspace** — Admin console → *Apps → Google Workspace → Gmail →
  Hosts* → add your relay's domain + port → *Gmail → Routing* → **Outbound
  gateway** → select the host you just added. Full walkthrough:
  [`smtp-relay/README.md` § Google Workspace
  routing](smtp-relay/README.md#google-workspace-routing-the-deployment-step).
- **Microsoft 365 / Exchange Online** — Exchange admin center → *Mail flow →
  Connectors* → add a connector routed through a smart host (your relay's
  domain + port). Full walkthrough: [`smtp-relay/README.md` § Microsoft 365 /
  Exchange Online
  routing](smtp-relay/README.md#microsoft-365--exchange-online-routing-the-deployment-step).

Also add your relay to your domain's **SPF record** (a DNS setting) — since
mail now leaves via the relay, downstream mail servers need to be told the
relay is allowed to send on your behalf, or they may flag your mail as spam.
Your IT/DNS admin or hosting provider can help with this if you're not sure
how.

### 4.5 — Start the relay

```bash
cd /opt/seceoknight
docker compose -f docker-compose.prod.yml pull smtp-relay
docker compose -f docker-compose.prod.yml up -d smtp-relay
docker compose -f docker-compose.prod.yml logs smtp-relay --tail 20
```
In the log output, look for a line like `STARTTLS enabled (cert=...,
required=True)` — that confirms the certificate from Step 4.2 loaded
correctly. If instead you see `STARTTLS not configured`, double-check the
`RELAY_TLS_*` lines in your `.env` file.

### 4.6 — Test it

Send a message containing a fake credit-card/SSN number through your normal
mail client (Gmail web, Outlook, etc.). It should bounce back with a
rejection notice; clean mail (no sensitive content) goes through normally.
See [`smtp-relay/README.md` § Test](smtp-relay/README.md#test) for a
ready-made test script you can run from a terminal instead.

Full reference (env vars, limitations, diagram): [`smtp-relay/README.md`](smtp-relay/README.md).

---

## Step 5 — Install the Browser Extension (Cloud Upload Guard) — Optional

Blocks uploads of Confidential/Restricted files to cloud apps (Gmail, Google
Drive, Outlook, Dropbox, OneDrive, Box, …) straight from Chrome/Edge on a
managed Windows endpoint — the moment someone tries to attach a sensitive
file and send it, the browser itself pauses the upload, checks it, and either
lets it through or blocks it with a red on-screen warning.

This has two parts working together on the same PC:
1. **The browser extension itself** (loaded into Chrome/Edge) — watches for
   file uploads to cloud websites.
2. **The native host** (a small program called `skdlp_host`) — the extension
   talks to it, and it talks to your DLP server to get an allow/block
   decision and record the event in your dashboard.

> **Do this on every Windows PC** where you want cloud-upload protection —
> it's a per-PC setup, same as the endpoint agent in Step 2.

> **This is a separate install from Step 2, even if you've already
> installed the agent on this PC.** The endpoint agent (Step 2) and the
> browser extension are two different programs that happen to work
> together — installing or reinstalling one does **not** set up the other.
> The agent only monitors things like file access, USB drives, and the
> clipboard; it has no idea a browser extension exists, and reinstalling it
> never touches Chrome/Edge or writes any of the files the extension needs.
> So even right after reinstalling the agent, you still need to go through
> Step 5 below to actually connect the browser extension — the only thing
> that changes is that Step 5.4's `install.ps1` can now find and reuse the
> agent's identity automatically, instead of you having to register a
> separate one by hand.

### 5.1 — Identity: do you already have the endpoint agent on this PC?

The native host needs to prove to the server who it is, the same way the
endpoint agent does. **If you already installed the endpoint agent (Step 2)
on this same PC**, you're in luck — as of the latest version, the agent
saves its own identity to a file, and the extension setup below will find
and reuse it automatically. You don't need to do anything extra here, just
make sure the agent has been installed and has run at least once (check that
it shows up in the dashboard's **Agents** page).

**If this PC does NOT have the endpoint agent installed** (e.g. you only
want browser-upload protection on it, not full endpoint monitoring), you'll
need to register a separate identity for the extension instead. Run this
from any machine that can reach the server:
```bash
curl -k -X POST https://YOUR_SERVER_IP/api/v1/agents/ \
  -H "Content-Type: application/json" \
  -d '{"name": "browser-ext-<this PCs hostname>", "os": "windows", "ip_address": "<this PCs IP>"}'
```
Copy the `agent_id` and `api_key` from the response — you'll pass them as
`-AgentId`/`-AgentKey` in Step 5.4 below instead of letting it auto-discover.

### 5.2 — Get the extension onto the PC

Copy `agents/browser-extension/` from this repo to the endpoint (e.g. to
`C:\SeceoKnight\browser-extension\`). Any way of copying it works — a shared
network drive, a zip file over email/USB, or `git clone` if the PC has git.

### 5.3 — Load the extension into Chrome or Edge

1. Open `chrome://extensions` (type that directly into the address bar) —
   or `edge://extensions` if using Edge.
2. Turn on **Developer mode** (a toggle switch, usually top-right).
3. Click **Load unpacked**, and select the `browser-extension` folder you
   copied in Step 5.2 (the one containing `manifest.json`).
4. The extension appears as **"SeceoKnight DLP — Cloud Upload Guard."**
   Under its name is a long ID (letters, e.g. `bjglolaooepjebiklcalmklppkokgjhm`)
   — copy it, you'll need it in the next step.

> For a large fleet, instead of manually loading it on each PC, your IT team
> can publish it and push it automatically via the `ExtensionInstallForcelist`
> Group Policy — ask your IT admin if this applies to your organization.

### 5.4 — Build and register the native host

Open PowerShell **as Administrator** (right-click PowerShell → "Run as
administrator"), then run:
```powershell
cd C:\SeceoKnight\browser-extension\native-host
pip install pyinstaller requests
pyinstaller --onefile skdlp_host.py
mkdir "C:\Program Files\SeceoKnight" -Force
copy dist\skdlp_host.exe "C:\Program Files\SeceoKnight\skdlp_host.exe"

.\install.ps1 `
  -ExtensionId  <EXTENSION_ID_FROM_STEP_5.3> `
  -ServerUrl    https://YOUR_SERVER_IP/api/v1 `
  -HostCommand  "C:\Program Files\SeceoKnight\skdlp_host.exe"
```
That's it — no `-AgentId`/`-AgentKey` needed if the endpoint agent is
already on this PC (Step 5.1); the script finds and reuses its identity
automatically, and you'll see a line like `Reusing endpoint agent identity
from: ...` confirming it worked.

If this PC does **not** have the endpoint agent installed, add the two
values you copied in Step 5.1 instead:
```powershell
.\install.ps1 `
  -ExtensionId  <EXTENSION_ID_FROM_STEP_5.3> `
  -ServerUrl    https://YOUR_SERVER_IP/api/v1 `
  -AgentId      <agent_id from step 5.1> `
  -AgentKey     <api_key from step 5.1> `
  -HostCommand  "C:\Program Files\SeceoKnight\skdlp_host.exe"
```

### 5.5 — Verify it's working

1. **Fully close** Chrome/Edge (every window) and reopen it — this is
   necessary for it to pick up the new native host registration.
2. Go to `chrome://extensions`, find the extension, and click **"service
   worker"** (a small blue link under its name) — this opens a Console
   window.
3. Look for the line `native host reachable (pong)`. If you see that, the
   whole chain (browser → extension → native host → your DLP server) is
   connected and working.
   - If instead you see `COULD NOT CONNECT to native host`, double-check the
     Extension ID you used in Step 5.4 matches exactly what's shown on
     `chrome://extensions`, then re-run `install.ps1` and fully restart the
     browser again.

### 5.6 — Test it

1. Sign in to Gmail, Outlook web, Google Drive, or any other cloud app in
   the browser.
2. Try uploading/attaching a plain text file with no sensitive content —
   it should go through normally. You'll see a `cloud_upload_allowed` entry
   in the dashboard's **Events** page.
3. Try uploading a file containing fake test data (e.g. a text file with a
   line like `Card: 4111 1111 1111 1111  SSN: 456-78-1234`) — you should see
   a **red warning banner** appear on the page, and `cloud_upload_attempt` +
   `cloud_upload_prevented` events in the dashboard.

Full step-by-step (with troubleshooting):
[`agents/browser-extension/INSTALL_WINDOWS.md`](agents/browser-extension/INSTALL_WINDOWS.md).

### 5.7 — How it actually works, and where to manage it

In plain terms: when someone tries to upload a file to a cloud website, the
extension pauses that upload, sends the file to your DLP server to be
checked, and gets back one of three answers — **allow** (nothing sensitive
found, upload continues normally), **alert** (something notable but not
severe — the upload still goes through, but it's logged for a DLP admin to
review), or **block** (sensitive content found — the upload is stopped, and
the person sees a red banner explaining why).

**Two different places control different parts of this:**

- **What counts as "sensitive" and what happens (allow/alert/block)** — this
  is controlled the same way as every other DLP feature: the dashboard's
  **Policies** page. If a genuinely sensitive upload isn't being blocked, or
  a legitimate upload keeps getting blocked, this is where to check/adjust
  the rules — the same policy that governs USB transfers, clipboard, etc.
  also governs cloud uploads (look for policies with an "Event Type" of
  **Cloud Upload**).
- **Which websites get watched at all** — Gmail, Outlook, Google Drive,
  Dropbox, OneDrive, Box, Slack, and several others are built in and always
  watched, out of the box, with no configuration needed. If you need to
  watch an *additional* destination not in that built-in list (e.g. a
  partner's file-sharing site), see the next section.

### 5.8 — Adding an extra website for the extension to monitor

If your organization uses a cloud upload destination that isn't in the
built-in list (Gmail, Outlook, Drive, Dropbox, OneDrive, Box, Slack, and a
few others are covered automatically), you can add it from the dashboard —
no reinstalling or redeploying anything to any PC required.

1. Log into the dashboard as an **admin** account.
2. Go to **Settings**.
3. Scroll to the section titled **"Cloud Upload Guard — Extra
   Destinations."**
4. In the **"Domain to monitor"** box, type the website's domain — just the
   plain domain, no `https://` (e.g. `sharefile.com`), and optionally add a
   short label for your own reference (e.g. "Partner file portal").
5. Click **Add**.

That's it — every PC running the browser extension will pick up this new
domain automatically within about 15 minutes, or immediately the next time
someone restarts their browser. To stop monitoring a domain you added, go
back to the same Settings section and click the trash-can icon next to it.

> This list only ever *adds* extra destinations on top of the built-in ones
> — it cannot be used to turn off protection for Gmail, Drive, or any of the
> other built-in destinations.

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
