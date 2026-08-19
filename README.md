# SeceoKnight DLP

SeceoKnight DLP is an enterprise Data Loss Prevention platform. It monitors your endpoints (Windows and Linux computers), detects sensitive data (credit card numbers, SSNs, passwords, confidential documents), and blocks or alerts when that data is about to leave your organization.

**What it does:**
- Monitors file access, USB transfers, clipboard, screen capture, and print jobs on Windows
- Monitors file system activity on Linux
- Classifies sensitive content automatically using 20+ detection rules, including inside binary documents (PDF/DOCX/XLSX/PPTX) — not just plain text
- Enforces policies: block, quarantine, encrypt, or alert
- Blocks sensitive **cloud uploads** (Drive, Gmail, Dropbox, OneDrive, Box, …) and enforces Web Activity Control (GenAI, webmail, file-sharing sites) straight from the browser — installed automatically on every Windows endpoint, no separate setup (see Step 5)
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

This also sets up the browser extension (Cloud Upload Guard + Web Activity Control) on this PC automatically — no separate step needed. See Step 5 if you want to verify it or it's not showing up.

**To stop the agent:**
```powershell
Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

**To start it again:**
```powershell
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

### Managing an already-installed agent

`install-agent.ps1` above is only for a **first-time install** on a machine that's never had the agent — don't re-run it on a machine that already has one. For everything after that (updating the binary, uninstalling, checking the browser extension's force-install status, or disabling Incognito/InPrivate), use the management console instead:

```powershell
irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/manage-agent.ps1 | iex
```

It opens an interactive menu:

- **[1] Install** — same as above, only relevant if this machine somehow doesn't have the agent yet
- **[2] Update** — downloads and verifies the latest published binary, replaces it, and restarts the agent
- **[3] Uninstall** — stops the agent and removes it completely
- **[4] Browser** — shows whether the browser extension is actually force-installed, flags a leftover "Load unpacked" copy shadowing the managed one, and lets you disable Incognito/InPrivate browsing

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

## Step 5 — Browser Extension (Cloud Upload Guard + Web Activity Control)

**This is now fully automatic — there is nothing to do here on a normal
install.** Step 1 (server) publishes the extension, and Step 2 (each Windows
PC) sets up everything the extension needs, including the piece it talks to
behind the scenes. Skip straight to Step 6 unless you want to verify it
(5.2) or something isn't showing up (5.3).

Blocks uploads of Confidential/Restricted files to cloud apps (Gmail, Google
Drive, Outlook, Dropbox, OneDrive, Box, …) and applies the dashboard's Web
Activity Control policy (see the **Policies** page) to GenAI/webmail/file-
sharing sites, straight from Chrome/Edge on a managed Windows endpoint — the
moment someone tries to attach a sensitive file, or use a watched site, the
browser itself pauses it, checks it, and either lets it through or blocks it
with a red on-screen warning.

### 5.1 — What happens automatically

- **Server (Step 1):** `install.sh` packages and publishes the extension
  (a signed, stable-id build) — nothing you need to run separately.
- **Each Windows PC (Step 2):** `install-agent.ps1` downloads two things
  alongside the main agent binary — a pre-built `skdlp_host.exe` (the
  native-messaging host the extension talks to; no Python needed on the
  endpoint), and it doesn't need a separate registration step, because:
- Within about 2 minutes of the agent starting, its **"SeceoKnight DLP
  Browser Extension Guard"** scheduled task (runs as SYSTEM, every 2
  minutes) reconciles everything: the Chrome/Edge `ExtensionInstallForcelist`
  policy, the native-messaging host's manifest + registry registration, and
  its config file — reusing this same PC's agent identity automatically,
  the same way the main agent authenticates. Nothing to copy/paste by hand,
  no extension ID to track down.
- Close and reopen Chrome/Edge once (or just wait for its normal policy
  refresh) and the extension appears force-installed, connected, and
  enforcing whatever policy is set on the dashboard.

### 5.2 — Verify it's working

```powershell
irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/manage-agent.ps1 | iex
```
Choose **[4] Browser** from the menu. It reports, per browser:
- whether the extension force-install policy is set
- whether the native-messaging host binary, manifest, and registry
  registration are all present
- whether an old manually-loaded ("Load unpacked") copy is shadowing the
  managed one — remove it via `chrome://extensions` if flagged

Then, in the browser: `chrome://extensions` → the extension → click
**"service worker"** → look for `native host reachable (pong)` in the
Console. That confirms the whole chain (browser → extension → native host →
your DLP server) end to end.

### 5.3 — If it's not showing up

- **Nothing published on the server at all** — `install.sh`'s extension
  packaging step is best-effort (needs `git` + Python's `cryptography`
  package on the server) and prints a warning if it was skipped. Run it by
  hand:
  ```bash
  git clone https://github.com/Seceo-Knight/Seceoknight-DLP.git && cd Seceoknight-DLP
  python3 scripts/pack-extension.py --out /opt/seceoknight/server/extension_dist --server http://<this-server>
  ```
- **Published on the server, but not on this PC yet** — the agent syncs
  policy periodically; wait a couple of minutes, or restart the "SeceoKnight
  DLP Agent" scheduled task. Confirm with `manage-agent.ps1` → **[4]
  Browser** (5.2 above).
- **`skdlp_host.exe` missing** — an install from before this feature
  existed. Run `manage-agent.ps1` → **[2] Update** once; it downloads it.
- Full step-by-step troubleshooting:
  [`agents/browser-extension/INSTALL_WINDOWS.md`](agents/browser-extension/INSTALL_WINDOWS.md).

### 5.4 — Manual path (only if you have a reason not to use Step 2)

For a PC that should get browser-upload protection **without** the full
endpoint agent, the extension can still be set up entirely by hand —
building `skdlp_host.exe` with PyInstaller, `Load unpacked`, and running
`native-host/install.ps1` yourself. This still works exactly as before; it's
just no longer the recommended path for a PC that also runs the endpoint
agent. Full walkthrough:
[`agents/browser-extension/INSTALL_WINDOWS.md`](agents/browser-extension/INSTALL_WINDOWS.md).

### 5.5 — How policy decisions get made

When someone tries to upload a file or use a watched site, the extension
sends it to your DLP server to be checked and gets back one of a few
answers — **allow** (nothing sensitive found), **alert**/**redact**
(something notable, logged or masked but not blocked), or **block**
(sensitive content found — stopped, with a red banner explaining why).
What counts as "sensitive" and what happens is controlled the same way as
every other DLP feature: the dashboard's **Policies** page (look for
"Event Type" = **Cloud Upload** or **Web Activity**).

### 5.6 — Adding an extra website for the extension to monitor

Gmail, Outlook, Google Drive, Dropbox, OneDrive, Box, Slack, and several
others are watched out of the box, no configuration needed. To watch an
*additional* destination (e.g. a partner's file-sharing site), no
reinstalling or redeploying anything to any PC is required:

1. Log into the dashboard as the **Super Admin** account (a domain-scoped
   admin won't see this section, since it affects every domain fleet-wide).
2. Go to **Settings** → **"Cloud Upload Guard — Extra Destinations."**
3. In the **"Domain to monitor"** box, type the plain domain (no
   `https://`, e.g. `sharefile.com`), optionally with a label.
4. Click **Add**.

Every PC running the browser extension picks up the new domain
automatically within about 15 minutes, or immediately on the next browser
restart. This list only ever *adds* to the built-in ones — it can't be used
to turn off protection for Gmail, Drive, or any other built-in destination.

---

## Updating to a New Version

```bash
cd /opt/seceoknight
curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/docker-compose.prod.yml -o docker-compose.prod.yml
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

`docker compose pull` only refreshes the *images* — it does not pick up changes to the compose file itself (new services, new env vars, changed healthchecks). Re-fetch `docker-compose.prod.yml` first if the release notes mention deployment-tooling changes, or you'll be running new images against an old compose definition.

If the release includes a database schema change (check `CHANGELOG.md`), run the pending Alembic migration after `up -d`:

```bash
docker compose -f docker-compose.prod.yml exec manager alembic upgrade head
```

Fresh installs don't need this step — `install.sh` builds the schema directly on first boot. It only applies when updating an existing deployment across a release that changed the schema.

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
