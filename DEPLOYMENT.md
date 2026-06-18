# SeceoKnight DLP — Deployment Guide

This is the canonical install guide for the SeceoKnight DLP platform.
It covers:

1. [Server installation](#1-server-installation) — one-liner on a fresh
   Ubuntu/Debian box. Pulls pre-built images from GHCR. **No source code
   ever lands on the production host.**
2. [Building the Windows agent](#2-building-the-windows-agent) — compile
   the C++ binary on a build box and publish it (with a SHA-256 sidecar)
   to the repo so endpoints can fetch a verified copy.
3. [Installing the Windows agent on endpoints](#3-installing-the-windows-agent-on-endpoints)
   — one-liner on each endpoint. Verifies the SHA-256 of the downloaded
   binary against the sidecar before running it.
4. [Day-2 ops](#4-day-2-ops) — updates, backups, troubleshooting.

> **Repo:** `Seceo-Knight/Seceoknight-DLP`
> **GHCR images:**
> - `ghcr.io/seceo-knight/seceoknight-dlp/dlp-manager:latest`
> - `ghcr.io/seceo-knight/seceoknight-dlp/dlp-dashboard:latest`
>
> Both packages must be public for the one-liner installer to work
> without authentication.

---

## 1. Server installation

### Prerequisites

- Ubuntu 20.04+ / Debian 11+ / any systemd Linux with `sudo`.
- Outbound HTTPS to `ghcr.io`, `raw.githubusercontent.com`, and
  `registry-1.docker.io` (Docker Hub for the postgres / mongo / redis /
  opensearch base images).
- 4 vCPU / 8 GB RAM minimum, 16 GB recommended.
- 50 GB free disk for OpenSearch + MongoDB volumes.

### One-liner install

```bash
curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install.sh | sudo bash
```

What this does, in order:

1. Installs Docker (via `get.docker.com`) if it's not already there and
   enables/starts the daemon.
2. Creates `/opt/seceoknight/`. Override with
   `INSTALL_DIR=/srv/seceoknight` env var if you want a different path.
3. Downloads `docker-compose.prod.yml` and `.env.example` from the
   repo via `raw.githubusercontent.com`. **No source tree, no `.git`,
   no Python files, no Dockerfiles are ever copied to the host.**
4. Generates `/opt/seceoknight/.env` (mode `600`, root-owned) with
   cryptographically random values for:
   - `SECRET_KEY` (48-char URL-safe random)
   - `JWT_SECRET` (48-char)
   - `ENCRYPTION_KEY` (48-char)
   - `POSTGRES_PASSWORD` / `MONGODB_PASSWORD` / `REDIS_PASSWORD` /
     `OPENSEARCH_PASSWORD` (24-char each)
   - `CORS_ORIGINS` and `ALLOWED_HOSTS` set to the host's first IP +
     `localhost` (no wildcard).
5. Generates a self-signed RSA-4096 TLS certificate in
   `/opt/seceoknight/certs/` with proper Subject Alternative Names.
   This satisfies the dashboard nginx bind mount; replace with a real
   cert later if you front the deployment with a TLS-terminating proxy.
6. `docker compose pull` — fetches all images from GHCR and Docker Hub.
7. `docker compose up -d` — starts all services.
8. Polls `http://localhost:55000/health` for up to 3 minutes.
9. Prints connection details and the bootstrap admin password from
   the manager log.

### What's installed

```
/opt/seceoknight/
├── docker-compose.prod.yml          # ~12 KB, fetched from repo
├── .env                              # mode 600, root-owned
├── .env.example                      # placeholders, harmless
├── certs/
│   ├── fullchain.pem                 # self-signed RSA-4096 + SAN
│   └── privkey.pem                   # mode 600, root-owned
└── data/                             # reserved for future host bind mounts
```

Containers running after install:

| Container | Image | Host port | Purpose |
|---|---|---|---|
| `seceoknight-postgres` | `postgres:16-alpine` | _none_ | Users, RBAC, audit logs |
| `seceoknight-mongodb` | `mongo:7.0` | _none_ | DLP events, alerts, incidents |
| `seceoknight-redis` | `redis:7-alpine` | _none_ | Token blacklist, rate limit, cache |
| `seceoknight-opensearch` | `opensearchproject/opensearch:2.11.0` | _none_ | Event search index |
| `seceoknight-manager` | `ghcr.io/seceo-knight/seceoknight-dlp/dlp-manager:latest` | **55000** | FastAPI API |
| `seceoknight-dashboard` | `ghcr.io/seceo-knight/seceoknight-dlp/dlp-dashboard:latest` | **80** → 3000 | React SPA + nginx |
| `seceoknight-celery-worker` | (same manager image) | _none_ | Async event processing |
| `seceoknight-celery-beat` | (same manager image) | _none_ | Scheduled tasks |

> **Database tier is internal-only** since the security audit. Postgres,
> Mongo, Redis, and OpenSearch are no longer published to `0.0.0.0`. For
> ops use `docker compose exec` (e.g.
> `docker compose -f /opt/seceoknight/docker-compose.prod.yml exec postgres psql -U seceoknight`).

### First-time login

After the install script finishes, it prints the bootstrap admin
password. If you missed it:

```bash
docker logs seceoknight-manager 2>&1 | grep generated_password
```

Open the dashboard at `http://<server-ip>/`, log in as `admin` with
that password, and **change it on the first login** (Settings → Profile
→ Change Password). The audit hardened `/api/v1/auth/change-password`
to require a valid JWT, so the dashboard's change-password flow is the
only way to rotate it.

> **Self-registration is disabled.** All new accounts must be created
> by an admin via the Users page (Admin → Users → New User), since the
> data layer doesn't have per-tenant scoping yet.

---

## 2. Building the Windows agent

The agent is a single C++ executable (`seceoknight_agent.exe`) compiled
on Windows with MSYS2 MinGW. It's checked into the repo as a binary,
along with a SHA-256 sidecar so endpoint installs can verify integrity.

### Prerequisites

- Windows 10/11 build box.
- [MSYS2](https://www.msys2.org/) installed.
- Inside the MSYS2 MinGW 64-bit terminal:
  ```bash
  pacman -S --needed mingw-w64-x86_64-gcc git
  ```

### Compile

```bash
# In MSYS2 MinGW 64-bit terminal
cd /c/seceoknight-dlp
git pull origin main
cd agents/endpoint/windows
./build.sh
```

`build.sh` runs:

```bash
g++ -std=c++17 -O2 \
    agent.cpp screen_capture_monitor.cpp print_monitor.cpp \
    -o seceoknight_agent.exe \
    -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 -lgdi32 \
    -lws2_32 -lsetupapi -ladvapi32 -lcfgmgr32 -lshell32 -lwinspool -static
```

You should see `seceoknight_agent.exe` (~4 MB) appear in the same
directory.

### Generate the SHA-256 sidecar

The endpoint installer verifies the binary against this sidecar before
running it.

```bash
# Same MSYS2 terminal
sha256sum seceoknight_agent.exe > seceoknight_agent.exe.sha256
cat seceoknight_agent.exe.sha256
```

You should see a line like:
```
3a9f4e1c5b7d... *seceoknight_agent.exe
```

> Pure-PowerShell alternative if you don't want MSYS2:
> ```powershell
> cd C:\seceoknight-dlp\agents\endpoint\windows
> (Get-FileHash -Algorithm SHA256 seceoknight_agent.exe).Hash.ToLower() `
>   | Out-File -Encoding ASCII seceoknight_agent.exe.sha256
> ```

### Commit + push

```bash
git add seceoknight_agent.exe seceoknight_agent.exe.sha256
git status   # confirm both are staged

git commit -m "build: agent $(date +%Y-%m-%d) (commit $(git rev-parse --short HEAD))"
git push origin main
```

Use a more descriptive message if you prefer, e.g.
`build: agent with screen-capture sticky-block fixes`.

### Verify the upload landed

```bash
curl -fsI https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/agents/endpoint/windows/seceoknight_agent.exe | head -1
curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/agents/endpoint/windows/seceoknight_agent.exe.sha256
```

Both should return successfully. The SHA-256 should match what you
generated locally.

> **Re-builds:** every time you change `agent.cpp` or one of the
> `*_monitor.cpp` files, repeat compile + sha256sum + commit + push.
> The sidecar **must** be regenerated with each new binary or the
> endpoint installer will refuse to run it.

---

## 3. Installing the Windows agent on endpoints

### One-liner install

Run this **as Administrator** on each Windows endpoint:

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install-agent.ps1 | iex"
```

What it does:

1. **Step 1 — Configuration.** Prompts for the server hostname/IP
   (`localhost`, an IPv4 literal, or an RFC1123 FQDN like
   `dlp.corp.local`), agent name, heartbeat interval, and policy sync
   interval. Tests `http://<server>:55000/health` before continuing.
2. **Step 2 — Cleanup.** Stops the existing scheduled task / process /
   service if present. Safe to re-run on an already-installed endpoint.
3. **Step 3 — Directories.** Creates `C:\Program Files\SeceoKnight`
   and `C:\ProgramData\SeceoKnight\{logs,quarantine,cache}`.
4. **Step 4 — OCR deps.** Installs Chocolatey + Tesseract if missing
   (used by the screen-capture classifier's Stage 4 OCR fallback).
5. **Step 5 — Agent binary download with SHA-256 verification.**
   - Pulls `seceoknight_agent.exe` from `raw.githubusercontent.com`.
   - Pulls the sidecar `.sha256` from the same location.
   - Computes the local SHA-256 with `Get-FileHash`.
   - **If the hashes don't match, deletes the binary and exits with
     code 2.** No tampered installs.
   - Optional `Get-AuthenticodeSignature` check (warn-only until an EV
     signing cert is provisioned).
6. **Step 6 — Environment.** Sets `SECEOKNIGHT_SERVER_URL` for the
   machine.
7. **Step 7 — Config file.** Writes
   `C:\Program Files\SeceoKnight\agent_config.json` with the
   monitored paths, file extensions, and intervals from step 1.
8. **Step 8 — Hidden launcher.** Drops `launch_agent.vbs` so the agent
   runs without a CMD window.
9. **Step 9 — Scheduled task.** Registers `SeceoKnight DLP Agent`
   with both `AtLogon` and `AtStartup` triggers, `RunLevel Highest`,
   `RestartCount 999` so it auto-recovers on crash.
10. **Step 10 — Start.** Runs the task and prints the PID.

### What gets installed

```
C:\Program Files\SeceoKnight\
├── seceoknight_agent.exe          # the binary, hash-verified
├── agent_config.json                # server URL, intervals, monitored paths
├── launch_agent.vbs                 # hidden-window launcher
└── seceoknight_agent.log          # written at runtime

C:\ProgramData\SeceoKnight\
├── logs\
├── quarantine\
└── cache\
```

Plus the scheduled task `SeceoKnight DLP Agent` (visible in
`taskschd.msc`).

### Verify

```powershell
# Process running?
Get-Process seceoknight_agent | Select-Object Id, StartTime, Path

# Tail the agent log
Get-Content "C:\Program Files\SeceoKnight\seceoknight_agent.log" -Tail 50

# Confirm the dashboard sees the agent
# (open http://<server>:80/ in a browser → Agents page)
```

### Re-install / update an existing endpoint

The same one-liner works — it cleans the previous install in step 2.
Operators don't have to uninstall first.

For just updating the binary without rerunning the full installer:

```powershell
Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue
Start-Sleep 2
Invoke-WebRequest -UseBasicParsing `
    -Uri "https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/agents/endpoint/windows/seceoknight_agent.exe" `
    -OutFile "C:\Program Files\SeceoKnight\seceoknight_agent.exe"

# Verify hash
$expected = (Invoke-WebRequest -UseBasicParsing `
    -Uri "https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/agents/endpoint/windows/seceoknight_agent.exe.sha256").Content.Trim().Split()[0].ToUpper()
$actual = (Get-FileHash -Algorithm SHA256 "C:\Program Files\SeceoKnight\seceoknight_agent.exe").Hash.ToUpper()
if ($expected -ne $actual) {
    Write-Host "HASH MISMATCH — refusing to start" -ForegroundColor Red
    exit 2
}

Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

### Uninstall

```powershell
Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "SeceoKnight DLP Agent" -Confirm:$false
Remove-Item "C:\Program Files\SeceoKnight" -Recurse -Force
Remove-Item "C:\ProgramData\SeceoKnight" -Recurse -Force
```

---

## 4. Day-2 ops

### Server — pull a new image and roll forward

The CI workflow at `.github/workflows/build-images.yml` rebuilds and
re-publishes both GHCR images on every push to `main`. To pull the new
versions onto the running server:

```bash
cd /opt/seceoknight
sudo docker compose -f docker-compose.prod.yml pull
sudo docker compose -f docker-compose.prod.yml up -d
sudo docker compose -f docker-compose.prod.yml ps
```

`up -d` will recreate only the containers whose images changed. Volumes
(postgres data, mongo data, opensearch index, etc.) are preserved.

### Server — full restart

```bash
cd /opt/seceoknight
sudo docker compose -f docker-compose.prod.yml down
sudo docker compose -f docker-compose.prod.yml up -d
```

### Server — backup the data tier

```bash
# Postgres (users, RBAC, audit log)
sudo docker compose -f /opt/seceoknight/docker-compose.prod.yml exec -T postgres \
    pg_dump -U seceoknight seceoknight | gzip > postgres-$(date +%F).sql.gz

# MongoDB (events, alerts, incidents)
sudo docker compose -f /opt/seceoknight/docker-compose.prod.yml exec -T mongodb \
    mongodump --uri "mongodb://admin:$(grep ^MONGODB_PASSWORD /opt/seceoknight/.env | cut -d= -f2)@localhost:27017/?authSource=admin" \
    --archive --gzip > mongo-$(date +%F).archive.gz
```

Don't forget to back up `/opt/seceoknight/.env` (offline, encrypted)
— it's the one thing you can't recover.

### Server — view logs

```bash
cd /opt/seceoknight

# All services
sudo docker compose -f docker-compose.prod.yml logs --tail=100 -f

# Just one service
sudo docker compose -f docker-compose.prod.yml logs --tail=100 -f manager
sudo docker compose -f docker-compose.prod.yml logs --tail=100 -f dashboard
sudo docker compose -f docker-compose.prod.yml logs --tail=100 -f celery-worker
```

### Endpoint — view agent logs

```powershell
Get-Content "C:\Program Files\SeceoKnight\seceoknight_agent.log" -Tail 100 -Wait
```

### Endpoint — stop / start the agent

```powershell
# Stop
Stop-Process -Name "seceoknight_agent" -Force -ErrorAction SilentlyContinue

# Start
Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"

# Disable auto-start (without uninstalling)
Disable-ScheduledTask -TaskName "SeceoKnight DLP Agent"

# Re-enable
Enable-ScheduledTask -TaskName "SeceoKnight DLP Agent"
```

### Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `denied: denied` on `docker pull ghcr.io/Seceo-Knight/...` | Stale `~/.docker/config.json` from previous account | `docker logout ghcr.io && rm /root/.docker/config.json` |
| `denied` even after logout | GHCR packages are still private | `https://github.com/Seceo-Knight?tab=packages` → Package settings → Change visibility → Public |
| `TLS handshake timeout` on Docker Hub | Transient or proxy/firewall | Re-run `docker compose pull`. Persistent → set up a registry mirror. |
| Manager unhealthy on first boot | OpenSearch still initialising | Wait 90s, check `docker logs seceoknight-opensearch`. |
| Manager 500s on `/auth/login` | `SECRET_KEY` not set / changed | Check `.env`. Restart manager. |
| Endpoint installer: `CRITICAL: SHA-256 mismatch` | Repo binary doesn't match its sidecar | Rebuild + regenerate sidecar (Section 2). |
| Endpoint can't reach manager | Firewall on port 55000 | `Test-NetConnection -ComputerName <server> -Port 55000` |
| Dashboard shows 0 agents | Agent not sending heartbeat | Tail `seceoknight_agent.log` for HTTP errors. |

### Verification commands (all the security fixes from the audit)

```bash
SERVER=http://<your-server>

# Self-registration is admin-only now
curl -i -X POST $SERVER/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"x@y.z","password":"Aa1!xxxxxxxx","full_name":"x","organization":"x"}'
# → 401 Unauthorized

# /agents/{id}/policy/evaluate now requires X-Agent-Key
curl -i -X POST $SERVER/api/v1/agents/abc/policy/evaluate \
  -H "Content-Type: application/json" -d '{}'
# → 401

# SIEM SSRF guard rejects metadata IPs
curl -i -X POST $SERVER/api/v1/siem/connectors \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"x","siem_type":"elk","host":"169.254.169.254","port":80}'
# → 400 "resolves to 169.254.169.254 which is in the blocked network..."

# Audit logs are admin-only
curl -i $SERVER/api/v1/audit-logs/ -H "Authorization: Bearer VIEWER_TOKEN"
# → 403 Forbidden

# Database tier is internal-only
nmap -p 5432,27017,6379,9200 $SERVER
# all should report closed/filtered (or `host down` if firewalled)
```

### Where to find more

- **Security audit findings + fix log**: `SECURITY.md`
- **Server compose**: `docker-compose.prod.yml`
- **Agent source**: `agents/endpoint/windows/`
- **CI workflow**: `.github/workflows/build-images.yml`
- **Persistent automation memory** for Claude Code: `~/.claude/projects/-home-soc-Data-Loss-Prevention/memory/`
