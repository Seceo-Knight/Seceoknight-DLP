# Cloud Upload Guard — Windows install (complete steps)

This sets up the browser extension + native-messaging host on a Windows
endpoint so that Confidential/Restricted files are blocked from uploading to
cloud apps, Internal files raise an alert, and Public files are allowed.

There are two pieces:
1. **The browser extension** (loaded into Chrome/Edge) — intercepts uploads.
2. **The native-messaging host** (`skdlp_host`) — asks the DLP server for the
   allow/alert/block decision and records the events.

---

## 0. Prerequisites
- Windows 10/11 with **Chrome** or **Microsoft Edge**.
- **Python 3.8+** on the machine, with the `requests` package
  (`pip install requests`) — *or* build the host as an `.exe` (Step 3, Option A).
- Network access from this PC to the DLP server (`https://<server>/api/v1`).
- An identity for the native host to authenticate with. Two ways to get one
  (see Step 5):
  - **Recommended:** the main SeceoKnight endpoint agent already installed
    and registered on this PC — `install.ps1` (Step 4) auto-discovers its
    `agent_id`/`api_key` from `C:\ProgramData\SeceoKnight\agent_key.json`,
    no extra registration needed.
  - Or a standalone registration (`curl -X POST .../api/v1/agents/`) if this
    PC won't have the main endpoint agent installed.

---

## 1. Get the extension onto the PC
The extension lives in this repo at `agents/browser-extension/` on whichever
machine hosts the SeceoKnight DLP checkout (server or admin workstation).
Package that folder as a zip for distribution, or copy it directly.

Copy it over (any one):
- **SCP/WinSCP** the zip from the server and unzip to `C:\SeceoKnight\browser-extension\`, **or**
- On the PC, if it has the repo: `git pull`, then use `agents\browser-extension\`.

You should end up with a folder that contains `manifest.json` — e.g.:
```
C:\SeceoKnight\browser-extension\
  manifest.json
  src\  (inject.js, content.js, background.js)
  native-host\  (skdlp_host.py, com.seceoknightdlp.dlp.json, install.ps1)
  README.md
```

---

## 2. Load the extension and copy its ID
1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode** (top-right).
3. Click **Load unpacked** and select the folder that contains `manifest.json`
   (`C:\SeceoKnight\browser-extension\`).
4. The extension appears as **“SeceoKnight DLP — Cloud Upload Guard.”**
   **Copy its ID** (a 32-character string under the name). You need it in Step 4.

> Managed fleet: instead of “Load unpacked”, publish/pack it and push via the
> `ExtensionInstallForcelist` group policy. The ID is fixed once published.

---

## 3. Make the host runnable
Pick ONE.

**Option A — build a standalone .exe (recommended, most reliable):**
```powershell
pip install pyinstaller requests
cd C:\SeceoKnight\browser-extension\native-host
pyinstaller --onefile skdlp_host.py
# → produces dist\skdlp_host.exe
mkdir "C:\Program Files\SeceoKnight" -Force
copy dist\skdlp_host.exe "C:\Program Files\SeceoKnight\skdlp_host.exe"
```
Host command = `C:\Program Files\SeceoKnight\skdlp_host.exe`

**Option B — quick .bat launcher (no build; needs Python + requests on PATH):**
Create `C:\Program Files\SeceoKnight\skdlp_host.bat` containing:
```bat
@echo off
python "C:\SeceoKnight\browser-extension\native-host\skdlp_host.py" %*
```
Host command = `C:\Program Files\SeceoKnight\skdlp_host.bat`
(If native messaging misbehaves with the .bat, use Option A.)

---

## 4. Register the host (manifest + registry + server config)
From the `native-host` folder, in an **elevated PowerShell** (Run as admin):

**If the main endpoint agent is already installed on this PC** (recommended
— see Step 5), you don't need `-AgentId`/`-AgentKey` at all:
```powershell
cd C:\SeceoKnight\browser-extension\native-host
.\install.ps1 `
  -ExtensionId  <PASTE_EXTENSION_ID_FROM_STEP_2> `
  -ServerUrl    https://<your-dlp-server>/api/v1 `
  -HostCommand  "C:\Program Files\SeceoKnight\skdlp_host.exe"   # or the .bat
```
It auto-discovers the identity from `C:\ProgramData\SeceoKnight\
agent_key.json` (written by the endpoint agent after it registers — see
Step 5) and prints `Reusing endpoint agent identity from: ...` to confirm.

**Otherwise** (this PC won't run the main endpoint agent), pass a standalone
identity explicitly:
```powershell
cd C:\SeceoKnight\browser-extension\native-host
.\install.ps1 `
  -ExtensionId  <PASTE_EXTENSION_ID_FROM_STEP_2> `
  -ServerUrl    https://<your-dlp-server>/api/v1 `
  -AgentId      <this PC's agent id> `
  -AgentKey     <this PC's agent API key> `
  -HostCommand  "C:\Program Files\SeceoKnight\skdlp_host.exe"   # or the .bat
```
This writes `C:\ProgramData\SeceoKnight\com.seceoknightdlp.dlp.json`, the
Chrome/Edge registry keys, and `C:\ProgramData\SeceoKnight\dlp-host.json`.

---

## 5. Where the agent id + API key come from
The host authenticates to the server exactly like the endpoint agent (the
`X-Agent-Key` header).

- **Recommended: reuse this PC's endpoint agent identity.** If the main
  SeceoKnight agent (from the repo's root `install-agent.ps1`) is installed
  and has registered at least once on this same PC, it saves its own
  `agent_id`/`api_key` to `C:\ProgramData\SeceoKnight\agent_key.json` —
  `install.ps1` in Step 4 reads this automatically. Nothing to copy by hand.
- **Standalone identity** (no endpoint agent on this PC): register one
  yourself —
  ```bash
  curl -k -X POST https://<your-dlp-server>/api/v1/agents/ \
    -H "Content-Type: application/json" \
    -d '{"name": "browser-ext-<hostname>", "os": "windows", "ip_address": "<this PCs IP>"}'
  ```
  Copy `agent_id`/`api_key` from the response — shown once, at registration.
  If you lose it, re-run the same command to get a fresh key.

---

## 5b. Verify the bridge (self-test) — do this BEFORE testing uploads
On browser start the extension pings the native host, so you can confirm the
whole chain without any upload.
1. `chrome://extensions` → the extension → click **"service worker"** → **Console**.
2. Look for:
   - ✅ `native host reachable (pong)` → the extension ↔ host bridge works. A
     fresh `C:\ProgramData\SeceoKnight\dlp-host.log` will contain
     `host started` and `ping received`.
   - ❌ `COULD NOT CONNECT to native host …` → the host registration is wrong
     (manifest path, registry key, or `allowed_origins` extension-id). Re-run
     `install.ps1` with the current Extension ID, then reload the extension.

## 6. Test
1. **Fully close** Chrome/Edge (all windows) and reopen.
2. Sign in to Google Drive or Gmail.
3. Upload a **plain text** file → **allowed** (a `cloud_upload_allowed` log
   shows in the dashboard Events).
4. Upload a file containing **PII / secrets** (e.g., a few test credit-card
   numbers) → **blocked**: a red banner appears, and `cloud_upload_attempt` +
   `cloud_upload_prevented` events show in the dashboard.

**Host log (for troubleshooting):** `C:\ProgramData\SeceoKnight\dlp-host.log`

---

## Troubleshooting
- **Nothing blocks / no log file** → the extension can't reach the host. Recheck
  the Extension ID in the manifest `allowed_origins`, the registry key, and that
  the `-HostCommand` path exists. Restart the browser.
- **Everything is allowed even sensitive files** → the host reached the server
  but got `allow`. Check `dlp-host.json` (`server_url`, `agent_id`, `agent_key`)
  and that the two `cloud_upload_prevention` policies are **active** in the
  dashboard. The host fails **open** on any error (see the log for the reason).
- **403 in the log** → wrong/expired `agent_key`.
- **Google Drive specifically may not block.** Drive performs uploads inside a
  Web/Service Worker that a page-level extension cannot see. To confirm: open the
  Drive tab's page console (F12) during an upload — if you see **no**
  `[SK-DLP] cloud request →` lines, the upload ran in a worker (unreachable).
  Test the extension on a simpler target (a plain file-upload page, Dropbox/Box
  web) to validate the chain; reliable Drive blocking needs the Phase B WFP
  driver.
- **Uploads via a native desktop client** (Google Drive/Dropbox app) are **not**
  covered by the extension — that's the Phase B WFP driver.

## Scope (this build)
- Windows, Chrome/Edge browser uploads. Blocks sensitive uploads to **all**
  cloud hosts (no sanctioned-domain allowlist). Content classified per file is
  capped at 10 MB. Fail-open everywhere.
