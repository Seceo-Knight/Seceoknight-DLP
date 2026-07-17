# SeceoKnight DLP — Cloud Upload Guard (browser extension)

Prevents uploading **Confidential / Restricted** files from a managed Windows
endpoint to cloud apps (Google Drive, Gmail, Dropbox, OneDrive, Box, …), while
**allowing** Public files (logged) and **alerting** on Internal files.

Enforcement decision matrix (server-driven — see the `cloud_upload_prevention`
policies):

| Classification | Upload | Events |
|---|---|---|
| Public | ✅ allowed | normal log |
| Internal | ✅ allowed | alert |
| Confidential / Restricted | ⛔ **blocked** | attempt + prevention alerts |

## How it works
```
page upload (fetch/XHR with a File to a cloud host)
  └─ inject.js (MAIN world)  ─ pauses the request, extracts the file
       └─ content.js (ISOLATED world)  ─ relays via chrome.runtime
            └─ background.js (service worker)  ─ Native Messaging
                 └─ skdlp_host.py  ─ POST /agents/{id}/policy/evaluate
                      └─ DLP server: classify → allow/alert/block
                 ◀── decision ── emits attempt/prevention events to /events
       ◀── block ⇒ abort upload + on-page banner ;  allow/alert ⇒ proceed
```
Fail-open at every hop: if the agent/host/server is unavailable or slow, the
upload proceeds (a DLP outage must never brick the browser). Blocks are only
asserted on an explicit `block` decision.

## Components
- `manifest.json`, `src/` — the MV3 extension (Chrome / Edge).
- `native-host/skdlp_host.py` — the native-messaging host (reference impl).
- `native-host/com.seceoknightdlp.dlp.json` — the host manifest template.

## Install (Windows, per managed machine)
1. **Load the extension**
   - Dev: `chrome://extensions` → Developer mode → *Load unpacked* → this folder.
   - Managed: pack/publish and force-install via the `ExtensionInstallForcelist`
     group policy (Chrome) / equivalent (Edge).
   - Note the **extension ID** it gets assigned.
2. **Install the native host**
   - Copy `native-host/skdlp_host.py` (or a PyInstaller `.exe`) to
     `C:\Program Files\SeceoKnight\`.
   - Edit `com.seceoknightdlp.dlp.json`: set `path` to the host executable and
     `allowed_origins` to `chrome-extension://<EXTENSION_ID>/`.
   - Register it (Chrome): create registry key
     `HKLM\Software\Google\Chrome\NativeMessagingHosts\com.seceoknightdlp.dlp`
     with the default value = full path to the manifest json. For Edge use
     `HKLM\Software\Microsoft\Edge\NativeMessagingHosts\com.seceoknightdlp.dlp`.
3. **Point the host at the DLP server + agent key**
   - Create `C:\ProgramData\SeceoKnight\dlp-host.json`:
     ```json
     { "server_url": "https://<dlp-host>/api/v1",
       "agent_id": "<this machine's agent id>",
       "agent_key": "<the agent's X-Agent-Key>" }
     ```
   - (or set `SKDLP_SERVER_URL` / `SKDLP_AGENT_ID` / `SKDLP_AGENT_KEY`.)
4. **Restart the browser** and test.

## Test
- Upload a **plain text** file to Drive/Gmail → allowed (a `cloud_upload_allowed`
  log appears in the dashboard).
- Upload a file containing **PII / secrets** (e.g., credit-card numbers) →
  **blocked**, an on-page red banner shows, and `cloud_upload_attempt` +
  `cloud_upload_prevented` events appear.
- Host activity/errors log to `C:\ProgramData\SeceoKnight\dlp-host.log`.

## Current scope / limitations (MVP, Phase A)
- Covers **browser** uploads (fetch/XHR carrying a File/Blob/FormData) on the
  cloud hosts in `inject.js`. Native **desktop sync clients** (Google Drive,
  Dropbox, OneDrive apps) are **out of scope** here — that's the Phase B WFP
  driver.
- Content sent for classification is capped at 10 MB per file.
- Blocks **all** cloud destinations for sensitive data (no sanctioned-domain
  allowlist yet — by design for the first cut).
