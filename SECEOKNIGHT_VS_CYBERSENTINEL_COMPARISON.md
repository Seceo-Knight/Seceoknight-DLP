# SeceoKnight DLP vs CyberSentinel DLP — Feature Comparison

**Date:** July 17, 2026
**Method:** Direct code inspection of both repositories (server, agents, dashboard) — no assumptions, every claim below is traced to a specific file.

Both projects share the same lineage — nearly identical server architecture (FastAPI, same model/service/API layout, same alembic migration base up to version 018), the same core Windows C++ agent structure, and the same dashboard framework. They have since diverged, and each has picked up real features and fixes the other is missing.

---

## Summary table

| Area | SeceoKnight | CyberSentinel |
|---|---|---|
| Cloud storage monitoring (OneDrive / Google Drive) | Fully implemented — OAuth, polling, event normalizers, background tasks, API endpoints | DB migrations exist for these tables, but **no service/API code at all** — the feature was scaffolded and never built (or was removed) |
| Compliance reporting | Full feature — dedicated `Reports.tsx` page, `/reports` API, `Report` DB model, `compliance_report_service.py` | Partial — `reporting_service.py`/`reporting_tasks.py` exist but no API endpoint, no DB model, no dashboard page |
| Browser-channel enforcement | Reactive — OS-level file system monitoring watches for uploaded file artifacts after the fact | **Proactive** — a real Chrome/Edge MV3 extension (`agents/browser-extension/`) intercepts the upload request itself (fetch/XHR) and can block *before* the file leaves the browser |
| Email (outbound) DLP | None | **Full SMTP relay** (`smtp-relay/`) — sits in the actual mail flow, extracts every attachment + body, classifies via the same policy engine, and does a true `550` reject at the protocol level before the message leaves. Covers Gmail web/mobile/Outlook/Thunderbird uniformly |
| Document content extraction (PDF/DOCX/XLSX/PPTX) | **Missing** — no `pypdf`/`python-docx`/`openpyxl`/`python-pptx` anywhere in the server; binary office files are never parsed to text before classification | **Present and explicitly documented as a bypass fix** (`document_extract.py`) — used by USB/file-transfer, browser upload, and SMTP relay alike |
| Audit trail UI | Backend model/API exists, no dedicated dashboard page | Dedicated `AuditTrail.tsx` page |
| Agent HTTP client reliability | Fixed this week — `shared_ptr` HTTP client + per-call lock instead of a mutex held for the whole network call, so one slow call can't block heartbeats | Does not have this fix — likely still exposed to the "agent shows offline / clipboard freezes" bug we just fixed in SeceoKnight |
| Session lock/unlock reconnect | Fixed this week — `WTSRegisterSessionNotification` triggers immediate reconnect on unlock | Not present |
| Screen-capture tool-launch cache contamination | Fixed this week (`ContentScanThread` now excludes capture-tool windows) | Has an earlier/simpler `CAPTURE_PROCESSES` check but not the same contamination fix — likely still misclassifies Snipping Tool's own window in some cases |
| USB quarantine cross-volume copy | Fixed | Already has the same `copy_file`+`remove` pattern |
| Kernel driver build tooling | Full Visual Studio project (`.sln`/`.vcxproj`), install script, two build docs | Bare source only (`.c`/`.h`/`.inf`/`sources`) — driver code exists but isn't packaged for an easy build |
| Dashboard UI component library | Rich — full Radix UI primitive set (dialog, popover, dropdown, tabs, tooltip, select, command palette via `cmdk`, toast via `sonner`) | Missing all of the above — dashboard likely has fewer polished UI primitives to build with |
| Deployment tooling | `docker-compose.prod.yml` only | `docker-compose.yml` + `docker-compose.deploy.yml` + `docker-compose.prod.yml`, plus `deploy.sh`/`deploy-ubuntu.sh` and two dedicated deployment write-ups (`GITHUB_DEPLOYMENT_COMPLETE.md`, `INTEGRATION_COMPLETE.md`) |
| DB migration granularity | 31 numbered migrations past the shared base (018) | 22 — same ground (RBAC, MFA, IP allowlist, SIEM, threat intel) covered more coarsely |

---

## The one finding that matters most

**CyberSentinel found and fixed a real DLP bypass that SeceoKnight still has.** `document_extract.py`'s own header comment explains it directly: a `.docx`/`.pdf`/`.xlsx`/`.pptx` file is a compressed binary container. If the server classifier scans the raw bytes of such a file instead of extracting its actual text first, sensitive content inside it decodes to garbage and always classifies as "Public" — a complete bypass. CyberSentinel fixed this everywhere content gets forwarded for classification (USB/file transfer, browser upload guard, SMTP relay) by adding a dedicated extraction layer with `pypdf`, `python-docx`, `openpyxl`, and `python-pptx`.

SeceoKnight has none of those libraries in `server/requirements.txt`, and no equivalent extraction code in `classification_engine.py` or `agents.py`. Practically, this means: if a user renames or saves sensitive content as an actual `.docx`/`.pdf`/`.xlsx`/`.pptx` (not a screenshot, not plain `.txt`) and transfers it via USB or browser upload, SeceoKnight's real-time classification almost certainly won't detect it today — the same class of bug we've been chasing all week (content not being read correctly before classification), just for a different file format than the ones tested so far.

## Where SeceoKnight is ahead

The reliability work done this week — the HTTP client refactor, session lock/unlock reconnect, and the screen-capture cache-contamination fix — doesn't appear to exist in CyberSentinel at all, based on the absence of `GetHttpClient`, `WTSRegisterSessionNotification`, and the newer capture-tool exclusion logic in its `agent.cpp`. CyberSentinel likely still has the "agent shows offline," "clipboard freezes during network calls," and "Snipping Tool captures misclassified" bugs SeceoKnight just resolved. SeceoKnight is also the only one of the two with a working OneDrive/Google Drive integration and a complete compliance-reporting feature (CyberSentinel has the database tables for cloud storage but never built the service layer).

## Recommendation

Two moves are worth considering, independent of each other:

1. Port `document_extract.py` (and the four parsing dependencies) into SeceoKnight's classification pipeline — this is a genuine security gap, not a nice-to-have, and CyberSentinel has already solved it in a way that's directly reusable.
2. Consider whether SeceoKnight needs its own browser extension and/or SMTP relay for outbound email — both are architecturally superior to what SeceoKnight currently does for those two channels (proactive interception vs. reactive file-system watching), and CyberSentinel's implementations are already documented and working.

Happy to start on either — the document-extraction port is the smaller, higher-priority piece if you want to begin there.
