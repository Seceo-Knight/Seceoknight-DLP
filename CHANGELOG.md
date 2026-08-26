# Changelog - Testing and Fixes

**Date:** November 14-26, 2025  
**Testing Environment:** WSL2 (Ubuntu on Windows)  
**Tested By:** Vansh-Raja

This document details all changes, fixes, and improvements made during testing and deployment of the SeceoKnight DLP platform.

---

## 🟢 Gap-scan: CyberSentinel-DLP USB fixes (August 26, 2026)

Fresh gap-scan against effaaykhan/cybersentineldlp-prod (their commit
history moved ~90 commits since our last scan). Reviewed the two USB
device-control fixes from that window:

**98b47af "honour an explicit device denial when the manager is
unreachable"** -- does NOT apply. That bug only exists because
CyberSentinel's offline allowlist matches broader than serial number
(manufacturer/device-id/model), so a vendor-level allow can silently cover
a serial that should be denied. SanctionedUsbDevice's docstring already
states SeceoKnight matches on serial_number alone, by design -- there is no
broader-than-serial allow rule for a deny to be shadowed by, so this class
of bug can't occur here. No change needed; confirmed via reading the model.

**7ae4671 "stop reporting a device as connected when its agent is
offline"** -- DOES apply, and did apply: `_annotate_connection_state()` in
usb_devices.py computed `connected` purely from the last connect/disconnect
event, with no check on whether the reporting agent was still alive. A
machine that's shut down never emits a disconnect, so its last connect
stands forever -- a stick unplugged months ago on an offline machine still
showed a green "connected" dot.

**Fix:** `_annotate_connection_state()` now cross-checks the reporting
agent's liveness via the same `_compute_lifecycle_status()` freshness rule
the Agents page uses, and reports one of three states instead of two:
`connected` (agent online, says attached), `unknown` (last heard attached,
but that agent has gone quiet -- an unplug could never have been reported),
`disconnected` (an actual unplug was reported, trusted regardless). Both
`list_devices` and `seen_devices` pick this up for free since they already
call the shared helper. Dashboard's `ConnectedDot` renders three states:
green / amber (unknown) / grey. No DB migration needed -- purely computed,
not persisted.

Scope note: CyberSentinel's commit also adds a "dismiss a seen-but-not-yet-
decided device" bookkeeping feature (separate table + endpoints). Left out
of this pass to keep it bounded -- can follow up if wanted.

---

## 🟢 Gap-scan: CyberSentinel-DLP extension update-mechanism fixes (August 26, 2026)

Continuing the gap-scan into their installer-reliability cluster (8 commits,
Aug 19) -- the same class of problem this session just fought by hand on a
real endpoint (extension stuck on 1.0.6, self-update never taking, no
DevTools access to see why).

**cd070e7 "answer HEAD, and exempt it from the IP allowlist"** -- applies
directly. `extension.py`'s three routes (update.xml, /info, /{filename})
were GET-only; a HEAD reachability probe got 405, or fell through to a 404
on update.xml, reporting a perfectly healthy feed as down. Fixed: all three
now answer GET and HEAD (`@router.api_route(..., methods=["GET", "HEAD"])`).
SeceoKnight's IP-allowlist exemption for this prefix was never method-gated
to begin with, so unlike CyberSentinel's original bug there was no second
layer to fix.

**42e827f "Update said agent not detected for an agent that was running"**
-- already fixed. `Update-Agent` in manage-agent.ps1 already retries the
post-restart process check instead of a single 3-second look, with a
comment dated August 19 crediting this exact CyberSentinel commit. No
change needed.

**63d77f5 / 261f852 / 90a2608 / 9e01900 / 996d2dd / c170346** (in-place
extension update, browser-close-without-force-kill, a Deploy/Repair/Update/
Diagnose menu) -- don't map cleanly. CyberSentinel's installer treats the
extension as something it imperatively deploys/repairs; SeceoKnight's
force-install is entirely reconcile-driven by the Browser Extension Guard
scheduled task, with no equivalent imperative action to patch. That
architectural gap is exactly what this session's live debugging hit: there
was no "make it try again right now" button, only a manual registry
remove/re-add. Added one: manage-agent.ps1's Browser controls menu gets a
new **[3] Force extension reinstall**, which removes the
ExtensionInstallForcelist entry (Chrome/Edge auto-uninstall on next policy
read), immediately triggers the guard task to re-add it, and tells the
operator to close/reopen the browser -- the exact procedure this session
worked out by hand, now a menu option instead of typed-out registry
commands. Deliberately does not force-kill the browser, on the same
"don't break what you're protecting" reasoning as the downloads-hook fix
above -- CyberSentinel's own 90a2608 documents real data loss from a
2-second force-kill grace window, so this waits for the user to close it
themselves.

---

## 🟡 Follow-up same day: real Drive download went undetected -- missing catalog domain (August 26, 2026)

Verification test on the test endpoint after the fix above (real extension
reinstalled clean at 1.0.8, confirmed no more cancel/reissue attempts and no
more "Failed - Forbidden" downloads): the actual test download still wasn't
detected at all. dlp-host.log showed why:

```
downloads.onCreated fired: url=https://drive.usercontent.google.com/download?id=...  referrer=
downloads: catalog check - enforced=true domains=47
downloads: resolved host=drive.usercontent.google.com watched=false
```

Google serves real Drive file downloads from `drive.usercontent.google.com`,
a distinct domain from `googleusercontent.com` (already seeded) --
`drive.usercontent.google.com` does not end with `.googleusercontent.com`,
it ends with `.usercontent.google.com`. The host-match in background.js is
a strict suffix check, so this was a silent miss: the download itself was
never at risk (this hook never blocks, per the fix above), but it also
never got inspected/classified, so a genuinely sensitive Drive download
would pass with no alert and no event.

Also present in the same log: a burst of ~30 "signal is aborted without
reason" inspection-fetch failures, all timestamped to the exact moment of
the forced extension reinstall (removing/re-adding the
`ExtensionInstallForcelist` registry entry, full Chrome restarts). These
are stale in-flight requests from the OLD 1.0.6 service worker being torn
down mid-fetch during that reinstall, not a live issue with 1.0.8 -- no
recurrence in the clean post-reinstall entries.

**Fix:** migration `040_app_catalog_drive_usercontent` adds
`usercontent.google.com` to `app_catalog` (file_sharing), closing the gap
via the existing suffix-match logic -- no extension code change needed.

**Verified end-to-end on the real endpoint** after `update.sh` applied the
migration (catalog domain count went 47 -> 48): a real Drive download of
the SSN test file now resolves `watched=true`, the inspection fetch
succeeds (200 OK, content read), gets classified Restricted (100%), and
correctly triggers the `file_sharing.download` = block cell -- downgraded
to a critical alert per the fix above, with the actual file still reaching
disk untouched. This is the full downloads-hook feature (Task #28) working
as designed: detected, classified, alerted, never broken.

---

## 🔴 REVISED same day: downloads hook was silently breaking real downloads (August 26, 2026)

Confirmed on a real endpoint, using the new dlp-host.log/debug_log tracing
below: the downloads hook shipped earlier today (cancel the download,
shadow-fetch the same URL for inspection, then re-issue it or leave it
cancelled) was breaking every real download from a catalogued host, not
just the sensitive ones it was meant to catch. `chrome://downloads` showed
repeated "Failed - Forbidden" / "Failed - Needs authorization" entries
attributed to the extension. Root cause: Google Drive and SharePoint/
OneDrive (and almost certainly most other providers) mint a one-time,
session-bound signed download URL -- Drive's `at=` token, SharePoint's
`tempauth` JWT. The instant Chrome's original request goes out, that link
is spent, so cancelling it and fetching or re-downloading the SAME url
ourselves gets flatly rejected. This is a hard MV3 limitation, not a bug in
the request logic: there is no blocking `onBeforeDownload`-style event in
Manifest V3, so "stop first, decide, resume" was always going to run into
this for any provider using signed links.

**Fix:** the downloads hook no longer calls `chrome.downloads.cancel()` or
`chrome.downloads.download()` at all. The real download always proceeds
completely untouched and always succeeds. It still makes a best-effort
attempt to fetch the same URL itself purely to classify the content for
the dashboard's Events/Alerts -- this will often fail for the exact
one-time-link reason above, and that's fine: it fails open into "detected,
but no content detail this time" rather than ever touching the real file.
`skdlp_host.py`'s `handle_web_activity()` now downgrades a "block" decision
for a download activity to a critical-severity alert rather than emitting
`blocked=True` -- the file already reached disk by the time this code runs
and always will, so claiming an enforcement outcome it can't deliver would
be a real, not just optimistic, false statement on the dashboard. The
Policies page's Download rows relabel "Block" to "Alert (Critical)" with a
hint explaining why, for the same reason.

**What this means for the feature:** downloads from watched apps are
detected and audited/alerted on, with content classification wherever the
inspection fetch happens to succeed -- but cannot be reliably prevented.
Same trade-off this codebase already made once before, deliberately, in
favor of "never break what you're protecting" over "attempt an enforcement
guarantee MV3 can't actually back up here."

Verified against the mock chrome/fetch test harness: a simulated one-time-
link failure (fetch returns 403) no longer touches `chrome.downloads` at
all -- zero `cancel()`/`download()` calls in any scenario now, by design.

---

## 🔧 Debugging aid: dlp-host.log now records every request, plus a debug relay from the extension (August 26, 2026)

Found while validating the downloads hook (previous entry) on a real endpoint:
Chrome's DevTools "Inspect views" appears to be blocked entirely for THIS
extension specifically -- across multiple attempts, in Chrome, with
Developer mode on, "service worker" never became clickable, before or
immediately after triggering a download that should have woken it. Working
theory: a Chrome enterprise-policy restriction on inspecting
force-installed (`ExtensionInstallForcelist`) extensions, as opposed to
ones loaded via "Load unpacked". Whatever the cause, it made the live
console entirely unusable for confirming whether client-side code was even
running.

Two changes, both purely additive (no behavior change):
- `skdlp_host.py` now logs every `web_activity`/`get_app_catalog` request
  and its outcome unconditionally, not just failures -- previously only
  errors were logged, so a request that arrived and was silently
  fail-opened to "allow" looked identical in the log to a request that was
  never sent at all.
- A new `debug_log` native-message type lets the extension relay its own
  step-by-step progress into `dlp-host.log` directly (`background.js`'s new
  `dlog()` helper, used throughout the downloads hook: onCreated fired,
  catalog/enforced check, host resolution, cancel, shadow-fetch
  request/response, decision, re-issue). Since `dlp-host.log` is a plain
  file with no DevTools dependency, this sidesteps the inspection-blocking
  issue entirely going forward, for this feature and whatever needs
  debugging next.

Extension version bumped 1.0.6 → 1.0.7 to ship `dlog()`.

---

## ✨ Downloads hook: watch downloads FROM monitored apps (gap-scan of CyberSentinel-DLP, August 24, 2026)

New Web Activity Control capability. Until now, "download" was a real
activity in the shared vocabulary (`app/core/web_activity.py`) that the
server-side evaluator already handled correctly, but nothing in the browser
extension ever sent it — file-sharing/webmail/collaboration downloads
passed through completely unmonitored while uploads/prompts/messages to the
same destinations were fully covered.

**Server side** (`server/app/core/web_activity.py`, `dashboard/src/types/policy.ts`,
`WebActivityControlPolicyForm.tsx`): added `(file_sharing, download)`,
`(webmail, download)`, `(collaboration, download)` to `MEANINGFUL_CELLS` and
the dashboard matrix. No server-side evaluation logic changed — the
`/agents/{id}/web-activity/evaluate` endpoint and `skdlp_host.py`'s
`web_activity` message handler were already fully generic per-activity;
only the vocabulary needed extending. `genai.download` deliberately left
out — not verified against real GenAI file-output domains yet. The dashboard
form doesn't offer "Redact" for download cells (no text stream to
substitute into for arbitrary downloaded bytes).

**Extension side** (`background.js`): `chrome.downloads` is the only hook
Chrome offers for a download already in progress, and `cancel()` is the
only way to stop one — there's no MV3 equivalent of a blocking
`onBeforeDownload`. So the shape here is cancel-first: `onCreated` fires →
if the initiating host (referrer, falling back to the URL itself) is in the
cached app catalog → `chrome.downloads.cancel()` → shadow-`fetch()` the
same URL ourselves (capped at 10MB read via a streaming reader, matching
`inject.js`'s existing upload cap, never buffering a whole multi-GB file
into memory) → send it through the same `web_activity` native-host round
trip as post/send/ai_response → block (leave cancelled) or
allow/alert/redact (re-issue via a fresh `chrome.downloads.download()`).

Three safety properties, given the Edge/`ExtensionSettings` incident's own
lesson about this codebase never being allowed to break what it's
protecting:
1. Only `http(s)://` downloads from a catalogued host are ever touched.
   `blob:`/`data:` downloads (e.g. a page's own "Export as CSV" button) are
   left completely alone — they can't be re-fetched from a service worker
   at all, so cancelling one would just destroy it with no way to recover.
2. Every failure of the shadow-fetch (network error, 15s timeout, a
   one-time signed URL that doesn't survive a second request) re-issues the
   *original* download rather than leaving it cancelled — fail-open, same
   posture as every other decision path in this extension.
3. A `downloadsWeReissued` set tracks URLs this code itself just
   re-triggered, so the re-issued download's own `onCreated` doesn't loop
   back into cancelling itself.

Verified with a mocked `chrome`/`fetch` harness (not a real browser, but
exercises the actual file's logic): watched-host block, watched-host allow
with correct basename-only re-issue filename, unwatched-host pass-through,
shadow-fetch failure fail-open re-issue, and the re-issue-echo guard all
behave as designed. Adds the `downloads` permission to `manifest.json`.
Extension version bumped 1.0.5 → 1.0.6.

---

## ✨ `wantVersion` push-trigger + update-check throttle fix (gap-scan of CyberSentinel-DLP 2.9.1, August 24, 2026)

Second-round gap-scan of CyberSentinel-DLP's repo turned up a refinement to
the extension self-update mechanism added below on August 19. The old
version called `chrome.runtime.requestUpdateCheck()` unconditionally on
every browser start, extension install, and hourly alarm tick — wasteful,
since that call is itself throttled by Chrome to a limited number of calls
per time window, so most of those calls were spent finding nothing and
potentially eating into the budget for when a check is actually needed.

This ports the safe half of CyberSentinel's fix (the half that doesn't
touch browser policy registry keys — see the Edge incident directly below,
which is exactly why the *unsafe* half, `minimum_version_required`, is not
being re-tried):

- `agent.cpp`'s Browser Extension Guard task now writes `wantVersion` (the
  currently-published extension version) into `chrome.storage.managed`
  alongside `serverUrl`/`agentId` — the same proven-safe write path, not
  `ExtensionSettings`.
- `background.js` reads `wantVersion` before calling
  `requestUpdateCheck()` and skips the call entirely when the installed
  version already matches it — turning an unconditional throttled call
  into a cheap, unthrottled comparison in the common case.
- `background.js` also now listens for `wantVersion` changing via
  `chrome.storage.onChanged` and checks immediately, so a freshly-published
  version reaches an already-running browser within about 2 minutes (the
  guard task's own tick) instead of waiting up to an hour for the alarm.

This is advisory only — `background.js` decides what to do with the value,
and nothing about it can force Chrome itself to act the way
`ExtensionSettings`/`minimum_version_required` tried to. It cannot repeat
that failure. Extension version bumped to 1.0.5 so the change actually
ships through the existing force-install/update pipeline.

---

## 🔴 REVERTED same day: minimum_version_required broke Microsoft Edge (August 19, 2026)

The `ExtensionSettings`/`minimum_version_required` policy added in the entry
directly below this one was deployed to a real endpoint and, within
minutes, Microsoft Edge stopped opening at all — not a crash, it just never
showed a window. Chrome on the same machine was separately in a bad state
(profile corruption, likely unrelated/pre-existing) which made isolating
this slower than it should have been, but the fix was unambiguous: removing
the `HKLM\...\ExtensionSettings` registry value this feature wrote (`Remove-
ItemProperty ... -Name ExtensionSettings` under both the Chrome and Edge
policy roots) made Edge open again immediately, with no other change.

Root cause not fully confirmed. Leading theory: having both
`ExtensionInstallForcelist` *and* an `ExtensionSettings` entry with
`installation_mode=force_installed` for the **same** extension id is a
combination Chromium doesn't handle cleanly — possibly blocking browser
startup on a forced reinstall that never completed (no network issue was
apparent, but the timing fits: this is exactly the mechanism that's
supposed to disable-and-reinstall an out-of-date extension).

**Action taken:** `WriteExtensionMinimumVersion()`'s call site in
`HandleApplyBrowserExtensionGuard()` is commented out (`agent.cpp`). The
function itself is left in place, unused, with a comment explaining why —
do not re-enable without testing against a real Chrome *and* Edge install
first, and consider not combining it with `ExtensionInstallForcelist` for
the same id (drop the forcelist entry when using `ExtensionSettings`
instead, rather than both at once).

**What's still in effect:** the extension's own self-update
(`requestUpdateCheck()`/`onUpdateAvailable` in `background.js`, previous
entry) is unaffected — that's extension-side JS calling standard,
documented Chrome APIs with no registry/policy involvement, and has none of
this failure mode. It's a weaker fix on its own (can't rescue a browser
that's already stuck on an old build with no self-update code, and only
polls hourly/on-restart rather than forcing immediately), but it's safe.

**Lesson:** a DLP agent must never be able to break the browser it's
protecting. This should have been tested against Edge specifically before
being wired into the repeating guard task that runs unattended on every
managed endpoint, not shipped on the strength of matching CyberSentinel's
own (also same-day, also still-settling) approach.

---

## ✨ Extension can now actually update itself (gap-scan of CyberSentinel-DLP, August 19, 2026)

CyberSentinel-DLP spent several commits today discovering and fixing a real
bug in their own extension force-install: `ExtensionInstallForcelist` only
guarantees the extension is *present*, never that it's *current*. Chrome and
Edge check the update feed on their own multi-hour timer regardless of
restarts, so an already-installed older copy can sit stale indefinitely even
with a newer version published and perfectly reachable — they had an
endpoint stuck on v2.5.0 for days with v2.7.0 published, every server-side
check (update.xml, the CRX, the signing-key-derived id) correct the whole
time. This is a mechanism we use identically (`SetExtensionForcelistEntry`
in `agent.cpp`), so it was very likely already true for us — it just hadn't
bitten yet because every endpoint tested so far got the extension fresh,
never as an update to an already-running older copy.

Ported both halves of their fix:

- **`agents/browser-extension/src/background.js`** (bumped to 1.0.4): the
  extension now calls `chrome.runtime.requestUpdateCheck()` itself — hourly,
  on browser start, and on install — and reloads immediately via
  `chrome.runtime.onUpdateAvailable` the moment a newer version has actually
  been downloaded (Chrome won't swap it in under a running extension
  otherwise; it waits for idle, which can be a long wait for a
  repeatedly-woken service worker).
- **`agent.cpp`** (`WriteExtensionMinimumVersion()`, wired into the existing
  elevated Browser Extension Guard task): writes `ExtensionSettings`'
  `minimum_version_required` alongside the forcelist entry, sourced from
  `/extension/info`'s `version` field (now also cached in
  `browser_extension_state.cache`). Telling the browser the installed copy
  is too old is a statement it has to act on — disables and reinstalls from
  `update_url` — unlike the forcelist, which it can silently defer forever.

Together: a browser that's running gets nudged proactively (self-update);
one that's badly stuck gets forced (minimum version). Also fixed the same
`Update-Agent` process-check race CyberSentinel caught in their own
installer today — `Get-Process` checked exactly once, 3 seconds after
`Start-ScheduledTask`, which only guarantees the task was *queued*, not that
the process exists yet. `manage-agent.ps1`'s Update now retries 6×2s like
Install already effectively does.

Known limitation, documented in `WriteExtensionMinimumVersion()`'s own
comment: `ExtensionSettings` is a single JSON blob per browser root and this
codebase has no JSON parser to safely merge into an existing one — our entry
replaces whatever was there. Not a concern on any fleet this has been
deployed to (nothing else writes this key), but the function logs a warning
if it ever detects otherwise.

---

## 🐛 Web Activity Control "Violations" count stuck at 0 (August 19, 2026)

Matching web_activity events were showing up correctly in the Events log
(alerted/blocked, right severity, right destination) but the specific
Web Activity Control policy's "Violations" count on the **Policies** page
never moved off 0.

Root cause: that count (`server/app/api/v1/policies.py` `GET /policies`) is
computed live by aggregating `matched_policies` on stored Mongo events —
it's not a column that gets incremented directly. `matched_policies` is
normally stamped by the generic background policy evaluator
(`DatabasePolicyEvaluator`), but that evaluator only understands policies
whose config is `conditions.rules` — Web Activity Control policies store a
matrix instead (`policy.config["matrix"]`), so the evaluator's `if not
conditions.get("rules"): continue` silently skipped every one of them,
every time. Meanwhile `evaluate_web_activity()` (`agents.py`) already
*does* resolve the correct policy per-request (it needs the matrix to
decide allow/alert/block/redact in the first place) — that result just
never made it onto the event the native host posts afterward.

Fix: `WebActivityEvaluationResponse` now returns `policy_id`/`policy_name`
alongside the decision; `skdlp_host.py` echoes them back on its `/events/`
POST (`EventCreate` gained matching fields); `create_event()` writes
`matched_policies` directly from that trusted value at insert time, in the
same shape the background evaluator itself produces, so `GET /policies`'
aggregation counts it identically either way. The background processor's
existing `if processed.get("matched_policies"):` guard means it never
overwrites this with an empty result for event types it can't match — so
this required no change there at all.

Requires both halves to update: a server rebuild (`docker compose -f
docker-compose.prod.yml pull && up -d` after CI publishes new images) for
the `policy_id`/`policy_name` fields and the `create_event()` change, *and*
a refreshed `skdlp_host.exe` on each endpoint (`manage-agent.ps1` → `[2]
Update`, or it'll pick it up automatically going forward — see the
zero-touch install entry above) since it's the one echoing `policy_id`
back on the event it posts. Old `skdlp_host.exe` + new server (or vice
versa) just means violations keep showing 0 until both sides are current
— it fails safe, not open.

---

## ✨ Browser extension + native host: zero-touch install (August 19, 2026)

Directly closes the gap flagged at the end of the previous entry below
("Known remaining gap: `skdlp_host` has no self-update mechanism") — and
goes further, since the actual ask was "no manual step at all, ever again,"
not just an update mechanism.

**Before:** `install-agent.ps1` only installed the endpoint agent. The
browser extension force-install policy (`ExtensionInstallForcelist`) was
already automatic from an earlier pass, but the native-messaging host
(`skdlp_host`, the program the extension actually talks to for allow/block
decisions) still needed a fully separate, by-hand process per machine:
install Python, `pip install pyinstaller`, `pyinstaller --onefile
skdlp_host.py`, then run `native-host/install.ps1` with the extension ID
copy-pasted in by hand. Without that manual step, the extension showed up
force-installed but did nothing — every decision silently fell through the
fail-open path, exactly the multi-hour debugging chain documented below.

**After:**
- CI (`.github/workflows/build-windows-agent.yml`, new `build-native-host`
  job) builds `skdlp_host.exe` via PyInstaller on every push touching
  `skdlp_host.py`, publishing it into the repo next to
  `seceoknight_agent.exe` with the same SHA-256 sidecar pattern.
- `install-agent.ps1` downloads it (Step 5b) the same way it downloads the
  main agent binary — no Python needed on the endpoint at all.
- `agent.cpp`'s existing elevated, repeating "Browser Extension Guard" task
  (`--apply-browser-extension-guard`, SYSTEM, every 2 minutes) now also
  writes the native-messaging host manifest (`com.seceoknightdlp.dlp.json`),
  registers it in the registry for both Chrome and Edge, and writes the
  host's own config (`dlp-host.json`) — reusing the extension ID, server
  URL, and agent identity it already tracks for the forcelist entry. See
  `WriteNativeMessagingHostRegistration()` / `WriteDlpHostConfig()`.
- `manage-agent.ps1`'s `Update-Agent` now refreshes `skdlp_host.exe` too
  (`Update-NativeHost`), so existing installs catch up via a normal Update,
  and its `[4] Browser` menu reports native-host binary/manifest/registry
  status alongside the existing extension force-install status — the exact
  diagnostics that took manual registry/log digging to work out by hand in
  the entry below now surface in one menu.
- `Uninstall-Agent` clears the two native-messaging-host registry keys on
  removal (the manifest/binary themselves already went with
  `$INSTALL_DIR`/`$DATA_DIR`).

**Net result:** `install.sh` on the server + `install-agent.ps1` on each
Windows PC is now genuinely the entire setup — extension force-install,
native host, and its registration all happen with zero extra commands,
zero Extension-ID copy-pasting, and zero Python dependency on the endpoint.
The old fully-manual path (`agents/browser-extension/INSTALL_WINDOWS.md`)
still works unchanged, for the one case that still needs it: a PC that
should get browser protection *without* the full endpoint agent.

---

## 🐛 Web Activity Control event flood on real ChatGPT traffic + stale native host binary (August 19, 2026)

### What happened, end to end

First live test against ChatGPT surfaced a chain of four independent, stacked problems, each hiding the next one until the previous was fixed:

1. `web-activity.js` never read a request body when the page called `fetch(new Request(url, opts))` instead of `fetch(url, opts)` — ChatGPT's bundle uses the former. Fixed same day (see the "silently skipped genai posts" entry below): added `resolveBodyText()` to handle both calling conventions.
2. Once that was fixed, the browser extension itself was stuck on 1.0.0 on the real test endpoint no matter how the server-published version was bumped (1.0.1, then 1.0.2) or how many caches were cleared. Root cause: profile-local corruption specific to that one Chrome profile — confirmed by testing a brand-new profile, which installed the current version correctly on the first try. Not a code bug; documented here for the next person who hits the same wall so they know to try a fresh profile before assuming the packaging pipeline is broken.
3. Even with a correctly updated extension, ZERO `web_activity` events reached the server. Root cause: the extension doesn't call the DLP server directly — it goes through a separate native-messaging host program (`skdlp_host`), and that program's `allowed_origins` on this endpoint was pinned to a stale extension ID (`bjglolaooepjebiklcalmklppkokgjhm`) left over from before the extension had a pinned signing key, not the current force-installed ID (`aiidhbnohkdododhkgjfbejfbipedejh`). Chrome silently refuses native-messaging connections for an ID that isn't listed — no error surfaced anywhere a user would see it.
4. Fixing the `allowed_origins` mismatch still produced nothing. Root cause: the deployed `skdlp_host.exe` itself was a standalone, manually-built binary with **no update mechanism of its own** — unlike the main agent (self-updates via `manage-agent.ps1`) and the extension (self-updates via `update.xml`), this component has never had one. It was built before Web Activity Control's `get_app_catalog` native-messaging call existed, so it silently didn't recognize that message type at all — confirmed by `dlp-host.log` showing successful `ping`/`get_hosts` traffic (older message types) but zero trace, ever, of `get_app_catalog`. Fixed for this endpoint by pointing the host manifest at a `.bat` wrapper running the current `skdlp_host.py` directly (no PyInstaller rebuild needed, since Python was already on the machine) instead of the stale `.exe`.

Every one of these needed a different diagnostic (extension caches, `chrome://policy`, `chrome://serviceworker-internals`, `dlp-host.log`, a direct `Invoke-RestMethod` call replicating what the native host does) because each layer looked healthy in isolation once the layer above it stopped hiding the truth.

### Then: event flooding once it actually worked

With the full chain finally connected, a single real "send message" in ChatGPT logged 4-6 near-duplicate `medium`-severity Web Activity events within the same second on the dashboard instead of one. Root cause: `background.js`'s `webActivity` message handler deliberately had no coalescing (`waWaiters` — "a genai prompt/response isn't a chunked upload, so there's no equivalent need for cross-request coalescing/piggybacking here"), on the assumption that one user action = one qualifying request. False in practice: ChatGPT's SPA fires several background POST requests (conversation metadata, moderation pre-checks, etc.) within the same second as the real message, each independently over `web-activity.js`'s 40-character gate.

### Fix

`agents/browser-extension/src/background.js`: added `waRecentDecisions`/`waRequestKeys`/`waCoalesceKeyFor()`, mirroring the existing `recentDecisions`/`requestKeys`/`coalesceKeyFor()` pattern already used for chunked cloud-upload requests — same `WA_COALESCE_WINDOW_MS` (4000ms) as that path's own window. Keyed on `host:activity` rather than content, since these background requests often carry different bodies for the same logical user action, so a content-based key wouldn't coalesce them. Deliberately **excludes `redact`** from the cache: a redact decision's `redactedContent` is specific to the exact request body that produced it, and reusing it for a different, later request within the coalesce window would substitute the wrong redacted text into that request — silent data corruption, not just a missed detection. `allow`/`alert`/`block` don't have that problem, since the action itself doesn't depend on which exact background request triggered it.

Bumped extension to 1.0.3.

### Known remaining gap, not fixed this pass

`skdlp_host` (the native-messaging host) has no self-update mechanism at all, unlike the main agent and the extension. Every other endpoint almost certainly has the same stale binary this one did, and will need the same manual fix (or a proper PyInstaller rebuild + redistribution) until this gets a real update path — worth folding into the main agent binary the way `--watchdog-check` was, so it can never go stale silently like this again.

---

## 🐛 Watchdog task's `wscript.exe`/`.vbs` launcher silently blocked by Windows 11 Application Control (August 18, 2026 evening)

### What happened

Gap-scan of CyberSentinel-DLP turned up two recent commits. One (unpacked-extension shadowing) was already ported. The other: their main agent launch task used to run `wscript.exe launch_agent.vbs` to hide the console window, and on a real Windows 11 endpoint under Application Control / Smart App Control that failed at every logon with `"An Application Control policy has blocked this file"` (0x800711C7) -- script hosts are blocked by default under those policies. Their fix was to point the task straight at the exe instead, since `--bg` already gives it a hidden window with no wrapper needed.

SeceoKnight's main launch task was already fixed the same way (it runs `seceoknight_agent.exe --bg` directly). But the health-check watchdog task -- a *different*, newer piece of this codebase, added to catch a genuinely HUNG (not exited) agent process via log-staleness -- had converged, after four separate rounds of console-flash debugging (Interactive->S4U logon, then wrapping powershell.exe in VBScript with SW_HIDE, then moving the whole staleness check into VBScript/COM so no interpreter ever spawned on the healthy path, then LogonType ServiceAccount as SYSTEM once S4U turned out to fail for Azure AD-joined accounts), on exactly the same `wscript.exe watchdog_launcher.vbs` pattern -- because the watchdog needs real decision logic (read a log's mtime, decide hung-or-not, taskkill + retrigger), not just "launch an exe", so the simple CyberSentinel fix didn't directly apply. Under the same Application Control policy, the watchdog task would silently never run at all -- no console flash to notice, no error anywhere, just crash-recovery quietly disabled on any endpoint with that policy on.

### Fix

Moved the decision logic natively into the agent binary itself instead of eliminating it: `agents/endpoint/windows/agent.cpp` gained `HandleWatchdogCheck()`, wired into `main()`'s existing one-shot-hook chain as `seceoknight_agent.exe --watchdog-check` (same pattern already used for `--apply-wireless-guard`/`--apply-browser-extension-guard`/`--cli-guard`). It's a direct port of `watchdog_launcher.vbs`'s logic -- not running -> no-op, within a 2-minute startup grace -> no-op, log stale >= 3 minutes -> force-kill + `schtasks /Run` -- using `CreateToolhelp32Snapshot`/`GetProcessTimes` for process discovery instead of the VBS's `Schedule.Service` COM calls, and killing by exact PID instead of `taskkill /IM` (precise to the one hung instance). Reuses the already-proven `RunHiddenCommand()` helper for the two console utility calls (`taskkill.exe`, `schtasks.exe`) rather than adding new CreateProcess boilerplate. Deliberately does NOT use the default `Logger()` (which opens `seceoknight_agent.log`, the very file this function checks the mtime of -- writing to it every 5-minute tick would have made the log look permanently fresh and defeated the whole check) -- uses its own `watchdog.log`, same as the .vbs it replaces.

This works with zero console risk for the same reason CyberSentinel's fix works: the agent binary is already GUI-subsystem (`-mwindows`, see `AttachForegroundConsole()`), so it never gets a console allocated regardless of how it's launched -- no `SW_HIDE`/`CREATE_NO_WINDOW` juggling needed at all, and no script host left for a policy to catch.

`install-agent.ps1`'s Step 9b no longer generates `watchdog.ps1` or `watchdog_launcher.vbs` at all, cleans up either file left by an older install, and registers the watchdog task's action against the exe directly. `manage-agent.ps1` gained `Test-WatchdogTaskCurrent`/`Repair-WatchdogTask` (mirroring CyberSentinel's own `Test-AgentTaskCurrent` pattern) so `Update-Agent` converges an already-installed machine onto the new task action too, not just new installs -- otherwise every endpoint installed before this fix would keep silently running the broken watchdog forever.

Not compiled/run on a real Windows machine (no Windows/C++ toolchain in the environment that wrote it, same caveat `RunHiddenCommand()` itself carries) -- build via the existing GitHub Actions workflow and verify on a real endpoint before relying on it.

---

## 🐛 web-activity.js silently skipped genai posts built via `fetch(new Request(...))` (August 18, 2026 evening)

### What happened

First real end-to-end test against ChatGPT: sent a message, got a normal reply back, but the server logged nothing at all -- not a `web_activity` decision, not even the older Cloud Upload Guard's `cloud_upload` event. A console error on `backend-api/sentinel/ping` (`ERR_BLOCKED_BY_CLIENT`) looked like the culprit at first, but it turned out unrelated: it fired regardless of whether web-activity.js's own logic ran, so chasing it further would have been chasing a red herring.

Root cause: `web-activity.js`'s `fetch` wrapper only ever read the request body from the second argument -- `var body = init && init.body`. That's correct for `fetch(url, { body })`, but ChatGPT's bundled/instrumented client calls fetch the other spec-legal way, `fetch(new Request(url, { body }))`, where the body lives inside the `Request` object itself and `init` is `undefined`. `body` resolved to `undefined`, `requestBodyToText()` returned `null`, and the code took its "too short / not text" fallback straight to `allow` -- no server round trip, no error, nothing to see in the console. A silent miss on exactly the traffic this feature exists to inspect, and a plausible failure mode for any modern bundled web app, not just ChatGPT.

### Fix

`agents/browser-extension/src/web-activity.js`: added `resolveBodyText(input, init)`, which tries the existing synchronous `init.body` path first and, if that comes back empty and `input` is itself a `Request` instance, falls back to `input.clone().text()` (async, since `Request` bodies are streams same as `Response` bodies). The main `fetch` wrapper now awaits this before deciding allow/post-for-decision, so both calling conventions are covered. Redaction handles the `Request`-as-`input` case too -- passing a `body` on `init` when `input` is a `Request` overrides the Request's own body per the Fetch spec, so `origFetch.call(window, input, finalInit)` still redacts correctly regardless of which convention the page used.

Bumped extension `manifest.json` to 1.0.1. Requires re-running `scripts/pack-extension.py` on the server to publish the new build; force-installed endpoints pick it up on their next `update.xml` poll (or immediately via `chrome://extensions` -> Update, or a browser restart).

---

## 🐛 Detect an unpacked copy shadowing the force-installed extension (August 18, 2026 evening)

### What happened

Hit live, on the very first real endpoint this was deployed to: the registry policy was correctly set (`ExtensionInstallForcelist` had the right entry), the scheduled task ran successfully, the server was serving the right extension id -- and Chrome still showed a Remove button. Every layer of the new mechanism was working, and it still looked broken.

Root cause: this endpoint had earlier been set up manually via "Load unpacked" (the only install method that existed before today's force-install work), from `C:\SecEoKnight\browser-extension`. Because `pack-extension.py` pins the signing key into `manifest.json`, an unpacked copy has the exact same extension id as the packaged, force-installed build -- deliberately, so the same thing you debug is what you deploy. But that means the leftover unpacked folder occupies the id slot the policy is trying to fill, and Chrome keeps showing that copy (Remove button and all) instead of the managed one. Confirmed identical to CyberSentinel-DLP's own `8c207b5` ("detect an unpacked copy shadowing the managed extension") -- they hit and fixed the exact same trap yesterday.

### Fix

Ported their diagnostic (not their whole deploy-tooling rewrite, just the detection) into `manage-agent.ps1`'s `[4] Browser` status view:
- `Get-BrowserProfileDirs` -- enumerates every Chrome/Edge profile across every Windows user account on the machine.
- `Get-ExtensionInstallSources` -- reads each profile's `Preferences`/`Secure Preferences` JSON and decodes the numeric `extensions.settings.<id>.location` field Chrome itself uses to record where an extension came from (1 = packaged crx, 4 = loaded unpacked, 10 = enterprise policy).
- `Show-BrowserControls` now calls this and, if any profile shows `location 4` for the published extension id, prints exactly which profile/folder it's coming from and the fix (Remove it in `chrome://extensions`, restart the browser) -- instead of a healthy-looking "policy set" status sitting next to a very confused admin.

### Immediate remediation for the affected endpoint

Told the user directly: `chrome://extensions` -> SeceoKnight DLP -> Remove -> close and reopen the browser. The policy is already correctly in place, so it reinstalls from the managed build on the next start.

---

## 🔧 install.sh now packages the browser extension automatically (August 18, 2026 evening)

### Why

Walking the user through a real deployment surfaced two problems the single-command installer needs to solve on its own, not leave as manual follow-up steps:

1. `python3 scripts/pack-extension.py` needs the `cryptography` package on the HOST (not the manager container), and a fresh server has neither `pip` nor `cryptography` installed by default -- hit exactly this running it live.
2. `pack-extension.py` also needs the extension's own source tree (`agents/browser-extension/`) on disk to zip -- which `install.sh` otherwise deliberately never does (see its own header comment: "no source code is ever placed on the production server"). A plain `git clone` into the install dir would work but breaks that stated principle.

### What changed

`install.sh` now packages the extension as part of the normal install flow, after the containers come up healthy:
- Installs `python3-pip` and the `cryptography` package if missing (non-fatal if it can't -- the rest of the install still completes).
- Clones the repo into a **temp directory** (`mktemp -d`), runs `pack-extension.py --out <install dir>/server/extension_dist`, then **deletes the temp clone immediately** (`trap ... EXIT` guarantees this even on early failure) -- so source code is only ever present transiently during packaging, never left on disk, consistent with the installer's existing principle.
- The signing key it generates (`/etc/seceoknightdlp/extension-signing.pem`) is the one thing that's meant to persist -- same as before, back it up.
- Every step here is best-effort/non-fatal: a server that can't package the extension for any reason still finishes installing everything else normally, same as today.

Verified by actually running the exact new block against the real, just-pushed repo (fresh clone, real packaging, real cleanup) -- confirmed correct `extension.json`/`.crx` output and that the temp directory is gone afterward, not just reading the code and assuming it works.

### Not yet done: `update.sh`

This fix is for a **fresh** `install.sh` run only. `update.sh` (used on an already-running server) doesn't call `pack-extension.py` at all yet -- an existing deployment that already has an extension published doesn't need anything, but a server that never packaged one still needs the manual command. Flagged to the user as a follow-up decision rather than silently added, since repackaging on every routine update has its own tradeoffs (repacking with an unchanged source produces the same output, but it's still worth deciding deliberately rather than bolting on).

---

## 🔍 Gap-scan CyberSentinel-DLP (second pass, August 18, 2026 evening)

Checked for updates again before continuing deployment, per request -- 6 new commits since the earlier scan, all from CyberSentinel iterating on their OWN force-install deploy/repair tooling (deleting-and-redownloading a cached extension corrupts Chrome's internal record of it; detecting "is a browser actually open" via `Get-Process` is wrong because background processes outlive closed windows; etc.).

None of it is a bug in what SeceoKnight just shipped -- confirmed by reading each commit, not assumed: SeceoKnight's `HandleApplyBrowserExtensionGuard()` never deletes on-disk extension files or toggles the forcelist entry off-and-on to force a refresh (the exact thing that kept breaking their flow); it only ever adds/updates a registry value and lets Chrome's own update-feed polling do the rest. Their "Send and Post were one gesture with two names" dashboard-matrix finding also doesn't apply -- SeceoKnight's `WebActivityControlPolicyForm.tsx` already renders one row per meaningful cell individually rather than a category-by-activity grid with cells that don't apply.

One honest caveat adopted from their findings: `manage-agent.ps1`'s Browser Controls status check reads the `ExtensionInstallForcelist` registry value, which confirms the POLICY is set, not that the browser has actually picked it up yet (Chrome/Edge only check for it at browser startup or their own periodic refresh). Reworded the status line and added a note about closing/reopening the browser to confirm, rather than let "policy set" read as "definitely protecting you right now."

---

## 🔒 Browser extension force-install + Incognito/InPrivate lockdown (August 18, 2026)

### Summary

Second gap-scan finding of the day, and a more serious one than the printer/GenAI gaps found earlier: CyberSentinel-DLP's `ac4567c` ("agent owns the browser extension's deployment") plus a string of installer fixes revealed that SeceoKnight's browser extension (Cloud Upload Guard AND today's new Web Activity Control) was only ever documented as a manual "Load unpacked" dev-mode install -- something an end user can disable in two clicks at `chrome://extensions`, with zero Incognito/InPrivate coverage anywhere in the repo. That meant both DLP browser controls built to date could be trivially bypassed. Verified this by actually reading SeceoKnight's own install scripts and agent.cpp before concluding it was missing, not assuming from the competitor's commit alone.

Checked and confirmed NOT broken by the same class of bug CyberSentinel just fixed (`a4cb6f2`, `f02edfe`): our `web-activity.js`/`masking.py` "redact"/"block" implementation does true network-level interception (buffer, classify, replace before the page sees it) rather than DOM-blur-with-CSS, and does span-based substitution on the raw request/response body rather than splitting fields apart -- confirmed both by re-reading the code and by an actual test run (see the "dashboard policy form" entry above, and the earlier chat record for the JSON-body redaction test). Those findings didn't require any changes.

### What was built

Ported in spirit from CyberSentinel-DLP's `scripts/pack-extension.py` + `server/app/api/v1/extension.py` + `agent.cpp`'s `ApplyBrowserExtensionPolicy`/`manage-windows-agent.ps1`'s private-browsing controls, adapted to SeceoKnight's existing architecture:

- **`scripts/pack-extension.py`** (new) -- generates a persistent RSA-2048 signing key (first run only), pins the public key into `agents/browser-extension/manifest.json` as `"key"` (this is what gives the extension a STABLE id shared between an unpacked dev load and the packed build -- an unpacked extension's id is otherwise derived from its folder path and differs on every machine), builds a signed CRX3 package (hand-rolled protobuf envelope, no external crx tooling needed), and writes `server/extension_dist/{seceoknightdlp.crx, extension.json}`. Verified by actually running it against the real extension directory -- confirmed it zips the correct 5 runtime files (manifest + all 4 `src/*.js`, correctly excluding `native-host/` and docs) and produces a valid CRX; the test run's throwaway key and its manifest.json changes were reverted before committing (see "Deliberately not run for real" below).
- **`server/app/api/v1/extension.py`** (new) -- three unauthenticated routes: `GET /extension/update.xml` (the gupdate feed Chrome/Edge poll, built per-request from the request's own host so one artifact works behind any reverse proxy or port), `GET /extension/info` (id/version/hash, so nothing downstream ever has an extension id typed in by hand), `GET /extension/{filename}.crx` (serves the signed package with the exact content-type Chrome requires). 404s honestly with a "run pack-extension.py" message when nothing's been published yet. Registered in `app/api/v1/__init__.py`; exempted from the IP allowlist in `app/middleware/ip_allowlist.py` (`_is_exempt`) since Chrome/Edge poll this as the browser process itself, with no credentials -- same posture as the existing agent endpoints.
- **`agents/endpoint/windows/agent.cpp`** -- new `FetchBrowserExtensionPolicy()`, called every `SyncPolicies()` cycle alongside the other `Fetch*Policy()` calls: pulls `GET /extension/info`, writes a 4-line state cache (extension id / update URL / agent id / server URL) to `C:\ProgramData\SeceoKnight\logs\browser_extension_state.cache`. Does NOT write the registry directly -- confirmed via task #147's own prior finding (documented in this same file) that the main agent process runs unelevated and `RegCreateKeyExA` under `HKLM\SOFTWARE\Policies\...` fails `ACCESS_DENIED` from it every time. Instead, a new elevated one-shot `HandleApplyBrowserExtensionGuard()` (dispatched via `--apply-browser-extension-guard`) reads that cache and writes the actual `ExtensionInstallForcelist` entry (reusing an existing slot for this extension id, or the lowest free integer -- never blindly appending, which would leave a stale entry install both old and new) plus managed config (`serverUrl`, `agentId` under `3rdparty\extensions\<id>\policy`, which the extension reads via `chrome.storage.managed`) for both Chrome and Edge policy roots. Exactly mirrors the existing Wireless Guard split (`ApplyWirelessControls`/`HandleApplyWirelessGuard`) for the identical reason.
- **`install-agent.ps1`** -- registers a new repeating SYSTEM/Highest scheduled task, "SeceoKnight DLP Browser Extension Guard" (every 2 minutes, same shape as the existing Wireless Guard task), running `seceoknight_agent.exe --apply-browser-extension-guard`. A no-op, not an error, on a server that hasn't published an extension yet.
- **`manage-agent.ps1`** -- new `[4] Browser` menu: shows per-browser extension force-install status (reading back the actual registry state, not what any script assumed it wrote) and the current Incognito/InPrivate state, plus an explicit, asked-not-assumed toggle to disable/re-allow private browsing (`IncognitoModeAvailability` for Chrome, `InPrivateModeAvailability` for Edge -- THE VALUE NAMES ARE NOT INTERCHANGEABLE, ported as a direct warning from CyberSentinel's own hard-learned bug where writing Chrome's name into Edge's key did nothing and read back looking like success). `Uninstall-Agent` now also clears the extension's `ExtensionInstallForcelist` entry and 3rdparty policy key (read from the cache before it's deleted) and removes the new guard task, so an uninstalled agent doesn't leave a browser permanently force-installing an extension pointed at a manager that no longer exists.
- **`.gitignore`** -- carved out `server/extension_dist/` from the blanket ignore rules (it's a published artifact endpoints force-install from, same reasoning as the existing Linux agent binary carve-out) while the blanket `*.pem` rule continues to protect the signing key if it's ever accidentally copied into the repo.

### Deliberately NOT run for real this session

The packaging script was run once against the real extension directory to verify it works (confirmed: correct file selection, valid CRX3 output, correct manifest key-pinning behavior) -- but using a throwaway signing key generated in this sandbox, which was then deleted along with the throwaway `manifest.json` change, before anything was committed. A real signing key is the extension's permanent identity: generating one in a sandbox that gets torn down at the end of this session, with no way to back it up, would mean the very first real force-install silently becomes unreconcilable the next time anyone re-packs. **Before this feature does anything on a real endpoint**, someone with access to persistent server storage needs to run `python3 scripts/pack-extension.py` on the actual DLP server (it will generate and save `/etc/seceoknightdlp/extension-signing.pem` -- back this up) and commit the resulting `server/extension_dist/*` files.

### Still required before this is live

Same as the GenAI/Web Activity Control entries above: nothing from today is deployed to the live server yet. In addition to those steps, this feature specifically needs: (1) `python3 scripts/pack-extension.py` run once on the server as described above, (2) a rebuilt Windows agent binary (for the `agent.cpp` changes), (3) `install-agent.ps1` re-run (or `manage-agent.ps1` → Update) on each endpoint to register the new Browser Extension Guard task, and (4) an explicit admin decision via `manage-agent.ps1` → `[4] Browser` on whether to disable Incognito/InPrivate (a browser-wide change, asked rather than assumed, exactly like CyberSentinel's own equivalent).

---

## 🆕 Web Activity Control / GenAI DLP — dashboard policy form (part 3 of 3, August 18, 2026)

### Summary

Final increment of the Web Activity Control / GenAI DLP build. Parts 1 (server foundation) and 2 (browser extension enforcement) shipped everything needed to detect and act on GenAI prompts/replies and webmail/collaboration sends, but there was no way for an admin to actually create a `web_activity_control` policy from the dashboard -- the only way to configure one was hand-writing `policy.config` JSON via the API directly. This part adds the actual policy-builder UI, completing the feature end to end.

### Deliberate scope decision: 4 rows, not a full matrix grid

`server/app/core/web_activity.py`'s `MEANINGFUL_CELLS` (set in part 1) only wires up `webmail.send`, `collaboration.send`, `genai.post`, and `genai.ai_response` -- `upload`/`attach`/`download` across all 4 app categories have nothing reaching them yet (see part 1/2 entries for why). A full 4-category x 6-activity checkbox/dropdown grid would render 24 controls, 20 of which would silently do nothing if configured -- the same trap already avoided once when narrowing `MEANINGFUL_CELLS` itself. So `WebActivityControlPolicyForm.tsx` renders exactly 4 rows, one per meaningful cell, each with a 5-way picker (Not configured / Allow / Alert / Redact / Block). Every control on the form does something real.

### Config shape

`policy.config` is `{ matrix: { "genai.post": "block", "genai.ai_response": "redact", ... } }` -- the flat string keys match `wa.cell_key()` server-side exactly (`"{category}.{activity}"`), so the form's output round-trips through the generic policies create/update endpoints unmodified, saved verbatim into `policy.config` the same way `printer_control`/`file_identity_denylist`/etc. already work (confirmed by reading `policies.py`'s create/update handlers in part 1 -- config is never reshaped server-side for this policy type). `server/app/api/v1/agents.py`'s `evaluate_web_activity()` (part 1) reads `(policy.config or {}).get("matrix")` directly, matching this shape.

### What was built

- **`dashboard/src/types/policy.ts`** -- added `'web_activity_control'` to the `PolicyType` union, new `WebActivityAction` (`allow`/`alert`/`block`/`redact`) and `WebActivityControlConfig` (`{ matrix: {...4 optional cell keys...} }`) types, added to the `PolicyConfig` union.
- **`dashboard/src/components/policies/WebActivityControlPolicyForm.tsx`** (new) -- the 4-row form described above, following the established form-component contract (`{ config, onChange }` props) used by every other traditional policy type.
- **`dashboard/src/components/policies/PolicyTypeSelector.tsx`** -- added the "Web Activity Control (GenAI DLP)" tile to the type-selection grid.
- **`dashboard/src/components/policies/PolicyCreatorModal.tsx`** -- added the new config type to the `TraditionalPolicyConfig` union, a `getDefaultConfig()` case (`{ matrix: {} }`), and the conditional render block for the new form, matching the pattern every other policy type already uses.
- **`dashboard/src/utils/policyUtils.ts`** -- added `web_activity_control` cases to `getPolicyTypeIcon` (Bot icon), `getPolicyTypeLabel`, `formatPolicyConfig` (lists configured cell:action pairs, or "No activities configured yet"), and the internal `getDefaultConfig` helper `transformApiPolicyToFrontend` falls back to.

No changes needed to `policyUtils.ts`'s `validatePolicy` -- like `network_share_transfer_control`/`print_content_prevention`/`messaging_app_control`, the default config (`{ matrix: {} }`, meaning "nothing configured yet") is always structurally valid; an admin can save a policy with zero rows set (equivalent to "off"), same posture as the other config-driven policy types.

### Verified

`npx tsc --noEmit` across the dashboard: same 24 pre-existing, unrelated errors present before this change (all in `ClassificationPolicyForm.tsx`, `ClipboardPolicyForm.tsx`, `GoogleDriveCloudPolicyForm.tsx`/`OneDriveCloudPolicyForm.tsx`, pre-existing `PolicyCreatorModal.tsx` `SetStateAction` typing gaps, `PolicyDetailsModal.tsx`, `PolicyRow.tsx`, `RuleModal.tsx`, `lib/utils.ts`) -- zero new errors introduced by this change.

### Still required before this is live

This completes the 3-part build in the repository, but nothing in any of the 3 parts is deployed to the live server yet. Deploying requires: `sudo bash update.sh` on the server (applies migrations 038 and 039, deploys the new API endpoints and this dashboard UI); rebuilding and deploying a new Windows agent binary (for the printer explicit-deny `agent.cpp` changes from earlier today); and rebuilding and deploying the updated browser extension package (for this whole GenAI/Web Activity Control feature -- parts 1-3 all need the extension update to do anything).

---

## 🆕 Web Activity Control / GenAI DLP — browser extension enforcement (part 2 of 3, August 18, 2026)

### Summary

Second increment following the server-side foundation (part 1). This wires the browser extension up to actually detect GenAI prompts/replies and webmail/collaboration message sends, call the new `/web-activity/evaluate` endpoint, and enforce allow/alert/block/redact in real time -- including live redaction of a GenAI response before it reaches the page. Part 3 (dashboard policy-builder UI) is still separate and not yet built, so there's currently no way for an admin to actually turn this on from the dashboard -- deploying this part alone changes nothing observable yet, same "safe to deploy standalone" posture as part 1.

### Deliberate scope decision: a new, separate interceptor file

Added `agents/browser-extension/src/web-activity.js`, loaded AFTER the existing `inject.js` in the manifest, rather than extending `inject.js` itself. `inject.js` is the mature, already-hardened Cloud Upload Guard file-upload interceptor (chunked-upload coalescing, real file capture, filename recovery, ...) -- editing it directly for a materially different, newer feature risked regressing a well-tested path. The two compose safely (each patches `window.fetch` once, in sequence; the second only acts on hosts/bodies it cares about and calls through to the first otherwise).

**What's covered end to end:** `post` (a text prompt sent to a GenAI destination -- ChatGPT, Copilot, Gemini, Claude, ...), `send` (a substantial composed-message body to webmail/collaboration, best-effort text-length heuristic since there's no reliable way to detect "the user clicked Send" from network traffic alone), and `ai_response` -- the reply streaming back from a GenAI destination, the actual headline capability this whole feature exists for.

**What's explicitly NOT covered by this part (documented, not silent):** `upload`/`attach`/`download` file-bearing activities still route through the OLDER, separate `CLOUD_HOSTS`/native-host `classify` path so the same file upload is never double-submitted/double-logged through two different classifiers -- unifying the two upload paths is future work. Matching this, `web_activity.py`'s `MEANINGFUL_CELLS` was narrowed in part 1 to only the cells this extension build actually reaches (`webmail.send`, `collaboration.send`, `genai.post`, `genai.ai_response`) rather than advertising cells nothing currently triggers. XHR-based streaming responses aren't intercepted either (modern GenAI chat UIs overwhelmingly use `fetch()` + `ReadableStream`).

### How `ai_response` redaction actually works

`window.fetch` is wrapped so that for a watched host, `resp.clone().text()` reads a COPY of the response body for classification while the original `resp` (and its stream) is left completely untouched -- if the verdict is "allow", the pristine original `Response` object is returned to the page. If "redact", a new `Response` is constructed from the server's redacted text (with `content-length`/`content-encoding` headers stripped, since a redacted body is neither the original byte length nor still gzip/br-encoded). If "block", an empty `403`-equivalent `Response` is returned instead.

Honest limitation: this whole decision requires the FULL response text to be buffered and classified before ANYTHING is returned to the page, which means live token-by-token streaming rendering is sacrificed for any GenAI reply while this feature is active -- there's no way to guarantee a sensitive value never reaches the page mid-stream without waiting for the stream to finish first. This only engages at all when the server reports a `web_activity_control` policy is actually active (`web_activity_enforced`), so an installation that hasn't configured this feature pays zero streaming-latency cost.

### What was built

- **`agents/browser-extension/src/web-activity.js`** (new) -- the interceptor described above.
- **`agents/browser-extension/manifest.json`** -- loads the new file after `inject.js` in the same MAIN-world content script entry.
- **`agents/browser-extension/src/content.js`** -- relays the new `webActivity` classify request / `webActivityDecision` response message pair (parallel to the existing `classify`/`decision` pair, kept fully separate), plus the `appCatalog` domain-list push (mirrors the existing `extraHosts` push) and a new on-page banner for block/redact/alert notices.
- **`agents/browser-extension/src/background.js`** -- new `waWaiters` map (deliberately simpler than the existing upload-coalescing `waiters`/`inFlightByKey`, since GenAI prompts/replies aren't chunked the way uploads are), a longer `WEB_ACTIVITY_TIMEOUT_MS` (16s vs. the existing 7s, since classifying a full GenAI reply takes longer than a small upload decision), and `fetchAppCatalog()` refreshed on the same alarm/startup triggers as the existing extra-hosts fetch.
- **`agents/browser-extension/native-host/skdlp_host.py`** -- new `evaluate_web_activity()` (calls `POST /agents/{id}/web-activity/evaluate`), `emit_web_activity_event()` (logs to `/events` with `event_type=web_activity`), `handle_web_activity()`, and `fetch_app_catalog()` (calls the new agent-facing `GET /agents/{id}/app-catalog`) -- all parallel to the existing cloud-upload-only functions, wired into the message loop as new `web_activity`/`get_app_catalog` message types that don't touch the existing `classify`/`get_hosts` handling at all.
- **`server/app/api/v1/agents.py`** -- new `GET /agents/{agent_id}/app-catalog`, mirroring the existing `get_cloud_upload_hosts` pattern: returns the watched-domain list plus `web_activity_enforced` (whether any `web_activity_control` policy is currently active), which is what lets the extension skip the response-buffering interception path entirely when the feature isn't configured.

### Verified

`node --check` on all four modified/new JavaScript files and `python3 -m json.load` on manifest.json (valid JSON after the content-script array change) -- no browser/extension runtime available in this environment to load-test the actual extension, so this needs a real end-to-end test on your Windows endpoint the way File Identity Denylist and other agent-side features were tested earlier (build/deploy the extension, visit a GenAI site, confirm the native host log shows `web_activity` requests and a configured policy actually blocks/redacts).

---

## 🆕 Web Activity Control / GenAI DLP — server-side foundation (part 1 of 3, August 18, 2026)

### Summary

First increment of the GenAI/web-activity control feature flagged in the previous gap-scan entry (the one deliberately deferred pending explicit user choice) — user chose "full build now." Design ported in spirit from CyberSentinel-DLP commits f435920/d3ed5e4/f02edfe, but built natively for SeceoKnight's own architecture rather than copied file-for-file, since their reference is Python-server + JS-extension while ours pairs a Python server with a C++ Windows agent and a separate browser extension.

This part is the server-side foundation only — the browser extension (GenAI/activity detection, real-time enforcement) and the dashboard policy-builder UI are separate, not-yet-built increments (parts 2 and 3). Nothing user-facing changes yet: no policy type exists in the dashboard to configure this, so the new endpoints are unreachable until the extension and UI land. Safe to deploy standalone -- purely additive (new tables/endpoints), touches nothing existing.

### What was built

- **`server/alembic/versions/039_app_catalog.py`** + **`server/app/models/app_catalog.py`** -- new `app_catalog` table classifying destination hostnames into `webmail | file_sharing | collaboration | genai`. Seeded with SeceoKnight's existing CLOUD_HOSTS baseline (re-categorized) plus the major GenAI vendors (ChatGPT, Copilot, Gemini, Claude, Poe, Perplexity, Character.AI, Hugging Face) -- previously entirely absent from the product; a repo-wide search for any GenAI vendor before this returned nothing.
- **`server/app/api/v1/app_catalog.py`** -- CRUD for the catalog (admin-only writes, analyst reads), same RBAC pattern as printers.py/usb_devices.py.
- **`server/app/core/web_activity.py`** -- the shared vocabulary (app categories x six activity types: upload/download/attach/send/post/ai_response x four actions: allow/alert/block/redact), defined once so the policy engine, the evaluate endpoint, and (in part 2) the extension can't drift from each other -- same lesson CyberSentinel's own commit called out.
- **`server/app/core/masking.py`** -- the new "redact" action's engine. classification_engine.py's rule matching uses `pattern.findall()` (positions not tracked, by design -- teaching the hot path every clipboard/USB/print/email event goes through to carry offsets would cost latency everywhere to serve a decision only this new path reaches). This module is a separate, additive pass: re-runs ONLY the rules that already matched, using `finditer()`/substring search to recover spans, then substitutes `[LABEL_N]` placeholders. Verified with a functional test (not just syntax-checked) reproducing CyberSentinel's own worked example exactly: `"Rahul Menon, Aadhaar 4321 8765 1234, card 4111 1111 1111 1111"` → `"Rahul Menon, Aadhaar [AADHAAR_1], card [CREDIT_CARD_1]"`. Disclosed limitation: dictionary-type rules aren't redacted (their match offsets aren't available without loading the dictionary file this module doesn't otherwise depend on) -- they still count toward classification, just don't get their own span replaced.
- **`server/app/utils/policy_transformer.py`** -- new `web_activity_control` case. Unlike every other policy type here, the matrix (up to 13 meaningful cells) doesn't fit the generic one-actions-dict-per-policy shape the DatabasePolicyEvaluator uses -- trying to force it through would need one Policy row per cell or silently collapse to one arbitrary cell winning (the exact bug class task #151 found in a different policy type). So the transformer emits an inert placeholder and the real matrix is read directly from `policy.config` by the new evaluator below, same approach CyberSentinel itself used for this same reason.
- **`server/app/api/v1/agents.py`** -- new `POST /agents/{agent_id}/web-activity/evaluate`. Classifies the destination host via app_catalog (unrecognized host -> immediate allow, not a watched destination), looks up the active `web_activity_control` policy's matrix cell for (category, activity), classifies the content when present, then gates the configured action on what was actually found: `block`/`alert` only fire when content is genuinely sensitive (Confidential/Restricted for block, Internal+ for alert), `redact` only fires when there's something to redact -- same content-aware philosophy as every other channel in this product, never a blunt "block all traffic in this channel regardless of content" rule. A separate endpoint from the existing `evaluate_policy_realtime`, not a branch inside it, since the evaluation shape is fundamentally different (config-matrix read vs. generic conditions/rules matching).

### Verified

`python3 -m ast` parse-check on all nine new/modified server files. Real import test against the live model registry (`from app.models import AppCatalogEntry, Policy, Rule` — confirms no SQLAlchemy mapper conflicts, not just valid syntax). Functional tests of `web_activity.classify_host()` (exact + subdomain matching), `normalize_matrix()`/`lookup_action()` (drops invalid cells/actions correctly), and `masking.redact_content()` (both the Aadhaar/credit-card worked example above and a case-insensitive multi-occurrence keyword-rule redaction) against fake DB/Rule objects standing in for a real Postgres session. `tsc --noEmit` on the dashboard shows zero new errors (no dashboard files touched in this part). Not deployed yet -- will deploy alongside part 2/3 once there's a way to actually configure and trigger this from the dashboard.

---

## 🔍 Gap-scan CyberSentinel-DLP (4-day batch) + port printer explicit-deny (August 18, 2026)

### Summary

Follow-up gap-scan at the user's request, checking the live `effaaykhan/cybersentineldlp-prod` GitHub repo for anything shipped since the last check (task #154, August 13/14). 36 commits had landed in the intervening 4 days.

### What was checked and skipped

- 11 commits consolidating their dashboard's dialog/modal design system ("one overlay instead of nineteen," shared form kit, colour tokens) -- internal UI consistency work on their end, not a DLP capability. SeceoKnight has its own coherent design system already.
- SSO/SIEM role + ABAC mapping (`ad46e71`) -- wiring their DLP into their own separate SIEM product's role vocabulary. Not relevant unless we're integrating an actual SIEM.
- Extension/CI build plumbing (force-install packaging, repack idempotency, versioning) -- deployment mechanics for their specific browser-extension pipeline.
- USB "honour an explicit denial when the manager is unreachable" (`98b47af`) -- checked against our own `get_usb_allowlist()` and confirmed we do NOT have this bug: our design is strict default-deny (a denied serial and an unlisted serial already have the identical effect in enforce mode), so there's no failure mode to inherit here.

### The big one, deliberately deferred: GenAI / web-activity control + real-time redaction

CyberSentinel shipped a new control layer (`f435920`, `d3ed5e4`, `f02edfe`): a matrix of app category (webmail / file-sharing / collaboration / **generative AI** -- ChatGPT, Copilot, Gemini) crossed with activity type (upload / download / attach / send / post / **AI response**), each cell settable to allow/block/**redact**/alert. Redact strips just the sensitive values out of the live outgoing payload (not just what gets logged) and lets the rest through.

Confirmed SeceoKnight has zero GenAI/AI-chat coverage anywhere in the codebase, and our browser extension's actual scope is narrowly "Cloud Upload Guard" (upload-to-cloud-host interception only). Their base matrix alone was ~2,400 lines across 17 files. This is a real, current gap (LLM leakage is a live 2026 DLP concern) but is multi-day feature work comparable to the SMTP relay or Data Matching builds -- deliberately scoped as a separate initiative per the user's explicit choice, not started this session.

### What was built: printer explicit-deny

`b7dc3f3` added a `decision` ('allow'|'deny') column to CyberSentinel's printer registry, checked in every policy scope, so a single printer can be explicitly blocked without moving the whole fleet into allowlist mode. Checked our own `SanctionedPrinter`/`printers.py`/`get_printer_policy()` and confirmed the identical limitation: allow-only (`is_enabled` bool), and the sanctioned list is only even consulted when scope=="allowlist". Also found and fixed two stale docstrings/UI copy claiming "the Windows agent doesn't monitor print jobs yet, so nothing is enforced" -- that was true when this module was first ported but is no longer accurate since tasks #114/#130-133 shipped real print device-control and content-inspection enforcement.

- **`server/alembic/versions/038_printer_deny.py`** -- adds `decision VARCHAR(10) DEFAULT 'allow'` to `sanctioned_printers`.
- **`server/app/models/sanctioned_printer.py`** -- added `decision`, mirroring the exact pattern `SanctionedUsbDevice.decision` already uses (tasks #58-59).
- **`server/app/api/v1/printers.py`** -- `approve_printer`/`update_printer` accept `decision`; `list_printers` returns `allow_count`/`deny_count` alongside the existing list, same shape as the USB devices endpoint. Corrected the stale "no agent enforcement" docstrings.
- **`server/app/api/v1/agents.py`** -- `get_printer_policy()` now returns `denied_printers` (deny-decision rows) **unconditionally**, regardless of `scope` -- unlike the existing `printers` allow-list, which still only ships in `scope=="allowlist"` as before.
- **`agents/endpoint/windows/agent.cpp`** -- new `deniedPrinters` set, populated in `FetchPrinterPolicy()`. `ShouldBlockPrinter()` checks the deny set first, in every scope, before falling back to the existing scope-based allow logic.
- **`dashboard/src/lib/printers-api.ts`** + **`dashboard/src/pages/Printers.tsx`** -- rebuilt the Printers page to split into "Sanctioned" and "Disallowed" sections with a flip button per row, same UX pattern as the USB Devices page. Corrected the page's stale "nothing is blocked" warning banner.

### Verified

`python3 -m ast` parse-check on all modified server files; a manual brace-balance check on the two touched `agent.cpp` functions (the whole-file naive scanner reports a false imbalance elsewhere in this 10k+-line file due to raw string literals it doesn't parse, same caveat noted for prior C++ edits); `tsc --noEmit` shows zero new dashboard type errors (same 25 pre-existing, unrelated errors as before). Not yet deployed -- needs `update.sh` (runs the migration) plus a new Windows agent binary + Update on endpoints, same two-step deployment as File Identity Denylist (task #152).

---

## 🔍 Gap-scan live CyberSentinel-DLP GitHub repo + port IP Allowlist master toggle (tasks #153/#154, August 13, 2026)

### Summary

User asked us to check whether CyberSentinel-DLP had shipped anything today that SeceoKnight is missing. The locally mounted `CyberSentinel-DLP` folder used for prior gap-scans (tasks #25/#93/#105/#119/#134) turned out to be a stale, non-git snapshot frozen around July 17, 2026 -- useless for checking "today." The user then supplied the actual live upstream: `https://github.com/effaaykhan/cybersentineldlp-prod`. Cloned it fresh (`git clone --depth 30`, public repo) and read real commit history/diffs instead of guessing from commit titles.

### What was checked

- **Today's commit** (`9b589f7`, "Fixed the CI logic with SHA tags") -- pure CI/build tooling (`.github/workflows/*.yml`, their `csdlp` ops CLI, `DEPLOYMENT.md`). No DLP-functionality content.
- **"Implemented TLS 1.3"** (`639cbe3`) -- misleading title; the diff is only deletions of three old install/uninstall/update PowerShell scripts (replaced by the `csdlp` consolidated CLI), not a TLS change.
- **"Added Nuitka flow for compilation"** (`8f19d2f`) -- compiles their Python server to a native binary via Nuitka for obfuscation/perf. Packaging choice, not a DLP capability; SeceoKnight's server ships as a normal Python/FastAPI container. Not pursued.
- **"Added Whitelist Toggle, improved network exfiltration, added thick clients"** (`0003851`) -- the network-exfil CLI (aws/rclone/s3cmd/azcopy/scp/pscp/winscp.com blocking) and thick-client messaging attachment control (Teams/WhatsApp/Telegram/Slack/Discord/Signal, alert-by-default/block-when-policy-opts-in) described in this diff match what SeceoKnight already ported in tasks #121 and #115/#137-140 -- already covered.
- **"Fixed numerous bugs, added hash capabilities, implemented policy import/export"** (`b3618b9`) -- policy import/export UI, pagination, incident coalescing script all match SeceoKnight's existing tasks #79/#80/#81 -- already covered.

### The one genuine gap found: IP allowlist had no master on/off switch

`0003851` also added a **master toggle** to CyberSentinel's IP-allowlist settings section (`IpAllowlistSection.tsx` + `toggleIpAllowlist`). SeceoKnight already has IP allowlisting (`server/app/middleware/ip_allowlist.py`, task #25-era port), but "enforced" was purely derived from *"does at least one entry have `is_enabled = true`"* -- there was no independent switch. To pause enforcement (e.g. an admin troubleshooting from a new office), you had to disable or delete every configured CIDR one at a time and remember to re-add them later. A single pause/resume switch that preserves the configured ranges is a real, low-risk usability/safety improvement, so it was ported.

### What was built

- **`server/alembic/versions/037_ip_allowlist_master_toggle.py`** -- new singleton table `ip_allowlist_settings (id=1, enabled boolean default true, updated_by, updated_at)`, seeded on migrate. Defaults to `enabled=true` so existing behavior is unchanged until someone touches the new switch.
- **`server/app/models/ip_allowlist.py`** -- added `IPAllowlistSettings` model alongside the existing `IPAllowlistEntry`.
- **`server/app/api/v1/ip_allowlist.py`** -- `GET /security/ip-allowlist` now also returns `enabled` (the master flag) separately from `enforced` (master flag AND >=1 enabled entry); new `POST /security/ip-allowlist/toggle` (admin-only, audit-logged as `security.ip_allowlist.toggle`).
- **`server/app/middleware/ip_allowlist.py`** -- `_load_nets()` now reads `ip_allowlist_settings.enabled` first and short-circuits to fail-open (empty net list) if the master switch is off, regardless of how many CIDRs are configured. If the settings table doesn't exist yet (pre-migration), the existing DB-failure handler already fails open safely -- no crash risk during rollout.
- **`dashboard/src/lib/api.ts`** + **`dashboard/src/components/settings/IpAllowlistSection.tsx`** -- added `toggleIpAllowlist()` and a switch UI next to the "Authorized IP Addresses" header, with three distinct states surfaced to the admin: **Off** (master switch disabled, ranges kept), **Not enforced** (master on but zero configured ranges), **Enforcing** (master on, >=1 active range).

### Verified

`python3 -m ast` parse-check on all four modified/added server files, `tsc --noEmit` on the dashboard confirms zero new type errors (the 25 pre-existing errors in unrelated files are untouched). Not yet deployed to the live server -- requires the standard `update.sh` cycle (runs alembic migrations automatically) plus a dashboard image rebuild, same as tasks #150-152.

---

## 🆕 Build File Identity Denylist agent-side enforcement from scratch (task #152, August 13, 2026)

### Summary

Before configuring this policy type for testing, checked whether it was actually wired end-to-end -- it wasn't. The dashboard create-policy form existed, and the server-side config transform (`_transform_file_identity_denylist_config`) correctly produced valid `conditions`/`actions` in the Policy table. But a full grep across `agent.cpp` for "denylist"/"file_identity" found zero matches: no agent-facing GET endpoint, no fetch function, no check function, nothing. Configuring a File Identity Denylist policy in the dashboard did literally nothing on any Windows endpoint -- worse than the Network Share bug (task #151), which at least had broken enforcement; this had none at all.

### What was built

- **Server**: `GET /agents/{id}/file-identity-denylist` in `agents.py`, mirroring the existing `application-control`/`wireless-policy` pattern -- picks the highest-priority active `file_identity_denylist` Policy row, returns `{enforced, action, extensions, hashes}`.
- **Agent**: `FetchFileIdentityDenylist()` (polled on the standard policy-sync cadence, keeps last-known-good on error), `IsFileDenylisted()` (checks extension first, only computes a SHA-256 hash if the extension didn't match and a hash list is configured -- avoids hashing every file for an extension-only policy), `QuarantineDenylistedFile()` (copy-then-delete, cross-volume safe, same pattern as `QuarantineNetworkShareFile`), `SendFileIdentityDenylistEvent()`.
- **Hook points**: `HandleNetworkShareNewFile()` and `HandleRemovableDriveFile()` (USB) -- the two channels that already reliably detect a file crossing an exfiltration boundary. Checked independently of each channel's own mode/policies, so a denylist match fires even if e.g. Network Share Transfer Control itself is set to "off".

### Known scope gap (documented, not silently skipped)

**Not** wired into `FileSystemMonitor()` (plain local file creation/modification). That thread only watches directories sourced from separate File System Monitoring policies (`monitoredDirectories`) -- a denylist-only deployment with no File System Monitoring policy configured would never see local file-write events at all. Covering that would need a general "watch everything" mechanism this agent doesn't have. Flagging as a follow-up rather than claiming full coverage.

---

## 🔧 Fix Network Share Transfer Control never blocking -- missing policy dispatcher case (task #151, August 13, 2026)

### Summary

After tasks #148 and #150 fixed the classification pipeline itself, retesting still showed `Decision: allow` for a file that classified at `Confidence: 100% / Level: Restricted`. Traced it to `policy_transformer.py`'s `transform_frontend_config_to_backend()` dispatcher: it had no case for `network_share_transfer_control`, so it fell through to the unknown-type branch and returned empty `conditions.rules`. `DatabasePolicyEvaluator.evaluate_event()` unconditionally skips any policy with empty rules -- so every content_aware Network Share Transfer Control policy anyone has ever created silently matched nothing, regardless of classification result.

This is a real, complete enforcement gap, not just a dashboard reporting bug: `evaluate_policy_realtime()`'s `should_block` only ever becomes `True` from an actual `DatabasePolicyEvaluator` match or a Data Matching hit -- there is no "classification says Restricted, block anyway" fallback anywhere in the pipeline.

Fixed by adding `_transform_network_share_transfer_config()`: content_aware mode now matches `event_subtype == network_share_transfer` AND `classification_level in [Confidential, Restricted]`, with block+alert or alert-only actions depending on the configured action. Also corrected a prior docstring note that had incorrectly grouped this policy type with the genuinely agent-side-only ones (wireless/print/printer control) as a "reporting-only" gap.

**Important:** existing Policy rows created before this fix have the old empty conditions baked into the database -- the transform only runs at create/update time. Any already-created Network Share Transfer Control policy needs to be opened and re-saved via the dashboard to pick up the fix.

---

## 🔧 Fix ML blend diluting high-confidence rule matches below block threshold (August 13, 2026)

### Summary

Retested Network Share Transfer Control after task #148's log-truncation fix, this time with genuine non-canonical content (`Customer SSN: 234-56-7890` + a Luhn-valid, non-test-value credit card number). Both rules matched at full weight and the false-positive check correctly cleared it (not a known test value, no example/test wording) -- yet the file still came back `Level: Confidential, Confidence: 71%, Decision: allow`.

Root cause: `_combine_scores()` blends rule confidence (50%), ML confidence (30%), and context adjustment (20%) into one score. With `rule_confidence=1.0` and `is_false_positive=False`, the raw blend was `1.0*0.5 + 0.7*0.3 + 0.0*0.2 = 0.71` -- a middling ML sub-score alone dragged an already fully-validated, dual-signal rule match (Luhn-checked card + format-matched SSN) down from what should be certain-Restricted to Confidential/allow, with zero false-positive evidence involved.

Fixed by flooring the blend: once content isn't flagged a false positive and `rule_confidence >= 0.8` (the same cutoff `_determine_classification` uses for Restricted), `combined = max(combined, rule_confidence)`. The ML score can still pull down weaker/ambiguous rule matches below 0.8, but can no longer single-handedly override a validated high-confidence detection. Added regression tests reproducing the exact live scenario (`test_high_confidence_rule_match_not_diluted_by_ml`) and the floor boundary (`test_high_confidence_floor_boundary`); adjusted the existing weighted-blend test to use a sub-floor rule confidence so it still isolates the raw math.

This is the third distinct classification-engine issue found via live end-to-end testing today (see also the KNOWN_TEST_VALUES false-positive explanation and the matched_rules array-truncation fix below) -- underscores why testing with real, non-canonical values matters: the known-test-value suppression was masking this separate, more serious bug the first time around.

---

## 🔍 Explain Network Share Transfer Control "allow" result + fix agent log truncation bug (August 13, 2026)

### Summary

Live-tested Network Share Transfer Control (`content_aware` mode) against a real UNC share (`\\192.168.1.4\d\Vaibhav`) with a test file containing `Customer SSN: 123-45-6789` and `Test card: 4111111111111111`. The file was evaluated but **allowed** (`Level: Public, Confidence: 25%`), while the local screen-capture/OCR classifier scanning the same content two seconds later correctly scored it `Restricted` (`score=1.8`). This looked like a real detection gap between two classification engines.

### Root cause: not a bug -- both test values are hardcoded false-positive suppressions

`server/app/services/context_analyzer.py`'s `KNOWN_TEST_VALUES` list explicitly includes `"123-45-6789"` (labeled "Universal test SSN") and `"4111111111111111"` (labeled "Visa test card") -- these are two of the most widely used placeholder/sandbox values in the industry (tutorials, Stripe/payment test docs, etc.), and the classification engine is deliberately built (see `ENTERPRISE_AUDIT.md`) to recognize known test/example values and suppress them so they don't trigger blocking actions in production.

`classify_content()` in `classification_engine.py` still runs the full regex pipeline first -- both the SSN rule (weight 0.9) and Credit Card Number rule (weight 0.95) matched, giving `rule_confidence = min(1.0, total_weight) = 1.0`. But `_combine_scores()` then hard-caps any content flagged as a false positive: `min(0.25, rule_confidence * 0.3) = min(0.25, 0.3) = 0.25` -- exactly the observed 25%, which lands under the 0.3 "Internal" cutoff and rounds down to `Public`/`allow`. The math confirms this is the exact code path, not a coincidence.

This explains the earlier-observed inconsistency too: the local OCR/screen-capture classifier (`stage4-ocr` in the Windows agent) has no context-analyzer/false-positive-reduction logic at all -- it's a simpler, standalone pattern matcher, so it has no mechanism to recognize "these are textbook example values" and correctly flagged them as Restricted. The server-side `ClassificationEngine` (used by Network Share Transfer Control and USB Transfer via `EvaluatePolicyRealtime()`) is the newer, more sophisticated path, and is working exactly as designed.

**Action for re-testing:** use a non-canonical fake SSN/card (any properly-formatted but not-industry-famous value, e.g. not `123-45-6789` / `4111111111111111` / the other entries in `KNOWN_TEST_VALUES`) to verify the underlying block/allow decision still fires correctly for Network Share Transfer Control.

### Real bug found and fixed along the way: agent log silently dropped matched rules past the first

While tracing this, found that `agent.cpp`'s `EvaluatePolicyRealtime()` response parser used `classificationObj.find("]", arrayStart)` to find the end of the `matched_rules` JSON array. Every matched-rule object contains its own nested array (`classification_labels: [...]`), so this naive search almost always landed on the closing bracket of the *first* rule's nested array instead of the outer array -- silently truncating the parsed rule list to one entry. This is why the agent log only ever printed `Credit Card Number` even when the server-side response actually matched both the SSN and Credit Card Number rules. Doesn't affect the block/allow decision (that comes from a separate top-level `action` field) -- it only under-reported detected data types in the log, which still matters for audit/triage accuracy. Fixed by reusing the existing depth-aware `FindMatchingBracket()` helper instead of a plain `find("]")`.

---

## 🔧 Fix CLI Guard IFEO writes: main agent task runs unelevated, needs a separate SYSTEM task (August 13, 2026)

### Summary

Following the previous fix's diagnostic logging, live testing traced the `rc=5 (ACCESS_DENIED)` failures to their real root cause -- and it had nothing to do with antivirus. `Get-ScheduledTask` showed the main **"SeceoKnight DLP Agent"** task runs as the logged-in user with `RunLevel: Limited` (a standard, non-admin token) -- this is a *deliberate* choice documented in `install-agent.ps1`: clipboard hooks, keyboard/mouse monitoring, and UI Automation all silently break under Windows UIPI if this process runs elevated. A standard user's token only has `ReadKey` on the Image File Execution Options registry path (confirmed via `Get-Acl`), so `RegCreateKeyExA` from that process was *guaranteed* to fail every time, regardless of Defender/AV settings. An elevated interactive PowerShell succeeded earlier purely because it used a different (admin) token, not because anything about the write itself was special.

### Why this wasn't caught before shipping the previous two fixes

Both earlier fixes (the CLI Guard feature itself, and the `SetIFEODebugger` error-logging fix) were correct in isolation -- they just assumed the calling process had the privilege to make the registry write succeed, which is true for the existing fsquirt.exe/Bluetooth IFEO block (task #113) *only because that gap was never actually verified live either* (flagged as a follow-up in the previous CHANGELOG entry, now elevated from "worth re-checking" to "very likely also broken" -- same code path, same unelevated caller).

### Fix

Mirrors the fix already used for the identical problem with USB blocking (`install-agent.ps1`'s existing `SeceoKnight DLP USB Block` task): added a new standalone agent mode, `seceoknight_agent.exe --apply-ifeo-guards` (`HandleApplyIfeoGuards()` in agent.cpp), that does nothing but register the 9 CLI Guard IFEO Debugger keys and exit. `install-agent.ps1` now registers a new **`SeceoKnight DLP CLI Guard`** scheduled task -- SYSTEM/Highest, `AtStartup` with a 15s delay, one-shot -- that runs it, and also triggers it once immediately at install time so the fix takes effect without waiting for a reboot. The main agent process no longer attempts this write itself (removed the doomed-to-fail call from `DLPAgent::Start()`, which was previously spamming an ERROR line every single startup for a failure it could never fix from that context). `manage-agent.ps1`'s `Uninstall-Agent` now also removes this new task alongside the other three.

### Not fixed here: fsquirt.exe / wireless control (task #113)

`ApplyWirelessControls()`'s `fsquirt.exe` IFEO block runs from the exact same unelevated main process and almost certainly has this exact same bug -- meaning the Bluetooth file-transfer block has likely never actually worked on any real deployment. Not fixed in this pass because it's architecturally harder: unlike CLI Guard (a static, always-on registration done once), wireless control is *dynamic* -- it needs to react to live policy changes (enforce/blockBt/blockNearby toggling), which a simple one-shot elevated task can't do on its own. Needs either a periodic elevated task that reads a cache file the main process writes, or an IPC bridge to a persistent elevated helper. Flagging as a real, confirmed follow-up, not a hypothetical one.

### Deployment

Windows agent (C++) + installer changes -- `agent.cpp`, `install-agent.ps1`, `manage-agent.ps1`. CI rebuilds the binary automatically. Existing installs need to re-run the install one-liner to pick up both the new binary and the new scheduled task; a fresh install gets it automatically.

---

## 🔧 Fix SetIFEODebugger silently swallowing registry write failures (August 13, 2026)

### Summary

Live testing of the CLI Guard feature below found it had no effect at all: `Get-ItemProperty` on `HKLM:\...\Image File Execution Options\curl.exe` came back empty even though the log clearly showed `CLI Guard (IFEO zero-race pre-launch) installed for 9 executables` and the pipe server thread had started. `SetIFEODebugger()` (used by both this feature and the existing Bluetooth fsquirt.exe block from task #113) never checked the return value of `RegCreateKeyExA`/`RegSetValueExA` — a failed write and a successful one produced byte-for-byte identical log output, so there was no way to tell from the log that anything had gone wrong.

### Fix

`SetIFEODebugger()` now checks and logs every registry API return code. If `RegCreateKeyExA` fails with `ERROR_ACCESS_DENIED` specifically, the log now says so explicitly and flags the likely cause: writing a `Debugger` value under Image File Execution Options for a well-known executable is a documented technique (MITRE ATT&CK T1546.012, "IFEO Injection") that antivirus and EDR real-time protection commonly block by default, even for a legitimate agent doing it for defensive reasons. Re-test after this fix will surface the actual Win32 error code so the real cause (AV block vs. a permissions/service-account issue vs. something else) can be confirmed rather than guessed at.

### Note

This same silent-failure gap has existed since task #113 (Bluetooth fsquirt.exe block) — if that write has also been silently failing on any endpoint, the Bluetooth transfer block would have been a no-op there too despite the log/dashboard showing "wireless controls applied". Worth re-verifying fsquirt blocking on a real endpoint once CLI Guard is confirmed working, using the same registry check.

---

## 🔧 Fix fsquirt.exe/Bluetooth block: same unelevated-process bug as CLI Guard, now confirmed live (August 13, 2026)

### Summary

Live-tested the Wireless/Bluetooth Transfer Control policy for the first time since it shipped (task #113) -- exactly the concern flagged in the CLI Guard fix's CHANGELOG entry. Result: confirmed broken. Policy sync worked correctly (`Wireless control: enforced=true mode=enforce bt_file_transfer=block`), but `Get-ItemProperty` on the `fsquirt.exe` IFEO key came back empty, and the log showed the identical failure as CLI Guard: `SetIFEODebugger: RegCreateKeyExA failed for fsquirt.exe rc=5`. Same root cause as task #145 -- the main "SeceoKnight DLP Agent" task runs unelevated (`RunLevel: Limited`) on purpose, and a standard user's token only has `ReadKey` on that registry path. This means the Bluetooth file-transfer block has almost certainly never actually worked on any real deployment since it shipped.

### Why this needed a different fix shape than CLI Guard

CLI Guard's IFEO registration is static -- the same 9 exe names, set once, never changes -- so a one-shot elevated task at startup was sufficient. Wireless control is **policy-driven**: `enforce`/`block_bluetooth_file_transfer`/`block_nearby_sharing` can change at any time the server-side policy changes, and the existing code already re-evaluates it on every sync (via a `lastWirelessSig` change-signature check). A one-shot task can't react to that.

### Fix

- `FetchWirelessPolicy()` no longer calls `ApplyWirelessControls()` directly (would just repeat the same `ACCESS_DENIED` every sync, forever). Instead, on every successful policy fetch, it writes the desired state to a small cache file (`SaveWirelessStateToCache()` -> `C:\ProgramData\SeceoKnight\logs\wireless_state.cache`, deliberately a trivial `1|1|0`-style format, not JSON) -- the same directory already used for the offline policy cache (task #95/#107), chosen specifically because it's writable by a standard user, unlike the registry key that started this whole investigation.
- New standalone agent mode `seceoknight_agent.exe --apply-wireless-guard` (`HandleApplyWirelessGuard()`): reads that cache and applies the `fsquirt.exe` IFEO redirect + the Nearby Sharing/CDP `EnableCdp` policy DWORD, with the same explicit return-code checking and logging as the CLI Guard fix (task #144's diagnostic-logging fix). No-ops cleanly (not a guessed default) if the cache doesn't exist yet.
- `install-agent.ps1` registers a new **`SeceoKnight DLP Wireless Guard`** scheduled task -- SYSTEM/Highest, repeating every 2 minutes indefinitely (same trigger pattern as the existing Watchdog task) -- so a policy change takes effect within 2 minutes rather than needing a reboot, and also runs it once immediately at install time.
- `manage-agent.ps1`'s `Uninstall-Agent` removes the new task on uninstall (the registry-key cleanup step from task #145 already covered `fsquirt.exe` itself).

### Deployment

Windows agent (C++) + installer changes -- `agent.cpp`, `install-agent.ps1`, `manage-agent.ps1`. CI rebuilds the binary automatically. Re-run the install one-liner on existing endpoints to pick up the new task; allow up to ~2 minutes after install (or after a wireless policy change) for the cache-then-apply cycle to complete before testing.

---

## 🔧 Add IFEO zero-race pre-launch interception for CLI upload tools (August 13, 2026)

### Summary

Live testing of the Application Control fix below surfaced a real detection gap: the CLI network-exfil monitor relies on WMI's `__InstanceCreationEvent` (`WITHIN 0.5`) to notice a new process, but WMI's real-world delivery latency is not bounded by that request — a fast, small `curl.exe -T file url` upload can fully complete (including the server's HTTP response) before WMI ever tells the agent the process exists. A 5-run live test on the endpoint confirmed this concretely: two log lines proved genuine blocks did happen (`NETWORK_BLOCKED pid=30892 exe=curl.exe reason=app_control` at 11:36:25, `pid=30988` at 11:48:55 matching a run that printed no output at all), but in a tight loop of 5 identical small-file curl invocations, only 1 was caught — the other 4 got real HTTP responses from the target server, meaning the request was never interrupted. Roughly a 1-in-5 catch rate is not an acceptable reliability bar for a security control.

### Root cause

WMI process-creation notification is fundamentally a polling mechanism with unpredictable real-world latency, not a guaranteed pre-execution hook — there is no way to tighten the existing `WITHIN` clause or add retries that closes this race; the only fix is not depending on WMI for the decision at all.

### Fix: Image File Execution Options (IFEO) zero-race interception

Added a second, higher-precedence detection path for a **scoped subset** of CLI tools, using the same IFEO "Debugger" redirect mechanism already used for the Bluetooth fsquirt.exe block (task #113), extended with a genuine allow/block decision instead of an always-block:

- **Scope — `NetworkExfilMonitor::IfeoScopedExecutables()`**: `curl.exe`, `wget.exe`, `rclone.exe`, `s3cmd.exe`, `azcopy.exe`, `aws.exe`, `scp.exe`, `pscp.exe`, `winscp.com`. Deliberately **excludes** `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`, `python*.exe`, `bitsadmin.exe`, `certutil.exe` — those are used pervasively by Windows itself and other legitimate software (Group Policy processing, Windows Update helper scripts, boot-time tooling, other installers/agents), so hijacking their system-wide launch path is too risky. They remain on the existing WMI-polling path with the same race documented above, which the team accepted as residual risk rather than block on a much larger, riskier change.
- **Mechanism**: `ApplyCliGuardIfeo()` (agent.cpp) sets `Debugger = "<agent.exe>" --cli-guard` under `HKLM\...\Image File Execution Options\<exe>` for each scoped tool, installed automatically on every agent startup (idempotent). When Windows launches one of these tools, it launches the agent instead. `HandleCliGuard()` connects to a new named pipe (`\\.\pipe\SeceoKnightCliGuard`) served by a new thread the running agent starts alongside the existing CLI monitor, sends the exe name + full original command line, and blocks briefly for a verdict.
- **On BLOCK**: the stub exits immediately without ever starting the real binary. Zero bytes ever leave the machine — this is strictly better than the old suspend-then-maybe-too-late-terminate approach, and there is no race window at all: the decision is made and enforced *before* the process exists, not after.
- **On ALLOW**: the stub copies the real binary to a randomly-named temp file and launches that (never the original path again — IFEO matches by filename only, so re-launching the original name would just redirect back to us; a differently-named copy is not intercepted), waits for it, and relays its exact exit code, so scripts checking `%ERRORLEVEL%`/`$LASTEXITCODE` see no difference from running the tool directly.
- **Decision logic** (`EvaluatePreLaunch()` in network_exfil_monitor.cpp): identical to the existing WMI path's `HandleCandidateProcess()` — same file-path extraction, same content read + classify, same `application_control` app-action check — just invoked before a process exists instead of after, and without any suspend/resume/terminate (nothing to suspend yet). Emits the same `NETWORK_REQUEST_DETECTED`/`NETWORK_BLOCKED`/dashboard-event shapes, tagged `source=ifeo_pre_launch` in the log for anyone diagnosing which path caught a given block.
- **Fail-open by design**: every error path in the stub (pipe unreachable, connect timeout, write/read failure) defaults to ALLOW, so an agent restart, crash, or update can never leave the user unable to run these tools. Only a failure to even stage the temp copy (disk full, permissions) genuinely fails the call, with a clear stderr message — deliberately not falling back to re-launching the original path, since that would risk real infinite IFEO recursion if the underlying problem persists.
- **Pipe security**: the server side installs an explicit DACL (`D:(A;;GRGW;;;WD)`) granting any authenticated user read/write on the pipe — the service runs as SYSTEM, whose default DACL would otherwise silently block standard (non-admin) users from ever reaching the guard, quietly disabling it for exactly the accounts most likely to be running these tools.
- **Uninstall hygiene**: `manage-agent.ps1`'s `Uninstall-Agent` now clears every IFEO `Debugger` value this agent may have set (fsquirt.exe from task #113, plus all 9 CLI Guard tools) before deleting the install directory, checking that the registered debugger string actually references `seceoknight_agent` before removing it (so a third party's own legitimate IFEO debugger entry, if any, is left untouched). Skipping this would have left the redirected tools **completely unable to launch** after uninstall, since Windows would try to run a debugger executable that no longer exists.

### What this does not fix

`powershell.exe`/`python*.exe`-based uploads (`Invoke-WebRequest`, `requests`, raw sockets, etc.) and `certutil.exe`/`bitsadmin.exe` still rely on WMI polling alone and carry the same race documented above. This is an accepted, disclosed tradeoff, not an oversight — see "Scope" above for the reasoning.

### Deployment

Windows agent (C++) change only — `agent.cpp`, `network_exfil_monitor.cpp`, `network_exfil_monitor.h`, plus `manage-agent.ps1` for uninstall cleanup. CI rebuilds `seceoknight_agent.exe` automatically on push to `main`. Requires `powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install-agent.ps1 | iex"` on each Windows endpoint to pick up the new binary; the IFEO registry keys are installed automatically the next time the agent service starts — no manual registry work needed. No server-side change.

---

## 🔧 Fix Application Control policy stuck at "0 violations" despite real agent-side blocking (August 13, 2026)

### Summary

Found before any live testing, by code review ahead of guiding a live test: `application_control` was missing from `policy_transformer.py`'s `transform_frontend_config_to_backend()` dispatcher -- the exact same bug class as messaging_app_control (task #137). Falling through to the "unknown type" branch produces empty `conditions.rules`, which `DatabasePolicyEvaluator.evaluate_event()` skips unconditionally. Real-time enforcement was never affected (the Windows agent's `IsAppActionAllowed()` reads `GET /agents/{id}/application-control` directly, independent of this file), but the Policies page's violations count for Application Control would stay stuck at 0 even when the agent genuinely blocked a disallowed CLI tool (curl, wget, powershell, bitsadmin, certutil, rclone, cloud-CLI, SCP).

### Fix

Added `_transform_application_control_config()`: matches `event_subtype == "cli_upload"` (the single event subtype the CLI network-exfil path emits, regardless of whether the block reason was app-control or content-sensitivity), always reports `actions={"alert": {}}` regardless of `config.mode`/`applications` -- same reasoning as messaging_app_control: the agent already executed the real block/allow decision (`TerminatePid`) before the event was created, and the event's own honest `action` field is ground truth; mapping to a declarative "block" action here would let `ActionExecutor.execute_block()` stomp that with an unverified `blocked=True`.

### Related gap, not fixed here

`network_share_transfer_control`, `wireless_transfer_control`, `print_content_prevention`, and `printer_control` are the same agent-polled-config-toggle pattern and are also currently missing from this dispatcher -- same "0 violations" display bug likely applies to all four. Flagging for a follow-up pass; real-time enforcement for these is unaffected either way.

### Deployment

Server-side Python change only (`policy_transformer.py`). Requires a fresh `dlp-manager` image build via CI and `bash update.sh` on the server -- no Windows agent rebuild needed. Policy re-save not required for this fix (transform runs on next create/update of an `application_control` policy, or can be forced by re-saving an existing one through the Edit Policy wizard).

---

## 📋 Disclose: Messaging App Attachment Control cannot inspect or block Teams content pre-send (August 13, 2026)

### Summary

Following up on the previous cross-thread UIA fix: live testing confirmed the UIA lookup also finds nothing for Teams' file-attach dialog (no `UIA cross-thread lookup matched` log line, safe honest `(unknown)` fallback used as designed). Researched a third option -- reading Teams' local IndexedDB (`replychains` object store, `properties.files` field) -- and determined it is not viable, for two independent reasons documented here for the record.

### Why the IndexedDB route was ruled out

1. **Timing**: Teams only writes the attachment's filename into `replychains.properties.files` once the message is actually *sent* (confirmed via a 2026 academic forensics paper analyzing the new WebView2-based Teams client's storage format, and a maintained open-source parser, `ms_teams_parser`/`forensicsim`). Our detection point is at file-picker dialog close, before Send. A reader built against this store would only ever see content *after* the message has already left the machine -- too late to block, only useful for after-the-fact alerting.
2. **Format fragility**: Teams 2.x's IndexedDB uses a custom LevelDB key comparator (`idb_cmp1`) that already broke existing open-source forensic parsers (`forensicsim`, `LevelDBDumper`) when Microsoft changed the serialization format. It is undocumented, Microsoft-controlled, and can change with any Teams/Edge update with no notice to us. Building and maintaining a bespoke reader for it inside the agent would be an open-ended liability, not a fixed cost.

### A more important finding: "Block" was already a no-op for Teams regardless

Traced the actual enforcement path in `HandleBrowserDialogFromHwnd()` (network_exfil_monitor.cpp, ~line 2126):

```cpp
if (sensitive && isMessaging && mv.block) {
    bool killed = TerminatePid(browserPid);   // force-kills the whole app process
    f.action = "BLOCK";
} else if (sensitive) {
    f.action = "ALERT";
}
```

`sensitive` is only ever true if file content was successfully read and classified as confidential/restricted. Since Teams' content can never be read before Send (three independent techniques now ruled out: Win32 child-window scan, UIA, IndexedDB), this branch is structurally unreachable for Teams -- `mv.block` being true never mattered, because content classification never got the chance to mark anything sensitive. This matches exactly what was observed live: policy set to Block, file still went through Teams unimpeded.

Practical implication: on a Messaging App Attachment Control policy, switching the action from Block to Alert for Teams specifically is not a reduction in protection -- Block was already providing none. Alert is simply an honest label for what has been happening all along. Other managed apps in this policy's scope (WhatsApp, Telegram) may use plain Win32 file dialogs rather than a WebView2 host and could still classify and block correctly -- this has not been separately verified.

Also worth noting for anyone reconsidering "Block" for a messaging app in the future: it terminates the entire process (`TerminatePid`), not just the one attachment -- ported from CyberSentinel-DLP as a blunt instrument, since there is no way to cancel a single already-selected file inside another vendor's app.

### Status

Documented as a known, permanent limitation for Teams pre-send content inspection. No further code changes planned here. The existing safety net (honest `(unknown)` instead of a false verdict) remains in place from the previous fix and is not affected by this decision.

---

## 🔧 Add safe cross-thread UIA lookup attempt for Teams file-attach detection (August 12, 2026)

### Summary

Follow-up to the previous fix, which made Teams' messaging_file_selection detection honest (no more false wrong-file misattribution) but left content inspection unresolved for that app specifically -- confirmed live that Teams' WebView2-hosted dialog exposes no Edit/file-list control to either the direct child-window scan or the owned-window scan, so every event still fell back to "(unknown)". This change adds one more real detection technique: a safe, cross-thread UI Automation (UIA) lookup.

### Why this wasn't just re-enabling the old UIA call

UIA calls were previously removed entirely from the per-dialog detached thread after they caused a confirmed production bug: a stuck COM/RPC call that only unblocked when the *next* dialog opened, causing every file's alert to permanently lag one dialog behind (misattributing file A's alert to file B's dialog, and so on). Calling `g_browserUia` directly from that thread is still forbidden.

### What was added

1. `g_browserThreadId` -- captured once at the top of `BrowserDetectorThread()` (the thread that owns `g_browserUia` and the only message pump in this component).
2. `UiaFilenameRequest` / `RunUiaLookupOnDialogThread()` -- a per-dialog detached thread calls this instead of touching UIA itself. It posts a `WM_APP_UIA_FILENAME_LOOKUP` message (via `PostThreadMessage`) carrying a `shared_ptr`-wrapped request/promise pair to `BrowserDetectorThread`, then waits on the paired future with a bounded 300ms timeout. Ownership is shared_ptr-managed so either side finishing first (a timed-out requester, or a late-completing lookup) is safe -- no dangling pointer, no double-free, no leak under normal operation.
3. `BrowserDetectorThread()`'s existing `PeekMessageW` loop now recognizes `WM_APP_UIA_FILENAME_LOOKUP` (thread messages bypass `DispatchMessageW`/window procedures entirely and must be handled inline), performs the actual `g_browserUia->ElementFromHandle()` + `FindFileNameFromDialog()` call **on the thread that already safely owns UIA**, and fulfills the promise.
4. Wired into `HandleBrowserDialogFromHwnd`: when the Win32 scan finds nothing and the dialog HWND is still valid (even if just hidden, before full destruction), try the UIA cross-thread lookup before falling through to the Shell MRU wait.

### Why this might actually work where Win32 scanning didn't

UI Automation providers can expose elements backed by non-HWND rendering surfaces (e.g. content rendered via DirectComposition) that raw Win32 window enumeration (`EnumChildWindows`/`EnumWindows`) fundamentally cannot see. This is a genuinely different technique, not a repeat of the already-failed approach -- but it is **not guaranteed to succeed**. If Teams' dialog content isn't exposed through the UIA tree either, this will also come up empty, and the honest "(unknown)" fallback (from the previous fix) remains the safety net either way -- never a wrong-file misattribution, worst case an honest detection gap.

### Verification

Custom brace-balance checker showed a `+4` delta from this file's established baseline on first pass. Investigated thoroughly: manually audited all three edited regions for correct open/close nesting (all balanced), confirmed via raw diff that added lines contain exactly 14 `{` and 14 `}` (balanced), and confirmed the checker's own per-line state tracking shows a `in_string=True` artifact spanning ~300 lines **already present in the unmodified baseline file** (line ~1400-1700, pre-dating this change entirely) -- a known limitation of this heuristic checker with escaped-backslash sequences in Windows path string literals (already documented from an earlier session as "pre-existing string/comment noise"), not a real syntax defect. The authoritative check is the CI build itself (`build-windows-agent.yml`): it only commits an updated `seceoknight_agent.exe` back to the repo on successful compilation, so a real syntax error would be self-evident as "no new binary" rather than a silent bad deploy.

### Deployment

Agent-side C++ change. Wait for CI to rebuild `seceoknight_agent.exe` (auto-triggered on push), then re-run `install-agent.ps1` on the Windows endpoint to pick up the new binary. Re-test a Teams attachment: check the log for a new `"UIA cross-thread lookup matched: ..."` debug line. If present, content inspection should now work for Teams too. If absent, the event still safely falls back to "(unknown)" as before -- no regression either way.

---

## 🐛 Fix messaging file-attach heuristic producing false wrong-file DLP verdicts (August 12, 2026)

### Summary

Live debug capture (`dialog_child`/Shell MRU log trace, requested and reviewed with the admin) proved that Teams' file-attach dialog attribution was worse than previously known: it wasn't just failing honestly with "(unknown)" — it was actively misattributing events to the WRONG file and producing a false ALLOW verdict on what was actually a sensitive attachment.

### Root cause (two distinct findings)

**1. The direct Win32 scan structurally cannot see Teams' dialog content.** A live `dialog_child` dump of the `#32770` dialog (`exe=msedgewebview2.exe`, owner `ms-teams.exe`) showed `EnumChildWindows` finds only 5 generic controls: two `Static` labels ("File name:", "Files of type:") and three `Button`s (Open/Cancel/Help) — no `Edit` control, no file-list control at all. This is a genuine structural difference from Chrome's dialog, where the same scan reliably finds an `Edit`-class control. The real interactive file-picker surface isn't a *child* of the `#32770` frame WinEvent hands us for this dialog composition.

**2. The last-resort `FindRecentlyAccessedCandidateFile()` heuristic actively produced a false, wrong-file, wrong-verdict event — confirmed live.** With the direct scan and MRU both failing, the heuristic fell back to "grab whichever file in Desktop/Documents/Downloads has the most recent NTFS access-time strictly after the dialog closed." In production this returned `salary_sheet_2026.txt` — the exact same file that was *already* the stale Shell MRU entry from before this dialog even opened, not the sensitive study-report file the admin had genuinely just selected in Teams. Something unrelated (Explorer preview/thumbnailing, AV scan, search indexing — anything that touches file metadata) evidently nudged that old file's access-time within the observation window, by pure coincidence. The agent then classified *that* file's real content (an unrelated, non-sensitive `EMAIL` pattern) and reported `category=Internal, decision=ALLOW` — a **false negative** on a genuinely sensitive attachment, misattributed to the wrong file entirely. A confidently-wrong file/verdict is more dangerous for a DLP product than an admitted detection gap, and is the opposite of the honesty principle this whole feature is built on (see the "(unknown)" fallback event added in the previous round).

### Fix

Two changes in `agents/endpoint/windows/network_exfil_monitor.cpp`:

1. **New owned-window scan** in the `tryWin32` lambda (`HandleBrowserDialogFromHwnd`): when the direct child-window scan finds nothing, additionally check windows *owned by* (not children of) the dialog HWND via `EnumWindows` + `GetWindow(hwnd, GW_OWNER)`, and scan that window's children too. This is a best-effort attempt at finding Teams' actual file-picker controls, based on the confirmed evidence that they aren't in the direct child tree. Not guaranteed to succeed if the real content renders through a non-HWND mechanism (e.g. DirectComposition) with no ownership-linked window at all — but it's a real additional detection layer, not a placeholder.
2. **Disabled `FindRecentlyAccessedCandidateFile()` for messaging events specifically** (`isMessaging` gate). Browsers are unaffected (they resolve reliably via Shell MRU and essentially never reach this branch). When neither the (now-enhanced) Win32 scan nor Shell MRU can identify the file, messaging events now consistently fall back to the honest "(unknown)" detection-gap ALERT event from the previous fix, instead of guessing and potentially misattributing to an unrelated file.

### Verification

Custom brace-balance checker (skips string/char literals and `//`/`/* */` comments) confirms `paren=1 brace=-2 bracket=-1` for `network_exfil_monitor.cpp` — matches this file's established pre-existing baseline exactly (confirmed unchanged by these edits).

### Deployment

Same as prior rounds: rebuild/redeploy the Windows agent installer (this is agent-side C++, not server-side — requires a new agent build + reinstall on endpoints, not just a server `update.sh`). After redeploying: re-test a Teams attachment. Best case, the owned-window scan finds the real filename and content inspection works properly. Otherwise, the event should now honestly report "(unknown)" instead of a wrong file — no more false ALLOW verdicts on misattributed content.

---

## 🐛 Fix Messaging App Attachment Control dashboard falsely showing "blocked" (August 12, 2026)

### Summary

Immediately after deploying the previous fix (below) and confirming it worked -- a real event now correctly matched "Messaging App Attachment Control" and the violations count incremented -- the admin reported a new, more serious problem: the event's badge showed "blocked" in red, but the file had genuinely gone through in Teams (attached and sent successfully). A DLP dashboard claiming something was blocked when it wasn't is a false-confidence bug, worse than the "0 violations" bug it replaced.

### Root cause

The previous fix's `_transform_messaging_app_control_config()` mapped the admin's UI choice (Alert/Block) directly into the backend policy's action list: `actions = {action: {}}`, where `action` could be `"block"`. Once the policy started matching (previous fix), every matching event ran through `EventProcessor.evaluate_policies()` -> `ActionExecutor.execute_block()` (`action_executor.py:354`), which does:

```python
async def execute_block(self, event: Dict, action: Dict) -> BlockResult:
    event["blocked"] = True
    ...
    return BlockResult(..., success=True, blocked=True, ...)
```

This is a purely declarative "policy says block" flag with **zero real-world verification** -- appropriate for event types where the server-side pipeline actually performs or confirms a block (e.g. clipboard's synchronous block-decision path). It is categorically wrong for messaging: enforcement here is 100% agent-side. `GetMessagingVerdict()`/`FetchMessagingAppPolicy()` in `agent.cpp` already decide and execute (or don't) the real Block/Alert action *before the event is even created and sent*. The event's own honestly-reported `action` field (`BLOCK`/`ALERT`/`ALLOW` -- see `EmitEvent()` in `network_exfil_monitor.cpp`) is already the ground truth, and gets correctly written to `action_taken` at ingest in `create_event()`. Declaratively calling `execute_block()` afterward let the server stomp that honest value with a hardcoded `"blocked"` string in `_process_event_background()`'s merge logic (`events.py`) -- even for the honest-fallback ALERT event, where the agent explicitly could not identify or inspect the selected file and never terminated anything.

This is the same class of bug previously fixed for USB (task: "Fix USB block event lying about success") -- declarative policy intent getting confused with confirmed real-world enforcement -- just not yet covered for this newly-wired policy type.

### Fix

`_transform_messaging_app_control_config()` now always returns `actions = {"alert": {}}`, regardless of `config.action`. This is intentional and permanent, not a placeholder: the backend/reporting action for this policy type should never be "block", because the server has no real enforcement capability to confirm for an event that's already fully decided by the time it arrives. The admin's Block/Alert selection remains fully effective where it actually matters -- the agent's local enforcement decision, delivered via `GET /agents/{id}/messaging-app-policy` -- completely unaffected by this change.

### Verification

`ast.parse()` clean. Confirmed via code read that `execute_block()` has no event-type-aware guard and would behave identically for any policy type -- this fix has to live in the transform (never emit `"block"` for this policy type), not in the shared executor.

Note: the two test events already created in Mongo before this fix (during testing) will keep showing "blocked" historically -- this fix only prevents new occurrences going forward, it does not rewrite existing documents.

### Deployment

1. `git pull` (image-based deployment: wait for CI to publish the new `manager` image, then `docker compose -f docker-compose.prod.yml pull manager && docker compose -f docker-compose.prod.yml up -d manager`, or run `update.sh`).
2. Re-open "Messaging App Attachment Control" in the dashboard and click through to "Update Policy" again (same as before -- the fix only regenerates a policy's `actions`/`conditions` on save, not retroactively).
3. Re-test a Teams attachment; the new event should show `ALERT`, never a false "blocked".

---

## 🐛 Fix Messaging App Attachment Control policy stuck at "0 violations" despite real detections (August 12, 2026)

### Summary

Fourth round on this feature. With the prior three fixes deployed, a real `messaging_file_selection` event was confirmed reaching MongoDB correctly (verified via direct `mongosh` query) and confirmed visible in the dashboard's Events page (verified via a direct authenticated `curl` against `GET /api/v1/events/`, bypassing the browser entirely). However, the admin reported the event wasn't being attributed to the "Messaging App Attachment Control" policy, and that policy's row on the Policies page showed "0 violations" even after the detection fired.

### Root cause

`transform_frontend_config_to_backend()` in `server/app/utils/policy_transformer.py` has a dedicated branch for most policy types (`clipboard_monitoring`, `usb_device_monitoring`, `email_send_prevention`, etc.) that converts the admin's UI config into a real `conditions.rules` list. `messaging_app_control` had no branch, so it fell through to the generic `else`:

```python
else:
    # Unknown type, return empty defaults
    return ({"match": "all", "rules": []}, {"log": {}})
```

Every `messaging_app_control` policy was therefore persisted with `conditions = {"match": "all", "rules": []}`. `DatabasePolicyEvaluator.evaluate_event()` skips any policy with empty rules unconditionally (`if not conditions.get("rules"): continue`) -- before comparing a single field. So no `messaging_file_selection` event could ever match this policy, regardless of how many managed-app file attachments the agent detected. This is why `matched_policies`/`policy_id` stayed empty on the event doc, and why the Policies page's violations aggregation (which counts events with a non-empty `matched_policies`) correctly, but misleadingly, showed 0.

This is a separate, narrower gap from the messaging App *enforcement* path (block/alert per configured app), which is agent-side and was already working correctly: the Windows agent polls `GET /agents/{id}/messaging-app-policy` directly and decides block/alert locally via `GetMessagingVerdict()`/`CanonicalMessagingAppName()` in `agent.cpp` before the event is ever sent. What was missing was purely the server-side bookkeeping that attributes an already-detected event back to the policy that's "responsible" for it, for reporting purposes.

### Fix

Added `_transform_messaging_app_control_config()` to `server/app/utils/policy_transformer.py` and registered it in `transform_frontend_config_to_backend()`'s dispatch. It matches any event with `event_subtype == "messaging_file_selection"` -- the one and only subtype `network_exfil_monitor.cpp` emits for this feature (both the normal classified-file path and the honest-fallback "(unknown)" detection-gap path use the same subtype), and applies the admin's configured action (`alert` or `block`) as the policy's own action for reporting purposes.

The per-app allow list itself is deliberately not re-checked server-side: the agent already filters to only managed apps before emitting the event, and the raw process name isn't reliably available server-side (`EventCreate` doesn't declare a `channel`/`process_name` field for this event type) -- re-deriving it here would be redundant at best.

### Verification

`ast.parse()` clean on `policy_transformer.py`. Confirmed via code read that `evaluate_event()`'s field-mapping (`database_policy_evaluator.py`) already supports `event_subtype` out of the box (`"event_subtype": ["event.subtype", "event_subtype"]`), and that `_build_processor_payload()` in `events.py` already threads `event.event_subtype` into `payload["event"]["subtype"]` for every event that carries one -- so no other file needed to change.

### Deployment

**This fix only affects policies created or edited AFTER it's deployed** -- `transform_frontend_config_to_backend()` only runs at policy create/update time, not retroactively. After redeploying the server:
1. Open the existing "Messaging App Attachment Control" policy in the dashboard.
2. Click Save (no changes needed -- just re-submitting it re-runs the transform and backfills real `conditions.rules` onto the existing policy row).
3. Re-test a Teams file attachment; the event should now carry a `policy_id`/`matched_policies` entry, and the Policies page's violations count should increment.

---

## 🐛 Fix messaging-app file selection silently producing zero events for Teams' WebView2 dialog (August 12, 2026)

### Summary

Third round on this feature. With both prior fixes deployed, the log showed detection now working correctly end to end -- the dialog was attributed to `ms-teams.exe` and matched as a managed app -- but attaching the sensitive test file through Teams still produced zero events.

### Root cause

Traced to filename resolution, not detection. The log showed the Win32 child-window scan found nothing, followed by "Shell MRU never showed an entry newer than dialog close within 10s". Teams' file dialog is a genuine native common-dialog window (class #32770, not a custom in-app control), but unlike Chrome's own sandboxed-helper dialog -- which the existing `OpenSavePidlMRU` registry mechanism already handles correctly -- it doesn't appear to record through Explorer's MRU the way a normal file-picker call does. Not diagnosable further without invasive per-machine tooling this project has deliberately ruled out for production fleet use. With the filename never resolved, the function silently `return`ed -- zero events, indistinguishable in the dashboard from "nothing was attached at all."

### Fix

Two parts, in `network_exfil_monitor.cpp`:

1. **`FindRecentlyAccessedCandidateFile()`** -- a last-resort heuristic. Opening a file to attach it still touches that file's last-access timestamp even when neither the child-window scan nor the MRU registry key fires. Scans Desktop/Documents/Downloads (shallow, non-recursive) for the most-recently-accessed file strictly after the dialog closed. Explicitly a heuristic, not an MRU-confirmed fact -- logged as such, and callers must treat it accordingly.
2. When even that fails for a **managed messaging app** specifically (browsers keep their existing behavior -- separately verified working via MRU/Win32 scan for every browser tested this session, so this fix is scoped to the gap just confirmed), emit an honest `ALERT`/`medium` event instead of the previous silent no-op. Same principle already applied to print content inspection: a detection gap must be visible on the Events page, not indistinguishable from nothing happening.

### Verification

Brace-balance check: `paren=1 brace=-2 bracket=-1`, matching the file's own established baseline.

### Deployment

Agent-only change. Reinstall the Windows agent via `install-agent.ps1`; no server redeploy needed.

---

## 🐛 Fix Messaging App Attachment Control: "teams.exe" policy doesn't match the ms-teams.exe process (August 12, 2026)

### Summary

Direct follow-up to the WebView2/owner-process fix above. With that fix deployed, the agent's log now correctly attributed a Teams file dialog to `ms-teams.exe` -- but attaching the sensitive test file still produced zero events. `GetMessagingVerdict("ms-teams.exe")` was still returning `managed=false`.

### Root cause

The admin's policy had exactly one app configured: `teams.exe` -- the only Teams option `MessagingAppControlPolicyForm.tsx`'s chip list offers. The process Microsoft actually ships for the current "new Teams" client is `ms-teams.exe`, an internal rename an admin has no way to know about. `GetMessagingVerdict()`'s exact-string set lookup (`messagingApps.count(exeLower)`) silently missed every real-world Teams attachment as a result -- not a detection bug this time, a naming mismatch between what the dashboard lets you configure and what actually runs.

### Fix

`agent.cpp`: new `CanonicalMessagingAppName()` maps `teams.exe` / `ms-teams.exe` / `msteams.exe` to one identity. `GetMessagingVerdict()` now does a symmetric check -- canonicalizing both the incoming process name and each configured app name before comparing -- so it no longer matters which of the known Teams exe-name variants an admin happened to pick versus which variant is actually installed.

### Verification

Brace-balance check on `agent.cpp`: unchanged (paren=-2 brace=-5 bracket=-1).

### Deployment

Agent-only change. Reinstall the Windows agent via `install-agent.ps1`; no server redeploy or policy change needed -- your existing `teams.exe` policy now covers `ms-teams.exe` automatically.

---

## 🐛 Fix Messaging App Attachment Control never firing for new Teams (August 12, 2026)

### Summary

Moved on to testing Messaging App Attachment Control. Policy was created and confirmed synced to the agent (`enforced=true action=block apps=1`), but attaching a sensitive file through Teams' native file-picker produced zero events -- not a wrong severity or a wrong filename, nothing logged at all.

### Root cause

Diagnosed from the agent's own debug log:
```
WinEvent #32770 created: exe=msedgewebview2.exe title=Open
WinEvent #32770 owner: exe=ms-teams.exe
```
The "new" Microsoft Teams client hosts its file-open dialog inside a `msedgewebview2.exe` helper process, not `ms-teams.exe` itself -- the exact same sandboxed-helper indirection Chrome uses for its own file dialog, which `network_exfil_monitor.cpp`'s `BrowserWinEventProc` already had an owner-window fallback for. But that fallback only ever checked whether the **owner** was a **browser**. It correctly resolved and logged the real owner (`ms-teams.exe`) on every single attempt, then never used that value for the messaging-app check -- `messagingPolicy()` was only ever called with the helper process's own name, which no admin's managed-apps list will ever contain, so it always came back `managed=false` and the detector silently did nothing on every Teams attachment.

### Fix

`network_exfil_monitor.cpp`: when the dialog's own creating process isn't a managed messaging app, also try `messagingPolicy()` against the owner process -- mirrors the existing browser fallback exactly. Also propagates the owner's PID into `browserPid`, since that's what a "block" verdict actually terminates downstream (`TerminatePid`); leaving it as the WebView2 helper's PID would have terminated the wrong process even after fixing detection, undermining Block silently in a different way.

### Verification

Brace-balance check: `paren=1 brace=-2 bracket=-1`, identical to the unmodified file fetched fresh from `origin/main` -- confirms this pre-existing imbalance is string/comment noise unrelated to this edit, not something the change introduced.

### Deployment

Agent-only change. Reinstall the Windows agent via `install-agent.ps1`; no server redeploy needed.

---

## 🐛 Fix print events ignoring the admin-configured policy severity (August 12, 2026)

### Summary

After the two fixes above, print-content events were finally blocking correctly and showing the right filename -- but the severity shown was still wrong. The admin had set severity to Critical on the "Print Content" policy (the same top-level Severity dropdown every policy type has), yet blocked jobs kept showing `high` and unverified-content jobs kept showing `medium`. Traced to `agent.cpp`'s print event builder, which hardcoded `Block -> "high"`, `content unavailable -> "medium"`, else `"low"` -- there was no path anywhere for the policy's actual configured severity to reach the agent. `GET /printer-policy` never returned it in the first place.

### Fix

`server/app/api/v1/agents.py` (`get_printer_policy`): compute a merged `content_severity` across every active `print_content_prevention` policy, same pattern as the mode/unknownContentAction merge two fixes ago -- highest-ranked severity wins (using the existing `_severity_rank()` helper). Defaults to `high` (the old hardcoded value) when no policy carries an explicit severity, so this is non-breaking. `agent.cpp`: new cached `printContentSeverity`, synced alongside `content_mode`/`unknown_content_action`. The print event builder now uses it for the two paths this policy actually governs -- a content-driven block, and content-unavailable. Device-control blocks (blocked by the separate `printer_control` policy type) keep their previous `high`, since that's a different policy with its own severity semantics untouched by this fix. A fully verified-clean allow stays `low` -- that's not a policy hit, and tagging routine clean prints as Critical would be actively misleading.

### Verification

Brace-balance on `agent.cpp` (unchanged, paren=-2 brace=-5 bracket=-1). `python3 -c "import ast; ast.parse(...)"` clean on `agents.py`.

### Deployment

Server + agent change. Redeploy via `update.sh`, then reinstall the Windows agent.

---

## 🐛 Fix print events showing generic "Local Downlevel Document" instead of the real filename (August 12, 2026)

### Summary

After the fail-closed fix above started actually blocking print jobs, the resulting Events showed `File: Local Downlevel Document` instead of the real document name -- for every job, on this printer. Traced to `JOB_INFO_1A.pDocument`: for this printer's driver class (a v4/XPS-class driver receiving a legacy GDI "downlevel" job), Windows itself renames the spooler job's document to that generic literal string during its internal XPS conversion shim -- confirmed this is not a parsing bug in the agent, the OS genuinely hands back that string via `EnumJobsA`. Same underlying driver-pipeline family as the earlier content-extraction gap.

### Fix

Best achievable fix with the public spooler API (a full fix needs a print processor/port monitor DLL earlier in the pipeline -- the same driver-signing-gated undertaking as content extraction): when `pDocument` comes back as that placeholder (or empty/"Unknown"), `print_monitor.cpp` falls back to the foreground window's title at the moment the job is detected. Jobs are picked up within ~2s via the change-notification handler or the poll, so this is very likely the actual source document. Labelled `"(inferred from active window)"` in the event description and `file_path` rather than presented with the same confidence as a real API-sourced name -- new `PrintEvent::documentNameInferred` bool threads this through from `print_monitor.h`/`.cpp` to `agent.cpp`.

### Verification

Brace-balance check on `agent.cpp` (unchanged, paren=-2 brace=-5 bracket=-1), `print_monitor.cpp`/`.h` (both 0/0/0).

### Deployment

Agent-only change. Reinstall the Windows agent via `install-agent.ps1`; no server redeploy needed.

---

## 🐛 Fix printer-policy endpoint silently ignoring one of multiple active print_content_prevention policies (August 12, 2026)

### Summary

Direct follow-up to the fail-closed feature below: after deploying it, a live test showed the agent consistently reporting `unknown_content_action=allow` even though the admin had set the policy to `block` in the dashboard and confirmed it saved. Diagnosed by adding `content_mode`/`unknown_content_action` to the agent's existing debug log line (agent-side confirmed it was faithfully receiving `allow` from the server on every single poll -- ruling out an agent caching bug), then querying Postgres directly: two active `print_content_prevention` policies existed at the same priority (100) -- an older "Block Sensitive Printing" policy with no `unknownContentAction` key, and the "Print Content" policy the admin was actually editing, correctly holding `unknownContentAction: "block"`.

### Root cause

`GET /{agent_id}/printer-policy` fetched the content policy via `.order_by(Policy.priority.desc()).first()`. On a priority tie, SQL does not guarantee row order, so this silently and non-deterministically returned one policy's config over the other's -- the admin's fail-closed setting on the policy they were editing was invisibly shadowed by an unrelated leftover policy every single poll, with no error, no warning, nothing in the UI to suggest a conflict existed.

### Fix

`server/app/api/v1/agents.py`: fetch every active `print_content_prevention` policy instead of one, and merge them by taking the strictest setting present in any of them (`enforce` beats `audit`, `block` beats `allow`). Multiple admin-authored policies of this type now compose safely instead of one arbitrarily shadowing another on a priority tie.

### Verification

`python3 -c "import ast; ast.parse(...)"` clean on `agents.py`.

### Deployment

Server-only change. Redeploy via `update.sh`; no agent reinstall needed. Also worth cleaning up any duplicate/leftover `print_content_prevention` policies in the dashboard so intent stays unambiguous even though the merge now handles it safely either way.

---

## 🛡️ Add fail-closed option for unverifiable print content (August 12, 2026)

### Summary

Direct follow-up to the print content-inspection honesty fix above, after being asked what an actually enterprise-grade answer looks like given that reading the SHARP AR-6020N's real content may never be solvable without a custom port-monitor/print-processor driver (a multi-week undertaking needing signing and tooling this environment doesn't have). The real gap wasn't just visibility -- it's that even fully aware a print job's content was never verified, the agent still let it print by default, every time, unconditionally. That's not a real enforcement posture for a security product; it's a permanent, silent no-op dressed up as a configured control for any printer that hits this class of gap.

CyberSentinel's own July 2026 changelog states the governing principle for exactly this situation, applied to file extraction: "content we could not fully inspect must never be treated as clean -- classification reports what it saw; policy decides what to do about not knowing." SeceoKnight already applies that principle to file transfers via `extraction_status`. This closes the same gap for print.

### What was added

An admin-configurable `unknownContentAction` (`allow` | `block`, default `allow` -- fully non-breaking) on the `print_content_prevention` policy type. When set to `block`, a print job whose content genuinely could not be read (as opposed to read-and-found-clean) is treated as a precautionary block instead of a silent pass, on the reasoning that unverified content in a strict environment is safer refused than assumed safe.

**Server** (`server/app/api/v1/agents.py`, `GET /{agent_id}/printer-policy`): reads `unknownContentAction` off the `print_content_prevention` Policy row's config, validated to `allow`/`block`, returned as `unknown_content_action`.

**Agent** (`agents/endpoint/windows/agent.cpp`): new cached field `printUnknownContentAction`, populated by `FetchPrinterPolicy()` alongside the existing `printContentMode`. `EvaluatePrintContent()` now forces `block = true` when content wasn't genuinely read AND the setting is `block` AND the server's own filename-based verdict didn't already say block -- deliberately scoped to "content unreadable locally", not "DLP server unreachable" (`status != 200` above it keeps its existing, separate fail-open behavior -- conflating the two would make one setting mean two different failure modes at once). Respects the existing audit-mode gate below it, so `audit` + `unknownContentAction=block` correctly logs "would block" without actually cancelling the job, consistent with how audit mode already behaves everywhere else in this policy type.

**Dashboard**: `PrintContentPreventionConfig` gained `unknownContentAction`; `PrintContentPreventionPolicyForm.tsx` got a new radio group explaining the tradeoff in plain terms, with both `getDefaultConfig()` implementations and `formatPolicyConfig()` in `policyUtils.ts` updated to match.

### Verification

Brace-balance on `agent.cpp`: unchanged (paren=-2 brace=-5 bracket=-1). `python3 -c "import ast; ast.parse(...)"` clean on `agents.py`. `npx tsc --noEmit`: 24 errors, identical to the established baseline, confirmed via grep that none are in any file this change touched.

### What this does and doesn't do

This does not solve the SHARP AR-6020N's underlying spool-file mystery -- that's still open, and a real fix (port monitor or print-processor DLL) is a genuinely separate, much larger undertaking. What it does: turns "we silently allow what we can't verify, always" into an actual admin decision, so a strict deployment can choose to refuse unverified print jobs rather than have content inspection be effectively decorative for whatever fraction of printers hit this gap.

### Deployment

Server + agent change (touches both `agents.py` and `agent.cpp`). Redeploy the server via `update.sh`, then reinstall the Windows agent. Defaults to `allow` for every existing policy -- nothing changes in behavior unless an admin explicitly opts a `print_content_prevention` policy into `unknownContentAction: block`.

---

## ✨ Add dedicated Email DLP (Outbound) policy type (August 12, 2026)

### Summary

Found via a gap-scan of CyberSentinel-DLP's changelog (task #134): CyberSentinel exposes `email_send_prevention` as a first-class policy type in its dashboard wizard, letting admins tune outbound-email severity/action independently from other channels. SeceoKnight's SMTP relay (`smtp-relay/`) already enforced DLP on outbound mail end-to-end, but rode on generic evaluator defaults with no admin-configurable policy object -- an email with no matching custom policy always returned `allow`, and there was no UI to change that.

### What was added

**Dashboard**: `email_send_prevention` added to `PolicyType`, plus a new `EmailConfig` (`action: block|alert|log`, `triggerLevels: Internal|Confidential|Restricted[]`). New `EmailPolicyForm.tsx` component, wired into `PolicyTypeSelector.tsx` (new picker entry with a Mail icon), `PolicyCreatorModal.tsx` (import, `TraditionalPolicyConfig` union, `getDefaultConfig()` case, render switch), and `utils/policyUtils.ts` (icon/label/format-config functions, plus the second, duplicate `getDefaultConfig()` implementation used by `transformApiPolicyToFrontend` -- both needed the same case to stay in sync, a pre-existing maintenance wart noted but not otherwise touched).

**Server**: unlike `printer_control`/`print_content_prevention`/`messaging_app_control` -- which are agent-polled config toggles read directly off `Policy.config` by a dedicated `GET /agents/{id}/<x>-policy` endpoint -- the SMTP relay has no polling loop. It's a synchronous component that POSTs each message's content straight to the generic `/agents/{id}/policy/evaluate` endpoint and expects an inline decision back from `DatabasePolicyEvaluator`'s conditions/actions rule engine (the same path `usb_file_transfer_monitoring` uses). So `server/app/utils/policy_transformer.py` got a new `_transform_email_config()` emitting `destination_type == "email"` + `classification_level in [...]` rules -- without this, an admin-created email policy would have silently done nothing, since the previous unhandled-type fallback returns empty rules. Also added `email_send_prevention` to `server/app/core/domains.py`'s `POLICY_TYPE_DOMAIN` map (as `DATA_PROTECTION`) so domain-scoped admins can actually manage it -- it was unmapped before, which would have silently fallen back to the `general` domain.

### Verification

`python3 -c "import ast; ast.parse(...)"` clean on both server files. `npx tsc --noEmit` on the dashboard: 24 errors, identical count to the established pre-existing baseline, none in any file touched by this change (confirmed via grep -- all 24 are pre-existing issues in `ClassificationPolicyForm.tsx`, `ClipboardPolicyForm.tsx`, `GoogleDriveCloudPolicyForm.tsx`, `OneDriveCloudPolicyForm.tsx`, `PolicyCreatorModal.tsx`'s unrelated `ClassificationPolicyConfig` typing, `PolicyDetailsModal.tsx`, `PolicyRow.tsx`, `RuleModal.tsx`, `lib/utils.ts`).

### Deployment

Dashboard + server change, no agent rebuild needed. Rebuild/redeploy the dashboard and server containers via `update.sh`. New policies of this type appear immediately in the policy wizard; existing SMTP relay traffic is unaffected until an admin creates one.

---

## 🛡️ Make print content-inspection failures honest instead of silent allow (August 11, 2026)

### Summary

Follow-up to the ACL fix directly below -- that fix was correct and confirmed working (`icacls` shows the grant in place, `GetLastError` moved from `5` ACCESS_DENIED to `2` FILE_NOT_FOUND), but the underlying mystery turned out to be deeper: for one specific real printer (SHARP AR-6020N) on this test endpoint, **no `.SPL` spool file is ever observable on disk, even for a single moment, during an actual print job** -- confirmed via a live 3-second/60-sample polling loop during active printing, and independently via the agent's own `FindFirstFileA` call (which unlike PowerShell's `Get-ChildItem` doesn't filter hidden/system files, so this isn't a visibility artifact). Every standard explanation was checked and ruled out in turn: "Print directly to the printer" is off (spooling is genuinely enabled), it's not a print-server-redirected queue (direct `Standard TCP/IP Port` to the printer's own IP), the spool directory isn't relocated (`DefaultSpoolDirectory` registry value is empty), it's not a Microsoft IPP Class Driver (genuine OEM "SHARP AR-6020N" driver, `Type: Local`), and it's not a custom vendor print processor (`Win32_Printer.PrintProcessor` is the standard `winprint`). The remaining tool that could settle this decisively -- Process Monitor, watching exactly what `spoolsv.exe` touches on disk in real time -- isn't practical to run across a production fleet, so the root cause of *why* this specific printer/driver/OS combination never produces a spool file remains genuinely open.

Rather than keep guessing at an increasingly deep systems-level mystery, pivoted to fixing the actual security problem this created: the agent was reporting `Print content inspection: ... -> allow (24 chars)` -- language that reads as "we checked, it's clean" -- when what actually happened was `ReadSpoolText()` returned nothing and `EvaluatePrintContent()` silently substituted the document name as a stand-in (`"Local Downlevel Document"` is, not coincidentally, exactly 24 characters). Content inspection failing open and looking *identical* to content inspection succeeding is a real gap for a security product, independent of whether the underlying file-access mystery ever gets solved.

### Fix

1. **`agents/endpoint/windows/print_monitor.h`**: `PrintContentCallback` now returns a `PrintContentResult{bool block, std::string status}` instead of a bare `bool`. `PrintEvent` gained `contentInspectionStatus` (`"not_configured"` | `"inspected"` | `"unavailable"`).
2. **`agents/endpoint/windows/agent.cpp`**: `EvaluatePrintContent()` tracks whether `ReadSpoolText()` returned real bytes (`realContentRead`) *before* the docName fallback overwrites `text`, and returns `"inspected"` or `"unavailable"` accordingly (also sends `content_inspected` as an honest extra field to the server's `/policy/evaluate` call). The print event JSON now includes `content_inspection_status`, bumps `severity` from `"low"` to `"medium"` when content genuinely couldn't be verified, and appends `"(content NOT verified -- ...)"` to the event description so it's visible directly in the Events page detail view, not just in agent logs.
3. **`agents/endpoint/windows/print_monitor.cpp`**: logs a `WARNING`-level `PRINT_CONTENT_UNAVAILABLE` line (not just DEBUG) whenever this happens, so it's visible without needing debug logging enabled.
4. **`server/app/api/v1/events.py`**: found and fixed a second, unrelated bug while wiring this through -- `EventCreate` (the incoming-event Pydantic model) never declared `content_inspection_status`, `block_reason`, or the `printer_name` key the Windows/Linux agents actually send (only a differently-named `printer` field was declared, which nothing sends), so all of these were being **silently stripped by Pydantic before `create_event()` ever saw them** -- the same undeclared-field bug class an earlier comment in this file already flagged for `file_hash`/`username`/`printer`. Declared all three and threaded them into `event_doc`, with `printer_name` and `printer` both merging into the same stored `printer` field for backward compatibility.

### Verification

Brace/paren/bracket balance checks against established baselines: `agent.cpp` unchanged (paren=-2 brace=-5 bracket=-1), `print_monitor.h`/`print_monitor.cpp` both unchanged (0/0/0). `events.py` verified via `python3 -c "import ast; ast.parse(...)"`. Confirmed via `Grep` that `EvaluatePrintContent`'s only caller (the `SetPrintContent` lambda) forwards the new return type automatically with no other call sites needing updates. Confirmed in the dashboard (`Events.tsx`) that `severity === 'medium'` already renders as a distinct (yellow) tone and `event.description` is already displayed in the event detail view, so this is visible end-to-end without further dashboard changes.

### What this does and doesn't fix

This does **not** make print content inspection actually work for the SHARP AR-6020N or any other printer hitting the same not-yet-understood spool-file gap -- that would need either the root cause found (a proper ProcMon trace against a live repro, done deliberately rather than across a fleet) or a fundamentally different interception point (a port monitor or print-processor DLL running inside the spooler process itself, a substantially larger undertaking than anything in this session). What it does fix: an admin looking at the Events page or agent logs can now tell the difference between "this document was inspected and found clean" and "we have no idea what was in this document," instead of both looking identical. Printer-level blocking (`printer_control` policies) and print job detection are both unaffected either way -- those don't depend on reading spool file content.

### Deployment

Both agent-side (Windows) and server-side changes. Wait for CI, redeploy the server via `update.sh`, and reinstall the Windows agent. Re-test print with sensitive content -- if this printer still can't be read, the event should now show medium severity and an explicit "(content NOT verified...)" description instead of a plain low-severity allow.

---

## 🛡️ Fix print content inspection: agent can't read spool files (August 11, 2026)

### Summary

Root cause found via the diagnostic logging added earlier the same day (entry below). The new `PRINT_SPOOL_PATH` log line spelled it out directly: `job 11 -- no spool file resolved (FP-prefix, plain, and newest-in-dir all missed)`, and `PRINT_SPOOL_TEXT` showed the "extracted" text was just `Local Downlevel Document` -- the docName fallback string itself (`EvaluatePrintContent()`'s `if (text.size() < 20) text = docName;` line), not real content at all. That string is exactly 24 characters, which is also exactly the "24 chars" every single prior test showed regardless of app or document content -- confirming `ReadSpoolText()` was returning empty every time, not reading a wrong file or hitting an opaque driver encoding as previously theorized.

Real root cause: `install-agent.ps1`'s scheduled-task principal deliberately runs the main agent process unelevated (`LogonType Interactive -RunLevel Limited`, at normal user privilege) -- required for clipboard/keyboard hook monitoring, which silently breaks if the process is elevated (documented at that principal's own definition). But `%SystemRoot%\System32\spool\PRINTERS\` -- where the actual spooled print job bytes live -- has a default ACL that does NOT grant regular (non-admin) users read access, even to their own print jobs, since those files are created by the SYSTEM-level Print Spooler service. So every attempt to open a job's spool file failed silently (`GetFileAttributesA`/`FindFirstFileA` return "not found" for access-denied too, not just genuinely-missing files), for every app and every printer, 100% reproducibly -- which is exactly the pattern observed across every test this entire investigation.

### Fix

Elevating the whole agent process was not an option (would break the hooks). Instead, since `install-agent.ps1` already requires and runs as Administrator (`#Requires -RunAsAdministrator`), added **Step 9c**: a one-time `icacls` grant of read+list access (`(OI)(CI)RX`) on the spool directory to the logged-in user, run once at install time in the already-elevated installer process -- not the agent process itself. The `(OI)(CI)` (Object Inherit / Container Inherit) flags mean every spool file created after this point automatically inherits the grant, so this doesn't need to run again per print job. Non-fatal on failure (warns and continues, consistent with the USB-block task's error handling right above it) -- job detection and printer-control (device) blocking don't depend on this and keep working either way.

Also improved `NewestSpoolFile()` in `agent.cpp` to log `GetLastError()` when the directory scan fails, specifically calling out `ERROR_ACCESS_DENIED` with the exact manual `icacls` command to run -- so if the installer's grant is ever missed (pre-existing install not re-run, GPO reset the ACL, etc.), the next log line says exactly what's wrong and how to fix it, instead of another multi-round investigation.

### Verification

Brace/paren/bracket balance check against the established baseline: unchanged (paren=-2 brace=-5 bracket=-1). `install-agent.ps1` change reviewed manually for balanced braces/quotes (no PowerShell interpreter available in this environment) and follows the exact same try/catch + non-fatal-warning pattern as the adjacent USB-block task.

### Deployment

This is an **installer-side** fix -- the ACL grant only happens during install, not from a plain agent binary update. Wait for CI to go green, then on the endpoint: **uninstall and reinstall** (not just re-running the agent exe) so `install-agent.ps1` actually re-runs Step 9c. Re-test print with sensitive content and confirm it's now detected/blocked; the `PRINT_SPOOL_PATH`/`PRINT_SPOOL_TEXT` debug lines will show a real resolved path and real extracted content instead of the "no spool file resolved" / docName-fallback pattern.

---

## 🔍 Add diagnostic logging for print content extraction gap (August 11, 2026)

### Summary

Follow-up to the ZIP/XPS entry directly below -- **that theory has been disproven by live testing.** The ZIP/XPS magic-byte warning added there never fired, not even once, across every subsequent test. More importantly: re-tested printing sensitive "Study Report" content from **Notepad** (a plain-text app that should use the classic EMF/RAW print path, explicitly called out as unaffected in the entry below) to the same physical printer, and it failed *identically* to the Word test -- job detected, docName still "Local Downlevel Document", classification still Public/allow, and critically, **exactly the same 24 characters extracted** as the earlier Word test, despite being a completely different app printing completely different document content.

That last detail is the important one: two different apps printing two different documents cannot legitimately produce the exact same extracted character count if the extraction were reading each job's real content. So this now looks like one of two things, and the evidence so far can't distinguish which:

1. The printer's driver (SHARP AR-6020N) converts every job -- regardless of source app -- to a "downlevel"/RAW printer-ready format (the "Local Downlevel Document" label is itself the tell: that's the generic name Windows' local print processor uses for non-EMF/RAW datatype jobs, not something specific to Word's XPS pipeline as originally assumed) where the actual page content is encoded as opaque PCL/PS binary graphics or raster operators, and the only literal readable ASCII left is constant driver/PJL boilerplate (job name, resolution, paper size headers) -- which would explain why the count never changes.
2. `ResolveSpoolFilePath()`/`NewestSpoolFile()` in `agent.cpp` is resolving to the same wrong or stale spool file on every job instead of each job's real data.

Both produce an identical "same small number every time" symptom, so guessing further without evidence would just be a third unproven theory. Instead of that, added targeted `logger.Debug()` instrumentation (no behavior change) in `ReadSpoolText()` and `EvaluatePrintContent()` (`agents/endpoint/windows/agent.cpp`) that logs the resolved spool file path + on-disk byte count, and the actual extracted text itself (truncated to 300 chars). The next live print test will show directly which of the two it is: a resolved path that's identical across different jobs points at (2); recognizable driver boilerplate (e.g. "PJL", "SHARP", resolution numbers) in the extracted text points at (1).

### Verification

Brace/paren/bracket balance check against the established baseline: unchanged (paren=-2 brace=-5 bracket=-1) -- pure logging additions, no control-flow changes.

### Deployment

Wait for CI to rebuild `SeceoKnightAgent.exe`, reinstall via `install-agent.ps1`, then print a document with sensitive content again and pull the new `PRINT_SPOOL_PATH` and `PRINT_SPOOL_TEXT` log lines for the job.

---

## ⚠️ Known limitation: print content inspection can't read XPS-pipeline spool jobs (August 11, 2026)

### CORRECTED (see entry above, same date)

**This entry's root-cause theory has been disproven by live testing** -- the ZIP/XPS magic-byte warning never fired, and a subsequent Notepad test (explicitly called out below as using the "unaffected" classic path) failed identically to the Word test with the exact same 24-character extraction result. The detection code below is harmless and left in place (it would still correctly flag a genuine ZIP/XPS spool file if one is ever hit), but it is **not** the explanation for the print-content-inspection gap. See the entry above for the corrected, still-open investigation.

### Summary

Found live while re-testing task #130's fix: print-job detection now works correctly (confirmed on the Events page -- the print job shows up, where before it didn't show up at all), but a Word document containing sensitive "Study Report" content, printed to a real physical printer, was still classified Public/low and not blocked -- while the exact same content tested via clipboard correctly showed `critical | blocked | STUDY_REPORT`.

Root cause: the print event's `File` field showed **"Local Downlevel Document"** -- not the real filename. That string is a generic label Windows itself assigns for print jobs that go through its newer XPS-based print pipeline (confirmed: the test printed from Word, a common trigger for this pipeline depending on the target driver). In that pipeline the spool file is a ZIP/OPC container -- the actual page text lives inside DEFLATE-compressed XML (`<Glyphs UnicodeString="...">` runs), not as plain ASCII/UTF-16 text sitting directly in the raw bytes the way the older EMF/RAW/PS/PCL spool formats do. `ExtractSpoolStrings()` (agent.cpp) scans raw bytes for readable text runs -- against a compressed ZIP entry it finds essentially nothing, and even the docName fallback in `EvaluatePrintContent()` is uninformative here since Windows itself reports "Local Downlevel Document" instead of the real filename for these jobs. Net effect: a genuinely sensitive document printed through this pipeline was silently classified as if it had no content at all.

### Why this isn't fixed yet

Properly parsing XPS spool content requires a ZIP/DEFLATE decompressor plus XML attribute extraction inside this agent -- real binary/memory-unsafe parsing territory. That class of code needs a compiler and a test harness to verify safely before it's trustworthy in a production security agent; neither was available in this environment. Rather than hand-write and ship untested binary-parsing code into a live DLP agent, this fix is deliberately scoped to detection-and-disclosure instead of a guess at full support.

### What was actually fixed (`ReadSpoolText()` in `agents/endpoint/windows/agent.cpp`)

Detects the ZIP local-file-header magic bytes (`PK\x03\x04`) at the start of a spool file and logs a clear WARNING explaining exactly what's happening and why, when it's hit. This turns a silent, hard-to-diagnose gap (which took a multi-round live investigation to trace, even with full log access) into something immediately searchable in the agent log the next time it's hit -- for this agent or any other affected endpoint.

### What still works today

Print content inspection is NOT broken in general -- it works correctly for the classic EMF/RAW/PS/PCL spool formats most apps (including plain-text apps like Notepad) still use with most printer drivers. The gap is specific to the newer XPS-based print pipeline that some applications (observed: Word) route through for some driver configurations.

### Verification

Brace/paren/bracket balance check against the established baseline: unchanged (paren=-2 brace=-5 bracket=-1) -- this is a pure detection/logging addition, no control-flow changes to the classification path itself.

### Recommendation for the user

To confirm the rest of the print-content pipeline (detection → server round trip → block decision → cancel) is genuinely working end to end, test with an app that uses the classic print path -- e.g. print a plain .txt file containing the same sensitive content from Notepad to the same printer. That isolates this specific XPS-format gap from the rest of the feature. Full XPS support would need to be built and verified in a proper Windows dev/test environment before shipping -- flagging this as a real, scoped gap for a future session rather than closing task #130 as fully complete.

---

## 🛡️ Fix Windows print monitor never detecting real print jobs (August 11, 2026)

### Summary

Hit live in production while testing print content inspection: with a `print_content_prevention` policy confirmed active on the agent (`content_inspection=true` in the log), printing a document containing sensitive content ("Study Report" data) to a real physical printer went completely undetected -- no event, no alert, nothing blocked, and critically, not even the baseline `PRINT_JOB_DETECTED` log line that should fire for every print job regardless of outcome. Confirmed the print monitor thread itself had started successfully hours earlier (`Print monitor started — monitoring print jobs` in the log) and had been running the whole time, ruling out a startup failure. A virtual/instant printer (which can finish before the monitor's poll catches it) was also ruled out -- this was a real physical printer.

Root cause, in `agents/endpoint/windows/print_monitor.cpp`'s `Start()`: the printer/print-server handle (`hPrinter`) was closed immediately after `FindFirstPrinterChangeNotification()` returned successfully, before the monitor thread ever started waiting on the resulting notification handle. Both API calls genuinely succeeded before that close, so `Start()` correctly logged success -- but per Microsoft's documented usage pattern for this API, the source printer handle must remain open for the entire lifetime of the wait loop, not just long enough to create the notification. Closing it early breaks notification delivery going forward, consistently and silently -- explaining why this reproduced every time, not intermittently.

### Fix

1. **Root cause**: `hPrinter` is now stored as a member (`m_hPrinter`) and kept open until `Stop()`, where it's closed alongside `FindClosePrinterChangeNotification()`, matching Microsoft's documented pattern.
2. **Defense in depth**: extracted the job-enumeration/classification/enforcement logic into a new `ProcessPendingJobs()` method, and added a fallback poll that runs it unconditionally every ~2 seconds (on every `WaitForSingleObject` timeout in `MonitorLoop`), not just when the notification fires. Windows print-spooler notification delivery has more than one way to silently fail depending on driver/permission/session specifics -- this bug was one of them, and there could be others. The poll means a real job sitting in a queue gets caught regardless of whether the notification ever fires again for some other reason.
3. To keep the new poll safe for slow physical print jobs (which can legitimately sit in the queue across many consecutive 2-second poll cycles), added `m_processedJobIds` (a per-monitor `std::set<int>`) so a job already classified/enforced isn't reprocessed on every subsequent poll. It's cleared whenever a full pass finds the queue completely empty everywhere -- a safe point to forget old IDs before job-ID recycling could cause a false-positive skip.

### Verification

Brace/paren/bracket balance check against the established baseline: `print_monitor.cpp`/`print_monitor.h` both balance cleanly (0/0/0, consistent with well-formed standalone files); `agent.cpp` (untouched this round) still matches its established baseline exactly. Not yet live-tested against a real print job on this build -- requires the next CI rebuild + agent reinstall to verify end-to-end.

### Deployment

Wait for CI to rebuild `SeceoKnightAgent.exe`, then reinstall via `install-agent.ps1` on the endpoint. Re-test: print a document containing sensitive content (or to a non-sanctioned printer under a `printer_control` allowlist policy) to a real physical printer, and confirm this time it shows up as a blocked/alerted event on the Events page.

---

## 🛡️ Fix Windows agent heartbeat starved by shared HTTP connection (August 11, 2026)

### Summary

Hit live in production right after a routine agent reinstall: the dashboard showed the agent as Disconnected even though the process was fully alive and actively working (baseline scan running, clipboard events being classified and evaluated in real time). Traced via the agent's own log: heartbeats succeeded every ~30s from process startup, then stopped completely and stayed stopped for 20+ minutes straight, while every other thread kept logging normally the entire time. Only a full agent restart cleared it.

Root cause, in `agents/endpoint/windows/agent.cpp`: `HttpClient::Post/Put/Get/Delete` each hold that instance's own private `requestMutex` for the full duration of the network call (up to ~45s worst case per `WinHttpSetTimeouts`). Every caller across the whole agent — heartbeat, clipboard policy checks, USB checks, event submission, browser-dialog forwarding, everything — gets the exact same shared `HttpClient` instance via `GetHttpClient()`, so they all serialize through that one mutex. A prior fix (see the long comment on `httpClientMutex`) made the *pointer itself* swappable without blocking other callers during reconnect, but never addressed this deeper issue: all requests through that one instance still queue behind each other. A burst of ordinary traffic on the shared client — in this case, real clipboard activity during a live troubleshooting session, each paste triggering a synchronous policy-evaluation HTTP call — can starve the heartbeat PUT behind it indefinitely. And because `HeartbeatLoop`'s own reconnect logic (reinitialize the client after 3 consecutive failures) only runs once `SendHeartbeat()` returns, it can never kick in if the call never gets the chance to run in the first place.

### Fix

Gave the heartbeat loop its own dedicated `HttpClient` instance (`heartbeatHttpClient`), with its own independent WinHTTP session, connection, and `requestMutex`, completely decoupled from the shared client used for everything else:
- Constructed alongside the main `httpClient` at agent startup.
- `SendHeartbeat()` now calls `heartbeatHttpClient->Put(...)` directly instead of `GetHttpClient()->Put(...)`.
- The existing "3 consecutive failures → reinitialize" recovery logic now reinitializes `heartbeatHttpClient` specifically, not the shared client (reassigning the shared client out from under unrelated in-flight callers would have been its own bug). Since only `HeartbeatLoop` ever touches `heartbeatHttpClient`, no mutex is needed to reassign it.

A heartbeat PUT can no longer queue behind any other traffic the agent generates, regardless of how busy the rest of the agent is.

### Verification

Brace/paren/bracket balance check (`/tmp/brace_check.py`) against the established compiler-verified baseline: unchanged (paren=-2 brace=-5 bracket=-1). Confirmed via grep that no other call site still references the old shared-client heartbeat path. Not yet independently re-tested against a live sustained clipboard-traffic burst beyond the manual recovery already performed (agent restart resolved the immediate incident; this fix prevents recurrence going forward but hasn't been stress-tested).

### Deployment

Same as any other agent-side fix: wait for CI to rebuild `SeceoKnightAgent.exe`, then reinstall via `install-agent.ps1` on each endpoint.

---

## 🛡️ Fix update.sh silently filling the disk with dangling image layers (August 7, 2026)

### Summary

Hit live in production immediately after deploying task #127: `sudo bash update.sh` failed with `dependency failed to start: container seceoknight-mongodb is unhealthy`. `docker logs seceoknight-mongodb` showed WiredTiger hard-crashing (`WT_PANIC`) on `No space left on device`, and `df -h /` confirmed the root filesystem was at 100% (0 bytes free). `docker system df` showed why: **30.54GB of Docker images, 24GB (78%) of it reclaimable** — dangling layers left behind by every previous `docker compose pull` across every past deployment on this server. Every update re-tags `:latest` to a new digest and leaves the old digest on disk, untagged; nothing was ever cleaning those up, so usage only ever grew until it took the database down with it.

This was an infrastructure gap in `update.sh` itself, not a one-off — every server running this script would eventually hit the same wall as more CI builds accumulate.

### Fix (`update.sh`)

Two changes, both using `docker image prune -f` (dangling images only — never touches an image any current container is actually using, so this can't remove real data or an in-use image):

1. **Before pulling** (new step 1.5): checks free space on the filesystem holding `INSTALL_DIR`; if under 5GB, proactively prunes and reports the new free space, so a long-neglected server doesn't run out of room mid-pull the way this one did.
2. **After a confirmed-healthy update** (new step 6): always prunes the now-superseded image digest(s) from the update that just completed, so usage stays flat across routine updates instead of growing indefinitely.

### Verification

`bash -n update.sh` clean. Not independently live-tested beyond the manual recovery already performed on the affected server (`docker image prune -a -f` reclaimed 24GB, restoring `df -h /` to 22GB free / 40% used, after which `update.sh` completed successfully end-to-end).

### Deployment

`cd /opt/seceoknight && sudo bash update.sh` picks up this fix on its own next run (it re-syncs nothing new here since `update.sh` isn't one of the two files it re-syncs from GitHub — re-download it directly: `curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/update.sh -o update.sh`).

---

## 🛡️ Fix USB block/quarantine file-lock race + dashboard mislabeling (August 7, 2026)

### Summary

Closes task #127. Found via a real live test: the user set an EDM source to Restricted, copied the matching CSV to a USB drive, and the dashboard showed a green "blocked" badge -- but the file was still physically present on the drive (confirmed by re-inserting it). Two independent bugs were involved, both real, both fixed.

### Bug 1 — Windows file-lock race on block/quarantine (agent-side, root cause)

The agent's log revealed the actual failure: `Failed to block USB transfer: filesystem error: cannot remove: The process cannot access the file because it is being used by another process [G:\User's List.csv]`. This is a genuine Windows race, not an edge case: the USB directory-watcher reacts the instant a new file is detected, but Explorer (or real-time AV scanning) frequently still holds a handle on the just-copied file for a short window afterward. `fs::remove()`/`fs::copy_file()` called immediately in that window throw `ERROR_SHARING_VIOLATION`, and there was no retry logic, so the block/quarantine attempt failed outright every time it raced.

Fix (`agents/endpoint/windows/agent.cpp`): added `RemoveFileWithRetry()` / `CopyFileWithRetry()` helpers (5 attempts, 200ms apart, using the `std::error_code` overloads so failures don't throw mid-retry) and swapped them in for the raw `fs::remove`/`fs::copy_file` calls in `HandleUSBFileTransferBlockNoTimestamp()` and `HandleUSBFileTransferQuarantineNoTimestamp()` (both the COPY and MOVE code paths in each).

### Bug 2 — Dashboard showed "blocked" for an event whose actual outcome was "block_failed" (server-side, the visible symptom)

Even before Bug 1 is fixed, the dashboard should have told the truth about the failure -- instead it actively hid it. Root cause, traced through `server/app/api/v1/events.py`:

1. The agent correctly reports the real outcome via `SendEvent()` with `action: "block_failed"` (or `"quarantine_failed"`) when the filesystem operation throws.
2. `create_event()` inserts the raw event with `action_taken="block_failed"` and `blocked=False` — correct so far.
3. A background task (`_process_event_background`) then re-evaluates the event against DB policies for classification/alerting purposes. `ActionExecutor.execute_block()` (`app/actions/action_executor.py`) sets `event["blocked"] = True` *unconditionally* whenever a matched policy's configured action is `"block"` — this is a **declarative** "policy says block this" flag, not a confirmation the endpoint actually deleted anything.
4. `_process_event_background` then did: `if processed.get("blocked"): update_fields["blocked"] = True; update_fields["action_taken"] = "blocked"` — silently clobbering the agent's correct `"block_failed"` back to `"blocked"`, two lines after it had just been set correctly from the same payload.

Net effect: the server's own "a block policy matched" bookkeeping overwrote the endpoint's ground truth, and the dashboard rendered a misleading green "blocked" badge for a file that never left the USB drive.

Fix (`server/app/api/v1/events.py`, `_process_event_background`): the agent-reported `action` is now checked first. If it ends in `"_failed"` (covers `block_failed` and `quarantine_failed`), that ground truth wins outright — `blocked`/`quarantined` are forced to `False` and `action_taken` is left as the agent's own failure string, never overwritten by the declarative policy-match signal.

Defense in depth on the dashboard (`dashboard/src/pages/Events.tsx`): added a dedicated `usbTransferFailed()` check so a `block_failed`/`quarantine_failed` USB transfer event now renders a distinct red "block failed — file still present" / "quarantine failed — file still present" badge (list view) and "Block Failed — file still present" (detail view), instead of silently falling through to no badge or (pre-fix) the misleading success badge. This is a second layer of protection — even if some other future code path sets `blocked` incorrectly, the dashboard now cross-checks the raw `action` string directly rather than trusting a single boolean field.

### Verification

`bash`/error-code based `fs::` calls verified via brace/paren/bracket balance check against the established compiler-verified baseline (unchanged: paren=-2 brace=-5 bracket=-1). `python3 -c "import ast; ast.parse(...)"` clean on `events.py`. `npx tsc --noEmit` on the dashboard shows the same pre-existing 24 errors as baseline — no new TypeScript errors from the `Events.tsx` changes.

**Not yet live-tested end to end** — the agent.cpp retry fix requires a CI rebuild of the Windows agent .exe and a fresh install before it can be verified against a real USB drive; the server-side fix requires `update.sh` on the server. See deployment note below.

### Deployment

1. **Server side** (fixes the dashboard mislabeling immediately, independent of the agent fix): `cd /opt/seceoknight && sudo bash update.sh` once this CI build is green.
2. **Windows agent side** (fixes the actual file-lock race): wait for CI to rebuild `SeceoKnightAgent.exe`, then reinstall via `install-agent.ps1` on the endpoint.
3. **Re-test**: repeat the exact same test — set an EDM source to Restricted, copy the matching file to a USB drive, confirm the file is actually removed from the drive this time (re-insert the drive to double check) and the dashboard shows a genuine "USB Transfer Blocked" / "blocked" badge, not a failure badge.

---

## 🛡️ Wire Data Matching into live enforcement (August 7, 2026)

### Summary

Closes task #126. Data Matching (EDM + document fingerprinting, task #123/#109) previously only worked through its own standalone API and the dashboard's "Test content" sandbox -- an admin could index a real CSV of sensitive records or a protected document, but nothing in actual live traffic (USB transfers, clipboard, browser uploads, email, print jobs) was ever checked against it. The user asked for this wired into real enforcement, with a specific mapping: a source classified Restricted should block the action; Confidential or Internal should alert only, not block.

Research (see `ClassificationEngine.classify_content()`, `server/app/services/classification_engine.py`) confirmed a single shared chokepoint already exists: every one of the 5 requested channels -- USB/clipboard/print/network-share via the Windows agent, browser upload via the extension's native host, and email via `smtp-relay/app/dlp_client.py` -- round-trips content to `POST /agents/{agent_id}/policy/evaluate` (`server/app/api/v1/agents.py`), which calls `ClassificationEngine.classify_content()` then `DatabasePolicyEvaluator.evaluate_event()` to decide the action. One edit at that chokepoint covers all 5 channels rather than touching five separate code paths.

### What was added

**`classification_engine.py`**: new `_check_data_match()` method calls `DataMatchIndexService.match_content()` (the exact same function the dashboard's "Test content" tool already calls, so live enforcement and the test tool can never disagree) and folds results into the classification pipeline as a new Step 1.5, right after the existing (unrelated) whole-file SHA-256 fingerprint check. A Restricted-classified source match is authoritative and short-circuits immediately, exactly like the legacy fingerprint check already does. Confidential/Internal hits are not authoritative -- they're merged into the normal pipeline, and the final classification level is the more severe of the regex-based result and the data-match result (via a new `_classification_rank()` helper), so neither can silently downgrade a stronger finding from the other. New `ClassificationResult.data_match_hits` field carries the raw per-source hits (with each source's own `classification`) through to the caller. Matched sources also get a synthesized entry in `matched_rules` ("Data Match: <name> (...)")  so they show up in the existing Events/Incidents matched-rules display with zero dashboard changes needed.

**`agents.py`** (`evaluate_policy_realtime`): new step reads `classification_result.data_match_hits` directly and forces `should_block`/`should_alert` per the user's exact requested mapping -- Restricted -> block, Confidential/Internal -> alert (severity "critical"/"medium" respectively). This is deliberately **not** routed through the existing `classification_level` -> `Policy` row matching used for everything else in this function: the seeded defaults in `data/default_policies.json` only cover the USB channel and map Confidential to block (stricter than what the user asked for specifically for Data Matching), and no default policies exist at all for clipboard/email/print/browser-upload. Forcing the action directly from each hit's own `classification` field means data-matching enforcement works identically across all 5 channels with zero policy configuration required, and never changes how existing regex/ML-based detections are enforced -- purely additive, only ever turns `should_block`/`should_alert` further on, never off.

### Deliberate scope decision

A separate `/decision/` endpoint (`server/app/api/v1/decision.py`) also calls `classify_content()` but resolves actions through a different engine (`DecisionEngine`, not `DatabasePolicyEvaluator`) that only receives the `classification_level` string, not the full `data_match_hits` list -- so it does not get the same forced block/alert behavior from this change. None of the 5 channels the user asked about were found to call this endpoint (all confirmed routed through `agents.py`'s `policy/evaluate` instead), so it was left untouched rather than expanding an already-safety-critical change further on unconfirmed usage. Flagging as a known follow-up if `/decision/` turns out to be live somewhere.

### Verification

`python3 -c "import ast; ast.parse(...)"`: clean on both modified files (`classification_engine.py`, `agents.py`). **Not live-tested** -- no database or running agent in this sandbox to actually upload a Restricted-classified CSV and confirm a real USB/clipboard/email/print/upload event gets blocked, or that a Confidential one only alerts. Before relying on this in production: create one test source of each classification tier via the dashboard, then trigger a matching transfer on each of the 5 channels and confirm the action (block vs alert) matches expectations, and that the event detail view shows the "Data Match: ..." entry in matched rules.

---

## 🛡️ New `update.sh` — fix nginx stale-upstream 502 on routine updates (August 7, 2026)

### Summary

Found and fixed during a real production incident on an existing install: running the update procedure that was previously documented everywhere in this repo (`docker compose pull && docker compose up -d`) recreated the `manager` and `dashboard` containers with new internal Docker IPs, but left the long-running `nginx` container untouched. nginx resolves those service names to a container IP and, having been running for days without a reload, kept proxying to the *old*, now-dead IPs. Every request 502'd -- and in the dashboard, that surfaced as a confusing "Invalid email or password" on login rather than an obvious connectivity error, since the frontend couldn't distinguish "backend rejected the credentials" from "backend unreachable." The admin password itself was never the problem; nginx was.

Two further gaps compounded this: (1) `docker compose pull` only refreshes container *images* -- it never re-fetches `docker-compose.prod.yml` or `nginx/nginx.conf` from the repo, which `install.sh` only ever downloads once, on first install. `nginx/nginx.conf` already had a dynamic-resolver fix for exactly this class of bug (`resolver 127.0.0.11 valid=10s;` + variable-based `proxy_pass`, added in an earlier pass), but that fix could never reach a server that was installed before it landed -- `pull` alone doesn't sync config files, only images. (2) Neither the old documented command nor a bare `up -d` runs `alembic upgrade head`, so pending migrations also silently never apply on a routine update unless an operator remembers to run it by hand.

### What was added

**`update.sh`** (new, repo root): the correct one-command way to roll an existing install forward. Re-syncs `docker-compose.prod.yml` and `nginx/nginx.conf` from the repo (backing up any existing file first, in case an operator hand-edited it -- diff instructions printed if so), pulls new images, then force-recreates `manager`, `dashboard`, `celery-worker`, `celery-beat`, **and `nginx` together, every time**, regardless of whether nginx's own image changed. Runs `alembic upgrade head` afterward and health-checks the API through nginx before reporting success.

**`install.sh`**: now downloads `update.sh` alongside the compose file and nginx config so it's already on disk the first time a box needs updating. The final "Useful commands" banner no longer prints the bare `pull && up -d` two-liner -- it now points at `update.sh` with an explanation of why the naive version is unsafe.

**`DEPLOYMENT.md`**: the "Day-2 ops → pull a new image and roll forward" section rewritten to lead with `update.sh`, with the full incident explanation inline so a future operator understands *why* the old command is wrong, not just that it's deprecated.

### Verification

`bash -n update.sh` and `bash -n install.sh`: both clean. Not live-tested against a second real update cycle in this sandbox (no running stack here) -- the sequence itself (re-sync configs → pull → force-recreate including nginx → migrate → health-check) is exactly what was run by hand, one command at a time, to actually recover the production box this was found on, so each individual step is field-verified; only the script wrapping them together is new and unexercised end-to-end.

---

## 🛡️ Behavioral risk scoring -- new capability, not ported from CyberSentinel (August 7, 2026)

### Summary

Closes task #120. After the final parity audit (task #119) confirmed 100% feature parity with CyberSentinel-DLP, the user asked for SeceoKnight to go beyond parity, specifically prioritizing smarter detection over other directions. Both products currently score *events*, not *people*: every detection (USB copy, clipboard paste, upload, print job) is classified and actioned in isolation, with severity coming from content/context of that one event alone. Neither product has ever looked at a user's pattern of activity over time or across channels. A user who touches USB, email, cloud upload, and printing all in the same afternoon, or who is unusually active at 2am, looks identical in both products' event streams to a user who did any one of those things once. This is a real blind spot in both, not just SeceoKnight -- so it's an area where SeceoKnight can become genuinely more advanced rather than just catching up.

### What was added

**Algorithm (`server/app/services/risk_scoring_service.py`)**: a transparent, statistically-grounded 0-100 per-user score over a rolling window (default 14 days), built from five weighted components -- `volume` (z-score of the user's event count against the population, 15%), `channel_diversity` (how many distinct channels -- USB, clipboard, print, browser upload, email, cloud, etc. -- the user touched, weighted highest at 25% since breadth-across-channels is the strongest behavioral tell), `off_hours` (share of events outside 07:00-19:00 or on weekends, 15%), `block_ratio` (share of events that were actually blocked/quarantined, 25%), and `severity_mix` (share of critical/high-severity events, 20%). Risk level buckets: critical ≥75, high ≥50, medium ≥25, low otherwise. Deliberately built as auditable statistical baselining (z-scores, ratios, weighted sums) rather than a black-box ML model -- there's no labelled training data or way to validate a model's accuracy in this sandbox, and a security product's risk scores need to be explainable to an analyst, not just accurate.

**Data model + migration**: `server/app/models/user_risk_score.py` (new `UserRiskScore` model, one current row per `user_email`, storing the score, level, full component breakdown as JSON, raw counts, and `score_previous`/`trend` for week-over-week movement) and `server/alembic/versions/036_user_risk_scores.py` (new `user_risk_scores` table + two indexes, `down_revision` chained onto `035_data_match_sources`).

**API (`server/app/api/v1/risk_scoring.py`, mounted at `/risk-scoring`)**: `GET /users` (paginated, filterable by minimum level, analyst-role), `GET /users/{user_email}` (full detail + recent events, analyst-role), `POST /recompute` (admin-role, recomputes all users over a configurable window). No scheduler is wired up yet -- `POST /recompute` is the interim manual/external trigger; a cron-style periodic recompute would be a natural follow-up.

**Dashboard (`lib/risk-scoring-api.ts`, `pages/RiskScoring.tsx`)**: new "Risk Scoring" page (new sidebar entry between Incidents and Log Explorer, `view_alerts`-gated to match the Alerts/Incidents audience) -- a ranked, filterable, paginated table of every scored user with a score bar, risk badge, trend arrow, event/block/channel counts, and a Recompute button; clicking a row opens a detail modal showing the full component breakdown (so an analyst can see exactly why a score is what it is) plus that user's recent events. An explainability banner states directly that this is statistical baselining, not a black box.

### Verification

`python3 -c "import ast; ast.parse(...)"`: clean on all 6 new/modified Python files (`user_risk_score.py`, `models/__init__.py`, `036_user_risk_scores.py`, `risk_scoring_service.py`, `risk_scoring.py`, `api/v1/__init__.py`). `npx tsc --noEmit -p tsconfig.json`: same 24 pre-existing errors as before this change (confirmed via diff), zero in `risk-scoring-api.ts`, `RiskScoring.tsx`, or the lines touched in `App.tsx`/`Sidebar.tsx`.

**Not live-tested.** This is a brand-new feature with no runtime testing in this sandbox -- no database to run the migration against, no live event data to run `recompute_all()` over, and no dev server to click through the dashboard page. The SQL query shape, the z-score/ratio math, the upsert-by-`user_email` logic, and the dashboard's rendering of live API responses are all unverified beyond static analysis and type-checking. This should be smoke-tested against a real database with real event data before being relied on in production: run the migration, POST `/risk-scoring/recompute`, and confirm the scores and component breakdowns look sane for a few known users.

---

## 🛡️ Data Matching (EDM + fingerprint) -- dashboard page (August 7, 2026)

### Summary

Closes task #123. The Exact Data Matching + document fingerprinting server API (`server/app/api/v1/data_matching.py`, `data_match_index_service.py`, `data_match_source.py`) was already fully ported in an earlier pass (task #109) and is mounted at `/data-matching` -- but nobody had built a dashboard page for it, so admins could only create a protected-data source or test content against one via raw API calls. The final parity audit caught this as a real, if narrower-than-it-first-looked, gap: the hard part (the matching engine itself) was done; only the management UI was missing.

### What was added

**`lib/data-matching-api.ts`**: new API client (`listSources`, `createEdm`, `createFingerprint`, `updateSource`, `deleteSource`, `testContent`, `fileToBase64`), typed against the exact response shape `DataMatchSource.to_dict()`/`match_content()` already return server-side -- confirmed field-for-field before writing this (`row_count`/`shingle_count`/`columns`/`min_fields`/`min_shingles`/`min_containment`/`classification`/`enabled` on sources; `source_id`/`name`/`type`/`classification`/`matched_rows` or `overlap`+`containment` on match results).

**`pages/DataMatching.tsx`**: new page -- a sources table (name, type badge, indexed-record/shingle counts, match threshold, resulting classification, enabled toggle, delete), a "New source" modal with EDM (CSV upload or paste) and Fingerprint (document upload or paste text) tabs, and a "Test content" modal that dry-runs pasted text against all enabled sources without creating an event. A trust banner states plainly what the backend already guarantees: plaintext is discarded after indexing, only keyed HMAC digests are stored. Added table pagination (`usePagination`/`DataPagination`) matching the established convention from task #80, which CyberSentinel's own version of this page doesn't have.

**Wiring**: new route (`/data-matching`) in `App.tsx`, new sidebar entry (between Printers and Reports, `Fingerprint` icon) in `Sidebar.tsx`, gated the same way as USB Devices/Printers (`create_policy`/`update_policy`) since the server enforces admin-only writes and analyst-level reads on this router too.

Reused SeceoKnight's own existing `cs-`-prefixed design tokens (`cs-panel`, `cs-hair`, `cs-indigo`, `btn`/`input`/`badge`/`table` utility classes) -- confirmed these already exist in SK's dashboard (shared with CyberSentinel's own convention, unlike the raw-Tailwind style used by the newer policy-wizard forms), so this page is a close, low-risk adaptation rather than a rewrite.

### Verification

`npx tsc --noEmit -p tsconfig.json`: same 24 pre-existing errors as before this change (confirmed via diff), zero in `data-matching-api.ts`, `DataMatching.tsx`, `App.tsx`, or `Sidebar.tsx`. Not runtime-tested -- no dev server run in this sandbox to click through creating an EDM source, a fingerprint source, and running a test match.

---

## 🛡️ Printer device control -- new policy type (August 7, 2026)

### Summary

Closes task #122. The final parity audit found that `printer_control` mode/scope enforcement -- both the server endpoint (`GET /agents/{id}/printer-policy`) and the Windows agent's enforcement (`ShouldBlockPrinter()`, wired up in task #114) -- were already fully built and reading a `Policy` row of `type="printer_control"`, but there was no way to actually create that policy row from the dashboard. `Printers.tsx` only exposes an allowlist on/off toggle; the coarser controls (block printing entirely, network-only, local-only) were configurable in the database but not in the UI.

### What was added

**`PrinterControlPolicyForm.tsx`**: new form, `mode` (enforce/audit) and `scope` (block_all/block_network/block_local/allowlist) as radio groups, matching the conventions from task #118's five forms exactly. Explicitly notes it's additive to and independent of `print_content_prevention` (device-level vs. content-level control) and that the allowlist itself is still managed on the Printers page -- this policy only controls whether/how that allowlist (and the coarser scopes) get enforced.

**Wiring**: `printer_control` added to `types/policy.ts`'s `PolicyType`/`PolicyConfig` (config shape matches the server's `agents.py` `printer-policy` endpoint exactly: `{mode, scope}`), a new `PolicyTypeSelector.tsx` tile, `PolicyCreatorModal.tsx` import/default-config-case/JSX-block, and `utils/policyUtils.ts` icon/label/summary/default-config cases -- no `validatePolicy` case needed since both fields already default to a valid combination.

This is dashboard-only: zero agent or server changes, since both already existed and were simply unreachable from the UI.

### Verification

`npx tsc --noEmit -p tsconfig.json`: same 24 pre-existing errors as before this change (confirmed via diff), zero in `PrinterControlPolicyForm.tsx` or any line this change touched. Not runtime-tested -- no dev server run in this sandbox.

---

## 🛡️ Network-exfil CLI monitoring: cloud-CLI + SSH secure-copy coverage (August 7, 2026)

### Summary

Closes task #121, the single most significant finding from a final CyberSentinel-vs-SeceoKnight parity audit run after the previous batch of work (tasks #111-118) was believed to close every remaining gap. The audit diffed `IsMonitoredExe()` between both agents directly: SeceoKnight's network-exfil monitor only recognized `curl.exe, wget.exe, powershell.exe, pwsh.exe, powershell_ise.exe, python*.exe, bitsadmin.exe, certutil.exe` -- CyberSentinel's also recognizes `aws.exe, rclone.exe, s3cmd.exe, azcopy.exe` (every major cloud-CLI upload tool) and `scp.exe, pscp.exe, winscp.com` (SSH/SFTP secure copy). None of those seven processes were suspended, inspected, or content-classified at all on SeceoKnight -- `aws s3 cp confidential.xlsx s3://...` or `scp secrets.txt user@host:` sailed through with zero visibility, a real hole in a core DLP capability rather than a cosmetic gap.

### What was added

**`network_exfil_monitor.cpp`**: added the 7 new executable names to `IsMonitoredExe()`'s target set, and ported CyberSentinel's cloud-storage/secure-copy argument parser into `ExtractFilePathsFromCmdline()` -- handles `--body`/`--file`/`--source`/`--src` flags (both `--flag value` and `--flag=value` forms) plus positional local-path arguments, while skipping option flags, remote URI schemes (`s3://`, `gs://`, `http(s)://`, `azure://`, `b2://`), and `scp`/`pscp` remote targets (`user@host:path`, detected by having both `@` and `:`) so only genuine local source files get resolved and handed to the existing suspend-read-classify-terminate pipeline. No changes to that pipeline itself -- these 7 tools now feed into exactly the same content classification and blocking decision every other monitored CLI tool already uses.

### Deliberate scope decision: no separate `network_exfiltration_prevention` policy type this pass

CyberSentinel also exposes a `network_exfiltration_prevention` policy type (`dataTypes`, `customPatterns`, `monitoredMethods`, `monitoredPorts`, `direction`, `action`) letting an admin configure which data categories and channels trigger a block. Investigated wiring an equivalent in: the block decision lives in exactly two places in `network_exfil_monitor.cpp` (`sensitive = category is Confidential/Restricted`, at the CLI-transfer path and the browser/messaging-dialog path), fed by a `classify()` callback with no channel-specific filtering today. Adding a real, enforced audit-vs-block toggle and per-category allowlist would mean modifying that shared classify-and-terminate decision path -- the same security-critical logic the module's own header comment flags as needing care -- with no compiler in this sandbox to verify the change. Given the actual detection-coverage gap (the 7 missing tools, now fixed) was the substantive issue and the content-classification pipeline already governs blocking consistently and correctly across every channel, this was judged not worth the risk of an unverified edit to that specific code path in this pass. Flagging as a candidate for a follow-up that includes real agent testing.

### Verification

Brace-balance check on `network_exfil_monitor.cpp`: `paren=1 brace=-2 bracket=-1`, identical before and after this edit (same corroborating-evidence method used for this file throughout this project, since it has no saved compiler-verified baseline in this sandbox). No changes to `network_exfil_monitor.h` or `agent.cpp`. **Not live-tested**: no MinGW compiler and no AWS CLI/rclone/scp installed in this sandbox to actually run a transfer and confirm the new argument parsing resolves real local file paths correctly.

---

## 🛡️ Dashboard UI forms for 5 new policy types -- new capability (August 6, 2026)

### Summary

Closes task #118, the last item off the CyberSentinel-parity list from this batch of work. The previous five entries (tasks #111-115) added real Windows-agent enforcement and server-side policy endpoints for network share transfer control, application control, wireless/Bluetooth control, print content prevention, and messaging app attachment control -- but an admin had no way to actually create or edit any of those five policy types from the dashboard; the only way to set one up was a raw API call. This entry adds the missing management surface.

### What was added

Five new form components in `dashboard/src/components/policies/`, each matching the established `FileIdentityDenylistPolicyForm.tsx`/`FileTransferPolicyForm.tsx` conventions exactly (plain Tailwind utility classes on the existing dark `gray-900`/`indigo-500` palette, no custom design-system class names, radio-group toggles for exclusive mode/action choices, comma-separated text inputs for exception lists, a defensive `rawConfig ?? default` rebuild at the top of every component so a freshly-selected policy type never dereferences `undefined`):

- `NetworkShareControlPolicyForm.tsx` -- mode (block_all/content_aware/off), action (audit/block), 4 exception-list inputs.
- `ApplicationControlPolicyForm.tsx` -- mode (allowlist/blocklist), a quick-toggle chip row of common CLI transfer tools (curl.exe, wget.exe, powershell.exe, bitsadmin.exe, certutil.exe, rclone.exe) plus free-text add, channels, 4 exception-list inputs.
- `WirelessTransferControlPolicyForm.tsx` -- mode (enforce/audit/off), two checkboxes for the two independently-toggleable channels (Bluetooth file transfer, Wi-Fi Direct/Nearby Sharing).
- `PrintContentPreventionPolicyForm.tsx` -- mode (enforce/audit) only, matching the backend's minimal config shape; explicitly notes this is content-level inspection, distinct from the printer-device allowlist already managed on the Printers page.
- `MessagingAppControlPolicyForm.tsx` -- action (alert/block, alert-first default matching the agent's own alert-first design), a quick-toggle chip row of the server's default managed-app list (teams.exe, whatsapp.exe, telegram.exe, slack.exe, discord.exe, signal.exe) plus free-text add, 2 exception-list inputs.

**Wiring** (4 files, all sequential-conditional/switch additions matching the existing style, no new abstractions):
- `types/policy.ts`: 5 new `PolicyType` literals, 5 new `XConfig` interfaces matching the server contract in `agents.py` exactly, added to the `PolicyConfig` union.
- `components/policies/PolicyTypeSelector.tsx`: 5 new tiles with `lucide-react` icons (`FolderInput`, `AppWindow`, `Bluetooth`, `Printer`, `MessageSquare`).
- `components/policies/PolicyCreatorModal.tsx`: 5 new form imports, 5 new `getDefaultConfig()` cases, 5 new Step-2 JSX conditional blocks. Introduced a `TraditionalPolicyConfig` type alias (the 14-member config union, up from 9) so the type doesn't have to be spelled out three times and drift.
- `utils/policyUtils.ts`: 5 new cases each in `getPolicyTypeIcon`, `getPolicyTypeLabel`, `formatPolicyConfig` (the events-list/policy-table one-line summary), `validatePolicy` (only `application_control` and `wireless_transfer_control` have a required-field check -- the other three are always valid at their defaults), and the second/duplicate `getDefaultConfig` used by `transformApiPolicyToFrontend` when hydrating a policy fetched from the API with no `config` yet.

### Design decision: `printer_control` stays separate, no changes to Printers.tsx

Investigated whether `print_content_prevention` should be merged into the existing printer-device-allowlist UI on the Printers page (since the agent-facing `GET /agents/{id}/printer-policy` endpoint combines both into one response). Confirmed they're independent `Policy` rows with independent config shapes and independent admin intents -- device-level printer allowlisting vs. content-level document scanning -- and the combined endpoint is purely an agent polling-cycle convenience, not evidence they should share one form. `print_content_prevention` got its own new wizard entry; `Printers.tsx`/`printers-api.ts`/`printer_control` (which was never in the generic policy wizard to begin with -- it has its own bespoke page) were left untouched.

### Verification

`npx tsc --noEmit -p tsconfig.json`: 24 pre-existing type errors, confirmed by file-by-file diff that every one is in a file/line this change didn't touch (`ClassificationPolicyForm.tsx`, `ClipboardPolicyForm.tsx`, `GoogleDriveCloudPolicyForm.tsx`, `OneDriveCloudPolicyForm.tsx`, `PolicyDetailsModal.tsx`, `PolicyRow.tsx`, `RuleModal.tsx`, `lib/utils.ts`, plus 5 pre-existing `setConfig(...)` call sites in `PolicyCreatorModal.tsx` that had the identical `{} | X` / broader-`PolicyConfig` type mismatch before this change too, since `getDefaultConfig()` already returned `X | {}` and the config state type never included `ClassificationPolicyConfig`). Zero errors in any of the 5 new form files, `types/policy.ts`, or `PolicyTypeSelector.tsx`. **Not runtime-tested**: no dev server was run in this sandbox to click through the wizard end-to-end and confirm a created policy round-trips correctly through the API; worth a manual smoke test (create one of each of the 5 new types, edit it, confirm the config JSON matches what the agent/server endpoints expect) before relying on this in production.

---

## 🛡️ Linux agent: local policy cache for offline restarts -- new capability (August 6, 2026)

### Summary

Closes task #95/#117 -- the other half of a misstatement made earlier in this session. An earlier CHANGELOG entry for the Windows agent's policy cache (task #107) claimed "the Linux agent already persisted its last-known-good policy bundle to disk." That was wrong (confirmed by direct grep, no `policy_cache` references anywhere in the Linux agent) and was corrected explicitly when caught. This entry actually closes that gap: before this change, `self.policy_bundle` lived only in Python-process memory -- an agent restarted while the server was unreachable (VPN down, server mid-deploy, laptop just booted off-network) enforced **nothing** until the next successful sync, the identical fail-closed-becomes-fail-open-on-restart hole task #107 fixed on Windows.

### Design note: CyberSentinel's own `policy_cache.py` is unused dead code

CyberSentinel-DLP does ship a `policy_cache.py` on Linux, but it's a much broader module (decision cache with TTL + full policy bundle persistence + an offline event queue + fail-open decision logic) that its own `agent.py` **never imports** -- confirmed via `agent_launcher.py`'s own comment: *"policy_cache and print_monitor are not imported by the current agent... forced in as hidden imports at build time"* purely so the PyInstaller self-test can prove the module is bundled. It's shipped but dead. Porting it wholesale would mean shipping SK's own dead code. Instead, this port takes only the piece that's actually needed and wires it in for real: persist-last-known-good-bundle-to-disk, matching the already-shipped, already-verified Windows `PolicyCachePath()`/`SavePolicyBundleToCache()`/`LoadCachedPolicyBundle()` pattern from task #107. (SK's own offline-queue equivalent was ported separately and correctly wired in the previous entry, task #96/#116.)

### What was added

**`agent.py`**: `_resolve_policy_cache_path()` (module-level, mirrors the existing `_resolve_log_path()` pattern) resolves the cache file to `/var/lib/seceoknight/policy_bundle.cache` -- the FHS-correct location for persistent application state, writable by the root user the systemd service always runs as -- falling back to `~/.seceoknight/policy_bundle.cache` only if that isn't writable (manual/unprivileged runs).

- `Agent._save_policy_bundle_to_cache(bundle)`: writes to a `.tmp` file and `os.replace()`s it into place (atomic on POSIX -- a slight improvement over the Windows version's plain truncate-and-write, since it removes the truncated-read window if a read raced a write). Called from `sync_policies()` right after a successfully-applied sync response, mirroring the Windows call site.
- `Agent._load_cached_policy_bundle()`: reads the cache file, sets `self.policy_bundle`/`self.active_policy_version`, and calls the existing `_apply_policy_bundle()` immediately -- so the agent is enforcing from cache before its first network call, not just holding the bundle in reserve. Called from `start()` right after `register_agent()` and before `sync_policies(initial=True)`, matching the Windows `Start()` call order exactly.

**`uninstall.sh`**: added `CACHE_DIR="/var/lib/seceoknight"`, treated the same as `CONFIG_DIR`/`QUARANTINE_DIR` -- kept by default so a reinstall resumes enforcing immediately from the cached bundle, removed only with `--purge`.

### Verification

`ast.parse` clean on `agent.py`. `bash -n` clean on `uninstall.sh`. Traced the call graph by hand: `_load_cached_policy_bundle()` is called from `start()` after `self.running = True` and after `__init__` has already constructed `self.print_monitor`/`self.usb_monitor`/`self.clipboard_monitor` (all needed transitively by `_apply_policy_bundle()` → `_reconcile_monitors()` → `start_file_monitoring()`), so calling it early doesn't hit any not-yet-initialized attribute. **Not live-tested**: no Linux runtime in this sandbox to actually kill server connectivity, restart the agent, and confirm it enforces from the cached bundle before the first sync completes. Worth a manual test before relying on this in production.

---

## 🛡️ Offline event spool + replay on reconnect -- new capability (August 6, 2026)

### Summary

Closes task #96 / the second half of the "agent goes offline" gap (the first half -- offline policy persistence -- was closed for Windows by task #107, and is still open on Linux as task #117). Before this change, `SendEvent()` would POST to `/events` and, on any failure (non-200/201 status or a thrown exception -- laptop asleep, VPN dropped, server mid-restart), just log a warning and silently discard the event. Every USB block, network-exfil block, print event, clipboard alert, etc. that happened while the agent couldn't reach the server was gone forever, with no dashboard record it ever occurred. Ported CyberSentinel-DLP's bounded on-disk spool-and-replay design.

### What was added

**`agent.cpp`**: `SendEvent()` keeps its existing `void` signature (not changed to `bool`, so its ~30+ existing call sites needed zero changes) but now calls a new `SpoolEvent()` on both of its failure paths (non-200/201 status, and the catch-all exception handler) instead of just logging and dropping.

- `SpoolFilePath()`: reuses the exact same `SECEOKNIGHT_LOG_DIR`-env-var-with-`C:\ProgramData\SeceoKnight\logs`-fallback directory rule as `PolicyCachePath()` (the task #107 policy cache) and the `Logger`, for the same non-admin-writability reason -- NOT exe-relative.
- `SpoolEvent(eventData)`: appends one JSON object per line to `seceoknight_events.spool`, guarded by a `MAX_SPOOL_BYTES` cap (16 MB, matching CyberSentinel's constant) so an outage that outlasts the cap stops growing the file instead of filling the disk; a `spoolFullWarned` atomic flag stops the "spool full" warning from spamming the log every single dropped event, resetting once space frees up on the next successful flush.
- `FlushSpooledEvents()`: reads the spool file, replays up to `MAX_FLUSH_BATCH` (100) lines per call via the same `/events` POST, and **stops at the first renewed failure** (`serverGoneAgain`) rather than hammering a server that's still warming up mid-recovery. Rewrites the spool file with only the unsent tail, or deletes it entirely once everything's replayed.
- Wired into `HeartbeatLoop()`: the moment `heartbeatOk` is true (a heartbeat that actually succeeded, using the `bool`-returning `SendHeartbeat()` from the earlier stale-connection-recovery fix in this same loop) `FlushSpooledEvents()` is called, matching CyberSentinel's own choice of "successful heartbeat" as the reconnect signal. Wrapped in its own try/catch so a flush issue can never take down the heartbeat loop itself.

### Verification

Brace-balance check on `agent.cpp` matches the established baseline exactly (paren=-2, brace=-5, bracket=-1), both before and after this change. `<fstream>` (needed for `std::ifstream`/`std::ofstream` in the new methods) and `std::filesystem` (`fs::exists`/`fs::file_size`/`fs::remove`) were already included and already in use by `PolicyCachePath()`/`LoadCachedPolicyBundle()`, so no new includes were needed. **Not live-tested**: no MinGW compiler and no way to simulate a real network outage/reconnect cycle in this sandbox, so the actual spool-growth-cap behavior, the batch-replay stop-on-failure logic, and the heartbeat-triggered flush haven't been exercised end-to-end. Worth a manual test before relying on this in production: kill server connectivity, generate a few blocked-transfer events, confirm they land in `seceoknight_events.spool`, restore connectivity, confirm the next heartbeat drains the file and the events appear in the dashboard.

---

## 🛡️ Messaging / thick-client app attachment control -- new capability (August 6, 2026)

### Summary

User asked to close every remaining gap between CyberSentinel-DLP and SeceoKnight. A fresh comparison sweep (after the four features above) found one genuine miss not caught by the earlier gap analysis: CyberSentinel intercepts file attachments in managed messaging/thick-client apps -- Teams, WhatsApp, Telegram, Slack, Discord, Signal -- alerting (default) or terminating the app when a sensitive file is picked. SeceoKnight had zero equivalent, agent or server side.

### Design decision: extend, don't duplicate

CyberSentinel implements this via a separate `IUIAutomationEventHandler` (`BrowserDialogHandler`, `UIA_Window_WindowOpenedEventId`) layered next to its browser-upload detector. SeceoKnight's own browser-upload detector is architecturally different -- a `SetWinEventHook(EVENT_OBJECT_CREATE)` + Shell MRU-registry fallback (`BrowserWinEventProc`/`HandleBrowserDialogFromHwnd`) -- and was independently hardened through several real production bugs already fixed in this codebase (stale-filename MRU fallback, one-test-lag from unstable timing, Gmail's JS-driven attach flow needing a freshness check against dialog-close time). Porting CyberSentinel's separate UIA handler wholesale would have meant two independent, overlapping file-dialog watchers competing for the same events. Instead, this port **extends SeceoKnight's existing, hardened detector** to also recognize messaging apps, reusing 100% of its capture/resolve logic and only branching at the final classify+enforce step.

### What was added

**`network_exfil_monitor.h`**: added `MessagingVerdict` (managed/block/exemptExtensions) and `MessagingPolicyFn` callback type to `Config`, plus an `enableMessagingDetector` toggle -- all ported from CyberSentinel's shapes.

**`network_exfil_monitor.cpp`**: `BrowserWinEventProc` now also checks `g_cfg.messagingPolicy(exe, username)` for the dialog's owning process when it isn't a browser, and dispatches to `HandleBrowserDialogFromHwnd` either way (now takes a `MessagingVerdict` parameter). The shared function's tail now branches: exempt file types skip inspection entirely and ALLOW; unreadable content ALERTs (as before); a sensitive attachment ALERTs unless the app is BOTH managed AND the policy's action is "block", in which case the app process is actually terminated (`TerminatePid`, the same helper the CLI-transfer path already uses) and the event carries `action=BLOCK`. Browsers are structurally excluded from ever reaching the terminate branch -- `isMessaging` is `mv.managed`, which is only ever true for a messaging-app dialog, never a browser one, so "we never block browsers" (this module's original, explicit design constraint) is unchanged.

**`agent.cpp`**: `FetchMessagingAppPolicy()` polls the new endpoint on the policy-sync cadence (own try/catch, mirrors `FetchApplicationControl()`), with the same built-in managed-app fallback list the server uses when a policy is active but names no apps. `GetMessagingVerdict(exeLower, userName)` is the local verdict function, fails to `managed=false` (ignored) when no policy is active or the user is excepted. Wired into `NetworkExfilMonitor::Config::messagingPolicy` at the existing `NetworkExfilMonitor::Start()` call site.

**Server** (`server/app/api/v1/agents.py`): new `GET /agents/{agent_id}/messaging-app-policy` endpoint (`X-Agent-Key` auth), driven by a `Policy` row of `type="messaging_app_control"` -- `action` (alert/block, audit-first default), `apps`, `exceptions.users`, `exceptions.file_types`. Registered `messaging_app_control` in `server/app/core/domains.py` as `PolicyDomain.THREAT`. No new event-type registration needed -- this module's events always carry `event_type="network_exfil"` regardless of subtype, and that's already registered.

### Verification

`ast.parse` clean on `agents.py`/`domains.py`. Brace-balance check on `agent.cpp` (paren=-2, brace=-5, bracket=-1) and `network_exfil_monitor.h` (0/0/0) both match their established baselines exactly. `network_exfil_monitor.cpp` has no saved pre-edit baseline in this sandbox (same limitation as the application-control port two entries back) -- verified instead by confirming its balance is `paren=1 brace=-2 bracket=-1` both immediately before and immediately after this batch of edits, i.e. unchanged, which is only possible if every individual edit in this pass was itself balanced (each was additionally traced by hand). **Not live-tested**: no MinGW compiler and no Teams/WhatsApp/Slack instance in this sandbox, so the actual dialog interception, extension-exemption logic, and the terminate-on-block path haven't been exercised against a real messaging app.

---

## 🛡️ Real print content inspection + printer device control -- new capability (August 6, 2026)

### Summary

Last item off the "why aren't you porting these" list. The original ask was narrower ("upgrade print monitoring from hash-only to content scanning"), but tracing CyberSentinel-DLP's implementation turned up that print content inspection and printer device control are genuinely one combined server response and one combined agent policy fetch (`GET /agents/{id}/printer-policy` returns both) -- and SeceoKnight's own `SanctionedPrinter` model docstring already said outright: *"this allowlist has no agent-side enforcement yet ... shipped now so the management surface is ready the moment print monitoring lands."* This is that moment, so both landed together rather than half-porting one endpoint.

### What was replaced

Before this change, the only "print content" signal was `printClassifier` in `agent.cpp` -- a static keyword list (`"restricted"`, `"confidential"`, `"ssn"`, `"salary"`, …) matched against the **document's filename only**. A file named `report.pdf` containing a customer's SSN sailed through as "Public"; a file named `confidential_notes.txt` containing nothing sensitive got flagged. It never looked at what was actually sent to the printer.

### What was added

**Server** (`server/app/api/v1/agents.py`): new `GET /agents/{agent_id}/printer-policy` endpoint (`X-Agent-Key` auth), combining two independent policies in one response (matching CyberSentinel's own design, and SK's existing `SanctionedPrinter` table which already existed with zero consumers): `printer_control` (device control: `mode` enforce/audit, `scope` block_all/block_network/block_local/allowlist, `printers` -- the sanctioned allowlist names, shipped only in allowlist scope) and `print_content_prevention` (`content_inspection`, `content_mode`). Registered `print_content_prevention` in `server/app/core/domains.py` as `PolicyDomain.THREAT` (`printer_control` was already registered, just unenforced). Updated `SanctionedPrinter`'s docstring to point at the new enforcement path instead of saying "not enforced yet."

**`print_monitor.h`/`.cpp`**: added `PrinterControlCallback` (return true to cancel a job by which printer it's going to, independent of content) and `PrintContentCallback` (pause the job, inspect it, return true to block) to `Config`/constructor args -- both optional, both additive, the existing `HashCallback` is untouched. Added a `blockReason` field to `PrintEvent` (`""` | `"content"` | `"printer_control"`) so the dashboard can tell which control fired. `MonitorLoop` now: computes `deviceBlocked` from the printer-control callback; when a content callback is set, pauses the job (`JOB_CONTROL_PAUSE`) before calling it and resumes (`JOB_CONTROL_RESUME`) if allowed; falls back to the old filename-keyword `isSensitive` result when no content callback is set, so an agent build without the new wiring behaves exactly as before.

**`agent.cpp`**: `FetchPrinterPolicy()` polls the new endpoint on the policy-sync cadence (own try/catch). `ShouldBlockPrinter()` is the device-control verdict (`IsNetworkPrinter()`/`NormalizePrinter()` helpers, ported verbatim). `EvaluatePrintContent()` is the content-control verdict: `ReadSpoolText()` resolves the spooled document's actual file path (tries the existing `GetPrintSpoolFilePath()` `"FP<jobid>.SPL"` convention first, then CyberSentinel's plain `"<jobid>.SPL"` convention, then the newest `*.SPL` in the spool directory as a last resort -- deliberately more defensive than either source alone, since spool naming varies by print-processor config) and `ExtractSpoolStrings()` pulls readable ASCII and UTF-16LE text runs out of the raw EMF/RAW/PS/PCL bytes (EMF's `ExtTextOutW` stores document text as UTF-16), then POSTs that real text to the same `/agents/{id}/policy/evaluate` endpoint the USB and network-share content-aware paths already use. `printMonitor->SetPrinterControl(...)`/`SetPrintContent(...)` wire both into the existing `PrintMonitor` construction, and the print event JSON now carries `printer_name`/`block_reason` so a device-control block is distinguishable from a content block in the dashboard.

### Deliberate deviation from CyberSentinel

CyberSentinel's version computes and sends both MD5 and SHA-256 of the spooled document using its own from-scratch MD5/SHA-256 implementations. SK doesn't have (and this port doesn't add) an MD5 implementation, and SK's existing `CalculateFileHash()` (SHA-256, already used by the pre-existing hash callback) is reused for `EvaluatePrintContent()`'s hash instead of porting new, unverified crypto code into a security product with no compiler available in this sandbox to test it against known test vectors. `lastSpoolHash` therefore stores SHA-256 only, not MD5+SHA-256.

### Verification

`ast.parse` clean on `agents.py`/`domains.py`/`sanctioned_printer.py`. Brace-balance check on `agent.cpp` (paren=-2, brace=-5, bracket=-1) matches the established baseline exactly. `print_monitor.h` and `print_monitor.cpp` both balance at 0/0/0, both before and after this change. **Not live-tested**: no MinGW compiler and no real printer in this sandbox, so the actual spool-file text extraction, the pause/resume timing around the server round-trip, and the printer-scope enforcement haven't been exercised against a real print job. Worth a real build + a manual print test (including a deliberately sensitive document, to confirm the pause survives the round trip and the job is actually cancelled, not just logged) before relying on this in production.

---

## 🛡️ Wireless / Bluetooth transfer control -- new capability (August 6, 2026)

### Summary

Third item off the list. This is the one genuinely IFEO-based control CyberSentinel-DLP has (application_control, ported in the previous entry, is not IFEO -- this is). Blocks the built-in Bluetooth file-transfer wizard (`fsquirt.exe`) and/or Wi-Fi Direct / Windows Nearby Sharing, an exfiltration channel none of SeceoKnight's existing controls (USB, network share, print, screen capture, network-exfil CLI interception) touched at all -- a user could always just Bluetooth a file to their phone.

### What was added

**Server** (`server/app/api/v1/agents.py`): new `GET /agents/{agent_id}/wireless-policy` endpoint (`X-Agent-Key` auth), driven by a `Policy` row of `type="wireless_transfer_control"` -- `mode` (`enforce` | `audit` | `off`), `block_bluetooth_file_transfer`, `block_nearby_sharing` (independently toggleable). Registered `wireless_transfer_control` (policy type) and `bluetooth_file_transfer` (event type, emitted when a blocked attempt fires) in `server/app/core/domains.py` as `PolicyDomain.THREAT`.

**Windows agent** (`agent.cpp`):
- `SetIFEODebugger(exeName, debuggerValue, block)` sets or clears an Image File Execution Options `Debugger` registry value under `HKLM\...\Image File Execution Options\<exeName>` -- when set, Windows launches the debugger process instead of the named exe. Used to redirect `fsquirt.exe` to the agent itself (`"<agent.exe path>" --blocked-launch`) instead of letting the Bluetooth wizard run. Audio (A2DP/HFP) and input (HID) Bluetooth profiles are untouched -- headphones, mice, keyboards keep working, since those don't go through `fsquirt.exe`.
- `SetPolicyDword` / `ApplyWirelessControls` sets the `EnableCdp` (Connected Devices Platform) group policy DWORD to disable Wi-Fi Direct / Nearby Sharing, reconciled both directions so clearing the policy restores the channel.
- `FetchWirelessPolicy()` polls the new endpoint on the policy-sync cadence and only touches the registry when the effective enforcement signature (`lastWirelessSig`) actually changed -- a routine sync tick with no policy change is a no-op, not a registry write every cycle.
- `HandleBlockedLaunch()` (new top-level function, plus a `--blocked-launch` argv hook checked at the very top of `main()`, before help-flag parsing or the normal agent lifecycle): when Windows launches the agent binary in fsquirt's place, this logs the attempt locally and POSTs a `bluetooth_file_transfer` event to `/events` directly (its own minimal `HttpClient`/`AgentConfig`/`JsonBuilder` usage, not the full running agent), then exits without ever running fsquirt. Added `ExeRelativePath()` (new helper) so this invocation resolves `agent_config.json` next to the actual executable rather than trusting the current working directory, which is unpredictable when launched via the IFEO Debugger mechanism instead of the agent's own service/scheduled-task launcher.

### Scope note

Same as the previous two entries: no dashboard UI in this pass, configurable via `POST /api/v1/policies` with `type: "wireless_transfer_control"`. Also: this covers the *built-in Windows* Bluetooth file wizard and Nearby Sharing specifically -- a third-party Bluetooth file-transfer utility that doesn't go through `fsquirt.exe` would not be caught by this control. That limitation is inherited directly from CyberSentinel-DLP's own implementation, not something narrowed in this port. Validate on real Bluetooth hardware before relying on this in production -- this sandbox has none.

### Verification

`ast.parse` clean on `agents.py`/`domains.py`. Brace-balance check on `agent.cpp` (paren=-2, brace=-5, bracket=-1) matches the established baseline exactly, both after the mid-class additions (`SetIFEODebugger`/`SetPolicyDword`/`ApplyWirelessControls`/`FetchWirelessPolicy`) and after the standalone pre-`main()` additions (`ExeRelativePath`/`HandleBlockedLaunch`). All new registry/COM/HTTP calls (`RegCreateKeyExA`, `RegOpenKeyExA`, `RegDeleteValueA`, `RegSetValueExA`, `CoInitializeEx`/`CoUninitialize`, `HttpClient`, `AgentConfig`, `JsonBuilder`, `Logger`) reuse functions/classes already used elsewhere in this exact file, confirmed by grep before use, not assumed. **Not live-tested**: no MinGW compiler and no Bluetooth hardware in this sandbox, so the actual IFEO redirect and the `EnableCdp` policy effect haven't been exercised end-to-end. Worth a real build + a manual Bluetooth-transfer-attempt test before relying on this in production.

---

## 🛡️ Managed-application file control -- new capability (August 6, 2026)

### Summary

Second item off the "why aren't you porting these" list. CyberSentinel-DLP's `application_control` feature -- initially assumed to be IFEO-based (it isn't; IFEO in that codebase is scoped only to the Bluetooth-wizard block, see the next entry) -- turned out to be a policy consulted by the network-exfil CLI-transfer-tool interceptor to block an upload by the identity of the acting process, independent of what the file actually contains. Ported it as a real callback wired into the existing blocking decision, not a bolt-on.

### What was added

**Server** (`server/app/api/v1/agents.py`): new `GET /agents/{agent_id}/application-control` endpoint (same `X-Agent-Key` auth pattern as network-share-policy above), driven by a `Policy` row of `type="application_control"` -- `mode` (`allowlist` | `blocklist`), `applications` (managed exe names), `channels` (empty = all), and an `exceptions` object (`applications` / `users` / `paths` / `file_types`). Registered `application_control` in `server/app/core/domains.py` as `PolicyDomain.THREAT`.

**`network_exfil_monitor.h`/`.cpp`**: added an optional `AppActionFn appAction` callback to `Config` -- given the acting process exe, file path, and extension, returns `true` to force a BLOCK regardless of content classification. Wired into the existing CLI-transfer-tool blocking decision (the same suspend -> classify -> terminate path that already catches `curl`/`wget`/PowerShell/`bitsadmin`/`certutil` uploading sensitive content): the decision is now `if (sensitive || appBlocked)`, and the emitted event's `reason`/`matchedRule` distinguish an app-control block ("Blocked curl.exe upload by application control") from a content-sensitivity block, so the dashboard shows which control actually fired. Purely additive -- when the callback is unset or returns false, behavior is byte-for-byte unchanged from before this pass.

**`agent.cpp`**: `FetchApplicationControl()` polls the new endpoint on the policy-sync cadence (own try/catch, same pattern as `FetchNetworkSharePolicy()`). `IsAppActionAllowed(channel, process, user, path, ext)` is the local verdict function -- fails open (allowed) when no policy is active, checks channel coverage then exceptions then allowlist/blocklist membership. Wired into `NetworkExfilMonitor::Config::appAction` at the existing `NetworkExfilMonitor::Start()` call site: `nemCfg.appAction = [this](proc, path, ext) { return !IsAppActionAllowed("network", proc, GetUsername(), path, ext); }`.

### Scope note

Same as network-share monitoring above: no dashboard UI in this pass, configurable via `POST /api/v1/policies` with `type: "application_control"` and a `config` of `{mode, applications, channels, exceptions: {applications, users, paths, file_types}}`. Also note this only covers the network/CLI-upload channel today (the one channel CyberSentinel itself wires `appAction` into) -- extending `IsAppActionAllowed()`'s `channel` coverage to USB/print/clipboard would need those handlers to call it too, not done here.

### Verification

`ast.parse` clean on `agents.py`/`domains.py`. Brace-balance check on `agent.cpp` (paren=-2, brace=-5, bracket=-1) matches the established baseline exactly. `network_exfil_monitor.h`'s balance is 0/0/0 (perfectly balanced) both before and after. `network_exfil_monitor.cpp` doesn't have a saved pre-edit baseline in this sandbox (no git history available for it locally), so its balance was verified by hand instead: every brace/paren/bracket introduced by this diff (`if (g_cfg.appAction) { try { ... } catch (...) {} }`, the `if (appBlocked && !sensitive) {...} else {...}` reason branch, and the ternary in the `LogWarn` call) was traced token-by-token and confirmed to net to zero, so the file's overall balance is unchanged by this edit regardless of what it was before. **Not live-tested**: no MinGW compiler in this sandbox to actually build `network_exfil_monitor.cpp` with the new callback wired in.

---

## 🛡️ Network share (UNC drive) exfiltration monitoring -- new capability (August 6, 2026)

### Summary

User pushed back on the "here are the remaining gaps" answer given after the second deep-dive pass, pointing out CyberSentinel-DLP already has these capabilities and asking why they weren't being ported given full read access to the source. This starts working through that list -- network share monitoring first, since it's a real exfiltration path USB device-control and content DLP entirely missed: copying a file to a mapped network drive (`\\server\share`) instead of a USB stick never touched either control.

### What was added

**Server** (`server/app/api/v1/agents.py`): new `GET /agents/{agent_id}/network-share-policy` endpoint (same auth as the existing USB-allowlist endpoint, `X-Agent-Key` header). Driven by a `Policy` row of `type="network_share_transfer_control"` -- no dedicated table, since (unlike USB device allowlisting) there's no per-share identity to track, just a mode/action/exception config. Two modes: `block_all` (any file copied to any mapped network drive) and `content_aware` (only files the classification engine scores as sensitive, same real-time evaluation path USB transfer uses). Two actions: `audit` (log/event only) and `block` (quarantine + remove from the share). Registered `network_share_transfer_control` / `network_share_transfer` in `server/app/core/domains.py` as `PolicyDomain.THREAT`, same category as USB/print/screen-capture.

**Windows agent** (`agent.cpp`): `FetchNetworkSharePolicy()` polls the new endpoint on the same cadence as the main policy sync (own try/catch, isolated from it, same pattern as `SyncUsbAllowlist()`). `NetworkShareTransferMonitor()` runs as its own worker thread, polling `GetLogicalDrives()`/`GetDriveTypeA()` for `DRIVE_REMOTE` drives every 750ms and diffing against a per-drive known-files set (pre-existing files on a drive are baselined on first sight, not treated as new transfers -- only files that appear *after* the agent starts watching a share are enforced). `ResolveDriveUnc()` calls `WNetGetConnectionA` to resolve a mapped drive letter to its real `\\server\share` UNC path for logging/exceptions/events. `HandleNetworkShareNewFile()` checks exceptions (share prefix, user, source-path prefix, file extension) then dispatches by mode -- `block_all` acts immediately per the configured action, `content_aware` calls the existing `EvaluatePolicyRealtime()` (same classification call USB transfer uses) and dispatches on its verdict. `QuarantineNetworkShareFile()` does copy-then-delete (not `fs::rename`), reusing the cross-volume-safe pattern already fixed for USB quarantine (`fs::rename` maps to `MoveFileExW` without `MOVEFILE_COPY_ALLOWED` on this MinGW build and fails across volumes/shares).

### 🔧 Build-system fix: MinGW/g++ needs an explicit `-lmpr`, not just a header include

Confirmed this project's Windows agent is compiled by `.github/workflows/build-windows-agent.yml` via **MinGW-w64 g++**, not MSVC -- every `#pragma comment(lib, ...)` already in `agent.cpp` is a **silent no-op** under this toolchain; the real link dependencies are the explicit `-l<name>` flags baked into the workflow's `g++` invocation. `WNetGetConnectionA` lives in `Mpr.dll`/`mpr.lib`, so it needed a real linker-flag addition, not a source-level `#pragma comment`. Added `-lmpr` to `build-windows-agent.yml`'s link line and to the top-of-file MinGW build-instruction comment, and added `mpr` to the "expected DLL" allowlist in the post-build `objdump` sanity check so it doesn't get flagged as an unexpected dependency. This is now a standing rule for any future WinAPI-dependent agent feature: check `build-windows-agent.yml`'s flag list, don't assume a `#pragma comment` is doing anything.

### Scope note

No dashboard UI was built for authoring this policy in this pass -- it's configurable today via `POST /api/v1/policies` with `type: "network_share_transfer_control"` and a `config` of `{mode, action, exception_shares, exception_users, exception_paths, exception_file_types}`. Building/testing new React form UI wasn't attempted here (no browser or dev server in this sandbox); a `PolicyCreatorModal.tsx` form is a reasonable, low-risk follow-up.

### Verification

`ast.parse` clean on `agents.py` and `domains.py`. `yaml.safe_load` clean on `build-windows-agent.yml`. Brace-balance check on `agent.cpp` (paren=-2, brace=-5, bracket=-1) matches the established baseline exactly -- no new imbalance introduced by any of these edits. **Not live-tested**: no MinGW compiler or live server available in this sandbox, so the actual build and a real mapped-drive transfer haven't been exercised end-to-end. Worth a real CI build (watch for the new `-lmpr` link) and a manual test against a real `net use`-mapped drive before relying on this in production.

---

## 🛡️ Second Deep-Dive vs CyberSentinel-DLP: agents/, server/, manage-windows-agent.ps1 (August 6, 2026)

### Summary

User asked for a second pass, this time on the `agents/` and `server/` folders plus `manage-windows-agent.ps1`. A subagent-driven comparison (read-only, no code changes) surfaced two genuine security/reliability gaps, two operational-tooling gaps, and one big missing enterprise-DLP capability -- all fixed/ported in this pass. It also confirmed several non-issues (SK already ahead in a few places, some CyberSentinel files are their own dead weight) that are worth recording so nothing gets second-guessed later.

### 🚨 Critical fix: Linux agent template shipped a hardcoded `agent_id`

`agents/endpoint/linux/agent_config.json` -- the template `install.sh` copies to every machine -- had a literal, committed `agent_id` GUID. `agent.py`'s config loader does `default_config.update(loaded_config)`, so that literal value silently overrode the freshly-generated `uuid.uuid4()` default on **every single install**. Every fleet-installed Linux agent from the unmodified template got the *same* `agent_id`, so they'd all collide as one agent record on the server (last heartbeat wins, events misattributed). Found while building `rollout.sh` (below) -- would have shipped broken fleet installs otherwise. Fixed by removing the `agent_id` key from the template entirely, letting `agent.py`'s existing per-machine generation take over as designed.

### Ransomware early-warning detection (Windows agent) -- new capability, previously absent entirely

`grep -rli ransomware` across the whole repo returned zero hits before this change. Ported CyberSentinel-DLP's two honestly-scoped heuristics into `agent.cpp` (detection/alert only -- `ReadDirectoryChangesW` carries no PID, so the agent cannot kill an encryptor; recovery still depends on EDR + offline backups):

- **Burst-rate detection** (`NoteFileChangeForRansomware`): a sliding window counts every file change under a monitored tree (deliberately unfiltered by policy extension, since an encryptor rewrites whatever it finds); N changes in a configurable window fires a critical `ransomware`/`mass_file_modification` event, cooldown-gated to avoid an alert flood.
- **Canary/tripwire files** (`PlantCanaryFile`/`IsCanaryPath`/`ReportCanaryTripped`): a hidden, non-read-only decoy file (`!!!SeceoKnightDLP-CANARY-DO-NOT-DELETE.docx`, leading `!` so it sorts first in a directory an encryptor walks alphabetically) is dropped in every monitored directory; any write/rename/delete to it fires a near-zero-false-positive critical alert.

Both are config-tunable via new `agent_config.json` keys (`ransomware_detection_enabled`, `ransomware_burst_threshold`, `ransomware_window_seconds`, `ransomware_cooldown_seconds`), all optional and defaulted so an existing config keeps working unchanged. Added `"ransomware": PolicyDomain.THREAT` to `server/app/core/domains.py` so these events get correctly domain-scoped for RBAC/reporting like every other threat-category event.

### Windows agent offline policy cache -- closes half of pending task #95

The Linux agent already persisted its last-known-good policy bundle to disk (`policy_cache.py`); the Windows agent -- the primary, most-developed platform -- did not. Ported `LoadCachedPolicyBundle()`/`SavePolicyBundleToCache()`/`PolicyCachePath()` into `agent.cpp`: every successful policy sync now writes the bundle to `C:\ProgramData\SeceoKnight\logs\seceoknight_policies.cache` (same directory-resolution rule as the Logger, not exe-relative -- reusing the already-fixed non-admin-writable-path convention rather than risking the same bug again under a different name), and `Start()` loads it before the first sync attempt. Previously, an agent that restarted while the server was unreachable enforced **nothing** until the next successful sync -- silently turning "fail closed on API error" into "fail wide open after a restart" (kill the agent, block the server, restart == free bypass; a laptop booting off-VPN hit the same hole with no malice at all). Task #95's other half (event spool for offline audit trail) is still pending.

### Linux endpoint `uninstall.sh` + `rollout.sh` -- new scripts

`agents/endpoint/linux/` had no scripted uninstall (the repo-root `uninstall.sh` tears down the *server* stack, a different thing) and no fleet-deployment helper. Added both, ported from CyberSentinel-DLP and adapted to SeceoKnight's actual install.sh behavior:

- **`uninstall.sh`**: data-safe by default (keeps `/etc/seceoknight` config + quarantine so a reinstall reuses the same agent identity), `--purge` to remove everything, with a 10-second warn-and-abort-window before deleting a non-empty quarantine directory (it may hold the only copy of exfiltrated data).
- **`rollout.sh`**: SSH/scp to a list of hosts (`--hosts`/`--hosts-file`), configurable concurrency, per-host failure logs printed at the end. Simpler than CyberSentinel's equivalent because SK's `install.sh` already self-downloads its checksummed binary from GitHub on each target -- no need to ship a binary payload over scp at all, only `--from-source` needs the extra files. Also added a `--server-url` flag to `install.sh` itself (previously the only way to set the server URL was hand-editing `agent_config.json`'s `YOUR_SERVER_IP` placeholder after install) via `sed`, not a Python/JSON edit, so it still works on the no-Python prebuilt-binary install path.

### Exact Data Matching (EDM) + document fingerprinting -- new server-side capability

The single biggest capability gap found: SeceoKnight's only content-fingerprinting was `fingerprint_service.py`'s whole-file SHA-256 hash (exact byte-identical matches only, task #78's file-identity denylist). Ported CyberSentinel-DLP's data-matching engine, which adds two things that hash matching structurally cannot do:

- **EDM (Exact Data Matching)**: upload a protected dataset (CSV or JSON rows -- e.g. real customer names+SSNs); the server indexes it as **keyed HMAC-SHA256 digests** (`derive_key`/`keyed_digest` in `data_matching_service.py`, keyed with `settings.SECRET_KEY` so a stolen index can't be brute-forced) and **discards the plaintext** immediately after indexing -- there is no "download source" endpoint, by design. Fires on **row-level field combinations** (e.g. name AND ssn from the same source record) rather than single values, which is what keeps false positives near zero.
- **Document fingerprinting**: winnowed k-word shingle hashing (`_shingle_hashes`/`_winnow`) catches a **partial or edited copy** of a protected document -- a paragraph pasted into an email, a reformatted excerpt -- not just an identical file.

New files: `app/services/data_matching_service.py` (pure, stdlib-only, no DB -- unit-tested standalone in this sandbox, see Verification), `app/services/data_match_index_service.py` (DB-backed orchestration), `app/models/data_match_source.py` (stores the keyed index only, never plaintext), `app/api/v1/data_matching.py` (REST: `POST /edm`, `POST /fingerprint`, `GET /`, `GET /{id}`, `PATCH /{id}`, `DELETE /{id}`, `POST /test`), registered at `/data-matching` (distinct from the existing `/fingerprints` whole-file-hash router). Migration `035_data_match_sources.py` adds the table. Matches CyberSentinel's own scope for this feature (management + a manual test endpoint) -- automatic wiring into the live classification pipeline is a natural follow-up, not done in this pass, same as upstream.

### Non-findings (checked, confirmed not gaps)

- `agents/endpoint/linux/agent_launcher.py` (CyberSentinel-only) is a PyInstaller entry point, not a crash-supervisor -- SK's `Restart=always`/`RestartSec=10` in the systemd unit already covers that.
- `manage-windows-agent.ps1` (750 lines) vs SK's `manage-agent.ps1` (418 lines): the size difference is UI polish + CyberSentinel's own legacy-rename cleanup cruft, not missing capability. SK is already ahead in two respects: it calls the server unregister endpoint on uninstall (CyberSentinel's doesn't -- the exact "ghost agent" bug SK fixed in task #48), and it tracks all three of SK's scheduled tasks vs. CyberSentinel's one.
- Kernel driver (`kernel/csfilter.c`) is a byte-for-byte identical skeleton in both products (only branding differs) -- SK actually has more surrounding tooling (`install_driver.ps1`, a real Visual Studio project) than CyberSentinel does.
- `docker-compose.deploy.yml` and `GITHUB_DEPLOYMENT_COMPLETE.md` (from the prior deployment-tooling pass) are confirmed CyberSentinel-internal dead weight, not gaps.

### Verification

`ast.parse` clean on every new/edited `.py` file. `python3 -c "import yaml"` not needed here (no YAML changes this pass). Brace-balance check on `agent.cpp` (paren=-2, brace=-5, bracket=-1) matches the pre-existing baseline exactly across all edits in this pass -- no new imbalance introduced. The pure EDM/fingerprint engine (`data_matching_service.py`) was actually **executed and asserted against** in this sandbox (no DB needed, since it's pure stdlib): built an EDM index from 2 synthetic records, confirmed a positive match on combined fields, confirmed a negative on a single field below `min_fields`, confirmed a random SSN-shaped number NOT in the index doesn't match; built a fingerprint index from 200 synthetic words, confirmed an exact match, a 50-word partial excerpt still matching (containment 1.0), and unrelated content not matching. All 6 assertions passed. C++ changes (ransomware detection, policy cache) and the new API/model/migration are **not yet live-tested** against a real compiler/database -- no MSVC or live Postgres in this sandbox. Worth a real build + a real `alembic upgrade head` run before relying on this in production.

---

## 🚨 Critical Fix: The Random Admin Password Fix Was Never Actually Live (August 6, 2026)

### Summary

Chasing a smaller deployment-tooling comparison against CyberSentinel-DLP surfaced something far more serious: the random-per-deployment admin password fix from earlier today (the `_generate_admin_password()` / `DLP_ADMIN_PASSWORD` change in `server/app/main.py`) **never actually took effect in a real Docker deployment.** `server/entrypoint.sh` was running `python scripts/seed_admin.py` on every manager container start, *before* `exec uvicorn app.main:app` — and `scripts/seed_admin.py` independently creates the admin account with a hardcoded default password (`Admin@1234` via `SEED_ADMIN_PASSWORD`) if no users exist yet. Since it ran first, it always won the race: by the time `app.main:app`'s own startup logic (`_auto_init_schema_and_admin()`, containing the fix) got a chance to check "does an admin exist yet," `seed_admin.py` had already created one with the weak, publicly-known password. The earlier fix was real, correct code — it just never ran, in any deployment that used the documented `install.sh` → `docker compose up -d` path, which is effectively all of them.

### Fix

Removed the `python scripts/seed_admin.py` call from `server/entrypoint.sh`. `_auto_init_schema_and_admin()` in `app/main.py` already does the identical job — create the first admin only if zero users exist — correctly (random CSPRNG password, `DLP_ADMIN_PASSWORD` support, `ON CONFLICT`-safe against concurrent uvicorn workers) via FastAPI's lifespan startup handler, so there's no gap left by removing the redundant call. `scripts/seed_admin.py` itself is left in the repo (for a non-standard deployment that might invoke it manually) but its docstring now explains it's unused by the normal path, and its own hardcoded-password fallback was replaced with the same CSPRNG random-password generation as `main.py`, so even a manual run no longer reintroduces the weak default.

### Verification

`ast.parse` clean on `seed_admin.py` and `main.py`. `bash -n` clean on `entrypoint.sh`. Traced the full startup order by reading `entrypoint.sh` → `alembic upgrade head` → (old: `seed_admin.py`) → `exec uvicorn app.main:app` → `lifespan()` → `_auto_init_schema_and_admin()`, confirming the ordering claim above rather than assuming it. Not yet live-tested against a real container rebuild — worth confirming with a genuinely fresh `docker compose up -d` (empty volumes) that `docker logs seceoknight-manager | grep generated_password` shows a real random password and that no `[seed_admin]` log lines appear at all.

---

## 🚀 Deployment Tooling Parity Pass vs CyberSentinel-DLP (August 6, 2026)

### Summary

User pointed out CyberSentinel-DLP had recent changes to `DEPLOYMENT.md`, `README.md`, `docker-compose.yml`/`docker-compose-prod.yml`, and `install.sh` worth checking. A deep comparison (full file diffs, not just filenames) turned up several real gaps and one latent correctness bug, on top of the admin-password issue above.

### Fixes

- **`docker-compose.prod.yml` — manager was missing `ENVIRONMENT`/`DEBUG`/`DLP_ADMIN_PASSWORD` env vars entirely.** Without `ENVIRONMENT=production` being passed into the container, the app defaulted to `ENVIRONMENT=development` — which silently disables the fail-closed behavior in `server/app/core/security.py` and `server/app/api/v1/auth.py`'s Redis-outage token-blacklist checks (they only fail closed with a `503` when `ENVIRONMENT=="production"`; otherwise a Redis outage lets a possibly-revoked token through with just a warning). Also, `DLP_ADMIN_PASSWORD` was never forwarded into the container, so even setting it in `.env` had no effect. Added all three.
- **OpenSearch healthcheck was missing `curl -f`.** Without `-f`, curl exits `0` on an HTTP 401 (wrong `OPENSEARCH_PASSWORD`), so a cluster rejecting our own credentials could still report "healthy" to Docker. One-flag fix.
- **`install.sh` printed a hardcoded `Admin@1234` in its completion banner**, which (now that the seed_admin.py issue above is fixed) is simply wrong — the real password is either pinned via `DLP_ADMIN_PASSWORD` or randomly generated and logged once. The banner now reads the actual password: checks `.env` for a pinned `DLP_ADMIN_PASSWORD` first, then falls back to grepping `docker compose logs manager` for the `generated_password` line the server logs on first boot, and clearly states which source it came from (or how to retrieve it manually if neither applies, e.g. a re-run against an existing DB).
- **`install.sh` never stamped the Alembic migration state on a fresh install.** Added a step (adapted from CyberSentinel-DLP's equivalent) that runs `alembic current` inside the manager container after health passes; if empty (fresh install), stamps `alembic stamp head` so a later real upgrade can apply cleanly via `alembic upgrade head` instead of either failing (tables already exist) or silently applying nothing.
- **Added `uninstall.sh`** (new file, repo root) — SeceoKnight had no scripted teardown at all. Ported from CyberSentinel-DLP's design: `docker compose down` (no `-v`) by default so data volumes survive and a reinstall restores over them; `--purge` for full volume + install-dir deletion, gated behind typing the literal word `DELETE` at a real TTY (or `--yes` to skip non-interactively); falls back to `docker compose ls`/name-prefix matching if the compose file was moved. Added one thing beyond the straight port: an optional `--backup` flag that `pg_dump`/`mongodump`s both databases to `/var/backups/seceoknight/<timestamp>/` before a purge, since DLP audit/incident data may carry retention requirements a generic product's uninstaller wouldn't need to consider. Backup failures warn but never block the teardown itself.
- **`DEPLOYMENT.md` and `README.md` had stale port/architecture documentation** — a leftover from before the Nginx reverse-proxy was added. They documented the manager as directly reachable on host port `55000` and the dashboard on `80 → 3000`, but the actual `docker-compose.prod.yml` only exposes `seceoknight-nginx` on `80`/`443`; manager and dashboard are both internal-only (`expose:`, no `ports:`). `install.sh` and `install-agent.ps1` already correctly health-check through Nginx — only the docs disagreed. Fixed the container/port table, the health-check description, the agent-installer connectivity description, and the firewall-troubleshooting row. Also added an "Updating to a New Version" caveat to `README.md`: `docker compose pull` only refreshes images, not the compose file itself, and a schema-changing release needs `docker compose exec manager alembic upgrade head` after `up -d` (which the new install.sh stamp step above makes safe to run).

### Non-findings (checked, no action needed)

- `docker-compose.deploy.yml` (CyberSentinel-only) — confirmed via their own `SECURITY.md` to be a legacy/superseded file with two previously-patched vulnerabilities, not their canonical path. Nothing to port.
- `GITHUB_DEPLOYMENT_COMPLETE.md` (CyberSentinel-only) — a one-time internal setup report, stale even within their own repo (wrong repo name, wrong ports). Not worth porting as a file; the underlying "first-time GHCR package visibility" gotcha may be worth a short `CONTRIBUTING.md` note later, but that's a nice-to-have.
- `docker-compose.yml` (CyberSentinel's dev-tier compose, source-mounted, DB ports exposed) — SeceoKnight has no equivalent. Flagged as a possible future addition for local dev ergonomics, not an operational-risk item like the ones above, so not done in this pass.

### Verification

`ast.parse` clean on `main.py`/`seed_admin.py`, `bash -n` clean on `install.sh`/`uninstall.sh`/`entrypoint.sh`, `yaml.safe_load` clean on `docker-compose.prod.yml`. Not yet live-tested end-to-end (no Docker host in this sandbox) — worth a real `install.sh` run against empty volumes, followed by `uninstall.sh --purge --backup` and a re-`install.sh`, before relying on this for a production rollout.

---

## 🔗 Linux Installers Pointed at the Wrong Repo, Plus Download Sanity Checks (August 6, 2026)

### Summary

While looking for CyberSentinel-parity gaps in deployment tooling (checksum verification on their Linux install, since SeceoKnight's Linux path downloads raw source instead of a signed release binary), found something more urgent: both `install_linux_agent.py` (`REPO_OWNER="seceoknight-06"`, `REPO_NAME="Data-Loss-Prevention"`) and `scripts/install_linux_agent.sh` (`REPO_URL` default `.../seceoknight-06/Data-Loss-Prevention.git`) pointed at a **wrong/stale repository**. Every other installer in the project (`install.sh`, `install-agent.ps1`, `manage-agent.ps1`) already correctly used `Seceo-Knight/Seceoknight-DLP`. Anyone running either Linux installer with default settings would have pulled from a repo that isn't this project — either failing outright (404) or, worse, silently succeeding against unrelated/stale content if that URL ever resolved to something.

### Fix

- `install_linux_agent.py`: corrected `REPO_OWNER`/`REPO_NAME` (and the two doc/help-text URL examples) to `Seceo-Knight`/`Seceoknight-DLP`.
- `scripts/install_linux_agent.sh`: corrected the `REPO_URL` default and its usage help text to `https://github.com/Seceo-Knight/Seceoknight-DLP.git`.
- `install_linux_agent.py`: added `_download_looks_bad()`, run against every downloaded agent file (`agent.py`, `requirements.txt`, etc.) right after `download_file()` writes it to disk, before install proceeds. Catches a download that's suspiciously tiny, that looks like an HTML error/rate-limit page instead of raw source, or (for `.py` files) that doesn't contain any `def`/`class` at all — cases where `urllib`'s `HTTPError` wouldn't fire because the CDN returned 200 with the wrong body. This is a content sanity check, not a cryptographic one: unlike CyberSentinel's versioned, CI-published binary (which has one stable checksum per release to pin against), these are individual source files that legitimately change on every commit to the target branch, so per-commit hash pinning isn't meaningful here without a separate checksum-publishing step server-side — tracked as a follow-up idea, not done in this pass.

### Verification

`python3 -c "import ast; ast.parse(...)"` clean on `install_linux_agent.py`. `bash -n scripts/install_linux_agent.sh` clean. Grepped both files afterward to confirm no remaining reference to the old `seceoknight-06/Data-Loss-Prevention` URL. Not yet live-tested against a real target host (no Linux VM in this sandbox) — worth a real run of both installers before relying on them for a fresh deployment.

---

## 🚨 Critical Fix: Windows Agent Failed OPEN on Every DLP Server Error (August 6, 2026)

### Summary

A parity scan against CyberSentinel-DLP's changelog turned up their `block_on_dlp_error` fix and prompted checking whether SeceoKnight had the same gap. It did — worse, in every error path, not just one: `EvaluatePolicyRealtime()` (the function real-time USB file-transfer content classification runs through) reported `evaluationSucceeded=true, action=allow` on a file over 10MB, a base64 encoding failure, any non-200 response from the classification API, and any thrown exception. In plain terms: **if the DLP server was unreachable, slow, or returned an error, USB content inspection silently let the file through** — stopping the server (intentionally or via an outage) was a full, live bypass of content-aware blocking with no indication anything had failed to enforce.

### Fix (`agents/endpoint/windows/agent.cpp`)

Added `ClassificationConfig::blockOnDlpError` (default `true`, overridable via `SECEOKNIGHT_BLOCK_ON_DLP_ERROR=0`/`false` for an operator who explicitly wants the old behavior, e.g. during a planned outage). All four fail-open sites in `EvaluatePolicyRealtime()` now set `result.evaluationSucceeded = !config.GetClassification().blockOnDlpError` instead of unconditionally `true`. This isn't a new code path — both call sites (`CheckUSBDriveForMonitoredFiles` and the classification-based USB transfer handler) already had a correct `!evaluationSucceeded` fallback branch that defers to the policy's own configured action (block/quarantine/alert); the bug was that the error paths were deliberately routing around that safer fallback and forcing `action=allow` instead. Flipping the flag routes errors through the fallback that was already there and already correct, rather than introducing new blocking logic.

### Verification

Brace-balance check (same script used throughout this project) against a fresh clone of the pre-change file confirms identical depth (paren=-2, brace=-5, bracket=-1). No C++ compiler in this sandbox. **Not yet live-tested** — worth confirming by pointing the agent at a deliberately-unreachable server URL and verifying a policy configured to block still blocks (not "allow") for a file that can't be classified.

---

## 🔐 Random Per-Deployment Admin Password (August 6, 2026)

### Summary

Checking CyberSentinel-DLP's changelog for updates worth porting surfaced their v2.1.1 fix — and this repo had the exact same bug: `server/app/main.py` seeded the first admin account with a **fixed** password, `Admin@1234`, written directly in source. Since this repo is source-available, every deployment shipped with a publicly-known admin credential until an operator happened to change it.

### Fix

`_auto_init_schema_and_admin()` now generates a random 20-character password per deployment via `secrets` (CSPRNG) — `_generate_admin_password()` explicitly includes one character from each required class (upper/lower/digit/symbol) before filling the rest and Fisher-Yates shuffling with `secrets.randbelow`, guaranteeing every generated password passes `validate_password_strength` (never relying on chance from a flat random draw). Logged exactly once on first boot:

```bash
docker logs seceoknight-manager 2>&1 | grep generated_password
```

A new `DLP_ADMIN_PASSWORD` setting lets an automated/scripted deployment pin the password from its own secrets manager instead — nothing is logged in that case. Either path only applies when seeding a brand-new database with zero existing users; it never rotates an existing admin's password.

### Verification

`python3 -c "import ast; ast.parse(...)"` clean on `main.py` and `config.py`. Standalone 20,000-sample test of the password generator (mirroring `validate_password_strength`'s exact rules outside the app, since the full app isn't importable in this sandbox without live Postgres/Mongo/Redis connections): 20,000/20,000 valid, 20,000/20,000 unique. Not yet tested against a live database seed.

---

## 🪟 Watchdog Console Flash, Take 4: It Was Never About the Action — S4U Logon Was Failing (August 6, 2026)

### Summary

After Take 3 shipped (VBScript-only launcher, no `powershell.exe` spawned at all on the healthy path) a user reinstalled and still saw the flash every 5 minutes. Given three consecutive fixes to the task's *action* had all failed, this round used live diagnostics on the actual endpoint instead of another theoretical fix — and it turned out none of the first three fixes could ever have worked, because the task was failing at a completely different, earlier stage.

### Root cause

`Get-ScheduledTaskInfo` showed the watchdog's `LastRunTime` stuck at Windows' classic "never run" placeholder (`30-11-1999`) with `LastTaskResult 267011` (`SCHED_S_TASK_HAS_NOT_RUN`). Enabling and reading the `Microsoft-Windows-TaskScheduler/Operational` event log confirmed why:

```
Event 104: Task Scheduler failed to log on "\SeceoKnight DLP Watchdog".
Failure occurred in "LogonUserS4U". Error Value: 2147943712.
```

`2147943712` is `0x80070520` — `ERROR_NO_SUCH_LOGON_SESSION`. The account on this endpoint is Azure AD / Entra ID-joined (`AzureAD\VaibhavHandekar`). `LogonType S4U` depends on being able to silently re-authenticate using a traditional cached local/domain credential — Azure AD accounts authenticate through Web Account Manager / Primary Refresh Token instead, which S4U has no way to hook into, so the logon step itself reliably fails for this (increasingly common) account type. The task never once reached its action across any of the last three fix attempts — every change to *how the action launches* (which process, which wrapper, `SW_HIDE` vs `CREATE_NO_WINDOW`) was chasing a stage the task never got to. The flash was very likely Task Scheduler's own handling of the repeated failed logon, not anything in our launcher.

### Fix (`install-agent.ps1`)

Changed the watchdog task's principal from a per-user `LogonType S4U` to `LogonType ServiceAccount` running as `SYSTEM` — the same pattern the existing USB-block task already uses successfully. Running as SYSTEM sidesteps user-credential logon entirely (no S4U, no dependency on account type — local, on-prem AD, or Azure AD all work identically), and still has more than enough rights for everything the watchdog does: reading a `ProgramData` log file, finding/killing the agent process by name, and querying/re-triggering the main agent task via `Schedule.Service`/`schtasks`. None of that requires being the specific logged-on user.

### Verification

PowerShell balance script against a fresh clone baseline: identical (0/0/0) in both. No PowerShell interpreter in this sandbox to actually execute a test logon. **Not yet live-tested** — this is the fourth attempt at this bug, but the first one backed by a confirmed root cause from real event-log evidence rather than a plausible theory; next step is reinstalling on the same endpoint and confirming both that the task's `LastRunTime`/`LastTaskResult` finally show a real, successful execution, and that the flash stops.

---

## 🪟 Watchdog Console Flash, Take 3: Stop Spawning powershell.exe At All (August 6, 2026)

### Summary

After the "Take 2" fix (VBScript wrapper + `LogonType S4U`) shipped, a user did a full reinstall, confirmed via diagnostics that the scheduled task really was running the new `wscript.exe watchdog_launcher.vbs` action with `S4U` — exactly the fixed configuration — and the console still flashed every 5 minutes. Two prior fixes in a row looked correct on paper and both failed to fully stop it on a real endpoint.

### Root cause

`WScript.Shell.Run`'s third argument (`0` = `SW_HIDE`) asks a **newly created** console window to start hidden. That is not the same guarantee as `CREATE_NO_WINDOW`, a `CreateProcess` flag that tells Windows not to allocate a console **at all**. `WScript.Shell.Run` has no way to request `CREATE_NO_WINDOW`. `powershell.exe` is a console-subsystem executable, so launching it from `wscript.exe` (itself console-less) still allocates it a brand-new console — and on current Windows, where Windows Terminal is the default console host, that allocation can paint a visible frame before the hide is honored, unlike the old lightweight `conhost.exe`. No amount of "hide it after creating it" trickery fully closes that gap; the only way to make the risk zero is to never create the console-subsystem process in the first place.

### Fix (`install-agent.ps1`)

`watchdog_launcher.vbs` no longer calls `watchdog.ps1` via `powershell.exe`. It now re-implements the entire staleness check directly in VBScript, running inside the already console-less `wscript.exe` host: `Schedule.Service` (COM) reads the main agent task's `State`/`LastRunTime` in place of `Get-ScheduledTask`/`Get-ScheduledTaskInfo`, and `Scripting.FileSystemObject` reads the log file's last-write timestamp in place of `Get-Item`. No process is spawned at all on a healthy cycle — there's nothing left to flash. Only on the rare path where a hang is actually detected does it spawn anything, and even then it's `taskkill.exe`/`schtasks.exe` (native, near-instant console utilities, not PowerShell) rather than a fresh `powershell.exe`. `watchdog.ps1` is still written to disk with the same logic, kept for manual/diagnostic runs, but the scheduled task no longer executes it automatically.

### Verification

Custom PowerShell brace/paren/bracket balance script (quote/comment/here-string aware, including `@'...'@`/`@"..."@`) against a fresh clone of the pre-edit file: identical (0/0/0) in both. No PowerShell or VBScript interpreter available in this sandbox — the VBScript body was reviewed by hand line by line, with particular attention to quote-embedding in the `schtasks.exe` command line (built via `Chr(34)` instead of nested `""` escaping specifically to avoid a subtle, hard-to-verify-without-execution escaping bug) and to explicit `Err.Clear` calls after every `On Error Resume Next`-guarded COM call, since VBScript does not reliably auto-clear `Err` between statements. **Not yet live-tested** — this is the third attempt at this exact bug; next step is confirming on the same endpoint that already saw two prior "fixes" fail.

---

## ⏱️ USB Content-Aware Quarantine: Reduce (Not Eliminate) the Race Window Against Fast Exfiltration (August 4, 2026)

### The gap

User-reported scenario: with a "block USB file transfer" content policy configured, copying a sensitive file to an approved USB drive correctly gets detected and the file gets quarantined off the drive — but if the drive is physically unplugged quickly enough after the copy finishes, the data has already left the machine before detection+quarantine completes, and no software on the endpoint can act on a drive that's no longer connected.

### Why this is a real, fundamental limitation, not a bug

`UsbFileTransferMonitor()` detects USB file transfers by polling: once per interval it lists every removable drive's files (`ScanDirectoryRecursiveUSB`) and diffs against the last-known state. Detection, content classification (`EvaluatePolicyRealtime`, a server round-trip), and the actual quarantine move/delete all necessarily happen **after** Windows has already finished writing the file to the physical USB media — this loop has no way to intercept the write itself before it completes. That's only possible with a kernel-mode minifilter driver that can deny an `IRP_MJ_WRITE` before it's committed — the mechanism real enterprise DLP suites use for genuine prevention (not just detect-and-clean-up) on removable media. This agent doesn't have one; building one is a legitimately large, separate engineering effort (WDK driver development, Microsoft code-signing/attestation, crash-safety testing — a bad kernel driver blue-screens the endpoint) and is out of scope for a same-session fix.

### What was actually changed

The poll interval was 1 full second (`sleep_for(std::chrono::seconds(1))`), which was itself a real, avoidable chunk of the exposure window on top of the unavoidable classification+quarantine time. Cut to 250ms — a ~4x tighter average detection delay. This is safe to do cheaply because `ScanDirectoryRecursiveUSB` only enumerates file names/paths (no content reads or hashing), so the extra scan frequency doesn't meaningfully add CPU or disk I/O even on drives with several thousand files.

### What this does NOT fix

This narrows the window, it does not close it. A fast, deliberate user copying a small file and yanking the drive within roughly a second (poll interval + classification round-trip + quarantine-move time) can still beat detection. Communicated this directly rather than overstating what changed.

### The actual preventive control (already in place, unaffected by this change)

Device-level allowlisting (`usb_devices` allowlist, default `mode: "enforce"`) is the one USB control here that's genuinely preventive, not reactive — an unsanctioned device is blocked before any file can be copied to it at all, not raced after the fact. For data that must never leave via removable media regardless of content, the allowlist (or disabling USB mass storage devices entirely for a given policy) is the reliable control today; content-aware quarantine is a detection/cleanup layer on top of that, useful for approved devices where policy still needs to catch specific sensitive content, with the residual race window above.

### Verification

Brace-balance check (same script used throughout this project) against a fresh clone of the pre-change file confirms identical depth (paren=-2, brace=-5, bracket=-1) — no new imbalance introduced. No C++ compiler available in this sandbox. **Not yet live-tested** — worth re-running the same copy-then-immediately-unplug test after updating the agent to confirm the tighter interval visibly reduces (not eliminates) the number of times a fast transfer slips through undetected.

---

## 🏷️ Fix: USB Devices Tab Showed Generic Name and Empty VID:PID for a Real SanDisk Drive (August 4, 2026)

### Summary

A user plugged in a real SanDisk pendrive. The event triggered correctly and the serial number was captured correctly, but the USB Devices tab's "Seen on Endpoints" row showed device name **"USB Mass Storage Device"** (a generic label, not "SanDisk...") and VID:PID as **"—"** (empty), even though task #56 earlier in this project specifically added VID:PID resolution and a real device-name lookup.

### Root cause

This agent registers USB device-arrival notifications for `GUID_DEVINTERFACE_USB_DEVICE`, whose interface path *is* the composite `USB\VID_xxxx&PID_yyyy` device node itself (e.g. `\\?\USB#VID_0781&PID_5567#serial#{GUID}`) — the numeric VID/PID is already sitting directly in that string. But the two functions responsible for VID:PID and device name were both written on the opposite assumption (that `deviceId` was a *child* USBSTOR disk-node path, which only has `Ven_`/`Prod_` text and needs a walk *up* to its parent to find the numeric ID):

- `GetUsbStorageVidPid()` skipped straight to `CM_Get_Parent()`. For this device, that parent is one level too far — the USB hub/controller node, which naturally has no VID/PID matching the flash drive at all. Result: VID:PID always empty.
- `GetBetterDeviceName()` correctly parsed VID_/PID_ from the composite node and located it via SetupAPI, but then read that composite node's own `FriendlyName`/`DeviceDesc` — and for a standard bulk-only mass-storage device, Windows' generic class driver sets that composite node's description to the fixed, generic string `"USB Mass Storage Device"` for *every* compliant flash drive, regardless of vendor. The real vendor-specific name ("SanDisk Cruzer Blade USB Device") lives one level *down*, on the actual "Disk drives" child node — which nothing was reading.

### Fix

- `GetUsbStorageVidPid()`: try parsing VID_/PID_ directly out of `deviceId` first (the common case for this agent's actual notification format); only fall back to the parent-walk if that fails, preserving compatibility with any deviceId format that genuinely lacks its own VID/PID.
- Added `GetUsbStorageChildFriendlyName()`: walks down from the composite USB device node (`CM_Get_Child`/`CM_Get_Sibling`, capped at 8 to guarantee termination) looking for the actual USBSTOR/SCSI disk child node, and reads *its* `FriendlyName`/`DeviceDesc` (via `CM_Get_DevNode_Registry_PropertyA`) — falling back to parsing `Ven_X&Prod_Y` text directly out of that child's own device instance ID if neither property is set. `GetBetterDeviceName()` now tries this child-node lookup before falling back to the composite node's generic description.
- The disconnect handler (`DBT_DEVICEREMOVECOMPLETE`) previously used the raw, un-resolved device description for both the classic-policy event and the dashboard visibility report — meaning unplugging a drive would silently revert its "Seen" row back to the generic name. It now runs the same `GetBetterDeviceName()` resolution as the connect path.

### Verification

Brace-balance check (same script used throughout this project) against a fresh clone of the pre-change file confirms identical depth (paren=-2, brace=-5, bracket=-1, the known pre-existing baseline) — no new imbalance introduced. All new Windows APIs used (`CM_Get_Child`, `CM_Get_Sibling`, `CM_Get_DevNode_Registry_PropertyA`, `CM_DRP_FRIENDLYNAME`, `CM_DRP_DEVICEDESC`) are declared in `cfgmgr32.h`/linked via `cfgmgr32.lib`, both already used elsewhere in this file for the existing `CM_Get_Parent`/`CM_Locate_DevNodeA` calls — no new includes or libraries needed. No C++ compiler available in this sandbox to build and test. **Not yet live-tested** — next step is rebuilding the agent and re-inserting the same SanDisk drive to confirm the USB Devices tab now shows its real name and VID:PID.

---

## 🧊 Critical Fix: Windows Agent Self-Deadlock Froze Entire Process on Log Rotation (August 4, 2026)

### Summary

After deploying the baseline-scan-backgrounding fix above, the agent would, after running for a while, go completely silent -- no heartbeats, no USB events, no clipboard events, no filesystem events, nothing -- and the dashboard would show the endpoint as "Offline and Disconnected" even though the process was still alive (visible in `Get-Process`, still consuming CPU). This is very likely the same underlying bug behind an earlier, less clear-cut hang seen during testing this session: agent alive with high accumulated CPU, scheduled task showing "Running," but the log file frozen at 0 bytes.

### Root cause

A genuine, pre-existing self-deadlock in `Logger::Log()` in `agent.cpp`. `Log()` acquires `logMutex` via `std::lock_guard`, writes the line, and then calls `CheckAndRotateLog()` **while still holding that lock**. `CheckAndRotateLog()` only does anything once every 30 minutes, and only actually rotates once the log file exceeds 10MB -- but when it does rotate, it announced the rotation by calling `Info("Log rotated...")` and `Info("Log file size was...")`. Both of those call back into `Log()`, which tries to acquire `logMutex` again **on the same thread that's already holding it**. `std::mutex` is non-recursive, so this doesn't queue or error -- it blocks forever. Since `logMutex` is never released, every other thread in the agent (heartbeat, USB monitor, clipboard monitor, filesystem monitor -- all of them log constantly) then blocks the instant it tries to log anything, freezing the entire process at once, permanently, with no crash and no error to indicate why.

This bug pre-dates this session's changes, but the baseline-scan-backgrounding fix (see below) made it far more likely to actually trigger in practice: running the baseline scan as a background thread means its heavy per-file "Stored baseline for existing file: ..." logging now runs continuously for as long as the scan takes, instead of as one blocking burst before other monitoring even started -- pushing the log past the 10MB rotation threshold much sooner than before.

### Fix

Extracted a new lock-free `Logger::WriteLine(level, message)` private method containing the actual timestamp-formatting, console-output, and file-write logic (previously inline in `Log()`). `Log()` now: acquires `logMutex`, calls `WriteLine(...)`, then calls `CheckAndRotateLog()` -- unchanged in structure. `CheckAndRotateLog()`'s two rotation-announcement lines now call `WriteLine("INFO", ...)` directly instead of `Info(...)`, so they write the same log lines without re-entering `Log()` or re-acquiring `logMutex`. Visible log output is identical; the reentrant-lock path is gone entirely.

### Verification

Brace-balance check (same script used throughout this project) against a fresh clone of the pre-change file confirms identical depth (paren=-2, brace=-5, bracket=-1, the known pre-existing baseline) -- no new imbalance introduced by the edit. No C++ compiler available in this sandbox to build and run. **Not yet live-tested** -- next step is rebuilding the Windows agent binary (via the existing CI pipeline or a local Windows build) and confirming a real log rotation (or a forced low `MAX_LOG_SIZE` test build) no longer freezes the process.

---

## 🔌 Fix: One USB Pendrive Insertion Showed as 5 Separate "Not Sanctioned" Devices (August 4, 2026)

### Summary

A user plugged in a single physical USB pendrive and the USB Devices dashboard page showed 5 separate "not sanctioned" rows for it, with no way to tell which one was the real device to approve.

### Root cause

Windows device identity for a mass-storage device includes a serial number pulled from the interface path (`ExtractUsbSerialFromDeviceId()`). Devices with a genuine hardware serial report the same one every time. Cheap/generic pendrives without one get a serial *synthesized* by Windows instead — and a single physical insertion of such a drive can trigger several genuine `DBT_DEVICEARRIVAL` notifications in quick succession (a known USB/hub power-negotiation re-enumeration quirk, especially on flaky ports or hubs), each carrying a **different** synthesized serial since it's derived from that specific notification's own interface path. The server's USB device identity (`SanctionedUsbDevice` model, `/usb_devices/seen` endpoint) is keyed purely on `serial_number` — correctly, since that's the only way to distinguish two genuinely different physical devices — but with no per-insertion coalescing on the agent side, each of those re-enumeration attempts reported itself as a distinct "device," turning one physical pendrive into up to 5 dashboard rows.

Confirmed this wasn't the more common cause (Windows firing one callback per device-interface class — USB, Disk, Volume): the agent only registers for `GUID_DEVINTERFACE_USB_DEVICE`, so `HandleUsbDeviceArrival()` already fires once per genuine arrival notification, not once per interface class.

### Fix

Added a debounce keyed on VID:PID (unlike the serial, this stays stable across re-enumeration of the same physical device) in `HandleUsbDeviceArrival()`: if the same VID:PID reports another arrival within 8 seconds of the last one, the dashboard-visibility report (`ReportUsbDeviceAuthorization`) is suppressed as a duplicate. Deliberately scoped narrowly -- the allowlist block/allow decision and drive-letter mapping used for actual enforcement run on every single arrival exactly as before, unaffected; only the redundant dashboard report is debounced, so file-transfer blocking behavior is unchanged. A device with no determinable VID:PID skips the debounce entirely rather than risk suppressing a real, distinct device. A genuine re-insertion of the same drive minutes later is still reported normally (8-second window, not a permanent per-boot suppression).

### Verification

Brace-balance check (character-by-character walk skipping string/char literals and comments, same script used throughout this project) against a fresh clone of the pre-change file confirms identical depth (-5, the known pre-existing baseline unrelated to this change) -- no new imbalance introduced. No C++ compiler available in this sandbox to build and test against real hardware. **Not yet verified against a real flaky pendrive** -- worth re-testing the exact device that surfaced this (unplug/replug it a few times) to confirm it now produces one dashboard row instead of five.

---

## 🎯 Reduce False Positives: Phone-Number Matches Now Context-Weighted (August 4, 2026)

### Summary

Investigated a user's suspicion that a "CONTACT" detection badge on a clipboard event was a false positive. It wasn't — the Email Address rule tags its matches with both `CONTACT` and `EMAIL` labels, so that badge was the same genuine email match shown twice under different names, not a separate misfire. But the investigation surfaced a real, separate gap worth closing for false-positive reduction: the phone-number rules had no secondary validation at all.

### The gap

`CREDIT_CARD`/`PCI` matches get a Luhn checksum before counting as a hit — a real algorithmic validation with a very low false-positive rate. `US Phone Number` and `Indian Mobile Number` (`server/data/default_rules.json`) had nothing equivalent: any 10-digit sequence in the right shape (with separators/parentheses in the right places) counted as a full-confidence match. An order ID, tracking number, or account number formatted like a phone number would match just as readily as an actual phone number, with no way to tell them apart.

### Fix

Phone numbers have no checksum the way card numbers do, so an outright reject-without-context approach was ruled out — it would trade false positives for false negatives (missing a genuine phone number that happens to appear with no surrounding words). Instead, added `_has_nearby_keyword()` to `classification_engine.py`: checks a ±40-character window around each matched digit sequence for a phone-context keyword (phone, mobile, cell, tel, call, dial, whatsapp, contact, sms, etc.). When a phone-type rule matches with no such keyword nearby, its confidence *contribution* to the overall score is discounted to 40% (`_PHONE_NO_CONTEXT_DISCOUNT`) rather than rejected outright — the match still shows up in the event's detected data (nothing hidden from the analyst), it just can no longer single-handedly push a document to Confidential/Restricted the way a genuinely phone-number-shaped-and-contextualized match would.

Standalone test of the keyword-window logic: `"Call me at 9876543210"` → context found (full confidence); `"Order ID: 9876543210 has been confirmed"` → no context (discounted); `"My mobile number is 9876543210"` → context found; `"Tracking: 9876543210, ETA Friday"` → no context. All four behaved as intended.

### Verification

`ast.parse()` confirms valid Python syntax. The standalone keyword-window test above ran directly (not just traced by hand) and passed all four cases. **Not yet run against the full classification pipeline with real database rules** — worth testing a genuine phone number both with and without context wording nearby, and confirming the resulting confidence score/classification level differ sensibly between the two.

---

## 🎯 Fix: Every "Detected Sensitive Data" Badge Showed the Same Confidence (August 4, 2026)

### Summary

In an event's detail view, the "Detected Sensitive Data" badges (e.g. CONTACT, EMAIL, NETWORK, IP_ADDRESS, STUDY_REPORT) all showed the exact same percentage as the overall classification confidence score — reported on a real clipboard event where every one of five distinct detected types showed an identical "70%", which is misleading: a deterministic EMAIL regex match and a fuzzy CONTACT heuristic match should not carry the same confidence.

### Root cause (two separate bugs stacked)

1. **No per-rule confidence was ever computed.** `classification_engine.py`'s rule-matching loop calculated a scaled confidence *contribution* per matched rule (`rule.weight * scale`) but only summed it into the single overall `total_weight`/`confidence_score` — the per-rule value itself was discarded. `event_processor.py` then built the event's `classification` list by stamping that one overall `result.confidence_score` onto every matched rule's entry, so every category necessarily showed the identical number.
2. **Even after computing per-rule values, the frontend couldn't have used them correctly.** `Events.tsx` tried to look up each badge's confidence via `classification[idx]?.confidence`, matching by array index against `classification_labels[idx]`. Those two arrays don't correspond 1:1 by construction: `classification_labels` is a *deduped* list of distinct sensitive-data types across all matched rules, while `classification` has one entry *per matched rule* (a rule can contribute multiple labels; two rules can contribute the same label) — different lengths, different order, in general. On top of that, `event.classification` was never actually persisted to the stored event document at all (`_process_event_background` in `events.py` only ever wrote `classification_metadata`, never the raw `classification` array), so the index lookup was always `undefined` and always fell through to the same overall score regardless.

### Fix

- `classification_engine.py`: each matched rule's `rule_result` now carries its own `confidence` (the same per-rule scaled contribution, capped at 1.0). `ClassificationResult` gained a new `label_confidence: Dict[str, float]` field — for every classification label a rule contributes, its confidence is rolled up as the *max* across every rule that contributed that label (so a weak rule tagging "EMAIL" can't drag down a strong rule that also found it). Correlation-derived extra rules/labels get the same treatment using their `bonus_weight`.
- `event_processor.py`: `classification[].confidence` now uses the per-rule value instead of the overall score; `classification_metadata` gained a `label_confidence` dict (keyed by the same strings as `classification_labels`) that's what actually reaches the dashboard, since the whole `classification_metadata` object was already being persisted.
- `Events.tsx`: rewrote the badge confidence lookup to read `event.classification_metadata?.label_confidence?.[label]` by name instead of the fragile, always-broken index lookup into a never-persisted array.

### Verification

`ast.parse()` on both edited Python files confirms valid syntax. Ran the project's own `tsc --noEmit` — 42 errors, identical to the established baseline, zero in `Events.tsx`. Traced the full data path by hand: rule match → per-rule `confidence` on `rule_result` → rolled into `label_confidence` in `ClassificationResult` → copied into `classification_metadata` in `event_processor.py` → persisted whole via the existing `update_fields["classification_metadata"] = ...` write in `events.py` (no new persistence code needed there) → read by label name in `Events.tsx`. **Not yet observed against a live event** — worth re-triggering the same clipboard test that surfaced this (content with email + IP + a study-report keyword match) and confirming the badges now show genuinely different percentages instead of one repeated number.

---

## 🚨 Windows Agent: Startup Baseline Scan Was Blocking ALL Monitoring (August 4, 2026)

### Summary

On a fresh install/reinstall (or the first time file policies become active), the Windows agent ran its existing-file baseline scan synchronously on the main thread, before spawning any monitor thread. A monitored folder with a large number of files -- confirmed on a real endpoint with a folder full of ICU/CLDR locale `.dat` files under Documents/Desktop/Downloads -- could keep this scan running for a long time, during which clipboard, USB, file-system, and every other monitor were simply not running yet. Symptom reported: agent process alive, log flooding with "Stored baseline for existing file: ..." lines, and a clipboard copy on the same machine produced no event at all.

### Root cause

`ScanAndStoreExistingFiles()` was called directly in `Start()`, right after the initial policy sync and before the block that spawns `workerThreads` (`HeartbeatLoop`, `ClipboardMonitor`, `UsbMonitor`, `FileSystemMonitor`, etc.). Since `ClipboardMonitor`'s thread object didn't exist yet, there was nothing to detect the clipboard event with -- the agent wasn't failing or dropping the event, it just hadn't started monitoring at all. A second call site in `PolicySyncLoop()` (fired when file policies newly become active mid-run) had the same synchronous-call pattern, which would stall that loop's next sync cycle for the scan's duration.

### Fix

- `Start()`: the baseline scan is now spawned as its own thread (`workerThreads.emplace_back(&DLPAgent::ScanAndStoreExistingFiles, this)`), added to `workerThreads` **after** every other monitor thread is already spawned -- so clipboard/USB/file-system/etc. are live immediately, and the baseline scan proceeds concurrently in the background instead of gating them.
- `PolicySyncLoop()`: same call replaced with a detached `std::thread(&DLPAgent::ScanAndStoreExistingFiles, this).detach()`, since this call happens from within a worker thread (not the main thread) where pushing into the shared `workerThreads` vector would race with a shutdown-time `Stop()` iterating/clearing it.
- `ScanAndStoreExistingFiles()` now checks the `running` flag at the top of both its per-directory and per-file loops and bails out early if the agent is shutting down -- bounds how long a huge folder can keep a scan thread alive after `Stop()` is called (relevant for the detached case, since nothing explicitly joins it) to roughly one file's worth of I/O instead of the entire remaining scan.
- No locking changes were needed: `ScanAndStoreExistingFiles()` already takes `policiesMutex` and `originalContentsMutex` around every read/write of the shared directory list and content map, so running it concurrently with the other monitors (which touch the same state) was already safe.

### Verification

No C++ compiler available in the sandbox this was written in. Verified with the same brace-balance script used earlier in this project (character-by-character walk skipping string/char literals and `//`/`/* */` comments): the edited `agent.cpp` reports the identical depth (-5) as a fresh clone of the pre-change file, confirming no new brace imbalance was introduced by these edits. Traced both call sites and the `Stop()`/join logic by hand to confirm `workerThreads.emplace_back` from `Start()` (main thread, before any worker thread exists yet) is safe, while the `PolicySyncLoop()` call site deliberately avoids the same pattern since it runs concurrently with a possible `Stop()`. **Not yet run on a real Windows endpoint** -- this needs `build-windows-agent.yml` to produce a new binary and a real reinstall/policy-toggle test (large monitored folder + immediate clipboard copy) before considering this closed.

---

## 🔧 CI Fix: Linux Agent Build Workflow Failing on Every Run (August 4, 2026)

### Summary

`build-linux-agent.yml` was failing at its final "Commit updated binary" step on every run, immediately after `git config --global --add safe.directory "$GITHUB_WORKSPACE"`, with `fatal: not in a git directory`.

### Root cause

The job runs inside a bare `python:3.9-slim-bullseye` container, which has no `git` binary preinstalled. The workflow's step order was: (1) `actions/checkout@v4`, then (2) `apt-get install ... git ...`. `actions/checkout@v4` requires `git` to perform a real clone; when it isn't found on `PATH`, checkout silently falls back to downloading the repository as a plain source tarball via the GitHub REST API instead -- which produces a normal-looking working tree with **no `.git` directory at all**. Every step after that ran fine (the build itself doesn't need git), until the final step tried to `git add`/`git commit`/`git push` against a directory that was never a git repo in the first place. `safe.directory` only fixes an ownership-mismatch error ("detected dubious ownership") -- it does nothing for "not in a git directory," which is a different failure mode entirely (no repo present, period).

### Fix

Reordered the two steps so `git` (and the rest of the system build dependencies) install before checkout runs. `actions/checkout@v4` then finds `git` on `PATH` and does a real clone, so `$GITHUB_WORKSPACE` is an actual git working tree by the time the commit-back step runs.

### Verification

Parsed the edited workflow with PyYAML to confirm it's still valid YAML and that the step order is now `Install system build dependencies` → `Checkout code` → ... → `Commit updated binary`. This is a config-only fix touching a `paths:`-filtered file (`.github/workflows/build-linux-agent.yml`), so pushing it re-triggers the workflow -- the resulting run itself is the real end-to-end verification of whether the checkout now includes a working `.git` directory.

---

## 🛠️ CyberSentinel Parity: Consolidated Windows Management Script (August 4, 2026)

### Summary

Sixth and last of the CyberSentinel-parity batch. Added `manage-agent.ps1` at the repo root -- a single entry point for Install / Update / Uninstall on a Windows endpoint, with a live status readout (running/stopped/broken/not installed, recent log errors, whether a newer build is published) shown before every action.

### Why not a straight port

The CyberSentinel reference project has an equivalent `manage-windows-agent.ps1`, but porting it as-is would have reintroduced a bug this project already fixed once and silently dropped a feature this project already has:

- Its uninstall function stops the process, removes the scheduled task, and deletes the install/data directories -- but never calls any server-side unregister endpoint first. That's exactly the "duplicate/ghost agent" bug fixed earlier in this project (see the "Fix 1: uninstall/reinstall calls unregister endpoint" entry below): once the agent's key file is deleted, nothing can ever tell the server the device is gone, and it lingers in the Agents view permanently.
- It only knows about one scheduled task. SeceoKnight's installer registers three (`SeceoKnight DLP Agent`, `SeceoKnight DLP Watchdog`, `SeceoKnight DLP USB Block`) -- a single-task uninstall would leave two of them orphaned on the machine.

`manage-agent.ps1` was written fresh against SeceoKnight's actual install layout instead, reusing the same unregister-before-delete pattern install-agent.ps1 already uses on reinstall, and removing all three tasks by name.

### What it does

- **Self-elevates** to Administrator (same pattern as the reference script), then detects whatever's actually on the machine: install dir, binary, process, all three scheduled tasks, and reads `agent_config.json`/`agent_key.json` for server URL / agent ID / agent name.
- **Status**: prints a health verdict (RUNNING / STOPPED but autostart configured / BROKEN - no autostart task / RUNNING but binary missing / NOT INSTALLED), whether the watchdog and USB-block tasks are present, the last 80 log lines scanned for error/critical/fatal/exception/traceback, and whether a newer build is published (SHA-256 sidecar comparison against the currently installed binary's hash).
- **[1] Install**: delegates to `install-agent.ps1` (downloads and runs it) rather than re-implementing OCR dependency setup, integrity verification, and scheduled-task creation a second time in this file -- avoids two copies of that logic drifting apart.
- **[2] Update**: binary-only swap. Downloads the latest exe, verifies its SHA-256 against the published sidecar (same verify-or-refuse logic as the installer), stops the task/process, replaces the file, restarts the task. Config and scheduled tasks are left untouched.
- **[3] Uninstall**: single `y` confirmation, then unregisters the agent identity from the server (best-effort, using the stored `agent_key.json`), kills the process, removes all three scheduled tasks, deletes both directories, and clears the machine-wide `SECEOKNIGHT_SERVER_URL` env var.

### Verification

No PowerShell interpreter was available in the sandbox this was written in (network-restricted, no package manager access), so this could not be run end-to-end. Verified structurally instead: a custom brace/paren/bracket balance checker (Python, aware of PowerShell single/double-quoted strings, `#` comments, and `@"..."@`/`@'...'@` here-strings) confirms no unclosed or mismatched delimiters. Manually cross-checked every constant (`$INSTALL_DIR`, `$EXE_NAME`, `$TASK_NAME`, the three task names, the config/key file names) against the exact values `install-agent.ps1` uses, and confirmed the unregister call matches the real `DELETE /agents/{id}/unregister` endpoint (`server/app/api/v1/agents.py`) and its `X-Agent-Key` header convention. **Not yet run on a real Windows endpoint** -- worth a supervised dry run (Status only, then Update on a disposable test VM) before relying on it for a production Uninstall.

---

## 🧩 CyberSentinel Parity: Incident Coalescing (August 4, 2026)

### Summary

Fifth of the CyberSentinel-parity batch. Auto-generated incidents (`_auto_create_incident` in `server/app/api/v1/events.py`, backing the MongoDB `incidents` collection that the Incidents dashboard page actually reads via `/incidents/auto/*`) now merge a burst of qualifying events from the same user into a single incident, instead of minting one incident per event.

### Root cause

The dashboard has two parallel incident systems: a PostgreSQL `Incident` model with full CRUD for manually-created/analyst-managed incidents, and a separate MongoDB `incidents` collection auto-populated whenever a blocked-Restricted/Confidential event or a critical/high-severity event comes through `POST /events`. `Incidents.tsx` displays the latter (`getAutoIncidents()`). The auto-create logic only de-duplicated on exact `event_id` (which can never collide across two different events), so five blocked events from the same user in ten minutes produced five separate incident rows in the queue for what's really one ongoing problem -- no merging across different qualifying events at all.

### Fix

`_auto_create_incident` now looks for an existing **open** incident from the same `user_email` created within the last hour before creating anything new:

- If found: folds the new event in via `$addToSet` on a new `related_event_ids` array field, bumps `event_count`, and ratchets `severity` up to the worse of the two (never down). The incident's original title is left alone unless this event pushes it past the repeated-violations threshold (5+ blocked events/hour), in which case the title is updated to reflect that.
- If not found: creates a new incident as before, now also stamping `event_type` and seeding `related_event_ids: [event_id]`.
- The window is anchored to the incident's own `created_at` (not extended/rolled forward by each new event), so a single user can't keep one incident open indefinitely -- once an hour passes since it opened, the next qualifying event starts a fresh incident.
- Idempotency: the old "does an incident already exist for this event_id" dedup check was widened to also check `related_event_ids`, so a retried/reprocessed event can't get folded into an incident twice and double-count `event_count`.

`GET /incidents/auto/{id}` (`server/app/api/v1/incidents.py`) previously computed "related events" at read time via a loose heuristic (same user, severity critical/high, last 20) that had no actual connection to what caused the incident. It now prefers the incident's real `related_event_ids` list when present -- the actual coalesced set -- falling back to the old heuristic only for incidents created before this field existed.

No frontend changes were needed: `Incidents.tsx` already renders `incident.event_count` and `incident.related_events` on the card and detail view, so a coalesced incident just shows a higher count and a longer related-events list automatically.

### Verification

`ast.parse()` on both edited files confirms valid Python syntax. Traced the idempotency path by hand (retried event → matches `related_event_ids` → early return, no double-count) and the window-expiry path (incident older than 1 hour → `existing_open` query excludes it → new incident opens instead of growing the old one indefinitely). Not yet exercised against a running server with a real burst of events -- worth confirming end-to-end (fire 3-4 blocked events from one test user within a minute, confirm one incident with `event_count: 4` rather than four rows) before considering this fully done.

---

## 📄 CyberSentinel Parity: Pagination on List Pages (August 4, 2026)

### Summary

Fourth of the CyberSentinel-parity batch. Six dashboard pages that rendered their entire result set into the DOM at once -- Alerts, Agents, Rules, USB Devices, Printers, Threat Intelligence (Indicators) -- now paginate, so a deployment with hundreds/thousands of rows doesn't dump them all into one unbounded table.

### What was actually needed (less than expected)

Before writing anything new, checked whether a shared pagination component already existed -- it did. `usePagination<T>()` (`src/lib/hooks/useTableState.ts`) and `<DataPagination>` (`src/components/ui/pagination.tsx`) already back the Events page's table, doing client-side windowing (slice the already-fetched array by page) with a "showing X-Y of Z" footer, rows-per-page selector, and first/prev/next/last controls. The task was reuse, not rebuild: wire that existing pair into the six pages that were rendering `filteredX.map(...)` directly with no windowing at all.

### What changed

- **Alerts.tsx, Agents.tsx, Rules.tsx**: each already computed a filtered array (`filteredAlerts`, `filteredAgents`, `filteredRules`) before rendering a `.map()` over it directly. Swapped the render to `usePagination(filtered, 25).pageRows.map(...)` and added a `<DataPagination>` footer below each table.
- **UsbDevices.tsx**: three independent lists on one page (Sanctioned, Disallowed, Seen-but-unsanctioned) -- each gets its own `usePagination` instance and footer, since they're logically separate tables that happen to share a page.
- **Printers.tsx**: same treatment for the single Sanctioned Printers table.
- **ThreatIntelligence.tsx**: paginated the Indicators (IOCs) table specifically -- left Recent Matches and TAXII Feeds unpaginated since those lists are inherently bounded (recent activity window / configured feed count), not something that grows toward hundreds of rows.
- **Real bug caught and fixed while wiring this in**: on Alerts.tsx, Agents.tsx, and Printers.tsx/UsbDevices.tsx, the natural place to add `usePagination()` was right before the JSX return -- but all of these components have an `if (isLoading) return <LoadingSpinner />` / `if (error) return <ErrorMessage />` earlier in the function body. A hook call placed after a conditional early return only executes on some renders (skipped during the loading render, executed once data arrives), which violates React's rules of hooks and can corrupt hook state across re-renders. Moved each `usePagination()` call (and the array derivation it depends on) above the early returns instead, relying on the existing `Array.isArray(...) ? ... : []` / `data?.field || []` guards that were already there to handle the `undefined`-while-loading case safely.

### Verification

Ran the project's own `tsc --noEmit` before and after this change -- identical error count (42), and confirmed via `grep` that none of the pre-existing errors are in any of the six touched page files or the pagination utilities. Manually traced the hook-ordering fix in each of the four affected files to confirm `usePagination()` now runs unconditionally on every render path (loading, error, and loaded). Not yet exercised in a running browser against a real large dataset (confirm page-size selector, first/last buttons, and the "showing X-Y of Z" count all render correctly against several hundred real rows) -- worth a quick visual check before considering this fully done.

---

## 📤 CyberSentinel Parity: Policy Import/Export (August 4, 2026)

### Summary

Third of the CyberSentinel-parity batch. Policies can now be exported to a portable JSON file and imported into any other SeceoKnight deployment -- useful for promoting a tested policy set from staging to production, sharing a starter policy pack across customers, or just backing up policy configuration outside the database.

### What's new

- **Server**: `GET /policies/export` returns a JSON bundle (`{version, exported_at, exported_by, policy_count, policies: [...]}`) built from the same domain-scoped RBAC filtering `GET /policies/` already applies, so a domain admin can only export what they can already see. Each exported policy is stripped down to exactly `PolicyUpsert`'s shape (name, description, enabled, priority, type, severity, config, match, conditions, actions, compliance_tags) -- deliberately omitting id, domain, agent_ids, timestamps, and created_by, none of which are meaningful on a different deployment.
- `POST /policies/import` accepts that same bundle shape and creates each policy independently through the exact same path `POST /policies/` (create_policy) uses -- same domain-RBAC check per item, same `transform_frontend_config_to_backend` for type+config policies. One policy failing (name collision, RBAC, invalid structure) doesn't abort the batch -- every outcome (created/skipped/errored) is collected and returned as a per-policy summary. A `?on_conflict=skip|rename` query param controls what happens when an imported name already exists; `rename` finds a free `"<name> (imported)"` / `"<name> (imported 2)"` slot rather than overwriting. Agent scoping is deliberately dropped on import (source agent UUIDs won't exist on the target) -- imported policies apply to all agents until manually re-scoped.
- Both routes are registered ahead of the existing `GET /{policy_id}` in `policies.py` -- FastAPI matches routes in registration order, so `/export` needed to come first or it would have been swallowed by the `{policy_id}` path parameter and thrown trying to parse "export" as a UUID.
- **Dashboard**: new Export/Import buttons on the Policies page toolbar. `ExportPoliciesModal.tsx` lists every visible policy with checkboxes (select-all default) and downloads the result as `seceoknight-policies-<date>.json` via the same blob/`createObjectURL` pattern the Reports page already uses for PDF/CSV downloads. `ImportPoliciesModal.tsx` accepts a `.json` file, parses and previews the policy names client-side before committing, surfaces the skip/rename choice, and displays the created/skipped/failed breakdown from the server's response after import.

### Verification

`python3 -c "import ast; ast.parse(...)"` clean on `policies.py`. Ran the project's own `tsc --noEmit` before and after -- identical error count (42), and confirmed via `grep` that none of the pre-existing errors are in any of the newly touched files (`ExportPoliciesModal.tsx`, `ImportPoliciesModal.tsx`, `Policies.tsx`, `lib/api.ts`). Not yet exercised end-to-end against a running server (export a real policy set, import into a second deployment, confirm it lands correctly) -- recommend testing that round-trip before relying on it for a real staging-to-production promotion.

---

## 🚫 CyberSentinel Parity: File Identity Denylist Policy Type (August 4, 2026)

### Summary

Second of the CyberSentinel-parity batch. New policy type that blocks files by *what they are* -- a known-bad extension (`.exe`, `.bat`, ...) or an exact SHA-256 hash -- independent of DLP content classification, the same way an antivirus denylist works. Applies to any event carrying a file path or hash: file system, file transfer, USB transfer, and print (now that print events carry a hash, per the previous entry).

### Why this needed almost no new matching code

`DatabasePolicyEvaluator` (`server/app/policies/database_policy_evaluator.py`) is already a generic field/operator/value rule engine, not a set of hardcoded per-policy-type handlers -- a condition like `{"field": "file_hash", "operator": "in", "value": [...]}` is evaluated the same way as every other policy's rules. The only gap was that `file_hash` wasn't in `_extract_field_value`'s field-mapping table, so a rule referencing it could never resolve to anything. Added `"file_hash": ["file.hash.sha256", "file_hash"]` to close that gap -- `file_extension` was already mapped and already auto-derived from `file.path` by `EventProcessor._enrich_file_event()`.

Also caught and fixed a shape mismatch introduced by the previous entry: `_build_processor_payload()` had set `payload["file"]["hash"]` as a flat string, but `EventProcessor._enrich_file_event()`'s own content-based hash fallback expects `file.hash` to be a dict (`{"sha256": "..."}`) -- left as a flat string, that fallback's `file_info.setdefault("hash", {})["sha256"] = ...` would have raised a `TypeError` the first time it ran against an agent-supplied hash. Fixed to set the dict shape directly, which also means the content-based fallback is correctly skipped (via `setdefault`) when an agent already supplied a hash instead of two different hash values coexisting.

### What's new

- **Server**: `_transform_file_identity_denylist_config()` in `policy_transformer.py` turns a simple `{extensions, hashes, action, quarantinePath}` frontend config into `{"match": "any", "rules": [...]}` conditions -- "any" because a file matching either the extension list or the hash list should be denied, not both. Registered in `domains.py`'s `POLICY_TYPE_DOMAIN` under `data_protection` (same domain as file_system/file_transfer monitoring, the closest sibling controls).
- **Dashboard**: new `file_identity_denylist` policy type in the creator wizard (`PolicyTypeSelector.tsx`, new `FileIdentityDenylistPolicyForm.tsx`), with extension chips (common exe/script extensions pre-listed, custom entry supported) and a hash list with SHA-256 format validation (64 hex chars) before a hash can be added. Wired into `PolicyCreatorModal.tsx`'s type/config dispatch and `policyUtils.ts`'s icon/label/summary/validation switches, matching every other policy type's integration points exactly.
- No agent changes needed -- extensions/hashes are evaluated server-side against fields the agents already send (or, for hashes, now send as of the print-hashing fix).

### Verification

`python3 -m ast.parse` clean on all four touched server files. Dashboard: ran the project's own `tsc --noEmit` before and after these changes and diffed the output -- identical error count (42) both times, and the only textual differences are pre-existing errors' union-type strings getting longer (because the new types were added to those unions), not new errors. Confirmed via a fresh clone of the currently-pushed `main` as the "before" baseline. Not yet exercised against a live policy evaluation (create a real denylist policy, trigger a matching file/print event, confirm it's blocked) -- recommend testing that end-to-end before relying on this for enforcement.

---

## 🔒 CyberSentinel Parity: Print-Job File Hashing + Fixed Silent Event-Field Drops (August 4, 2026)

### Summary

First of a batch of CyberSentinel-parity features. Both agents now compute a SHA-256 hash of the actual spooled print document (not just its filename) and send it with the print event, so printed documents can eventually be matched against the same hash-based denylists used for file transfers (Task #78, next up). Along the way, found and fixed a real pre-existing bug: the server was silently dropping `file_hash` (and two smaller fields, `username`/`printer`) off every event agents sent, for events of every type -- not just print.

### Root cause (the bigger fix)

`server/app/api/v1/events.py`'s `EventCreate` -- the Pydantic model FastAPI validates every `POST /events` body against -- never declared `file_hash`, even though the Windows agent has been sending it on file-system, USB-transfer, and file-block events since early in the project (`json.AddString("file_hash", fileHash)` appears at four separate call sites in `agent.cpp`). Pydantic models with no `class Config: extra = "allow"` silently strip any JSON field that isn't explicitly declared -- FastAPI never errors, the agent never errors, the field just vanishes before `create_event()`'s handler body ever sees it. This is the exact same class of bug found and fixed in `alerts.py`'s `user_email` field earlier in this project. Concretely, this meant `ioc_service.py`'s `event.get("file_hash")` IOC matching, `siem/base.py`'s SIEM export hash field, and `decision.py`'s file-hash lookups have all been silently getting `None` for these fields this whole time, regardless of what the agent actually sent.

### Fix

- `EventCreate` now declares `file_hash`, `username`, and `printer` (the latter two were already being sent by the Linux agent's print/clipboard events, same silent-drop problem on a smaller scale).
- `create_event()`'s `event_doc` construction (the dict actually written to MongoDB) now includes all three, so `ioc_service.py`/`event_mapper.py`/`siem/base.py`/`decision.py` -- which all read these fields straight off the stored document -- actually receive them.
- `_build_processor_payload()` also threads `file_hash` into the policy-evaluator payload (`payload["file_hash"]` and `payload["file"]["hash"]`), ahead of Task #78's file-identity denylist work, which will need to match on it.

### What's new (the print-hashing feature itself)

- **Linux** (`print_monitor.py`): new `_hash_job_file()` resolves the CUPS spool file for a job (`/var/spool/cups/d<NNNNN>-<NNN>`, where `<NNNNN>` is the numeric CUPS job ID zero-padded to 5 digits) and SHA-256-hashes it. Computed *before* the print event is handed to `agent.py`'s callback, which is what may cancel (and thus delete) the job's spool file if it classifies as Restricted -- hashing first means blocked jobs, the case this matters most for, still get a hash instead of silently missing one.
- **Windows** (`print_monitor.h/.cpp`, `agent.cpp`): `PrintMonitor` gained an injected `HashCallback` (same pattern as its existing `ClassifyCallback`) so it can reuse `agent.cpp`'s existing `CalculateFileHash()` (CryptoAPI SHA-256) without duplicating a second hash implementation. New `GetPrintSpoolFilePath()` resolves the job's spool file at `%SystemRoot%\System32\spool\PRINTERS\FP<jobid>.SPL` (the Windows spooler's default naming/location). Hashing is invoked in `MonitorLoop()` immediately after the job ID is read -- before the `CancelPrintJob()` enforcement call -- for the same before-cancellation-deletes-it reason as Linux.
- Both platforms degrade gracefully: if the spool file can't be found or read (custom spool directory, already purged, permissions), the print event is still sent with no `file_hash` field, exactly as before this change -- hashing is additive, never blocking.

### Verification

`python3 -m py_compile` clean on `print_monitor.py`/`agent.py`. `python3 -c "import ast; ast.parse(...)"` clean on `events.py`. C++ changes checked with a comment/string-aware brace-depth walker across `print_monitor.h`/`print_monitor.cpp` (both balance to 0) and confirmed the pre-existing (unrelated, baseline) imbalance in the much larger `agent.cpp` is identical before and after this change, by diffing against a fresh clone of the currently-pushed `main` -- i.e. these edits introduced no new imbalance. Not yet live-tested against a real CUPS or Windows print spooler -- the spool file naming/location assumptions (especially Windows' default spool directory, which admins occasionally relocate) should be confirmed on a real print job before relying on this for compliance/audit purposes.

---

## 🔧 Linux Agent CI: Fixed False-Failure on Missing `file` Command (August 3, 2026)

### Summary

The first two real runs of `build-linux-agent.yml` both failed -- but the actual build succeeded both times (a working 6.6MB binary, confirmed in the logs).

### Root cause

`python:3.9-slim-bullseye` doesn't ship the `file` command by default (it's a minimal image). The build step's last line, `file dist/seceoknight_linux_agent`, was purely informational, but with no `|| true` its "command not found" (exit 127) failed the entire step -- and every step after it (the smoke test, checksum generation, and committing the binary back to the repo) never even ran.

### Fix

Added `file` to the container's installed packages, and `|| true` on the diagnostic line itself as a second line of defense against this exact class of failure recurring.

### Verification

YAML parses clean. Not yet confirmed green on GitHub Actions -- this push itself will be the first real test of the smoke-test/checksum/commit-back steps, since the previous two runs never reached them.

---

## 📋 Linux Agent: Clipboard Monitoring (X11 + Wayland) (August 3, 2026)

### Summary

Last piece of the Linux DLP feature-parity pass: clipboard monitoring, the one capability with no existing Linux code to build on at all. The hard part wasn't reading the clipboard -- it's *whose*.

### The root architectural problem

`seceoknight-agent.service` runs as root (required for cross-user file/USB monitoring), but the clipboard is a property of a specific logged-in user's X11 or Wayland session. Root has no `$DISPLAY`/`$WAYLAND_DISPLAY` of its own, and X11 in particular generally refuses a connection from a different UID than the one that owns the session. This is the same "who's actually logged in" problem CyberSentinel's Linux agent solves for file-owner attribution via `who`/`loginctl` -- solved here the same way, applied to clipboard access instead: find the active graphical session's owning user via `loginctl`, then read the clipboard *as that user* (`sudo -u` with that session's `DISPLAY`/`WAYLAND_DISPLAY`/`XAUTHORITY`/`XDG_RUNTIME_DIR` set), rather than trying to access it as root directly.

### What's new

New `clipboard_monitor.py`, wired into `agent.py` the same unconditional way print/USB monitoring are (no server policy category exists to gate any of these three on):

- **Session discovery**: `find_active_graphical_session()` parses `loginctl list-sessions`/`show-session` for the active, local (non-SSH), X11-or-Wayland session and its owning user -- re-checked every 30s so a user switch or new login is picked up without an agent restart.
- **X11**: polls `xclip -selection clipboard -o` (there's no blocking-read primitive for X11 selections short of a native X11 event-loop client, too heavy a dependency for this). Content is hashed and compared to the last read so unchanged clipboard state doesn't spam events.
- **Wayland**: uses `wl-paste --watch cat`, which blocks and emits on each actual clipboard change where the compositor supports it (most do, via wlr-data-control) -- genuinely event-driven, no polling needed.
- Classified with the exact same `_classify_content()` rules file events already use, reported in the same shape the Windows agent's clipboard pipeline sends (`event_type=clipboard`, `event_subtype=clipboard_copy`).
- Deliberately **does not** clear/block clipboard content on a match -- detect-and-report only for this first pass, matching how the Windows agent's own clipboard handling in this codebase already works (it doesn't clear the clipboard either). Clearing risks surprising a user after they've already pasted, for no actual DLP benefit once the paste has happened.
- Degrades to a logged no-op (not a crash) if `xclip`/`wl-clipboard` aren't installed, or no active graphical session is found (e.g. a headless server) -- same posture as print/USB monitoring.

`install.sh` now also installs `xclip`/`wl-clipboard`/`sudo` as system dependencies, and the CI build (`build-linux-agent.yml`) bundles the new module into the frozen binary.

### Verification

`python3 -m py_compile` clean on all agent modules. Directly exercised in the sandbox (not just syntax-checked): constructed a full `DLPAgent` with all three new monitors (print/USB/clipboard) wired in and no import errors; `ClipboardMonitor.start()`/`stop()` cycled cleanly with a graceful "no active graphical session" result (expected -- this sandbox is headless). Not live-tested against a real X11 or Wayland desktop session -- do that (both a real copy-to-clipboard on each display server, and a fast user switch to confirm session re-detection) before relying on this in production.

---

## 📦 Linux Agent: PyInstaller Single-Binary Packaging + CI (August 3, 2026)

### Summary

Installing the Linux agent from source required `apt-get install python3 python3-pip` plus compiling pyudev's C extension against libudev on every single target machine -- a much heavier footprint than the Windows agent's single self-contained `.exe`. Added the same packaging model for Linux: a frozen, dependency-free binary built by CI, matching CyberSentinel-DLP's approach.

### What's new

**`.github/workflows/build-linux-agent.yml`**: builds `agent.py` (+ `policy_cache.py`/`print_monitor.py`/`usb_monitor.py`) into a single `seceoknight_linux_agent` binary via PyInstaller, triggered on any push touching the Linux agent's `.py` files. Builds inside a `python:3.9-slim-bullseye` container specifically (not `ubuntu-latest`'s own newer glibc) -- PyInstaller bundles the Python interpreter but not glibc itself, and glibc is backwards- but not forwards-compatible, so building against bullseye's older glibc (2.31) means the binary runs there and on everything newer, while building against a newer glibc would refuse to run on anything older. `--collect-all pyudev` bundles pyudev's compiled `_libudev` extension into the binary so the target machine needs no Python/pip/compiler at all, only `libudev` itself (present on essentially every Linux install already). A smoke test confirms the frozen binary actually boots without an ImportError before it's committed. Same commit-the-binary-back-to-the-repo + fetch/rebase-retry-on-push-race pattern as `build-windows-agent.yml`.

**`install.sh`**: now downloads and checksum-verifies the pre-built binary by default (`curl` from the same `raw.githubusercontent.com` convention `install-agent.ps1` uses for the Windows `.exe`), and generates `/etc/systemd/system/seceoknight-agent.service` itself with the right `ExecStart` for whichever install path actually succeeded. Falls back automatically to installing from local `.py` source (today's behavior, needs python3/pip on the target) if the binary download or checksum verification fails, or if `--from-source` is passed explicitly -- e.g. for local development or an air-gapped target with no route to GitHub.

**`seceoknight-agent.service`** (the checked-in copy): now documented as a reference for `--from-source`/fully-manual installs only, since `install.sh` generates the real unit file itself.

### Verification

`bash -n install.sh` clean, workflow YAML parses clean. Not yet run end-to-end on GitHub Actions (needs an actual push to trigger it) or tested on a real target machine -- verify the first CI run produces a working binary and that a fresh Debian/Ubuntu VM can install and start the agent via the new `install.sh` before relying on this in production.

---

## 🖨️🔌 Linux Agent: Print Job Monitoring + USB Storage Monitoring (August 3, 2026)

### Summary

Following the Linux agent bugfix pass below, added the two biggest CyberSentinel-adjacent capability gaps: print job monitoring (the module already existed as `print_monitor.py` but was never imported into `agent.py`) and USB storage device monitoring (new — nothing on Linux detected USB connect/disconnect before this).

### What's new

**Print monitoring** (`agent.py` + existing `print_monitor.py`): CUPS print jobs are now polled via `lpstat -o`, classified by filename using the exact same restricted/internal keyword lists as the Windows agent's `printClassifier` (so "Q3_Payroll.pdf" gets the same verdict on either platform), and reported to `/events` in the same shape the Windows agent uses (`event_type=print`, `event_subtype=print_job`). Restricted documents are blocked by best-effort `cancel <job_id>` while the job is still queued in CUPS.

**USB storage monitoring** (new `usb_monitor.py`): uses `pyudev` to watch the kernel's own hotplug mechanism (there's no Linux equivalent of Windows' `WM_DEVICECHANGE`; udev monitoring is the standard approach) for USB block devices. Extracts vendor_id/product_id/serial_number the same way Windows' USBSTOR registry path does — from the USB device descriptor — so a physical device's identity matches across platforms and an allowlist built from Windows connection history works unmodified for Linux. Fetches the same `/agents/{id}/usb-allowlist` endpoint the Windows agent polls, and reports connect/disconnect via the same `/agents/{id}/device/authorize` endpoint with identical field names, so both platforms' USB history lands in the same Events/USB Devices UI. Enforcement (when a `usb_device_control` policy is active in `enforce` mode) unmounts any partition on a non-allowlisted device — a weaker guarantee than Windows' USBSTOR registry block (a user could remount manually afterward), but the same class of mitigation CyberSentinel's Linux agent uses; a true kernel-level block would need a udev rule or blacklisting `usb-storage` entirely, a larger and more invasive change.

Both features degrade gracefully (log a clear message, no crash) if their system dependency (`cups-client`/`lpstat` or `libudev`/`pyudev`) isn't present — matching the "additive, never blocks core file monitoring" design already used for quarantine-folder-missing and similar edge cases elsewhere in this agent.

### Verification

`python3 -m py_compile agent.py usb_monitor.py print_monitor.py policy_cache.py` clean. `pyudev` installed and exercised directly against the sandbox's real udev database (not just a syntax check) — `UsbMonitor` correctly walked existing block devices and extracted vendor_id/product_id/serial_number from a live device, confirming the udev property names used are correct. Not live-tested against real CUPS print jobs or physical USB hardware — do that before relying on it in production.

---

## 🐧 Linux Agent: Fixed Startup Path Mismatch, Wrong Log Path, Root-Only User Attribution (August 3, 2026)

### Summary

Started scoping a CyberSentinel-DLP-style Linux agent effort and found SeceoKnight already has one (`agents/endpoint/linux/`, present since the initial release, with two prior bugfix commits) — file system monitoring, classification, quarantine/block, non-USB transfer detection, policy sync, heartbeat, all wired into the same server APIs as the Windows agent. While reviewing it end-to-end before deciding what (if anything) to add, found three real bugs.

### Root cause

1. **`install.sh`/README copied `agent.py` to `/opt/seceoknight/agent.py`, but `seceoknight-agent.service`'s `ExecStart` points at `/opt/seceoknight/agent/agent.py`** (a subdirectory). Following the documented install steps exactly would leave the systemd unit failing to start with "No such file or directory" — the installer prints "✓ Installation complete!" regardless, since it doesn't check `systemctl start` actually succeeded.
2. **`agent.py` logged to `os.path.expanduser('~/seceoknight_agent.log')`**, which resolves to `/root/seceoknight_agent.log` under the systemd service (`User=root`) — but both `README.md` and `install.sh`'s own "Useful Commands" output tell operators to check `/var/log/seceoknight_agent.log`, a path the agent never actually wrote to. Same class of bug as the Windows agent's Logger-default-path fix from earlier testing.
3. **Every event's `user_email`/`username` was derived from `pwd.getpwuid(os.getuid())`** — the agent process's own UID. Since the systemd service always runs as root, every single Linux DLP event would attribute to `root@hostname` regardless of which user actually created/modified/copied the file — defeating the point of per-event user attribution (the same gap the Windows agent's event-attribution work just fixed, reintroduced here for a different reason).

### Fix

- `install.sh` / `README.md`: install `agent.py` (plus `policy_cache.py`/`print_monitor.py`, previously written but never copied by the installer at all) into `/opt/seceoknight/agent/`, matching the service file.
- `agent.py`: added `_resolve_log_path()` — prefers `/var/log/seceoknight_agent.log` (the documented path), falls back to the home-directory path only if `/var/log` isn't writable (e.g. running unprivileged for local testing).
- `agent.py`: added `_get_file_owner_username(file_path)` — resolves the actual file's owning UID via `os.stat()` instead of the agent process's UID, for both file-system events and file-transfer events. Falls back to the process user only if the stat itself fails.

### Verification

`python3 -m py_compile agent.py` clean, `bash -n install.sh` clean. Diffed against a fresh clone of pre-edit HEAD to confirm no unintended changes.

---

## 👤 Event & Alert User Attribution Surfaced in the Dashboard (August 3, 2026)

### Summary

Following CyberSentinel-DLP's newer "event-level user attribution" feature, audited SeceoKnight's own pipeline end-to-end. The underlying data was already there — the Windows agent has attached `user_email` (`GetUsername() + "@" + GetHostname()`) to nearly every event since long before this change, and `events.py` already stores/searches/ABAC-resolves it. The actual gaps were entirely on the display side, plus one real backend bug in the Alerts API.

### Root cause

1. **Events list view** (`Events.tsx`): `user_email` was only rendered inside the per-event detail modal, not the compact list row analysts scan first.
2. **Alerts API** (`alerts.py`): the `alert_service.py` → `action_executor.py` path already writes `user_email` into both the PostgreSQL `Alert` row and the MongoDB `alerts` document that actually powers `GET /alerts/`. But the endpoint's Pydantic `Alert` response model didn't declare a `user_email` field, so Pydantic silently dropped it from every response — a real bug, not just a missing display. The event-fallback path (used before any alert has been materialized) never read `user_email` off the source event at all.
3. **Alerts UI** (`Alerts.tsx`, `AlertDetailsModal.tsx`): no user attribution shown anywhere, list or detail.

### Fix

- `alerts.py`: added `user_email: Optional[str]` to the `Alert` response model; populated it in both the list and single-alert event-fallback branches from `event_doc.get("user_email")`.
- `Events.tsx`: added a "User: {email}" chip to the list-row summary line (Agent / User / timestamp / event ID), suppressed for the `agent@system` placeholder.
- `Alerts.tsx`: added the same "User:" chip to the list row, and included `user_email` in the search-box matching.
- `AlertDetailsModal.tsx`: added a "User:" row to the Alert Summary section, preferring the live event's `user_email` over the alert's stored copy.

No agent.cpp changes were needed — the Windows agent was already sending everything required.

### Verification

`python3 -m py_compile server/app/api/v1/alerts.py` clean. `npx tsc --noEmit` clean for `Events.tsx`, `Alerts.tsx`, `AlertDetailsModal.tsx` (remaining tsc errors in the full run are pre-existing, unrelated to `policies`/`rules` files).

---

## 🪟 Watchdog Console Flash, Take 2: LogonType Alone Wasn't Enough (August 1, 2026)

### Summary

The previous fix (switching the watchdog task's principal to `LogonType S4U`) didn't fully eliminate the periodic console flash — a user confirmed it was still happening after that change.

### Root cause

`LogonType S4U` changes whether the scheduled task needs a stored password or the user to be logged on — it does not guarantee the launched process is barred from the interactive window station when the user *is* actively logged in. Combined with `-WindowStyle Hidden` being a hint the console host applies only after the window briefly exists (not a guarantee enforced before anything is drawn), a flash could still slip through.

### Fix (`install-agent.ps1`)

Replaced the direct `powershell.exe -WindowStyle Hidden` invocation with the standard, long-established zero-flash technique: a tiny VBScript wrapper (`watchdog_launcher.vbs`, written to the install directory) that calls `WScript.Shell.Run(command, 0, True)`. The `0` there is a real `SW_HIDE` flag applied at process-creation time, not a post-hoc hint, and `wscript.exe` itself is a GUI-subsystem host with no console of its own to flash in the first place. The scheduled task's action now runs `wscript.exe watchdog_launcher.vbs`, which in turn launches the actual `watchdog.ps1` fully hidden. `LogonType S4U` is kept as defense in depth, not as the sole fix this time.

### Verification

Brace/paren balance of `install-agent.ps1` verified identical (0/0) against a fresh clone of the pre-edit file. No PowerShell/VBScript interpreter in this sandbox to execute either script directly — reviewed manually, paying particular attention to the doubled-quote escaping needed to embed the file path inside the VBScript string literal. Not live-tested on a real endpoint yet. A retrofit snippet was given for the one endpoint already running the S4U-only version, writing the new `.vbs` wrapper and updating just the task's Action (not its trigger, settings, or principal).

---

## 🪟 Watchdog Task Flashed a Console Window Every 5 Minutes (July 31, 2026)

### Summary

After deploying the hang-detection watchdog (previous entry below), a user reported a command-window flash on the endpoint at regular intervals.

### Root cause

The watchdog task's principal was `LogonType Interactive` — same as the main agent task. That runs `powershell.exe` inside the visible desktop session every 5 minutes to perform its check, and `-WindowStyle Hidden` is a best-effort hint, not a guarantee: PowerShell can still briefly create a visible console window before the hidden style applies. The main agent task genuinely needs `Interactive` (clipboard/keyboard hooks require running in the desktop session), but the watchdog script only calls `Get-Process`/`Stop-Process`/`Start-ScheduledTask` — none of which need desktop access at all.

### Fix (`install-agent.ps1`)

Changed the watchdog task's principal to `LogonType S4U`. S4U runs the task outside the interactive session entirely, so there's no window to flash in the first place — a root-cause fix rather than a hidden-window workaround. S4U doesn't require storing a password (unlike `LogonType Password`), so no credential prompt or config change is needed. The main agent task is untouched and stays `Interactive`.

### Verification

Brace/paren balance of `install-agent.ps1` verified identical (0/0) against a fresh clone of the pre-edit file. No PowerShell interpreter in this sandbox to execute it directly. Not live-tested on a real endpoint yet — a retrofit `Set-ScheduledTask` snippet was given for the one endpoint already running the old `Interactive` version, changing only the principal without touching the script or trigger.

---

## 🐕‍🦺 Watchdog Trigger Powerless Against a Hung (Not Exited) Agent Process (July 31, 2026)

### Summary

A real production endpoint (`CYBER-SEC`) sat "offline" for 2+ hours after a server redeploy, despite the scheduled-task watchdog trigger added earlier this session (see "Scheduled Task Watchdog" entry below) supposedly making the agent self-heal.

### Diagnosis

`Get-Process` showed the agent's process (PID 13508) still alive and `Responding: True`, but `C:\ProgramData\SeceoKnight\logs\seceoknight_agent.log` had stopped being written to entirely — the process had deadlocked (likely a blocking network/HTTP call on a worker thread; the message-pump thread was still alive, which is why `Responding` showed true). `Get-ScheduledTaskInfo` showed the 10-minute watchdog trigger *was* firing on schedule the whole time, but `LastTaskResult` was `2147946720` (`0x800710E0`, "the operator or administrator has refused the request") on every single attempt.

Root cause: the main task's `-MultipleInstances IgnoreNew` setting treats "process still alive" as "healthy, don't touch it" — it has no way to distinguish a hung process from a working one. So the watchdog trigger fired every 10 minutes exactly as designed, and Task Scheduler correctly-by-its-own-logic refused to start a replacement each time, because as far as it's concerned the task is already running. `RestartCount`/`RestartInterval` don't help either — those only fire on a non-zero exit code, and a hung process never exits.

Switching `MultipleInstances` to `StopExisting` was considered and rejected: that would force-kill and restart the agent every 10 minutes unconditionally, including when it's perfectly healthy — worse than the bug it'd fix (routine disruption to clipboard/USB/screen monitoring every 10 minutes, forever).

### Fix (`install-agent.ps1`)

Added a genuinely separate mechanism: a second scheduled task, "SeceoKnight DLP Watchdog", running its own PowerShell script (`watchdog.ps1`, written to the install directory) on a 5-minute cadence. It checks a real liveness signal — has the agent's log file been written to in the last 3 minutes (the agent logs at least once per 30-second heartbeat when healthy) — before ever touching the process. Only when the log has gone stale (and the task itself isn't within a 2-minute post-(re)start grace period) does it force-kill the process by name and immediately call `Start-ScheduledTask` to bring it back — a killed process is a real exit, so this doesn't fight the existing `MultipleInstances`/`RestartCount` settings, it just supplies the "has this actually hung" signal Task Scheduler itself can't provide. A healthy agent is never touched by this task.

### Verification

Brace/paren balance of the full `install-agent.ps1` verified identical (0/0, fully balanced in both) against a fresh clone of the pre-edit file. No PowerShell interpreter available in this sandbox to execute it directly — reviewed manually line by line, and one multi-line statement relying on implicit `-and` continuation was rewritten onto a single line to remove any doubt, since a silent parse failure here would make the watchdog a no-op on every single run without any visible error (the whole script is wrapped in `$ErrorActionPreference = "Stop"` plus a catch-all `try/catch`). Not live-tested on a real endpoint yet.

### Immediate remediation given for the affected endpoint

`Stop-Process` on the hung PID + `Start-ScheduledTask` to bring `CYBER-SEC` back online right away, independent of this code fix landing. A retrofit snippet was also provided to register the new watchdog task on already-installed endpoints without a full reinstall.

---

## 🔌 USB Devices: Disallow List, Alias, Live Connected Status, Insertion History (July 31, 2026)

### Summary

Ported the remaining CyberSentinel-DLP USB Device Control enhancements: an explicit "Disallow" decision distinct from just never approving a device, an inline-editable friendly alias, a live connected/offline indicator, and a click-through insertion history per serial.

### What changed

- **Schema** — migration `034_usb_device_decision_alias.py` adds `decision` (`'allow'` or `'deny'`, default `'allow'`, CHECK-constrained) and `alias` columns to `sanctioned_usb_devices`. Idempotent (`ADD COLUMN IF NOT EXISTS`), applied automatically by `entrypoint.sh`'s `alembic upgrade head` on next deploy; the SQLAlchemy model was updated in step so a fresh install's `create_all()` also gets the columns.
- **Disallow (deny)** — `POST /usb-devices/` and `PATCH /usb-devices/{id}` both accept `decision`. A denied serial is excluded from `GET /agents/{id}/usb-allowlist`'s allow set (same effective block outcome in enforce mode as an unlisted device) but — unlike an unlisted device — it's also excluded from the "Seen" enrolment queue (already true, since that query excludes any decided serial regardless of decision) and carries an audited paper trail. **No agent.cpp change was needed for the block behavior itself** — the agent already treats "not in the allow set" as unsanctioned; deny just means a serial never enters that set.
- **Alias** — new `alias` field, editable inline on the dashboard, independent of the `label` set at approval time.
- **Live connected/offline indicator** — new `_annotate_connection_state()` in `usb_devices.py` computes it from the most recent `usb_device_authorization` event per serial. This exposed a real gap: `HandleUsbEvent()` (the classic monitored-policy pipeline) silently no-ops when no classic USB policy is configured, so **disconnect events were never reported at all** for allowlist-only deployments — a device would show "connected" forever. Fixed in `agent.cpp` by having the `DBT_DEVICEREMOVECOMPLETE` handler call `ReportUsbDeviceAuthorization(..., event="disconnect")` directly, independent of classic policies (mirroring how connects were already reported independently). `ReportUsbDeviceAuthorization()` gained an `event` parameter (`"connect"`/`"disconnect"`, defaults preserve the existing connect call sites) and `log_device_authorization()` stores it as `usb_event` on the event doc.
- **Insertion history** — new `GET /usb-devices/activity?serial_number=...` returns every connect/disconnect for a serial, most-recent first, with the resolved agent/host. Dashboard: a "History" button on both Sanctioned/Disallowed and Seen rows opens a modal built on this endpoint.
- **Dashboard** (`UsbDevices.tsx`, `usb-devices-api.ts`): Sanctioned devices split into two sections (Sanctioned / Disallowed) by `decision`; connected/offline dot per row; inline-editable alias cell; Allow↔Disallow toggle on existing rows; Seen rows gained a "Disallow" button next to "Approve".

### Known limitation (disclosed)

Agents running a build older than this fix never sent a disconnect signal at all (only connects). A serial last seen on an old build will show as "connected" until it's reconnected/disconnected once on a current agent build — not a bug in the computation, just a consequence of needing the new binary to observe the event.

### Verification

`python3 -m py_compile` passes on all changed server files. `npx tsc --noEmit` shows the same 25 pre-existing, unrelated errors (none in the changed files). `npm run build` succeeds (`dist/` removed after). `agent.cpp` brace/paren balance verified identical to a fresh clone of the pre-edit file. Not live-tested — no server/Windows-agent/Postgres access in this sandbox; the migration itself was not executed against a real database.

---

## 🖥️ Agents Page: Real OS Build, Logged-In User, Agent Version (July 31, 2026)

### Summary

Ported CyberSentinel-DLP's agent identity precision: the Agents page already had (unused) `hostname`/`os_version` columns in its TypeScript types, but the server never populated them and the agent sent a hardcoded `"os_version": "Windows 10"` and `"version": "1.0.0"` on every registration, regardless of the actual OS or the auto-updater having since shipped a newer binary. There was also no logged-in-username reporting at all.

### Root cause

`RegisterAgent()` in `agent.cpp` hardcoded `os_version` and `version` as string literals. Separately, it *did* send `hostname` — but `agents.py`'s `AgentCreate`/`AgentBase` pydantic models never declared that field, so FastAPI silently dropped it on every registration; the dashboard's `agent.hostname` reference had nothing to ever display.

### Fix

- **`agent.cpp`**: new `GetOSVersion()` reads `ProductName`/`DisplayVersion` (falling back to `ReleaseId` on pre-2004 builds)/`CurrentBuildNumber`/`UBR` from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, correcting `ProductName` to "Windows 11" when `CurrentBuildNumber >= 22000` (some images still report "Windows 10" in the registry despite running 11). New `AGENT_VERSION` constant (`"2.5.0"`) replaces the hardcoded `"1.0.0"`. `RegisterAgent()` now sends real `os_version`, `username` (via the already-existing but previously-unused `GetUsername()`), and `AGENT_VERSION`. `SendHeartbeat()` now refreshes `username`/`os_version`/`version` on every heartbeat too, so a shared workstation or RDP handoff reflects the currently logged-in user rather than whoever was logged in at agent start.
- **`agents.py`**: `AgentBase`/`AgentCreate` gained `hostname`/`os_version`/`username` fields (fixing the silent-drop bug for `hostname`); `register_agent()` persists them on both new and re-registration paths (only overwriting on re-registration when the agent actually sent a value, so an older agent build re-registering can't blank out data a newer build previously reported); `HeartbeatRequest` gained `username`/`os_version`/`version` and the heartbeat handler refreshes them.
- **Dashboard**: `Agent` type gained `username`; `Agents.tsx` gained "User" and "Version" columns.

### Verification

`python3 -m py_compile` passes. `npx tsc --noEmit` shows the same 25 pre-existing, unrelated errors. `npm run build` succeeds (`dist/` removed after). `agent.cpp` brace/paren balance verified identical to a fresh clone of the pre-edit file. Not live-tested — no server/Windows-agent access in this sandbox.

---

## 🏷️ USB Devices Page: Empty VID:PID + Raw Agent ID Instead of a Name (July 31, 2026)

### Summary

Two display bugs on the USB Devices page: the VID:PID column always showed "—" for both Seen and Sanctioned devices, and the "Agent" column in the Seen table showed a raw agent_id (a UUID-looking string) instead of the real agent name.

### Root cause — VID:PID always empty

Two stacked problems. First, `ReportUsbDeviceAuthorization()` in `agent.cpp` — the function that reports every USB connect/block decision to the server for the Seen/Sanctioned lists — never sent `vendor_id`/`product_id` at all; the server-side model already had fields for them, but the agent simply never populated them. Second, even fixing that naively wouldn't have helped: a USBSTOR device *interface* path (what `WM_DEVICECHANGE` hands the agent, e.g. `\\?\USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00#serial#{GUID}`) never contains a numeric `VID_xxxx&PID_yyyy` — only `Ven_`/`Prod_` text strings. The real numeric vendor/product ID only exists on the *parent* USB device node one level up in the device tree (e.g. `USB\VID_0781&PID_5567&REV_0100\...`).

### Root cause — raw agent ID instead of a name

`usb_devices.py`'s `seen_devices()` endpoint returned the raw `agent_id` from the matching event with no lookup against the `agents` collection — the same class of bug already fixed once this session on the Events page's cloud-upload display (`events.py`'s `_attach_agent_info`), just never applied to this newer USB allowlist feature.

### Fix

- `agent.cpp`: new `GetUsbStorageVidPid()` converts the device interface path to a device instance ID, calls `CM_Locate_DevNode` → `CM_Get_Parent` → `CM_Get_Device_ID` (all already available via the already-included/linked `cfgmgr32.h`/`cfgmgr32.lib`, no new build dependency) to read the parent USB node's hardware ID, then parses the real `VID_`/`PID_` out of *that*. `ReportUsbDeviceAuthorization()` now accepts and sends these values.
- `usb_devices.py`'s `seen_devices()`: batch-resolves `agent_id` → `name`/`agent_code` against the `agents` collection, same pattern as `events.py`'s `_attach_agent_info`.
- `usb-devices-api.ts` / `UsbDevices.tsx`: `SeenDevice` gained `agent_name`/`agent_code`; the Agent column now renders the resolved name (with `#code`), falling back to the raw ID only if the agent record can't be found at all.

### Verification

`python3 -m py_compile` passes. `npx tsc --noEmit` shows the same 25 pre-existing, unrelated errors (none in the changed files). `npm run build` succeeds (`dist/` removed after). Brace/paren balance of every new `agent.cpp` block verified against a fresh clone of the pre-edit file (identical pre-existing imbalance in both). Not live-tested — no server/Windows-agent access in this sandbox.

### Result

The USB Devices page now shows real vendor/product IDs and a real agent name instead of "—" and a raw UUID.

---

## 🔓 Approved USB Devices Ignored by an Active Block Policy (July 31, 2026)

### Summary

User set a classic "Block" USB policy AND approved a specific pendrive in the new USB Devices allowlist, expecting the approved drive to be let through. It kept getting blocked on every reinsertion.

### Root cause

Two independent mechanisms, only one of which could ever win. The classic "block on usb_connect" policy sets `shouldBlock = true` unconditionally whenever it matches — the allowlist could only *add* a block decision (`allowlistShouldBlock`) when no classic policy had already decided to block, never remove one. So with a blanket block policy active, it alone was sufficient to block everything, and approving a device in the allowlist had no effect at all.

There's a second layer to this: the classic block's actual mechanism (`BlockUSBStorageViaRegistry` + `DisableAllUSBStorageDevices`) disables the USB mass-storage driver class system-wide — it has no concept of "except this serial," it's a blanket kill switch (the code's own comment already called this out: "act globally, not per-serial"). So even exempting one device from *triggering* a new block wouldn't help if an earlier unapproved device had already tripped it — the driver would still be globally disabled.

### Fix (`agent.cpp`, `HandleUsbDeviceArrival`)

An approved device (`allowlistEnforced && sanctioned`) is now treated as an explicit administrative override:

- It no longer sets `shouldBlock = true` even when a classic block policy matches (the match is still recorded for logging/event data).
- It proactively calls `EnableAllUSBStorageDevices()` + `BlockUSBStorageViaRegistry(false)` to restore access, covering the case where an earlier unapproved device already tripped the global kill switch.
- Deliberately does **not** touch `usbBlockingActive` — that flag reflects whether the classic block policy is still configured active and must keep governing the *next* unapproved device's connect event. This is a one-time "let this specific device through," not a change to the standing policy.

Applies in either allowlist sub-mode (enforce or audit) — an approval is an explicit "this one's fine," not something that should depend on the allowlist's own audit/enforce distinction (that only governs *unsanctioned* devices).

### Known limitation (accepted)

Because the block primitive is class-wide rather than per-device, briefly restoring access for an approved device could transiently also let a *different*, unapproved device that happens to be plugged in at the same moment slip through — until the next unapproved connect event re-trips the block. True per-device isolation while blocking would need a different Windows mechanism (e.g. Device Installation Restriction group policy with per-hardware-ID allow/deny lists), which is a substantially larger change. Discussed with the user, who accepted this tradeoff.

### Verification

Brace/paren balance verified against a fresh clone of the pre-edit file (identical pre-existing imbalance in both, confirming all new braces/parens are self-balanced). Not live-tested — no server/Windows-agent access in this sandbox.

### Result

A device approved in the USB Devices allowlist is now let through even when a separate blanket "block all USB" policy is active, instead of the approval being silently ignored.

---

## 📊 Dashboard "Active Agents" Tile Disagreed With the Agents Page (July 31, 2026)

### Summary

After reinstalling and confirming the agent showed online on the Agents page, the Dashboard overview's "Active Agents" tile showed 0 for the same machine.

### Root cause

`server/app/api/v1/dashboard.py`'s `get_dashboard_overview` defined its own local `AGENT_TIMEOUT_SECONDS = 60` for the active-agents count — a completely different, much tighter threshold than the 300-second (5-minute) window `agents.py` uses everywhere else (the default agent list, `lifecycle_status`, etc). With the default 30-second heartbeat interval, a 60-second cutoff leaves almost no slack — any normal network jitter or an unlucky poll timing and the count drops to 0, even though the same agent is clearly fine by every other measure on the same dashboard.

### Fix

Removed the locally-hardcoded constant; `dashboard.py` now imports and reuses `AGENT_TIMEOUT_SECONDS` from `agents.py` so there's a single definition of "active" instead of two silently drifting ones.

### Verification

`python3 -m py_compile` passes. No circular import (checked `agents.py`'s own imports first). Not yet re-verified live against the running server.

### Result

The "Active Agents" KPI tile and the Agents page now agree with each other.

---

## 🩹 Watchdog Trigger Broke Task Registration Entirely (July 31, 2026)

### Summary

Live-tested the watchdog trigger below on a real endpoint (reinstall via `install-agent.ps1`). `Register-ScheduledTask` failed: `"The task XML contains a value which is incorrectly formatted or out of range. (18,42):Duration:P99999999DT23H59M59S"`. Worse, the script's `try/catch` didn't catch it — `Register-ScheduledTask` raises a non-terminating error by default, so execution fell through and printed `"Scheduled task created successfully!"` regardless. The endpoint was left with **no scheduled task at all** — a regression, worse than the bug the watchdog trigger was meant to fix.

### Root cause

`-RepetitionDuration ([TimeSpan]::MaxValue)` (~29,247 years) exceeds what Task Scheduler's XML schema accepts for the `Duration` element. `Register-ScheduledTask` doesn't stop the script on this failure unless explicitly told to.

### Fix

- Changed `-RepetitionDuration` to `(New-TimeSpan -Days 3650)` (10 years) — comfortably "indefinite" for any real deployment, well within the schema's accepted range.
- Added `-ErrorAction Stop` to the `Register-ScheduledTask` call so a real failure is actually caught by the surrounding `try/catch` and reported honestly instead of printing a false "success."

### Verification

No PowerShell interpreter in this sandbox; reviewed manually, brace/paren counts balance. Not yet re-verified live — next reinstall on the test endpoint will confirm.

### Result

Reinstalling now registers a working scheduled task with the watchdog trigger intact, and any future registration failure will be reported truthfully instead of silently leaving no task behind.

---

## 🐕 Scheduled Task Watchdog — Agent Didn't Self-Heal From a Clean Exit (July 31, 2026)

### Summary

Live-tested the duplicate-agent/reactivation fixes below on a real endpoint. Confirmed the reactivation logic works correctly — but surfaced a separate, real gap: after the agent process exited cleanly (a manual Ctrl+C during testing), the scheduled task sat in "Ready" state indefinitely and never came back on its own. Had to manually run `Start-ScheduledTask`. Not viable across a fleet.

### Root cause

`install-agent.ps1`'s scheduled task only had `AtLogOn` and `AtStartup` triggers, plus `RestartCount 999` / `RestartInterval 1 minute`. That restart setting only applies when Task Scheduler considers the task *failed* (non-zero exit code) — a graceful/clean exit (Ctrl+C, someone running `Stop-ScheduledTask`, a shutdown handshake that returns 0) is not a "failure," so nothing brings the task back except the next logon or reboot.

### Fix

Added a third trigger: a repeating "watchdog" that re-fires every 10 minutes, indefinitely (`-RepetitionInterval`/`-RepetitionDuration`). `MultipleInstances IgnoreNew` (already set) makes each tick a safe no-op while the agent is already running — it only actually does anything when the task has stopped for any reason. This closes the gap regardless of *why* the agent stopped, rather than trying to special-case exit codes.

### Verification

No PowerShell interpreter in this sandbox; reviewed manually, brace/paren counts balance. Confirmed on the live endpoint used for testing: `Start-ScheduledTask` brought the agent back and the dashboard showed it active again.

### Result

An agent that stops for any reason short of an intentional uninstall (which now properly unregisters, see below) comes back within 10 minutes on its own — no one has to notice and manually restart it on any given endpoint.

---

## 🧹 Duplicate Agent Records + False "Offline While Idle" (July 30, 2026)

### Summary

User reported two enterprise-readiness issues: (1) installing the agent + browser extension on an endpoint sometimes left multiple entries for the same machine in the Agents tab that had to be removed by hand, and (2) an agent would show as offline whenever the endpoint had simply been idle for a while, even though nothing was actually wrong with it.

### Root cause — duplicate agents

Not a race condition and not the browser extension (it already correctly reuses the main agent's identity — confirmed in code). The actual gap was the install/uninstall lifecycle:

- `install-agent.ps1`'s cleanup step, and the documented manual uninstall, both used `Stop-Process -Force` — a hard kill that never lets the agent run its own graceful-shutdown/unregister code.
- The documented uninstall then deletes `C:\ProgramData\SeceoKnight`, wiping `agent_key.json` — the file that lets a reinstalled agent reuse its previous `agent_id`.
- A reinstall with no persisted identity mints a new `agent_id`. If it re-registers under the *same* name (hostname) it's fine — dedup-by-name-and-os already updates the existing row in place. But if the previous record had ever been decommissioned/soft-deleted (via a prior clean self-unregister, or an admin's "Mark as Decommissioned" click), re-registering never cleared those flags, leaving a live, heartbeating agent stuck looking retired/hidden.

### Root cause — false offline while idle

An earlier fix (see below) already made the agent detect workstation lock/unlock (`WM_WTSSESSION_CHANGE`) and force an immediate reconnect on unlock. There was no equivalent for the OS's own idle-sleep power plan: when a machine sleeps after its configured idle timeout, the whole process is suspended, heartbeats stop, and after `AGENT_TIMEOUT_SECONDS` (5 min) the dashboard correctly shows it offline — because nothing is arriving. On wake there was nothing forcing an immediate reconnect, so it could sit "offline" for a while after the user was already back, waiting on the passive heartbeat/retry cycle.

### Fixes

- `install-agent.ps1` — before killing the previous process, reads the persisted `agent_key.json` (and the previous `agent_config.json`'s `server_url`) and calls the existing `DELETE /agents/{id}/unregister` endpoint to retire the old identity server-side. The printed manual "Uninstall" instructions now include the same call before removing `ProgramData`.
- `server/app/api/v1/agents.py` (`register_agent`) — when a re-registering agent's existing record was previously decommissioned or soft-deleted, those flags are now cleared automatically. A machine that's actively heartbeating again no longer stays stuck with a stale "Decommissioned" badge or hidden from the default view.
- `agent.cpp` — added `WM_POWERBROADCAST` handling (`RegisterSuspendResumeNotification`, mirroring the existing `WTSRegisterSessionNotification` pattern used for lock/unlock) so the agent reinitializes its HTTP client and sends a heartbeat immediately on resume from sleep, instead of waiting on the passive retry cycle. `RegisterSuspendResumeNotification`/`UnregisterSuspendResumeNotification` are Windows 8+ APIs gated out of scope by this file's `_WIN32_WINNT 0x0601` (Windows 7) target, so they're forward-declared locally rather than bumping the file-wide WINNT target (which would silently change behavior of unrelated APIs).

Deliberately not done: preventing the machine from sleeping at all (`SetThreadExecutionState`). That would override the endpoint's power plan fleet-wide, which most IT teams don't want just to keep a DLP agent's heartbeat alive — the fix here is to make wake-up recovery instant instead.

### Verification

`python3 -m py_compile` passes on the changed server file. Brace/paren balance of every new `agent.cpp` block verified against a fresh clone of the pre-edit file (identical pre-existing imbalance in both, confirming all new braces/parens are self-balanced). No PowerShell interpreter available in this sandbox to execute `install-agent.ps1` directly; reviewed manually and brace/paren counts balance. Not live-tested — no server/DB/Windows-agent access in this sandbox.

### Result

Reinstalling an agent (including via a full documented uninstall) no longer leaves an orphaned duplicate row behind, and a machine coming back from a decommissioned/deleted state is automatically reactivated instead of looking stuck. A workstation waking from idle sleep reconnects within seconds instead of sitting "offline" until the next scheduled heartbeat happens to land.

---

## 🔌 USB Device Control — Sanctioned-Device Allowlist (Ported from CyberSentinel-DLP) (July 30, 2026)

### Summary

A comparison against the CyberSentinel-DLP reference project found three genuine gaps: Exact Data Match/fingerprinting, an ML-classifier admin page, and a sanctioned USB/printer allowlist. This ports the first (and smallest) of the three: a strict allowlist-by-serial-number for USB storage devices, plus the matching (currently management-only) allowlist for printers.

### Design

USB device control is **strict allowlist / default-deny**: when enforcement is on, a removable storage device is authorized only if its serial number has an enabled row in the new allowlist; every other device is blocked the moment it connects — independent of (and in addition to) the existing "block on usb_connect" monitored-event policies.

- `server/app/models/sanctioned_usb_device.py`, `sanctioned_printer.py` — new tables (`serial_number`/`printer_name` as the unique match key, `is_enabled`, approval metadata).
- `server/alembic/versions/033_sanctioned_devices.py` — idempotent `CREATE TABLE IF NOT EXISTS`, chained after `032_cloud_upload_hosts` (the prior head).
- `server/app/api/v1/usb_devices.py`, `printers.py` — admin-write/analyst-read CRUD (`list` / `approve` / `update` / `revoke` / `seen`), plus a `POST .../enforcement` toggle that finds-or-creates the backing `usb_device_control`/`printer_control` Policy row directly (SeceoKnight's generic policy-creator UI doesn't have a form for these types yet).
- `server/app/api/v1/agents.py` — new agent-facing `GET /agents/{id}/usb-allowlist` (the agent polls this on the same cadence as policy sync and enforces it locally — no per-connect server round trip, so it still works through a brief network blip) and `POST /agents/{id}/device/authorize` (visibility-only: logs the agent's local block/allow decision as an event).
- `server/app/core/domains.py` — mapped `usb_device_control` (access_control) and `printer_control` (threat) for RBAC.

### Agent changes (`agent.cpp`)

- `HttpClient::Get()` — the client only had Post/Put/Delete; needed for the new polling endpoint.
- `ExtractUsbSerialFromDeviceId()` / `NormalizeUsbSerial()` — parses the USB serial out of the `dbcc_name` device-interface path Windows hands the agent (the same identifier Windows' own Device Installation Restrictions GPO uses for allow/deny lists).
- `SyncUsbAllowlist()` — pulls and caches the allowlist on the same cadence as `SyncPolicies()`; also restores USB access if the allowlist was the *only* thing blocking and enforcement gets turned off/switched to audit (mirrors `ApplyPolicyBundle()`'s existing restore-on-disable logic for the separate monitored-event path).
- `HandleUsbDeviceArrival()` — now proceeds if *either* the classic monitored-event policies or the allowlist is active (previously required the former), checks the connecting device's serial against the cached allowlist, and can independently set `shouldBlock` even with no matching monitored-event policy.
- `ReportUsbDeviceAuthorization()` — fires the connect-time decision to the new `/device/authorize` endpoint off a detached thread (never blocks the thread that pumps Windows device-arrival messages).
- USB connect events now include `serial_number` so the dashboard's "seen but unsanctioned" enrollment list has real data to show.

Printer control ships as **management-only** for now: SeceoKnight's agent doesn't monitor print jobs, so the allowlist and its enforcement toggle exist and are ready, but nothing is blocked by it yet (the Printers page says so explicitly).

### Dashboard changes

- `lib/usb-devices-api.ts`, `lib/printers-api.ts` — API clients.
- `pages/UsbDevices.tsx`, `pages/Printers.tsx` — new pages (enforcement toggle, approve-by-serial/name form, sanctioned list, seen-but-unsanctioned enrollment list for USB).
- `App.tsx` / `components/Sidebar.tsx` — new `/usb-devices` and `/printers` routes and nav entries.

### Verification

`python3 -m py_compile` passes on all new/changed server files. `npx tsc --noEmit` shows only the same 25 pre-existing, unrelated errors as before (none in any new/changed dashboard file). `npm run build` succeeds (`dist/` removed after). Brace/paren balance of every new `agent.cpp` block verified in isolation (no C++ compiler available in this sandbox). Not live-tested — no server/DB/Windows-agent access in this sandbox; the migration, new endpoints, and agent enforcement all need real deployment verification. This session's mounted copy of the repo has no `.git`, so changes were made directly in place and not committed/pushed — that needs to happen from a real checkout.

### Result

Admins can build a USB device allowlist and turn on strict enforcement (or audit-only) from a new USB Devices page; the Windows agent blocks any unsanctioned serial the moment it's plugged in, independent of the existing monitored-event USB policies. A parallel Printers page is ready for when print-job monitoring is added.

---

## 🏷️ Cloud Upload Events Showed Raw Agent ID Instead of the Real Agent Name (July 21, 2026)

### Summary

User reported that a cloud-upload (browser extension) "Blocked" event showed the agent as `Agent 0D989F1E` instead of the real name `CYBER-SEC` — while clipboard events from the exact same machine correctly showed `CYBER-SEC`.

### Root cause

The browser extension's native host (`skdlp_host.py`) reads its agent identity **once**, from a static snapshot file (`%ProgramData%\SeceoKnight\dlp-host.json`) written by `install.ps1` whenever it was last run, and tags every cloud-upload event it sends with that frozen `agent_id`. The main endpoint agent's own identity, by contrast, used to regenerate on every restart (see the "Agent Showed Disconnected After Reboot" entry above) — so by the time of this test, the main agent had re-registered under a newer id several times over, while the browser extension's snapshot still pointed at an old one (`0D989F1E...`) that no agent record matches anymore. The dashboard resolves an event's agent name by looking up its `agent_id` against the current agents list (`dashboard/src/lib/utils.ts`'s `formatAgentLabel()`); when that lookup fails, it falls back to showing the truncated raw id — which is exactly the `Agent 0D989F1E` text reported. Clipboard events come straight from the main agent process itself, which always tags them with whatever its *own current* id is, so that lookup always succeeds.

### Fixed

`agents/browser-extension/native-host/skdlp_host.py`: added `_load_live_agent_identity()`, which live-reads `C:\ProgramData\SeceoKnight\agent_key.json` — the file the main agent actually rewrites every time it (re)registers, i.e. the true current identity, as opposed to `dlp-host.json`'s one-time snapshot. `load_config()` now prefers this live value over the static snapshot whenever the file exists, so cloud-upload events automatically track the main agent's current identity without ever needing a manual `install.ps1` re-run again. Falls back to the static `dlp-host.json` value when the file doesn't exist — the standalone-identity case (a PC with no main endpoint agent installed at all, per the README's Step 5.1) is unaffected.

### Verification

`python3 -m py_compile` passes. Not live-tested in this sandbox (no browser/native-messaging environment here) — needs a real redeploy (rebuild the frozen `.exe` via PyInstaller if using Option A, or just redeploy the `.py` if using the plain-Python launcher) and a fresh cloud-upload test to confirm the agent name resolves correctly.

### Result

Cloud-upload events now show the real agent name (e.g. `CYBER-SEC`) instead of a raw id, and stay correct going forward even if the main agent's identity ever changes again — no more manual re-sync needed. Immediate fix for an already-affected machine (works without this code change too, since `install.ps1`'s own auto-discovery re-reads the current identity at run time): re-run the browser extension's `install.ps1` and fully restart the browser.

---

## 💤 Agent Stayed "Disconnected" After Unlock+Some Time — Heartbeat Failures Were Never Actually Detected (July 21, 2026)

### Summary

User reported the agent reconnecting fine right after unlocking a Windows machine, but going back to "Disconnected" on the dashboard some time later, despite the machine being on with a working internet connection.

### Root cause

`SendHeartbeat()` caught every possible failure internally — network unreachable, non-200 HTTP status, any thrown exception — and always returned normally (`void`) without ever rethrowing. `HeartbeatLoop()`'s own `try { SendHeartbeat(); consecutiveFailures = 0; } catch (...) { consecutiveFailures++; }` could therefore never observe a real failure: the `catch` block was unreachable dead code, and `consecutiveFailures` was unconditionally reset to 0 immediately after every call regardless of whether the heartbeat actually succeeded. The 3-consecutive-failures HTTP-client-reinit logic right below it — whose own comment explicitly says it exists to handle "stale WinHTTP sessions after network drops, sleep/wake, or IP address changes" — could never trigger. So if the connection went stale for any reason (exactly the sleep/lock-unlock scenario the comment describes), the agent would silently "send" a failing heartbeat every 30 seconds forever, with no working recovery path, until the process was fully restarted.

### Fixed

`agents/endpoint/windows/agent.cpp`: `SendHeartbeat()` now returns `bool` — `true` only on an actual HTTP 200, `false` for every other outcome (unreachable, non-200, exception) — instead of silently logging and returning. `HeartbeatLoop()` now branches on that return value instead of relying on an exception that was never thrown, so 3 real consecutive failures now correctly reinitialize the HTTP client as originally intended.

### Verification

Brace/paren delta checked against the pre-edit file (2/2 braces, 7/7 parens added, matched pairs). No C++ compiler available in this sandbox — relying on the Windows CI build's auto-commit as the compile check, same as the other agent.cpp changes in this session.

### Result

An agent whose connection goes stale (sleep/wake, lock/unlock, brief network blips, IP changes) now actually recovers on its own within about 3 heartbeat intervals (roughly 90 seconds at the default 30s interval), instead of staying silently "Disconnected" until someone notices and restarts it.

---

## 🪪 Agent Showed "Disconnected" After Reboot — Identity Regenerated on Every Restart (July 21, 2026)

### Summary

After rebooting both the server and a Windows endpoint machine, the endpoint's agent kept showing "Disconnected" on the dashboard even though the process was confirmed alive and working (OCR running, heartbeats going out) — the log showed `Heartbeat response: HTTP 404`.

### Root cause

`C:\Program Files\SeceoKnight\agent_config.json` — confirmed by inspecting the actual file on the affected machine — has no `agent_id` key at all. It's written directly by `install-agent.ps1`'s own PowerShell (`$config | ConvertTo-Json ...`), which never included this field. `AgentConfig::LoadFromFile()` falls back to `GenerateUUID()` whenever the key is missing, but that freshly-generated id was never written back to disk (`SaveToFile()` only runs the very first time the config file is created, never again). The result: **every single agent restart — reboot, crash recovery via the scheduled task's `RestartCount`, or a manual relaunch — silently generated a brand new random identity** and re-registered as if it were a different machine. The server's `register_agent()` matches existing agents by name+OS and adopts whatever new id the client sends, orphaning the previous one. This is invisible as long as the fresh registration round-trips successfully before the next heartbeat — but any hiccup in that window (confirmed via the agent's own log: three different Agent IDs logged across three restarts on this one machine, `FD5D1175...`, `0D989F1E...`, `616EA778...`) leaves the running process heartbeating with an id the server has never seen, i.e. permanent `404 Agent not found` until the next restart happens to land cleanly.

### Fixed

`agents/endpoint/windows/agent.cpp`: added `AgentConfig::LoadPersistedIdentity()`, which reads the already-existing `C:\ProgramData\SeceoKnight\agent_key.json` (the file `SaveApiKeyFile()` writes to after a successful registration, and that the browser extension's `install.ps1` already reads for the same reason — ProgramData is writable at runtime by the non-elevated scheduled-task user, unlike Program Files). `LoadFromFile()` now checks this file for a previously-registered id before generating a new one, and only mints + immediately persists a brand new UUID on a machine's genuinely first-ever run. Also guarded the `api_key` extraction right after it so it doesn't clobber an `apiKey` just loaded from the ProgramData file with an empty value from `agent_config.json` (which never actually contains this key in practice).

### Verification

Brace/paren delta checked against the pre-edit version of the file (both added in exactly matching pairs — 5/5 braces, 33/33 parens). No C++ compiler available in this sandbox; the GitHub Actions Windows build (`build-windows-agent.yml`) auto-commits the compiled binary on push, which is the available confirmation that this compiled successfully.

### Result

An agent's identity is now stable across restarts — reboots, crashes, and manual relaunches all reuse the same `agent_id`/`api_key` going forward, so the "Disconnected after reboot" failure mode described here can't recur. Immediate remediation for a machine already affected: `Stop-ScheduledTask -TaskName "SeceoKnight DLP Agent"` then `Start-ScheduledTask -TaskName "SeceoKnight DLP Agent"` forces one fresh, clean re-registration; the updated binary prevents needing to do that again after future restarts.

---

## 🌐 Whole Dashboard (Including Login) Broke After a Routine Update — Stale Nginx Upstream IP (July 20, 2026)

### Summary

After a normal `docker compose pull && docker compose up -d` update (which recreated `manager`/`dashboard`/etc. with fresh container images), the entire dashboard broke — the overview page showed "Failed to load dashboard data," and login itself failed with "Invalid email or password" even with correct credentials.

### Root cause

`nginx/nginx.conf` used plain-hostname `proxy_pass` targets (`http://manager:55000`, `http://dashboard:3000`). Nginx resolves a plain-hostname `proxy_pass` target **once** and caches the resolved IP for the entire lifetime of the worker process. Nginx itself isn't recreated by a routine update (its image, `nginx:1.27-alpine`, doesn't change) — but `manager`, `dashboard`, and the other services *are* recreated and get a brand-new internal Docker IP every time. Nginx kept sending every request to the previous container's now-dead IP, so everything failed with `502 Bad Gateway` (confirmed via `docker compose logs nginx`: `connect() failed (111: Connection refused) ... upstream: "http://172.28.0.7:55000/..."`). The dashboard's generic error messages ("Failed to load dashboard data," "Invalid email or password") made this look like an auth or data problem, when the actual requests never reached the backend at all.

### Fixed

Every `proxy_pass` in `nginx.conf` now targets a `set`-declared variable (e.g. `set $upstream_manager manager:55000; proxy_pass http://$upstream_manager;`) instead of a bare hostname — this forces nginx to re-resolve through a `resolver` directive on a TTL instead of caching indefinitely. Added `resolver 127.0.0.11 valid=10s;` (Docker's embedded DNS, which resolves internal service names and transparently forwards anything else to the host's real DNS) at the top of the config, and updated the HTTPS server block's own OCSP-stapling `resolver` line to the same value (a server-context `resolver` overrides the http-context one, so both needed updating, not just one).

### Verification

Brace-balance and line-termination checked via a Python parse of the file (12/12 braces, every non-comment line properly terminated). No nginx binary or Docker available in this sandbox to run `nginx -t` directly — the `docker-compose.prod.yml` nginx healthcheck already runs `nginx -t` every 30s and will flip the container unhealthy immediately if there's a config problem, which is the next real checkpoint.

### Result

Future `docker compose pull && up -d` updates will no longer require a manual `docker compose restart nginx` afterward — nginx now re-discovers a recreated container's new IP automatically within 10 seconds.

### If you're hitting this right now (before pulling this fix)

Immediate relief: `docker compose -f docker-compose.prod.yml restart nginx`. To get the permanent fix onto an existing install, re-download the updated config file and reload nginx:
```bash
cd /opt/seceoknight
curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/nginx/nginx.conf -o nginx/nginx.conf
docker compose -f docker-compose.prod.yml restart nginx
```

---

## 🕐 Audit Trail Timestamp Column Showed Blank/Dot for Every Row (July 20, 2026)

### Summary

User reported the **Timestamp** column on the dashboard's Audit Trail page showed just a bare `.`/`-` for every row, no matter which event it was.

### Root cause

`dashboard/src/pages/AuditTrail.tsx` read `log.timestamp`, but the `/audit-logs/` API (`AuditLogOut` schema in `server/app/api/v1/audit_logs.py`) returns the field as `created_at` — matching the `AuditLog` model's actual database column. `log.timestamp` was therefore always `undefined`, so every row fell through to the column's `'-'` fallback regardless of its real timestamp.

### Fixed

`AuditTrail.tsx` now reads `log.created_at` (falling back to `log.timestamp` for forward-compatibility if the API shape ever changes).

### Verification

Confirmed via the actual API response contract: `AuditLogOut` in `audit_logs.py` explicitly declares `created_at: datetime` with no `timestamp` field. No dashboard build available in this sandbox — needs a redeploy + a real Audit Trail page load to see the fix live (`docker compose -f docker-compose.prod.yml pull && docker compose -f docker-compose.prod.yml up -d` on the server, matching the "Updating to a New Version" section of the README).

### Result

The Audit Trail's Timestamp column now shows the real date/time (IST-formatted) each audit event actually happened.

---

## 🏁 Two Events Instead of One — Piggyback In-Flight Classify Requests (July 20, 2026)

### Summary

After the file-identity coalescing fix below cut duplicate browser-extension alerts from four to two, the user asked for it to go all the way to one event per upload.

### Root cause

`recentDecisions` (the coalescing cache) is only populated **after** the native host's decision actually arrives, inside the `port.onMessage` handler. If two of Gmail's chunked upload requests for the *same* file both reach the `classify` handler before the first one's round trip to the native host completes, the second one finds nothing cached yet — the cache can't help until a decision exists — so it independently sends its own `classify` message to the native host, producing a second server-side event for one upload. The earlier file-identity fix closed the gap for requests that arrive *after* a decision is cached; it couldn't close this one, which is a pure timing race between two requests that both arrive first.

### Fixed

`agents/browser-extension/src/background.js`: added an `inFlightByKey` registry (keyed the same way as `recentDecisions`) that tracks the in-progress "leader" request per file. A request that finds a leader already in flight for its key piggybacks on it — it's added to the leader's waiters list and answered when the leader's real decision arrives, instead of sending its own message to the native host. The leader's `waiters` entry is now a fan-out function that resolves every piggybacked caller at once. The in-flight marker is cleared as soon as a real decision is cached, and on every fail-open path too (send failure, timeout, native-host disconnect), so a dropped leader can never permanently block future requests for that key.

### Verification

`node --check` passes. Not live-tested in this sandbox (no browser access here) — needs a real redeploy + retest. The service worker console should show `piggybacking on in-flight request for file:<name>:<size>` for the second request of a chunked upload instead of a second `classify:` line going out to the native host.

### Result

A single file upload should now produce exactly one browser-extension alert/event, even when the underlying upload protocol issues multiple concurrent requests for the same file before the first classification completes.

---

## 🔁 Real File Capture Fix Resurfaced Duplicate Alerts — Coalesce by File Identity, Not Host (July 20, 2026)

### Summary

After the real-file-capture fix (correct filename + content classification for Gmail's chunked uploads), the user reported a single file upload now firing **four** alerts instead of one.

### Root cause

`background.js`'s cross-frame duplicate-event coalescing cache was keyed by **destination host**. Gmail's chunked/resumable upload protocol splits one file's bytes across multiple network requests, and those requests don't necessarily all go to the same host — some can hit different subdomains. Before the file-capture fix, those extra requests were misclassified as generic `upload.bin` with no extractable content, so the duplication mostly went unnoticed (they were harmless "Public/allowed" noise). Now that every one of them carries the real captured file's name and content, each classifies correctly — including firing its own alert — unless they're recognized as the same upload.

### Fixed

`agents/browser-extension/src/background.js`: the coalescing cache key is now the file's own identity (`fileName:fileSize`) when a real filename is available (not the `upload.bin` fallback), instead of destination host. This is what's actually stable across however many requests/hosts one upload produces. Falls back to host-based keying when there's no real filename to key on, preserving the original behavior for that case. `requestHosts` renamed to `requestKeys` throughout to reflect the more general key.

### Verification

`node --check` passes. Not live-tested in this sandbox (no browser access here) — needs a real redeploy + retest. The service worker console should show `classify: ... | key: file:<name>:<size>` and, on repeat requests for the same file, `reusing cached decision for file:<name>:<size> -> <action>`.

### Result

A single file upload should now produce exactly one alert/event, regardless of how many underlying network requests the upload protocol splits it into or which hosts they target.

---

## 💥 install.ps1 Crashed With "Unexpected token" — Em-Dash Mojibake Breaking the PowerShell Parser (July 20, 2026)

### Summary

Live-reproduced by the user: running the browser extension's `install.ps1` (downloaded via `Invoke-WebRequest -OutFile`, then executed as `.\install.ps1 ...`) failed with cryptic parser errors — `Unexpected token '" +'`, `Missing closing ')'`, `The string is missing the terminator: '`.

### Root cause

The script's comments and one `throw (...)` error-message string used a Unicode em-dash (`—`, U+2014). The file is authored/served as UTF-8 with no BOM. Windows PowerShell 5.1's script-file parser (not `irm | iex`, which decodes into an in-memory string first and doesn't hit this) falls back to the system ANSI codepage when there's no BOM to detect UTF-8 from, so the em-dash's 3 UTF-8 bytes get misread as several separate mojibake characters (`â€”`). Where that corruption landed inside an actual string literal (`throw (... "api_key — " + ...)`), the mangled bytes broke the tokenizer outright — not just a display glitch, an actual crash.

This didn't show up during my own review because I never round-tripped the file through Windows' file-encoding path in this sandbox (no PowerShell interpreter available here) — only `node --check`/`python3 -m py_compile`-equivalent structural checks were possible, which don't catch this class of bug at all.

### Fixed

- `agents/browser-extension/native-host/install.ps1`: every em-dash replaced with a plain ASCII ` - `.
- `install-agent.ps1` (the main one-liner agent installer): same sweep, even though it currently isn't hit in practice — it's normally run via `irm ... | iex`, which sidesteps this exact bug by never re-parsing the script from a saved file. But it contains 43 non-ASCII characters (em-dashes and box-drawing separator characters, `─`) inside real `Write-ColorOutput "..."` string literals, several of which would crash exactly the same way if anyone ever downloads it to disk and runs it directly (a completely reasonable thing for an IT admin to do before running an admin-elevated script) instead of the documented one-liner. Fixed proactively before anyone hits it, given this is the very first script most users run.

### Verification

`python3` scan confirms zero non-ASCII characters remain in either file. Brace/paren counts re-checked (install-agent.ps1: perfectly balanced 98/98 braces, 148/148 parens; install.ps1: unchanged from before, previously verified by manual line-by-line review). No Windows PowerShell interpreter available in this environment to literally re-run the script — the user's own retry after this fix is the real verification.

---

## 🔐 SMTP Relay Had No Inbound TLS — Added STARTTLS Support (July 20, 2026)

### Summary

Resuming the SMTP relay / Google Workspace routing setup paused earlier this session (server public reachability was unclear at the time). The README already said TLS was "strongly recommended" for exposing the relay to Google's outbound gateway over the public internet, but nothing in the code actually supported it — `main.py` constructed the `aiosmtpd` `Controller` with no `tls_context` at all, so the listener was plaintext-only regardless of configuration. Found via code inspection before telling the user to open a port to it.

### Fixed

- `smtp-relay/app/config.py`: new `RELAY_TLS_CERT_FILE` / `RELAY_TLS_KEY_FILE` (PEM cert+key paths) and `RELAY_REQUIRE_STARTTLS` (reject commands before STARTTLS is negotiated) settings. All unset by default — a relay with no cert configured behaves exactly as before (plaintext, e.g. for LAN-only use).
- `smtp-relay/app/main.py`: builds an `ssl.SSLContext` from those files when both are set and passes it as `tls_context` (aiosmtpd forwards `Controller(**kwargs)` straight to the underlying `SMTP()` class, which natively supports `tls_context`/`require_starttls`).
- `docker-compose.prod.yml`: added the new env vars plus a read-only volume mount (`RELAY_TLS_CERT_DIR`, defaults to `./smtp-relay/certs`) so a host-side cert (e.g. Let's Encrypt) can be mounted into the container.
- `smtp-relay/README.md`: new "TLS (inbound STARTTLS)" section (cert acquisition via `certbot`, config, renewal) and a note in the Google Workspace routing section for on-prem/behind-a-firewall deployments (port-forward/VIP + firewall policy needed; Google's Hosts config accepts any port, so ISP port-25 blocking can be worked around with an alternate port).

### Verification

**Actually tested end-to-end in this environment** (unlike most of tonight's other changes — this one doesn't need Windows/a browser): installed the relay's real dependencies, generated a self-signed cert with `openssl`, started the relay with `RELAY_TLS_CERT_FILE`/`RELAY_TLS_KEY_FILE`/`RELAY_REQUIRE_STARTTLS=true`, and connected with `smtplib`:
- `EHLO` correctly advertised `STARTTLS`.
- `STARTTLS` handshake succeeded (`220 Ready to start TLS`), followed by a clean post-TLS `EHLO` and a successful message send.
- A second connection confirmed `RELAY_REQUIRE_STARTTLS=true` actually enforces the requirement: `MAIL FROM` issued before `STARTTLS` was correctly rejected with `530 Must issue a STARTTLS command first`.
- `docker-compose.prod.yml` validated with a YAML parser after the edit.

Not yet tested: a real Let's Encrypt cert (only a self-signed test cert was used here), and the actual Google Workspace Hosts/routing configuration, which needs a real public IP/port-forward — infra the user is setting up.

---

## 🔑 Agent Now Persists Its Own api_key — Browser Extension Can Reuse It (No More Per-Machine Registration) (July 20, 2026)

### Summary

Flagged earlier this session as a real fleet-scale concern: the browser extension's native host needs its own registered agent identity, and until now that meant a separate manual `curl` registration per machine — impractical past a handful of endpoints. Root cause: `RegisterAgent()` in `agent.cpp` sent the registration request but only ever checked the HTTP status — the server-issued `api_key` in the response was read nowhere and discarded, so the endpoint agent had no credential of its own to hand to anything else, including the extension.

### Fixed

- `AgentConfig` gains an `apiKey` member, extracted from the registration response's `api_key` field in `RegisterAgent()`.
- Persisted via a new `AgentConfig::SaveApiKeyFile()` to `C:\ProgramData\SeceoKnight\agent_key.json` — deliberately **not** folded into the existing `SaveToFile()` (which owns `C:\Program Files\SeceoKnight\agent_config.json`). Two reasons: the agent's scheduled task runs as a standard, non-elevated user (`RunLevel Limited`) that can't write to Program Files — the exact same class of bug already fixed once for the Logger's default path earlier in this project — and `SaveToFile()` doesn't know about the `quarantine_path`/`log_path`/`cache_path` keys `install-agent.ps1` also writes into that file, so rewriting it from `RegisterAgent()` would have silently wiped those out. `C:\ProgramData\SeceoKnight\` is already proven writable by this exact process (quarantine/logs/cache already live there).
- `agents/browser-extension/native-host/install.ps1`: `-AgentId`/`-AgentKey` are now optional. When omitted, the script reads them from `C:\ProgramData\SeceoKnight\agent_key.json` (falling back to an explicit error telling the admin to either update the agent first or pass the values explicitly). The main agent must already be installed and have registered at least once.

### Result

At fleet scale, setting up the browser extension on a machine that already has the endpoint agent installed no longer needs a separate manual registration step — `install.ps1` just reuses the agent's own identity, and browser-extension events now show up under the same agent record as that machine's real endpoint agent. Passing `-AgentId`/`-AgentKey` explicitly is still supported for a standalone/distinct identity.

### Verification

No C++ compiler is available in this environment (agent.cpp is Windows-only, depends on `windows.h`/`wincrypt.h`/etc.), so this was verified by careful manual review only: the diff was re-read in full, brace/paren balance around the specific edited regions was checked, and the exact call chain (`AgentConfig::apiKey` → `RegisterAgent()` → `SaveApiKeyFile()` → `install.ps1`) was traced end to end. **Real verification requires GitHub Actions' `build-windows-agent.yml` to actually compile this on a Windows runner, then a live install + registration test.** Do not treat this as verified until CI is green and it's been tested on a real machine.

### Not yet done

Distinguishing which physical machine a browser-extension event came from: `emit_event()` in `skdlp_host.py` doesn't send a hostname today, so under either the old (per-machine) or new (shared with the main agent) identity model, the dashboard's "Agent" column doesn't by itself tell you which machine fired a given cloud-upload event — a possible follow-up if that's needed.

---

## 🔍 Gmail/Filebin Uploads Not Blocked — Content Was Never Actually Extracted (July 20, 2026)

### Summary

Live evidence from the manager's own logs, provided by the user for a Gmail upload event that fired as `Cloud upload cloud_upload_allowed (Public)` (not blocked) despite the same file already being flagged by the older, unrelated "Detect Browser Upload" (`network_exfil`) feature:

```
"file_name": "upload.bin", "kind": "unsupported", "reason": "binary/unknown format .bin", "event": "Content not extractable"
"classification": "Public", "confidence": 0.0, "matched_rules_count": 0, "event": "Content classified"
```

### Root cause

This is not the cosmetic filename issue it looked like — it's a real content-detection bypass. `document_extract.py` picks which parser to use **by file extension**. Because the extension could never recover Gmail's real filename (the byte-content request goes to an opaque resumable-upload session URI carrying no filename — the real name only exists in an earlier, separate metadata-initiation request), the server received the generic fallback name `upload.bin`, didn't recognize `.bin` as a known/textual format, extracted **zero content**, and classified it Public by default. Nothing was ever actually inspected. Every previous filename fix (URL query params, then URL path segments) narrowed this gap for services that don't hide the name, but structurally could never fix Gmail/Drive's chunked pattern, because their content-bytes request simply doesn't contain the filename anywhere for us to recover.

### Fixed — capture the real file at the source instead of guessing downstream

`inject.js` now listens for `change` events on `<input type="file">` elements and `drop` events (capture phase, so nothing a site does can suppress it), and captures the actual `File` object — real name, real untouched bytes — the moment the user selects/drops it, before Gmail (or any site) reads and repackages those bytes into its own upload request(s).

When a later network request's body has no usable identity of its own (a bare `Blob`/`ArrayBuffer`/typed array — the same case that previously fell back to `upload.bin`), `collectFiles()` now substitutes the most recently captured real file instead (exact-size match preferred; otherwise the most recent capture within 60s — because a chunked upload's individual byte-range request never equals the full file's size, but is still the same file). This means classification now runs against the complete, correctly-named original file — sidestepping Gmail's chunking rather than trying to parse a fragment of it — and the server's extension-based parser dispatch (docx/pdf/xlsx/text/...) works the way it's supposed to.

This is strictly additive: with no captured file available, behavior is identical to before (same URL-based guess, same `upload.bin` fallback) — a capture never happens more than once per real file selection, so it doesn't add or duplicate any classify/log requests.

### Verification

`node --check` passes. Not live-tested in this sandbox (no browser/Gmail access here) — needs a real re-test after redeploying `inject.js` and reloading the extension. The service worker / page console should now show `[SK-DLP] using captured file selection for classification: <realname> (<size> bytes)` when this path is taken.

### Result

Gmail and filebin uploads should now classify against the real file's actual content and show the real filename in dashboard events, instead of silently defaulting to Public because the content was never extracted. Needs a live redeploy + retest to confirm blocking now fires correctly for a genuinely sensitive test file.

---

## ⚙️ Dashboard-Managed Extra Cloud Upload Destinations (July 20, 2026)

### Summary

Every destination the browser extension (Cloud Upload Guard) watches was hardcoded in `inject.js`'s `CLOUD_HOSTS` array — adding one more (e.g. a partner's file-sharing portal) meant editing the file and redeploying it to every endpoint. Added a dashboard-managed, admin-only list of extra destinations that the extension picks up without a redeploy.

### Design

Followed this codebase's existing convention for admin-managed settings (no generic key-value settings table exists — each gets its own model + migration + router, per the IP-allowlist precedent):

- `server/app/models/cloud_upload_hosts.py` — new `CloudUploadHost` table (`domain`, `label`, `is_enabled`, `created_by`, `created_at`).
- `server/alembic/versions/032_cloud_upload_hosts.py` — idempotent `CREATE TABLE IF NOT EXISTS`, chained after `031_siem_connectors` (the current migration head).
- `server/app/api/v1/cloud_upload_hosts.py` — admin-only `GET/POST/DELETE /security/cloud-upload-hosts`, mounted alongside `ip_allowlist` in `app/api/v1/__init__.py`.
- `server/app/api/v1/agents.py` — new agent-authenticated `GET /agents/{agent_id}/cloud-upload-hosts` (uses the existing `verify_agent_key` dependency) returning the enabled domain list, for the extension's native host to poll.

This is purely **additive**: the table only ever extends the extension's built-in baseline list, never disables or replaces an entry that ships built in — a dashboard mistake here can't silently turn off protection for Gmail, Outlook, etc.

### Extension changes

- `skdlp_host.py` — new `get_hosts` native-messaging request type; `fetch_extra_hosts()` calls the new agent endpoint (fail-open to the last-known list on any error, 120s in-process cache).
- `background.js` — fetches the extra-hosts list on startup/install and every 15 minutes via `chrome.alarms` (a plain `setInterval` isn't reliable since MV3 service workers can be killed between page loads), and mirrors it into `chrome.storage.local`.
- `content.js` (ISOLATED world, has `chrome.storage` access) — reads the stored list and relays it into the page via `postMessage`, plus listens for `chrome.storage.onChanged` so open tabs pick up an admin's edit without a reload.
- `inject.js` (MAIN world, no `chrome.*` access) — listens for the relayed list and checks it in `isCloudUrl()` alongside the existing hardcoded `CLOUD_HOSTS` baseline.
- `manifest.json` — added the `alarms` permission (`storage` was already present).

### Dashboard changes

- `lib/api.ts` — `CloudUploadHost` type + `getCloudUploadHosts`/`addCloudUploadHost`/`deleteCloudUploadHost`.
- `components/settings/CloudUploadHostsSection.tsx` — new admin-only section (add/list/remove domains), modeled on `IpAllowlistSection.tsx`.
- `pages/Settings.tsx` — renders the new section under the same `isSuperAdmin` (role === ADMIN) gate as the IP allowlist.

### Verification

`python3 -c "import ast; ast.parse(...)"` passes on all new/changed server files. `node --check` passes on `inject.js`, `background.js`, `content.js`. `python3 -m py_compile` passes on `skdlp_host.py`. `npx tsc --noEmit` shows only the same pre-existing, unrelated errors as every prior dashboard change this session (no new errors). `npm run build` succeeds; `dashboard/dist/` reverted afterward. Not live-tested — no server/DB/browser access in this sandbox; migration, endpoints, and the extension's fetch/merge/refresh cycle all need real deployment verification.

### Result

Admins can now add (and remove) extra monitored cloud-upload destinations from the dashboard, and endpoints pick the change up within about 15 minutes — or immediately after a browser restart — without needing `inject.js` redeployed to every machine.

---

## 📮 Outlook Web Wasn't in CLOUD_HOSTS at All — Extension Never Fired for It (July 20, 2026)

### Summary

Live-tested against Outlook web and `filebin`: Outlook triggered zero extension events (only the older, unrelated `network_exfil` browser-upload detector fired); `filebin` did trigger correctly but still showed `upload.bin`.

### Root cause (Outlook)

`inject.js`'s `CLOUD_HOSTS` allowlist had `office.com` and `live.com`, but Outlook web actually runs on `outlook.office365.com` and bare `outlook.com` — neither matches those entries (`office365.com` is a different root domain from `office.com`; bare `outlook.com` doesn't end with `.live.com`). Given this product is explicitly required to support both Gmail and Outlook (per this session's earlier instruction), this was a direct, concrete gap for that requirement, not a corner case.

### Fixed

- Added `outlook.com`, `outlook.office.com`, `outlook.office365.com`, `outlook.cloud.microsoft`, and `microsoftonline.com` to `CLOUD_HOSTS`.

### Filename (further improvement)

`guessFileNameFromUrl()` previously only checked URL query parameters. Some services (S3-backed uploaders, `filebin`-style services) encode the filename as the **last path segment** instead (e.g. `PUT /uploads/abc123/report.pdf`). Added a path-segment fallback, only trusted when it looks like a real filename (has a short extension) rather than an opaque session/object ID — so it won't mistake a UUID-style upload token for a filename.

### Verification

`node --check` passes. Not live-tested in this sandbox.

### Result

Outlook web uploads should now be intercepted at all. Filename recovery now also covers path-encoded filenames (e.g. `filebin`), in addition to the earlier query-param case. Gmail/Drive's resumable-upload filename gap remains open and documented — neither of today's two filename improvements touches that specific pattern.

---

## 🚧 Filename Best-Effort Recovery + Policy Exception Operators (not_equals / not_in) (July 20, 2026)

### Summary

Three enterprise-usability gaps raised together: (1) blocked browser-extension events still show `upload.bin` instead of the real filename, (2) no way to allow a specific destination/case while an existing block policy stays active for everything else, (3) 50-agent scale concern about the browser extension needing its own separate registered identity per machine (tracked separately — not fixed in this entry, flagged as a larger follow-up needing explicit sign-off given it touches the Windows agent's C++ registration code).

### Filename (partial, honest fix)

`inject.js` now tries to recover a real filename from the request URL's query string (`filename`/`fileName`/`name`/`title`/`upload_name` params) before falling back to `upload.bin`. This helps for services that pass the filename that way. It does **not** fix Gmail/Drive's specific resumable-upload pattern — the byte-content request goes to an opaque session URI with no filename anywhere in that request; the real name only exists in an earlier, separate metadata-initiation call. Correlating two distinct requests per upload safely would need to be built against real captured traffic, which isn't available in this environment — documented as a known, still-open limitation rather than guessed at blind.

### Exception operators — the real fix for "how do I allow some"

Checked the actual precedence logic in `evaluate_policy_realtime()`: if *any* matching policy says `block`, that wins outright, unconditionally — a separate "allow" policy can never override a matched "block" policy, regardless of priority. So exceptions have to be expressed as an exclusion condition **on the block policy itself** — but no negation operator existed anywhere (backend or dashboard), so that couldn't be expressed at all.

- `database_policy_evaluator.py`: added `not_equals` and `not_in` operators (mirrors the existing `equals`/`in` case-insensitive matching, inverted).
- `ClassificationPolicyForm.tsx`: added both to the operator dropdown, and extended the multi-value comma-separated input (from the earlier "in"-operator fix) to also apply to `not_in`.

Example this unlocks: on the "Cloud upload" block policy, add `destination_path not_in sanctioned-partner.com` to let that one destination through without touching the block for everything else.

### Verification

`python3 -c "import ast; ast.parse(...)"` passes on the evaluator. `npx tsc --noEmit` and `npm run build` pass on the dashboard (same two pre-existing unused-import warnings as every prior dashboard change this session); `dist/` reverted after building. `node --check` passes on `inject.js`. None of this is live-tested — needs real verification once deployed.

### Result

Admins can now build real exceptions onto existing block policies. Filenames are more often correct for non-Google cloud destinations; Gmail/Drive's `upload.bin` limitation remains open and documented. The 50-agent registration-scaling concern is explicitly deferred, not silently dropped — see the Pending note above.

---

## 🖼️ Per-Frame Coalescing Cache Didn't Stop Duplicate Events — Moved to the Shared Service Worker (July 20, 2026)

### Summary

Live-tested the coalescing fix from two entries below: still saw contradictory events 1.5 seconds apart for what should have been one upload — one correctly `Confidential`/blocked, the very next `Public`/allowed, both to `mail.google.com`.

### Root cause

`manifest.json` injects `inject.js` into **every frame on the page** (`"all_frames": true`). Each frame gets its own separate, isolated JS global scope — so the per-frame `recentDecisions` cache added in the previous fix only coalesced requests within a single frame. Gmail is built from multiple frames; a real content request from one frame and unrelated traffic from another frame, milliseconds apart, each started from a blank cache and got classified independently. The 4-second window was working exactly as designed — it just wasn't shared across the one boundary that mattered.

### Fixed

- Moved the coalescing cache from `inject.js` to `background.js` — the single shared service worker every frame's "classify" message already converges on via `chrome.runtime.sendMessage`, so a cache there is genuinely cross-frame (and cross-tab).
- Only caches a decision when a **real** response arrives from the native host (`port.onMessage`) — timeout/send-failed/disconnect fail-opens are explicitly excluded via a `requestHosts` map that's deleted before any fail-open path responds, so a transient hiccup can never get cached and silently suppress the next real check.
- Left the earlier per-frame cache in `inject.js` in place too — harmless, still shortcuts same-frame chunk bursts a little faster, just no longer relied on as the sole mechanism.

### Verification

`node --check` passes on both `background.js` and `inject.js`. Not live-tested in this sandbox — needs re-test on the real deployment.

### Result

A single upload that spans requests from multiple frames of the same page should now produce one decision (and one event), not one per frame.

---

## 🌊 One File Upload Flooded the Dashboard With Duplicate Events (July 18, 2026)

### Summary

First fully-working live test of the browser extension (blocking finally confirmed end to end): attaching one file in Gmail produced a large number of near-identical events in the dashboard, all named `upload.bin`.

### Root cause

Gmail's attachment upload isn't a single network request — like Google Drive, it uses a chunked/resumable upload protocol under the hood (an init call, one or more content chunks, progress pings, etc.). `inject.js`'s `decideForBody()` treated **every** intercepted cloud-host request carrying file-like bytes as an independent file to classify — so attaching one real file triggered several separate classify → decide → log round trips, one per underlying network request. None of those individual chunk requests are real `File` objects with a `.name` (only `Blob`/`ArrayBuffer` bodies), which is the same root cause behind the `upload.bin` filename — both symptoms trace back to the same gap: the page-level interception only sees raw bytes, not the logical "one file" the user actually attached.

### Fixed

- Added a short (4s) per-destination-host coalescing cache in `inject.js`: repeated requests to the same cloud host within the window reuse the most recent decision instead of re-classifying and re-logging. A `block` decision is always reused as `block` (never weakens); documented trade-off is that a genuinely different file uploaded to the same host within the 4s window would inherit the prior decision rather than being freshly classified — kept short specifically to bound that risk.

### Verification

`node --check` passes. Not live-tested in this sandbox (no browser available) — needs a real re-upload test to confirm the event count drops to one (or few) per file.

### Result

Attaching one file should now produce roughly one event instead of a flood. The `upload.bin` filename issue is a separate, still-open cosmetic gap (browsers don't expose a filename on raw `Blob`/`ArrayBuffer` upload bodies at all — fixing it fully would need protocol-specific knowledge of Gmail's/Drive's resumable-upload metadata calls, out of scope for today).

---

## 🔒 Browser Extension Never Actually Worked — Silent TLS Verification Failure Against the Self-Signed Cert (July 17, 2026)

### Summary

Live-tested end to end today with a real Windows PC and a real server: the bridge worked (`native host reachable (pong)`), the extension intercepted every Gmail upload and logged `classify → decision`, but the manager's logs showed **zero** `/agents/{id}/policy/evaluate` requests ever arriving — for any test, including the very first one. The browser extension's real-world classification calls had never actually reached the server, from the start.

### Root cause

`install.sh` provisions a **self-signed TLS certificate** by default (every curl example throughout this session's docs uses `-k` for exactly this reason). `native-host/skdlp_host.py`'s `evaluate()` and `emit_event()` call `requests.post()` against the server's public HTTPS URL with default certificate verification — which fails with an SSL error against a self-signed cert. Both calls wrap the request in a broad `except Exception` that logs to `dlp-host.log` (never the browser console) and returns the fail-open default (`action=allow`), so the extension's background-console log always showed a normal-looking `decision → allow` with no visible sign anything had failed. This is a different failure mode from the "Cloud upload" policy's condition bug fixed two entries above — that bug meant a correctly-delivered request would never match a block rule; this bug meant the request was never being delivered to the server at all.

### Fixed

- `skdlp_host.py`: both `requests.post()` calls now pass `verify=CFG.get("verify_tls", False)`, defaulting to `False` to match the self-signed cert every fresh install ships with.
- Added a `verify_tls` config option (`SKDLP_VERIFY_TLS=1` env var, or `"verify_tls": true` in `dlp-host.json`) so an admin who replaces the server's cert with a real CA-signed one (see README's "Getting a Trusted SSL Certificate" section) can turn verification back on.
- Suppressed `urllib3`'s `InsecureRequestWarning` (goes to stderr, can't corrupt the native-messaging stdout protocol either way, but keeps logs clean).
- Confirmed the **SMTP relay is not affected** by the same class of bug: `smtp-relay/app/dlp_client.py` talks to the `manager` container directly over plain HTTP on the internal Docker network (`DLP_SERVER_URL=http://manager:55000/api/v1` in `docker-compose.prod.yml`), never through the public HTTPS/self-signed-cert path.

### Verification

`python3 -m py_compile` passes. No live Windows/browser test possible in this sandbox — needs a re-test on the actual deployment (rebuild `skdlp_host.exe` with the updated script, or re-run un-frozen) to confirm requests now reach the server.

### Result

Once the native host is rebuilt with this fix and deployed, the browser extension's classification calls will actually reach the server for the first time — everything built and tested today (the event-type dropdown fix, the "in"-operator input fix, this fix) was necessary but this was the final blocker.

---

## ⌨️ "in"-Operator Value Box Ate Commas/Spaces After the First Entry (July 17, 2026)

### Summary

Immediately hit while actually using the previous fix: building a policy with `Classification Level in Confidential, Restricted` was impossible — typing a comma or space after the first value did nothing visible, making it look like the field only accepted one value.

### Root cause

`ClassificationPolicyForm.tsx`'s "in"-operator value box derived its displayed text straight from the **parsed** array on every keystroke: `onChange` split the typed text on `,`, trimmed, and `filter(Boolean)`'d out empty tokens, then the input's `value` was that array re-joined with `', '`. The instant a user typed a trailing comma (`"Confidential,"`), the split produced `["Confidential", ""]`; `filter(Boolean)` dropped the empty second element; the re-joined display snapped back to `"Confidential"` — silently erasing the comma (and, for the same reason, a trailing space) the user just typed. It wasn't broken after the *first* value specifically — it was broken after *every* separator, which made the field look stuck right after value #1.

### Fixed

- Added a small `inDrafts` state (per condition-row raw text) so the box now displays exactly what was typed, while `condition.value` still receives the clean parsed/filtered array underneath — the fix from the previous entry (typing `event_type`/`cloud_upload` conditions) now actually works.
- Draft is cleared on blur (re-syncing to the clean value) and whenever a row's field/operator changes or a row is removed (stale index safety).

### Verification

`npx tsc --noEmit` shows no new errors (two pre-existing unused-import warnings in this same file, `useEffect`/`X`, predate this change). `npm run build` succeeds; `dist/` reverted after building.

### Result

Multi-value `in` conditions (e.g. `Classification Level in Confidential, Restricted`) can now actually be typed and saved, which is required to build a working block policy for the browser extension / SMTP relay.

---

## 🚫 No Way to Actually Build a Blocking Policy for Cloud Uploads or Email — Dropdown Missing the Event Types (July 17, 2026)

### Summary

Live-tested the browser extension end to end today: extension loaded, native host registered, bridge verified (`native host reachable (pong)`), and the extension correctly intercepted a Gmail attachment upload containing a fake credit-card number — but the server returned `allow` every time. Traced this to a real dashboard gap, not a config mistake: **there was no way to create a policy that would ever return `block` for the browser extension's or SMTP relay's events at all.**

### Root cause

The browser extension sends `event_type: "cloud_upload"` / `destination_type: "cloud"`, and the SMTP relay sends `event_type: "email_send"` — confirmed by reading `native-host/skdlp_host.py` and `smtp-relay/app/dlp_client.py`. The only dashboard policy type generic enough to match on `event_type` (**Classification-Aware Policy**) restricts that field to a fixed `<select>` dropdown in `dashboard/src/components/policies/ClassificationPolicyForm.tsx` — and neither `cloud_upload` nor `email_send` was in the list (only `file_transfer, clipboard, file_create, file_modify, file_delete, usb_connect`). The backend evaluator (`database_policy_evaluator.py`) is completely generic — it does a plain case-insensitive string match on whatever `event_type` value a condition specifies, no restriction at all — so this was purely a frontend dropdown gap, not a backend limitation. Also confirmed there's no separate "Cloud Upload Prevention" policy type either (the CyberSentinel docs' mention of "two cloud_upload_prevention policies" refers to a UI template that was never ported) and the existing "Browser Upload Monitoring" policy type is a different, older, alert-only feature (`network_exfil` — confirmed via `network_exfil_monitor.cpp`'s own comment: `// Alert only - not blocked`), unrelated to the new extension.

### Fixed

- `ClassificationPolicyForm.tsx`: added `cloud_upload` and `email_send` to the `event_type` field's dropdown options, and `cloud` to `destination_type`'s options (`email` was already present, which is what the SMTP relay already uses).

### Verification

`npx tsc --noEmit` shows zero new errors (all remaining errors pre-exist in unrelated files, same set noted throughout this session). `npm run build` succeeds; `dist/` reverted after building per this repo's established practice of not committing local build artifacts.

### Result

An admin can now build a **Classification-Aware Policy** with condition `event_type equals cloud_upload` (or `email_send`) + `classification_level in [Confidential, Restricted]` → action `block`, and it will actually take effect — closing the gap that made every browser-extension and SMTP-relay evaluation return `allow` regardless of content.

---

## 🐛 Browser Extension's `native-host/install.ps1` Was Documented But Never Actually Created (July 17, 2026)

### Summary

Both `README.md` (Step 5) and `agents/browser-extension/INSTALL_WINDOWS.md` instruct the reader to run `native-host\install.ps1` to register the native-messaging host — but the file was never ported from CyberSentinel in the first place, only described in the docs. A user following the guide hit `The term '.\install.ps1' is not recognized...` after building the host `.exe` successfully.

### Root cause

CyberSentinel's copy of this script lives one directory higher, at `agents/browser-extension/install.ps1` (not inside `native-host/`). When the browser-extension port was done earlier this session, every other file in that tree was copied and rebranded — this one was missed entirely (not moved to the wrong place; simply never copied).

### Fixed

- Added `agents/browser-extension/native-host/install.ps1`, ported from CyberSentinel's `agents/browser-extension/install.ps1` and rebranded (`CyberSentinel` → `SeceoKnight`, `com.cybersentineldlp.dlp` → `com.seceoknightdlp.dlp`, `csdlp_host.exe` → `skdlp_host.exe`, `C:\ProgramData\CyberSentinel` → `C:\ProgramData\SeceoKnight`). Placed inside `native-host/` (not one level up, matching CyberSentinel's own layout) since that's the path already documented in both `README.md` and `INSTALL_WINDOWS.md`.
- Confirmed via `git check-ignore` the new `.ps1` file isn't silently excluded (learned this lesson the hard way with `.gitignore`'s blanket `*.json` rule earlier this session).

### Verification

No PowerShell interpreter available in this environment to execute the script directly; verified structurally by diffing against the CyberSentinel original it was copied from (same logic, only identifier strings changed) and confirming it isn't git-ignored.

### Result

`.\install.ps1 -ExtensionId ... -ServerUrl ... -AgentId ... -AgentKey ... -HostCommand ...` now exists and runs from `native-host\`, exactly as both docs already instructed.

---

## 🔑 README Didn't Explain Where RELAY_AGENT_ID/KEY or the Extension's AgentId/Key Actually Come From (July 17, 2026)

### Summary

Step 4 (SMTP relay) and Step 5 (browser extension) told the reader to set `RELAY_AGENT_ID`/`RELAY_AGENT_KEY` / `-AgentId`/`-AgentKey` without saying where those values come from or that a real API call is required first. Step 5 additionally told readers to "reuse this PC's existing endpoint-agent id/key" — checked against the actual Windows agent code (`agents/endpoint/windows/agent.cpp`, `RegisterAgent()` at line 3713) and confirmed **that's not possible**: the endpoint agent never parses or stores an `api_key` from its own registration response at all (`AgentConfig::SaveToFile` only ever persists `server_url`/`agent_id`/`agent_name`/intervals), and the dashboard's Agents page never displays a key either way (it's a one-time value returned only at registration). The old instruction would have sent a reader down a dead end.

### Fixed

- Step 4.1: added the full request→response walkthrough (what to run, where to run it, an example JSON response, and which two fields map to which two env vars), plus an explicit "you cannot reuse an installed agent's key" note.
- Step 4.2: made the `.env` edit fully explicit — exact command to open the file, exact lines to add, explicit "don't paste the example values literally" warning.
- Step 5: replaced the incorrect "reuse this PC's existing agent id/key" suggestion with a dedicated registration step (mirroring Step 4.1) for the native host's own identity, and renumbered the rest of the section accordingly.

### Verification

Independently re-confirmed (grep, not just the sub-agent's report) that `agent.cpp` has no `api_key` parsing anywhere outside the unrelated "detect API keys in scanned content" classification rule — `RegisterAgent()` only checks the HTTP status code on success and never reads the response body.

### Result

Both setup sections are now runnable by someone with no prior context: exact commands, exact file paths, and an accurate description of which values exist where.

---

## 📖 Main README Had No Setup Steps for the SMTP Relay or Browser Extension (July 17, 2026)

### Summary

The SMTP relay and browser extension were fully built, ported, and documented in their own subdirectory READMEs (`smtp-relay/README.md`, `agents/browser-extension/INSTALL_WINDOWS.md`), but the top-level `README.md` — the file anyone deploying the product actually starts from — never mentioned either feature. A new user following the main README top to bottom would have no idea these features existed, let alone how to turn them on.

### Fixed

- `README.md`: added two new step-by-step sections, **Step 4 — Enable the SMTP Relay (Email DLP)** and **Step 5 — Install the Browser Extension (Cloud Upload Guard)**, both marked Optional, placed right after the Linux Agent step. Each gives the condensed end-to-end path (register an agent identity, set env vars / run `install.ps1`, point the mail platform or browser at it, test) and links out to the full subdirectory guide for details.
- Added `RELAY_AGENT_ID`/`RELAY_AGENT_KEY` acquisition steps inline (`POST /api/v1/agents/` → one-time `api_key`), matching the actual `register_agent` endpoint contract in `server/app/api/v1/agents.py`.
- Updated the "What it does" bullet list to mention binary-document classification, Cloud Upload Guard, the SMTP relay (both Gmail and Outlook), and the Audit Trail page.
- Updated the Documentation table with links to `smtp-relay/README.md` and both browser-extension docs.

### Verification

Re-read the full `README.md` end-to-end; confirmed the new sections' links to `smtp-relay/README.md#google-workspace-routing-the-deployment-step` and `#microsoft-365--exchange-online-routing-the-deployment-step` match that file's actual header slugs (checked earlier this session). Confirmed the `POST /agents/` request body shown matches the real `AgentCreate` model (`name`, `os`, `ip_address` required) and that the response contains `agent_id` + a one-time `api_key`, by reading `server/app/api/v1/agents.py`'s `register_agent()`.

### Result

Everything shipped this session (document extraction, browser extension, SMTP relay for both Gmail and Outlook, Audit Trail) is now discoverable and configurable directly from the main README — no need to already know a subdirectory exists.

---

## 📧 SMTP Relay Docs Were Google-Only — Added Microsoft 365 / Exchange Online Routing (July 17, 2026)

### Summary

The ported `smtp-relay/README.md` only documented deployment for Google Workspace (Admin console → Gmail → Hosts/Routing → outbound gateway). For an "enterprise grade DLP" product this is a real gap: an org's mail platform can't be assumed, and the relay itself is plain SMTP and was always platform-agnostic — only the setup instructions were narrow.

### Root cause

Documentation-only gap, not a code defect. The relay (`app/main.py`, `app/handler.py`, `app/dlp_client.py`) has no Google-specific logic anywhere — it just needs to sit in the outbound mail path, however that org's platform routes mail there.

### Fixed

- `smtp-relay/README.md`: added a full **Microsoft 365 / Exchange Online routing** section (mirrors the Google Workspace section) — Exchange admin center → Mail flow → Connectors → smart host, scoping via a mail-flow rule to outbound-only traffic, TLS, SPF, and `RELAY_NEXT_HOP_HOST` guidance (typically `<tenant>-com.mail.protection.outlook.com` if mail loops back through Exchange Online).
- Updated the intro and the "How it works" diagram to be platform-neutral, with links to whichever routing section applies.
- Updated the Limitations section's last bullet to name both platforms' bypass paths (Google's outbound gateway vs. Microsoft's connector/mail-flow-rule).

### Verification

Read through the full file end-to-end; confirmed the two intro anchor links (`#google-workspace-routing-the-deployment-step`, `#microsoft-365--exchange-online-routing-the-deployment-step`) match GitHub's auto-generated header slugs exactly. Routing mechanics cross-checked against Microsoft Learn's connector/mail-flow documentation.

### Result

The same relay binary/config now has documented, equally-supported setup paths for Gmail (Google Workspace) and Outlook (Microsoft 365) orgs — no assumption about which platform a customer runs.

---

## 🐳 SMTP Relay Wasn't Deployable via the One-Liner Installer (July 17, 2026)

### Summary

`install.sh` (the `curl -fsSL .../install.sh | sudo bash` one-liner) is built on the principle of never placing source code on the production server — it only downloads `docker-compose.prod.yml`, `.env.example`, and the nginx config, then pulls pre-built images from GHCR. The `smtp-relay` service added earlier today used `build: context: ./smtp-relay` only, with no pre-built image — so on a server deployed purely via the one-liner (no git clone), `docker compose up -d` would fail specifically on `smtp-relay` with a missing-build-context error, since that folder was never fetched. `manager` and `dashboard` were unaffected since they already had pre-built GHCR images.

### Fixed

- Added a `Build and push smtp-relay image` step to `.github/workflows/build-and-push.yml`, matching the existing manager/dashboard steps exactly — pushes to `ghcr.io/seceo-knight/dlp-smtp-relay:latest` (and a commit-sha tag) on every push to `main`.
- Added `image: ghcr.io/seceo-knight/dlp-smtp-relay:latest` to the `smtp-relay` service in `docker-compose.prod.yml`, alongside the existing `build:` block (same dual pattern already used by `manager`/`dashboard` — `image:` is what `docker compose pull` fetches; `build:` remains for local/dev builds).

### Verification

`docker-compose.prod.yml` and `build-and-push.yml` both validated with `yaml.safe_load`.

### Result

`curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install.sh | sudo bash` now brings up all three services (manager, dashboard, smtp-relay) correctly on a completely fresh server with zero source code present, once this CI run completes and pushes the new image.

---

## 📋 New Feature: Audit Trail Dashboard Page — Ported from CyberSentinel (July 17, 2026)

### Summary

SeceoKnight already has a full audit log backend (`app/models/audit_log.py`, `app/api/v1/audit_logs.py`, `app/services/audit_service.py`) but no dashboard page to view it — admins had no UI way to see who did what. Ported CyberSentinel's `AuditTrail.tsx` page and **wired it into routing and navigation**, which CyberSentinel's own copy is not: it's an orphaned file in their repo — never imported by their `App.tsx` or any nav component, so it's unreachable in their actual running app.

### What it does

A filterable, paginated table of every admin/system action (action type, date range), each row expandable to show the raw `details`/`metadata` JSON. Uses the dashboard's existing `getAuditLogs()`/`getAuditActions()` API functions and `formatDateTimeIST()` util — both already present in `lib/api.ts`/`lib/utils.ts`, so no new dependencies were needed.

### Wiring

- Added the route `audit-trail` → `<AuditTrail />` in `App.tsx`.
- Added a sidebar nav entry ("Audit Trail", `ClipboardList` icon) gated with `adminOnly: true` — matching the existing "Threat Intel" entry's pattern, since `/audit-logs/` is `require_role("admin")` server-side (coarse role check, not a permission string), same reasoning documented in the `NavItem.adminOnly` comment.

### Verification

`npx tsc --noEmit` shows zero new errors introduced by `AuditTrail.tsx`, `App.tsx`, or `Sidebar.tsx` (only pre-existing unrelated errors in other policy-form components). `npm run build` succeeds. Confirmed the backend response shape (`{logs: [...], total: N}`) matches what the ported page already expects.

---

## 📧 New Feature: SMTP Relay (Email DLP) — Ported from CyberSentinel (July 17, 2026)

### Summary

SeceoKnight had no outbound email DLP at all. Ported CyberSentinel's SMTP relay — a small standalone service that sits in the actual mail flow and blocks sensitive outbound email at the protocol level, before it ever reaches a recipient.

### What it does

Google Workspace's outbound gateway (or any smarthost) routes outbound mail through `smtp-relay/`. It parses the MIME message, extracts text from every attachment (pdf/docx/xlsx/pptx/csv/txt/…) using its own bundled document parsers plus the message body, and calls the same `/agents/{id}/policy/evaluate` endpoint every other channel (USB, browser upload) uses — one classifier, one policy engine, everywhere. Public mail is forwarded and logged, Internal mail is forwarded with an alert, and Confidential/Restricted mail gets a `550` rejection at the SMTP `DATA` stage — a true block: the sending MTA never receives a `250`, so the message is never delivered and the sender gets a bounce. Fails open by default (a DLP outage must not stop company mail) but both `RELAY_BLOCK_UNEXTRACTABLE` and `RELAY_BLOCK_ON_DLP_ERROR` are available for stricter, opt-in enforcement.

Deliberately a separate, slim Docker image (`python:3.11-slim` + `aiosmtpd`/`aiosmtplib`/`httpx` + document parsers) rather than reusing the manager image's multi-GB ML stack.

### Adaptation notes (porting from CyberSentinel)

- Rebranded throughout: `CyberSentinel DLP` → `SeceoKnight DLP` in README/config/main entrypoint (the reject message, docstrings). No functional code changes were needed — the relay already calls `/agents/{id}/policy/evaluate` and `/events/` generically and already sends `inspection_skipped` for unreadable attachments, which lines up exactly with the `inspection_skipped`/`extraction_status` handling added to `evaluate_policy_realtime()` earlier today for the document-extraction fix.
- Added a `smtp-relay` service to `docker-compose.prod.yml` (container name `seceoknight-smtp-relay`, on the existing `seceoknight` network, `depends_on: manager` with a health condition), matching CyberSentinel's service definition but using SeceoKnight's existing manager/network naming conventions instead of introducing new ones.

### Verification

`python3 -m py_compile` passed on all six Python files (`__init__.py`, `config.py`, `dlp_client.py`, `extract.py`, `handler.py`, `main.py`). `docker-compose.prod.yml` validated with `yaml.safe_load`. Confirmed zero remaining `CyberSentinel` references anywhere in the ported directory.

### Deployment

Requires Google Workspace admin access to route outbound mail through the relay (Admin console → Apps → Google Workspace → Gmail → Hosts/Routing), a public-facing host/DNS for the relay (Google's gateway must reach it over the internet), and SPF record updates for the relay/next-hop. Set `RELAY_AGENT_ID`/`RELAY_AGENT_KEY` (a registered agent's id + `X-Agent-Key`) and `RELAY_NEXT_HOP_HOST`/`_PORT` in `.env`, then `docker compose -f docker-compose.prod.yml up -d smtp-relay`. Full walkthrough in `smtp-relay/README.md`.

---

## 🌐 New Feature: Browser Extension (Cloud Upload Guard) — Ported from CyberSentinel (July 17, 2026)

### Summary

SeceoKnight previously had no way to intercept a browser-based upload before it reached a cloud destination — the existing browser-upload monitoring is reactive (it watches for the resulting file artifact after the fact). Ported CyberSentinel's browser extension, which pauses the actual upload request and blocks it before any bytes leave the browser.

### What it does

A Chrome/Edge MV3 extension (`agents/browser-extension/`) patches `fetch`/`XMLHttpRequest` in the page context to detect uploads (File/Blob/FormData/ArrayBuffer) to a fixed list of cloud hosts (Google Drive/Gmail, Dropbox, OneDrive/SharePoint, Box, WeTransfer, Slack, S3, etc.). Each upload is paused, base64-encoded, and relayed through a content script → background service worker → native-messaging host (`skdlp_host.py`), which calls the same `/agents/{id}/policy/evaluate` endpoint every other channel uses. Public files are allowed and logged, Internal files are allowed with an alert, Confidential/Restricted files are aborted client-side with an on-page banner, and `cloud_upload_attempt`/`cloud_upload_prevented` events land in the dashboard. Fails open at every hop — a DLP outage never bricks the browser.

### Adaptation notes (porting from CyberSentinel)

- Rebranded throughout: `CyberSentinelDLP`/`CyberSentinel DLP` → `SeceoKnight`/`SeceoKnight DLP` (matching the existing `C:\Program Files\SeceoKnight` / `C:\ProgramData\SeceoKnight` convention used by the main endpoint agent), `csdlp_host.py` → `skdlp_host.py`, `com.cybersentineldlp.dlp` → `com.seceoknightdlp.dlp`, `CSDLP_*` env vars → `SKDLP_*`, internal `__csdlp` postMessage marker → `__skdlp`.
- **Fixed an additional instance of the same document-extraction bypass found and fixed earlier today**: `skdlp_host.py`'s `evaluate()` was decoding the uploaded file's raw bytes as UTF-8 text (`errors="replace"`) and sending them as `file_content` — for a real `.docx`/`.pdf`/`.xlsx`/`.pptx` upload this produces garbled replacement characters, not real text, exactly like the USB transfer bug. Changed it to send the already-base64-encoded raw bytes as `file_content_b64` instead (the bytes were already available from `inject.js` — no new encoding needed), so the server's `document_extract.py` does real parsing on browser uploads too.
- Removed a hardcoded internal server path from `INSTALL_WINDOWS.md` (`/home/soc/Data-Loss-Prevention/...`) that was specific to CyberSentinel's own deployment box, replaced with a generic instruction.

### Verification

`node --check` passed on all three JS files (`background.js`, `content.js`, `inject.js`). `python3 -m py_compile` passed on `skdlp_host.py`. Both JSON files (`manifest.json`, `com.seceoknightdlp.dlp.json`) validated with `python3 -m json.tool`. Confirmed zero remaining `CyberSentinel`/`csdlp` references anywhere in the ported directory.

### Deployment

Server-side: none — it calls the existing `/agents/{id}/policy/evaluate` and `/events` endpoints unchanged. Per-endpoint: follow `agents/browser-extension/INSTALL_WINDOWS.md` (load the extension, build/install the native host, run `install.ps1` with the machine's agent id + key). Managed rollout: force-install via the `ExtensionInstallForcelist` Chrome/Edge group policy once packaged.

---

## 📄 Binary Documents (PDF/DOCX/XLSX/PPTX) Were Never Actually Classified — Real DLP Bypass (July 17, 2026)

### Summary

A comparison against the sibling CyberSentinel DLP project surfaced a real, unpatched bypass: sensitive content inside an actual `.docx`/`.pdf`/`.xlsx`/`.pptx` file (as opposed to a screenshot or plain `.txt`) transferred via USB was never being detected, no matter what policies were configured.

### Root cause

Two independent bugs on two sides of the same pipeline:

1. **Agent side** (`EvaluatePolicyRealtime()` in `agent.cpp`): for any non-image file, the agent read the file's raw bytes and "escaped" them character-by-character for the JSON request body, replacing every non-printable byte with a space. A `.docx`/`.xlsx`/`.pptx` file is itself a ZIP container and a `.pdf` has a binary structure — almost the entire file is non-printable bytes. The content that reached the server was effectively a wall of spaces regardless of what the document actually said.
2. **Server side** (`evaluate_policy_realtime()` in `agents.py`): even if real bytes had arrived, there was no code anywhere on the server that parsed PDF/DOCX/XLSX/PPTX binary formats into text before classifying — `pypdf`/`python-docx`/`openpyxl`/`python-pptx` weren't even in `requirements.txt`.

Both bugs individually would have let sensitive Office/PDF documents slip through as "Public" on every channel that forwards file content for real-time classification (USB transfer, and — once built — the browser upload guard and SMTP relay).

### Fixed

- Added a `Base64Encode()` helper to the agent (using the already-linked `wincrypt.h`/crypt32, no new dependency) and changed `EvaluatePolicyRealtime()` to send raw file bytes as `file_content_b64` instead of destructively space-escaping them. Image files still go through the agent's existing local OCR path unchanged (works today, no server-side Tesseract required).
- Ported `document_extract.py` from CyberSentinel into `server/app/services/` — a defensive, format-aware text extractor for pdf/docx/xlsx/pptx/text/archives (zip/tar/gz/7z, with zip-bomb guards), plus OCR fallback for scanned PDFs/images when Tesseract is available server-side.
- Wired it into `evaluate_policy_realtime()`: when the agent sends `file_content_b64`, the server now decodes and extracts real text before classification instead of relying on `file_content`. Added `pypdf`, `python-docx`, `openpyxl`, `python-pptx`, `py7zr`, `pytesseract`, `pdf2image` to `requirements.txt`, and `tesseract-ocr`/`tesseract-ocr-eng`/`poppler-utils` to the server `Dockerfile`'s runtime stage.
- Added `extraction_status`/`extraction_kind` to both the request handling and the response, so an operator can write a policy like "extraction_status equals unreadable → block" to catch encrypted archives/scanned images that can't be inspected at all — these are surfaced as uninspectable, never silently treated as clean.
- **Preserved the existing quarantine support** (`should_quarantine`/action precedence block > quarantine > alert > allow) that was already fixed earlier this session — this port merged CyberSentinel's extraction logic into SeceoKnight's evaluator rather than replacing it wholesale, since CyberSentinel's own version doesn't have quarantine support at all.
- Ported the corresponding `test_document_extract_truncation.py` test file.

### Verification

Ran the ported test file directly (`pytest tests/test_document_extract_truncation.py`) — 7 passed. Also manually verified extraction against a real generated `.docx` (containing "Study Report: Aadhaar ...") and `.xlsx` (containing an email address) — both correctly extracted the actual text, confirming this closes exactly the gap found during testing this week where a Study Report document's content wasn't being read correctly. Brace-balance check on `agent.cpp` unchanged at -5. `agents.py` and `document_extract.py` verified with `ast.parse`.

---

## 📁 USB Transfer Quarantine Fallback Directory Didn't Match the Configured Quarantine Folder (July 17, 2026)

### Summary

A screenshot copied to a USB drive triggered a "USB Transfer Quarantine" event and correctly disappeared from the USB drive, but the file was nowhere to be found in `C:\ProgramData\SeceoKnight\quarantine`. An earlier test the same day (a plain `.txt` file) had quarantined correctly into that exact folder, making this look inconsistent/broken.

### Root cause

`HandleUSBFileTransferQuarantineNoTimestamp()` (and its dead-code duplicate `HandleUSBFileTransferQuarantine()`) resolve the destination folder as `policy.quarantinePath.empty() ? "C:\\Quarantine" : policy.quarantinePath` — i.e. if the policy that fired doesn't have an explicit quarantine path configured on the server, it silently falls back to `C:\Quarantine`, a completely different, hardcoded folder that has nothing to do with the actual configured default (`C:\ProgramData\SeceoKnight\quarantine`, used everywhere else in the agent, including the `QuarantineConfig` struct's own default). A fresh screenshot with no `monitoredPaths` match falls through to the classification-only "scan everything" policy path (PASS 2 in `CheckUSBDriveForMonitoredFiles`), which is exactly the kind of policy less likely to have a quarantine path explicitly set — so the file wasn't lost, it just landed in a folder nobody was told to check. Confirmed by asking the user to check `C:\Quarantine` directly on affected test, and by a subsequent test (which matched a policy with a configured path) correctly landing in `C:\ProgramData\SeceoKnight\quarantine`.

### Fixed

Changed the empty-`quarantinePath` fallback in both `HandleUSBFileTransferQuarantineNoTimestamp()` and the dead-code duplicate to `C:\ProgramData\SeceoKnight\quarantine`, matching the real default used everywhere else. Also corrected `QuarantineConfig::folder`'s default value for the same reason, so there's exactly one default quarantine location across the whole agent instead of two disagreeing ones.

### Verification

Brace-balance check on `agent.cpp` unchanged at -5 (matches established baseline, no structural regression).

### Still open

The same screenshot's OCR-detected content only matched "Email Address" — the "Study Report" text also visible in the screenshot wasn't flagged. Not yet root-caused; needs a retest with the corrected quarantine path (so the file is actually recoverable for inspection) to compare what OCR extracted against what's visible in the image.

---

## 🔍 Clipboard Classification Debug Output Was Invisible in Production (July 17, 2026)

### Summary

After reinstalling the agent (post Snipping Tool cache-contamination fix), a copy/paste test of a Word document with "Study Report" content produced no visible reasoning in `seceoknight_agent.log` for why it was or wasn't blocked — even though the same session's log showed clipboard blocking working correctly twice (a "Study Report" match and an email match), the exact content and matched-policy detail for later paste attempts couldn't be confirmed from the log file at all.

### Root cause

`HandleClipboardEvent()` printed its diagnostic trail (captured content preview, loaded clipboard policies, classifier match counts) via `std::cout` only. `std::cout` has no destination when the agent runs as a background scheduled task with no attached console — the log FILE only receives whatever is explicitly sent through `logger.Debug()`/`Info()`/`Warning()`. This meant every clipboard classification decision was effectively a black box in production: we could see that an event was "allowed" or "blocked", but not what content was actually read from the clipboard or which policies/data types were loaded at that moment, making it impossible to diagnose reports like "it didn't block this specific document."

### Fixed

Routed all of `HandleClipboardEvent()`'s diagnostic output through `logger.Debug()` instead of `std::cout`, so it lands in `seceoknight_agent.log`: content preview + length, loaded clipboard policy names/data types, and classifier match counts. No behavior change — purely a visibility fix so the next clipboard test can be diagnosed precisely from the log instead of guessing.

### Verification

Brace-balance check on `agent.cpp` unchanged at -5 (matches established baseline, no structural regression).

---

## 🖼️ Snipping Tool Fix Was Ineffective — the Cache Itself Was Getting Contaminated (July 17, 2026 — follow-up)

### Summary

After the previous fix (use the cached pre-launch state instead of freshly classifying Snipping Tool's own window), retesting still showed the exact same symptom: `content` still contained Snipping Tool's own toolbar text, and two consecutive identical screenshots even produced two *different* wrong results (one showing a stray "CONTACT/PHONE" match against garbled OCR noise, the next showing nothing).

### Root cause

The previous fix made `HandleCaptureAttempt()` read the cached `m_screenIsSensitive`/`m_lastScannedText` instead of classifying fresh — but that cache is continuously maintained by a *separate* thread, `ContentScanThread`, which polls the foreground window on its own independent ~1 second cadence regardless of what `ProcessMonitorThread` is doing. Snipping Tool's window wasn't in `IsTransientForegroundWindow()`'s skip-list, so the moment `ContentScanThread`'s own poll cycle landed on Snipping Tool being foreground (which happens almost immediately after launch, independent of the tool-launch detection), it re-classified Snipping Tool's own toolbar and overwrote the shared cache with that — contaminating the exact state the previous fix was relying on to be correct. Two consecutive tests randomly landing on different OCR noise from the toolbar explains the two different (both wrong) results.

### Fixed

`IsTransientForegroundWindow()` now also checks the foreground window's owning process against the same capture-tool list `ProcessMonitorThread` already uses (`SnippingTool.exe`, `ScreenClippingHost.exe`, `ScreenSketch.exe`, etc.) and treats it as transient too — so `ContentScanThread` leaves the cache alone while a capture tool is focused, the same way it already does for the taskbar/desktop/start menu. `CAPTURE_PROCESSES` was moved from private to public on `ScreenCaptureMonitor` so this free function can reference the same list instead of duplicating it.

### Verification

Brace-balance check on screen_capture_monitor.cpp/.h: 0 (matches established baseline).

---

## 🖼️ Snipping Tool Screenshots Never Detected Content — Classifying the Tool's Own Toolbar Instead of the Document Underneath (July 17, 2026)

### Summary

A screenshot taken via Snipping Tool of content containing a "Study Report" keyword match and an IP address still showed the screen_capture event as "Public," no detection. The raw event's `content` field revealed the actual bug: it contained `"@ snipping Tool = o x |\n...\nPress ff + Shift + S to start a snip\n..."` — the OCR had read the Snipping Tool's own toolbar and instructional overlay text, not the document being captured.

### Root cause

`ProcessMonitorThread()` detects a capture-tool process (Snipping Tool, Snip & Sketch, etc.) the moment it appears in the process list and immediately classifies `GetForegroundWindow()` at that instant — but by then the tool has already launched and stolen focus, so the "foreground window" being classified is the tool's own overlay, never the document underneath. This was true both for the tool's own auto-terminate-if-sensitive enforcement check, and — after last session's fix that made `HandleCaptureAttempt()` classify fresh instead of using the cache — also for the reported event, which made this specific case (capture-tool-launch detection) consistently wrong instead of just occasionally stale. Keyboard-triggered captures (PrintScreen, Win+Shift+S) don't have this problem since those keys don't change the foreground window.

### Fixed

Both the auto-terminate check in `ProcessMonitorThread()` and `HandleCaptureAttempt()` (specifically for the `capture_tool` method only) now use the cached `m_screenIsSensitive` / `m_lastScannedText` — maintained continuously by `ContentScanThread` from whatever the last *real* foreground window was — instead of freshly classifying the capture tool's own just-launched window. Keyboard-shortcut-triggered captures are unaffected and still use the fresh classification from the previous fix, since a focus change isn't a concern there.

### Verification

Brace-balance check on screen_capture_monitor.cpp: 0 (matches established baseline).

---

## 📸 Screen Capture Events Inconsistently Detected Sensitive Content — Timing Race With the Background Scanner (July 17, 2026)

### Summary

Taking a screenshot of the same kind of sensitive content (email, Study Report keyword, etc.) sometimes produced a correctly-classified event and sometimes came back "Public" with nothing detected — inconsistent across otherwise-identical tests.

### Root cause

`HandleCaptureAttempt()` in screen_capture_monitor.cpp built the reported event's `classification`/`containsSensitiveData`/`detectedText` fields from `m_screenIsSensitive` / `m_lastScannedText` — values set by a *separate background thread* (`ContentScanThread`) that only re-OCRs the foreground window on its own independent ~1-1.3 second cadence. Pressing PrintScreen doesn't wait for that cycle to land — if the screenshot was taken shortly after a scan cycle had already cached a stale verdict (e.g. right after switching windows, or right after typing new content into the same window), the event reported whatever that last cached scan happened to see, not what was actually on screen at capture time. That's an inherent race, not a one-off bug, which is why it looked random from test to test.

Note this only affected the *reported* classification. The real-time block-or-allow decision correctly still uses the fast cached flag, since the keyboard hook that makes that call must return immediately and can't run OCR synchronously — that part was never the problem.

### Fixed

`HandleCaptureAttempt()` already runs on a detached background thread (dispatched from the keyboard hook, not the hook itself), so there's no real-time constraint stopping it from doing a fresh, synchronous classification of the current foreground window at the moment the event is actually built — instead of trusting the potentially-stale cache. It now calls the same classifier used by `ContentScanThread` directly, and only falls back to the cached scan text if the fresh call finds nothing readable. `actionTaken` (Block/Allow) is unchanged and still reflects what the hook actually enforced in real time.

### Verification

Brace-balance check on screen_capture_monitor.cpp/.h: 0 (matches established baseline).

---

## 🕳️ USB File Transfer Quarantine Never Triggered — Real-Time Evaluation Had No Concept of "Quarantine" (July 17, 2026)

### Summary

With a path-based ("monitoredPaths") USB File Transfer policy set to quarantine, copying a sensitive file (`Configuration.docx`, `MicrosoftAzure.txt`, `Fail2Ban.txt`) onto a USB drive logged "Traditional Policy: USB File Transfer (action: quarantine)" and then... nothing. No block, no quarantine, no error — the file just stayed on the USB drive with no further log output for that transfer at all, across every single test.

### Root cause

Two matching bugs, one on each side of the real-time classification call:

1. **Server** (`server/app/api/v1/agents.py`, `evaluate_policy_realtime()`): the loop that reads each matched policy's configured actions only recognized `action_type == "block"` and `"alert"` — there was no `elif action_type == "quarantine"` case at all. So a quarantine-actioned policy's action was silently ignored, and the endpoint always fell through to its final `action = "block" if should_block else "allow"` — meaning quarantine policies were unconditionally reported back as `"allow"`.
2. **Agent** (`agent.cpp`, `EvaluatePolicyRealtime()`): even if the server had reported the action correctly, the agent computed `result.shouldBlock = (result.action == "block")` and every USB-file-transfer call site branched only on that boolean — `if (evalResult.shouldBlock) { BLOCK } else { ALLOWED }`. There was no path for "quarantine" at all; it would have been funneled into the same "allowed" branch as truly benign content.

Together: any USB file transfer policy configured for quarantine (going through the real-time classification path, which is the normal/common case whenever the classification API call succeeds) was **always silently allowed**, with no enforcement action and no error indicating why.

### Fixed

- `agents.py`: added the missing `elif action_type == "quarantine": should_quarantine = True` case, with response precedence block > quarantine > alert > allow (matching the precedence already used elsewhere, e.g. `agent_policy_transformer.py`).
- `agent.cpp`: both `CheckUSBDriveForMonitoredFiles()` call sites (path-based and classification-only) now dispatch on `evalResult.action` directly (`"block"` / `"quarantine"` / else-allowed) instead of the `shouldBlock` bool that only ever recognized `"block"`, and call `HandleUSBFileTransferQuarantineNoTimestamp()` on the new quarantine branch.

### Verification

Server: `python3 -c "import ast; ast.parse(...)"` — no syntax errors. Agent: brace-balance check on agent.cpp: -5 (matches established baseline).

---

## 🔌 Agent Goes "Offline" When Idle/Locked, Machine's Copy-Paste Breaks, No Auto-Reconnect on Unlock (July 17, 2026)

### Summary

Reported: the dashboard shows the agent offline even though the endpoint is on and has internet; while this happens, the *entire machine's* copy/paste stops working; locking the screen triggers the disconnect, and unlocking never brings it back — only a full reinstall fixed it. Three separate but related bugs, all now fixed.

### Root causes

1. **The clipboard was held open during slow work, freezing copy/paste machine-wide.** `ClipboardMonitor()` called `OpenClipboard()`, then — while still holding it open — ran OCR (an external Tesseract process, can take seconds) and/or full policy classification plus an HTTP POST to the server (`HandleClipboardEvent()` → `SendEvent()`), before finally calling `CloseClipboard()`. The Windows clipboard is a single systemwide resource: while one process holds it open, no other process (Explorer, Office, browsers — anything) can copy or paste. On a slow or degraded network connection to the DLP server, that HTTP call could take up to ~45 seconds (the configured WinHTTP timeout) before failing — and for that whole window, the entire machine's clipboard was unusable. This is exactly the "misbehaves, copy paste stops working" symptom, and it's tied to network health, matching "when the agent machine is disconnect then agent machine is misbehave."
2. **A slow event-send could block the heartbeat, making the agent falsely appear offline.** All server calls (heartbeat, clipboard/file/USB events, policy sync) shared one `httpClient` object guarded by a single mutex that was held for the *entire* network call, not just the pointer access. If any one of those calls got slow (e.g. the same network degradation above), the heartbeat thread would block trying to acquire that same mutex — so heartbeats silently stopped reaching the server, and the dashboard showed the agent offline, even on a machine with working internet.
3. **No awareness of screen lock/unlock at all.** The agent had zero handling for Windows session lock/unlock events, so if anything left it in a bad connection state around a lock, there was no mechanism to detect the unlock and proactively reconnect — it just sat there until the next scheduled heartbeat (or indefinitely, per bug #2 above).

### Fixed

- `ClipboardMonitor()` restructured so only the fast clipboard reads (grab text, or dump the image to a temp file) happen between `OpenClipboard()`/`CloseClipboard()`. OCR and all classification/network work now run strictly *after* the clipboard is already closed. Split `TryOcrClipboardImage()` into `ExtractClipboardDibToBmpFile()` (fast, needs clipboard open) + a separate OCR step (slow, clipboard already closed).
- `httpClient` changed from `unique_ptr` to `shared_ptr`; all ~9 call sites now use a new `GetHttpClient()` helper that holds the mutex only long enough to copy the pointer (a refcount bump), then make their network call unlocked. No call can ever block another anymore — the heartbeat is now completely independent of how slow any other in-flight request is.
- Added `WTSRegisterSessionNotification` on the existing USB-monitor message-only window, handling `WM_WTSSESSION_CHANGE`: on `WTS_SESSION_UNLOCK`, the agent now immediately reinitializes its HTTP client and sends a heartbeat on a background thread, instead of waiting for the next scheduled interval.
- Added `-lwtsapi32` to the Windows build workflow's link step for the new API.

### Verification

Brace-balance check on agent.cpp: -5 (matches established baseline, no structural regression).

---

## 🗄️ USB File Transfer Quarantine Silently Failed for Cross-Volume Moves (July 16, 2026)

### Summary

Testing USB File Transfer Monitoring with action set to "quarantine": the resulting event correctly showed a quarantine outcome, but the file never actually appeared in the configured quarantine directory (`C:\ProgramData\SeceoKnight\quarantine`) on the endpoint.

### Root cause

`HandleUSBFileTransferQuarantineNoTimestamp()` used `fs::rename()` to move the file from the USB drive straight into the quarantine folder. `fs::rename()` on this MinGW build maps to `MoveFileExW()` without the `MOVEFILE_COPY_ALLOWED` flag, which **fails whenever source and destination are on different volumes** (e.g. USB drive `E:\` → local `C:\` quarantine folder) — exactly the case for every USB quarantine action, and especially for classification-only policies (no `monitoredPaths` configured), where the "source" and "USB" paths are literally the same file on the same drive. The 2-minute auto-restore thread had the identical bug in reverse (`C:\` quarantine → back to the USB drive).

### Fixed

Replaced `fs::rename()` with `fs::copy_file()` + `fs::remove()` in both the quarantine action and its 2-minute restore thread — this works reliably across volumes, and matches the pattern the BLOCK handler's MOVE case already used for the same reason. Also added an explicit log line printing the full resolved quarantine destination path, so a future mismatch between configured and actual path is immediately visible in the agent log instead of requiring code inspection.

### Verification

Brace-balance check on agent.cpp: -5 (matches established baseline). Same fix applied to the corresponding (but currently unreachable/dead-code) duplicate handler for consistency, at zero behavior risk.

---

## 📦 USB File Transfer Events Never Marked Blocked/Quarantined in the List (July 16, 2026 — pre-emptive fix ahead of testing)

### Summary

Found while preparing to test USB File Transfer Monitoring: `SendUSBTransferEvent()` in agent.cpp (used by `HandleUSBFileTransferBlockNoTimestamp`/`...QuarantineNoTimestamp`) only sets an `action` string (e.g. `"blocked_copy"`, `"quarantined_move"`, `"allowed"`) — it never sets the top-level `blocked`/`quarantined` booleans the way other event types do. Events.tsx's list row only checked those booleans, so a genuinely blocked or quarantined USB file transfer would render as a plain, unmarked event — the same class of display bug already found and fixed for File System Monitoring and USB Device blocking earlier this week.

### Fixed

`Events.tsx` now also treats a `usb_file_transfer` event as blocked/quarantined when its `action` field starts with `"blocked"`/`"quarantined"` (via a new `usbTransferOutcome()` helper), applied to the row's icon tint, the blocked/quarantined badges, and a new descriptive event-type label ("USB Transfer Blocked" / "USB Transfer Quarantined" / "USB Transfer").

### Verification

`npm run build` (Vite) and `npx tsc --noEmit -p .` succeeded with no new errors (pre-existing unrelated errors in other files only); `dashboard/dist/` reverted after local build.

---

## 🔌 USB Block Event Claimed Success Even When Windows Never Actually Blocked the Drive (July 16, 2026)

### Summary

Testing USB Device Monitoring: with the policy action set to "block," inserting a pendrive produced an event reporting the device as blocked, but the drive remained fully accessible in Windows Explorer. Also, connect and disconnect events were indistinguishable in the Events list without opening each one.

### Root cause

1. **Block event lied about outcome.** `HandleUsbDeviceArrival()` in agent.cpp attempts three block methods in sequence (HKLM registry write to disable the USBSTOR driver, `CM_Disable_DevNode`/SetupDi device disable, and eject IOCTL on removable drives), tracking a `blockSuccess` bool. But the JSON sent to the server unconditionally set `"action": "blocked"` and a "USB device blocked by policy" description regardless of whether `blockSuccess` was true or false — so even a total failure was reported as a successful block.
2. **The failure is expected on this deployment's architecture, not incidental.** `install-agent.ps1` deliberately registers the main agent's scheduled task with `RunLevel Limited` (not elevated) — required because clipboard/keyboard hook-based monitoring breaks if the process runs elevated. But USB blocking (`RegOpenKeyExA(HKEY_LOCAL_MACHINE, ...)`, `CM_Disable_DevNode`) requires admin/SYSTEM rights. Since the real-time monitoring process is intentionally unelevated, both block methods fail with ACCESS_DENIED every time a block is attempted live; only a separate one-shot elevated scheduled task (`SeceoKnight DLP USB Block`, SYSTEM, runs once at boot) has the needed privilege, and it isn't invoked per-policy-match. The eject IOCTL (Method 3) also typically doesn't work on standard USB flash drives even when elevated, since `IOCTL_STORAGE_EJECT_MEDIA` targets media-eject-capable devices (optical drives, some card readers), not generic mass storage.
3. **Events list showed "usb" for every USB event.** The row badge in Events.tsx rendered the raw `event.event_type` field, which is always the literal string `"usb"` for connect, disconnect, and blocked events alike — the distinguishing `event_subtype` (`usb_connect`/`usb_disconnect`/`usb_blocked`) was never surfaced in the list view, only inside the detail modal.

### Fixed

- `agent.cpp`: the blocked-event JSON now reports `action`/`description`/`blocked` based on the real `blockSuccess` result, with a description that explains *why* it may have failed (privilege limitation) instead of always claiming success.
- `Events.tsx`: the list-row badge now shows "USB Connected" / "USB Disconnected" / "USB Blocked" based on `event_subtype` for USB events, instead of the generic `"usb"` string, so connect vs. disconnect is visible without opening the event.

### Known limitation (not fixed, needs a design decision)

Real-time USB block enforcement cannot reliably succeed under the current unelevated agent process model. Making USB block actually work end-to-end would require either: running the whole agent elevated (breaks clipboard/keyboard hooks per the existing install-script comment), or splitting USB blocking into a separate small elevated helper process/service that the main agent signals on a block decision. This needs to be discussed before implementing, since it changes the agent's process architecture.

### Verification

- Brace-balance check on agent.cpp: -5 (matches established baseline, no structural regression).
- `npm run build` (Vite) succeeded with no new errors; `dashboard/dist/` reverted to tracked state after local build.

---

## 🏷️ "Detected Sensitive Data" Widget Showed Stale Labels Despite Correct Detection (July 16, 2026)

### Summary

A browser upload of a file containing an email address, a phone number/bank account reference, and "Study Report" text was tested end-to-end. The raw event confirmed everything actually worked: `classification_metadata.classification_labels` correctly listed `CONTACT, EMAIL, NETWORK, IP_ADDRESS, STUDY_REPORT`, and both the "Browser Upload" and "Sensitive Detection" policies correctly matched on `classification_labels contains STUDY_REPORT`, driving the event to critical/blocked/quarantined. But the dashboard's "Detected Sensitive Data" widget on that same event only showed "EMAIL" — this was a display bug, not a detection failure.

### Root cause

Two different `classification_labels` fields exist on an event: a top-level one (set once from whatever the *agent's own local* classifier detected, e.g. `["EMAIL"]`) and a nested `classification_metadata.classification_labels` one (set later by the *server's* full rule engine, e.g. `["CONTACT","EMAIL","NETWORK","IP_ADDRESS","STUDY_REPORT"]`). `_process_event_background()` in `events.py` already promoted `classification_metadata.classification_level` and `.confidence_score` to their top-level fields after the rule engine ran, but never did the same for `.classification_labels` — so the top-level field stayed frozen at the agent's narrower, original snapshot. The dashboard's "Detected Sensitive Data" widget reads the top-level field, so it never saw the full, correct result even though policy matching (which reads the nested field directly) worked correctly.

### Fixed

- `server/app/api/v1/events.py`: `_process_event_background()` now also promotes `classification_metadata.classification_labels` to the top-level `classification_labels` field when present, matching the existing treatment of `classification_level`/`confidence_score`.

### Verification

`python3 -c "import ast; ast.parse(...)"` confirms valid syntax. Dashboard's `Events.tsx` already reads `event.classification_labels` (confirmed at line 219) — no dashboard change needed, this was purely a server-side gap.

---

## 🔁 Browser Upload Alerts Always Reported the PREVIOUS Upload, Never the Current One (July 16, 2026)

### Summary

After the previous MRU-subkey fix, the very next test showed a new symptom: alerts consistently reported the *previous* test's uploaded file, never the one just uploaded (upload `salary_sheet.txt` → alert shows the earlier screenshot; upload the screenshot again next → alert shows `salary_sheet.txt`). Confirmed as a genuine one-test lag, not a one-off.

### Root cause

The MRU-fallback logic accepted an entry as soon as it differed from the value captured *before* the dialog opened (`mruBefore`), and — critically — if nothing new showed up within the poll window, it fell back to blindly trusting "whatever's in the MRU right now". A web-app-driven upload (Gmail's JS-based attach flow, as opposed to a plain desktop file save) can take longer than any fixed poll window for Windows to actually persist the new MRU entry. When that happens, an *earlier* test's delayed write can land during the *current* test's wait — or, on timeout, "whatever's there" is still whatever the previous test eventually wrote once its own delayed write landed. Either path produces a result that's exactly one test behind, matching what was observed.

### Fixed

- `network_exfil_monitor.cpp`: `GetLastOpenedFileFromMRU()` now optionally returns the winning subkey's own last-write `FILETIME`. The caller captures a `dialogCloseTime` timestamp right when the dialog closes and only accepts an MRU entry whose *own* write time is strictly after that point — not merely "different from before". This also correctly handles re-selecting the same file (its write-time still gets refreshed), so the old "same file re-selected, trust whatever's there" fallback — the actual source of the wrong attributions — was removed entirely. Poll window extended to 10 seconds to give a slow web-upload flow room to actually write the entry; if nothing qualifies within that window, the event is now sent without guessing a filename rather than silently attributing the wrong one.

### Verification

Every changed code block was checked in isolation (fresh parser state) and balances to exactly zero; no duplicated or truncated functions (confirmed via symbol-count grep). The whole-file naive brace counter reads differently than the previous commit's baseline, but this file has 25 raw-string regex literals (e.g. `R"(\d{4})"`) that a naive quote-toggling counter cannot parse correctly regardless of any real edit — already noted as a pre-existing quirk of this specific file in an earlier entry. Not compiled locally (no Windows toolchain in this sandbox) — real verification is two back-to-back upload tests confirming each alert matches its own upload.

---

## 📂 Browser Upload Reported Stale Filename From a Previous, Unrelated Test (July 16, 2026)

### Summary

Uploading `salary_sheet.txt` via Gmail's attach dialog in Chrome produced a browser-upload event, but it reported the file as `Screenshot 2026-07-16 130118.png` — a completely different file from an earlier, unrelated file-system-monitoring test. Confirmed via `seceoknight_agent.log`: the Win32 child-window scan found nothing (expected — Chrome renders its file picker content in a separate process, invisible to `EnumChildWindows`), so the code fell back to the Shell "recently opened files" registry key (`ComDlg32\OpenSavePidlMRU\*`). That key never showed a new entry within the 1-second wait window, so the code gave up and reused whatever was still sitting in that key from the earlier test — logged explicitly as `Shell MRU fallback (same file re-selected)`.

### Root cause

Two compounding issues in `GetLastOpenedFileFromMRU()` / its caller:
1. Windows Explorer maintains the Open/Save MRU **per file extension** (`.txt`, `.png`, etc.) in addition to a generic `*` subkey — the code only ever read `*`, so a selection that Explorer recorded under an extension-specific subkey would never show up as "new" no matter how long it waited.
2. The wait window for a new MRU entry to appear was capped at 1 second, which real-world testing (a web-app upload flow, not a plain desktop file dialog) showed can be too short.

### Fixed

- `network_exfil_monitor.cpp`: `GetLastOpenedFileFromMRU()` now enumerates **every** subkey under `OpenSavePidlMRU` (not just `*`) and returns the entry from whichever subkey has the most recent key-level last-write time, via a new `ReadMruSubkeyLatest()` helper.
- The post-dialog-close wait for a new MRU entry increased from 1 second (10×100ms) to 3 seconds (30×100ms).

### Verification

Brace-balance check on `network_exfil_monitor.cpp` unchanged from its pre-existing baseline (4). Not compiled locally (no Windows toolchain in this sandbox) — real verification is the next Gmail-attach test, confirming the event reports the actual uploaded filename instead of a stale one.

---

## 🌐 Browser Upload Events Never Forwarded Content — Custom Rules Could Never Match (July 16, 2026)

### Summary

While preparing to test Browser Upload Monitoring, found the same content-forwarding gap already fixed for screen_capture and clipboard: browser file-upload events only ever get classified against `NetworkExfilMonitor::ClassifyNetworkContent()`'s fixed local pattern list (credit card, SSN, Aadhaar, PAN, IFSC, phone, email, AWS/private keys, JWT, Indian passport). A custom database Rule like "Study Report" can never match a browser upload, no matter how the policy condition is configured, because the raw file content was never sent to the server at all — only the derived `classification_level`/`classification_labels` from the agent's own fixed pattern set.

### Fixed

- `network_exfil_monitor.cpp`: added a `content` field to `EventFields` and `EmitEvent()`, and wired it up in `HandleBrowserDialogFromHwnd()` so browser-upload events now forward the actual file content (capped at 5000 chars, consistent with other event types). This lets the server's `classify_event()` → `ClassificationEngine` run the full database Rule set against browser uploads too. Confirmed via `database_policy_evaluator.py` that `classification_metadata.classification_labels` (set by `classify_event()`) is read *before* `evaluate_policies()` runs in the same request, so a matching custom Rule will be visible to the policy condition in the same pass — no extra round trip needed.

### Verification

Brace-balance check on `network_exfil_monitor.cpp` unchanged from its pre-existing baseline (4 — not compiler-relevant, just this file's regex/literal quirks tripping up the simple bracket counter). Not compiled locally (no Windows toolchain in this sandbox).

---

## 🏷️ Events List Never Showed a "Quarantined" Tag (July 16, 2026)

### Summary

File System Monitoring is now correctly detecting content (confirmed working — a real quarantined screenshot's event showed "email: 4 found" with the actual matched values) and quarantining the file. But the Events *list* row only ever showed a "blocked" tag when `event.blocked` was true — there was no equivalent tag for `event.quarantined`, so a correctly-quarantined file system event looked identical in the list to a plain unactioned alert; you had to click into the event to see it was actually quarantined.

### Fixed

- `dashboard/src/pages/Events.tsx`: the event list row now also renders a "quarantined" badge when `event.quarantined` (or `action_taken`/`action` equals `"quarantined"`) is true and the event wasn't already blocked, and the row's icon tint now recognizes quarantined events too (previously only checked `blocked`).

### Verification

`npm run build` (Vite) succeeds; `tsc --noEmit` shows no new errors.

---

## 📋 Screen Capture Reported Wrong "content" — Stage 2 Chrome Text Locked Out Stage 4's Real OCR Match (July 16, 2026)

### Summary

Screen capture blocking itself now works correctly (severity "high", classification "Restricted", action "blocked" all confirmed correct in a real test against Snipping Tool). But the raw event's `content` field — what gets forwarded to the server for full Rule-based classification — showed only `"DesktopWindowXamlSource\nSnipping Tool\n"`, the Snipping Tool app's own window chrome text, not the actual sensitive data (Study Report/email/phone) that had been captured. Consequently `detected_content`, `classification_labels`, and `classification_score` all came back empty/zero even on a correctly-blocked event.

### Root cause

`screenClassifier`'s Stage 2 (WM_GETTEXT window-text read) sets `outText` unconditionally whenever it finds *any* text longer than 10 characters — regardless of whether that text actually matched a sensitive pattern. For an app like Snipping Tool, Stage 2 reads its own UI chrome (window class/title text), finds nothing sensitive, and falls through to Stage 4 (OCR of the window's actual pixels — which, for Snipping Tool, shows the captured screenshot itself and is what really matched "Restricted"). But Stage 4 only overwrote `outText` when it was still *empty*, so Stage 2's irrelevant chrome text — already set — silently blocked the real OCR match from ever reaching the reported event.

### Fixed

- `agent.cpp`: Stage 4 now always overwrites `outText` with its OCR text once reached (removed the `if (outText.empty())` guard), since reaching Stage 4 at all means Stage 2/3 didn't already find a match — OCR of the actual window pixels is the more meaningful content in that case.

### Verification

Brace-balance check on `agent.cpp` unchanged from baseline (-5). Not compiled locally (no Windows toolchain in this sandbox) — real verification is the next screenshot-of-sensitive-content test, checking that the raw event's `content` field now shows the actual matched text instead of window chrome.

---

## 🔍 OCR Failures Were Indistinguishable — Added Real stderr Capture (July 16, 2026)

### Summary

`ocr_diagnostics.log` showed nearly every clipboard-image OCR call and every real screenshot `.png` file OCR call failing with "RunHiddenCommand returned 1", *despite* `--tessdata-dir` resolving correctly to an existing directory — while a self-constructed 24bpp BMP (the foreground-window screen-capture path) OCR'd successfully. That pattern (custom-built simple BMP works, clipboard-reconstructed BMP and real screenshot PNGs both fail) points at an image-format-specific decode failure, not a tessdata problem — but `RunHiddenCommand()` redirects Tesseract's stderr to `NUL`, so every possible cause (missing tessdata, corrupt image, unsupported format, wrong arguments) produced the exact same generic "returned 1" with no way to tell them apart.

### Fixed

- `agent.cpp`: added `RunHiddenCommandCaptureStderr()` — identical to `RunHiddenCommand()` except stderr is redirected to a real temp file and read back instead of discarded to `NUL`.
- `RunTesseractOnFile()` now uses this variant and logs Tesseract's actual stderr text into `ocr_diagnostics.log` on any non-zero exit, instead of just the exit code.

### Next step

This is a diagnostics-only change — it does not fix the underlying OCR failure by itself. Once this build is deployed, the next failed OCR attempt will log Tesseract's real error message, which will show the actual cause (e.g. an unsupported image format, a missing decode library in the Tesseract install, a bad file path) instead of a generic exit code.

### Verification

Brace-balance check on `agent.cpp` unchanged from baseline (-5). Not compiled locally (no Windows toolchain in this sandbox).

---

## ⏱️ Screen Capture Rescan Interval Too Slow For Type-Then-Screenshot (July 16, 2026)

### Summary

Even after the previous stale-cache fix (below), screenshots taken immediately after typing/pasting new sensitive content into an already-open window (the exact way this feature gets tested) could still slip through as "no sensitive data" — a residual, narrower race left over from that fix.

### Root cause

`ContentScanThread` only re-classifies the same window once every 3 seconds, and only polls once per second. Typing sensitive text into an open window and immediately hitting PrintScreen (a completely normal, fast user action) can easily land inside that combined ~1-4 second stale window, so the screenshot gets allowed and reported as a plain "screen capture detected — no sensitive data" event with no policy match, even though the on-screen content absolutely matched.

### Fixed

- `screen_capture_monitor.cpp`: `kRescanInterval` reduced from 3s to 1s, and the poll loop's cadence reduced from ~1s to ~300ms. Worst-case staleness drops from ~4s to ~1.3s. Safe to tighten because the classifier's cheap stages (window title keywords, then a `WM_GETTEXT` read of the window's actual text) cover ordinary text apps — Notepad, Word, browsers — with no Tesseract OCR invocation at all; only windows with no readable text at all (pure images, remote desktop) fall through to the OCR stage, so this mostly affects how often those OCR-only windows get re-scanned, not typical text-app usage.

### Verification

Brace-balance check on `screen_capture_monitor.cpp`/`.h` still balances to 0. Not compiled locally (no Windows toolchain in this sandbox) — real verification is the next agent build plus a fresh type-then-immediately-screenshot test.

---

## 🕵️ Screen Capture Stale-Classification Cache + File System Monitoring Had No Content Patterns At All (July 16, 2026)

### Summary

After clipboard OCR started working correctly, screenshots and Downloads file-saves of the same Study Report/email/mobile-number content still only produced generic "normal" events with no detection. Two separate, previously-hidden bugs, one per pipeline.

### Root cause 1 — screen capture cached classification with no expiry

`ContentScanThread`'s background scanner (the ~1Hz loop that decides whether the current foreground window is sensitive) cached its verdict keyed on `(window handle, window title)` with **no time-based expiry**. If a window (e.g. an already-open Notepad, title unchanged) was scanned once and classified "Public" *before* the user typed or pasted new sensitive content into it, every subsequent screenshot of that same window kept reusing the stale "Public" verdict indefinitely — the classifier was never invoked again until the user switched windows (changing the cache key). This fully explained "OCR works (confirmed via logs) but the actual test screenshot still doesn't detect."

### Root cause 2 — File System Monitoring policies have no content-pattern selector

Unlike Clipboard Monitoring (which has a "Detection Patterns" section — predefined pattern toggles + custom regex builder), the File System Monitoring policy form only ever exposed monitored paths, file extensions, and action. There was no way to tell it *what content* to look for. With `dataTypes` always empty, `ContentClassifier::Classify()` on the agent falls through to a generic "pure monitoring" path that alerts/quarantines on any matching file regardless of content — so a Downloads screenshot always produced a bare "file accessed" event, never a specific content match, no matter how good OCR was.

Separately, even a *correctly configured* custom pattern would have failed silently: `patterns.custom` is an array of **objects** (`{"regex": "...", "description": "..."}`), but the agent's `ExtractJsonArray()` only understands arrays of plain quoted strings — object arrays were silently skipped. And even a correctly-parsed custom regex had nowhere to go: `ExtractDataType()`'s dispatch only recognized ~17 built-in names (email, phone, ssn, etc.) with no fallback for an arbitrary custom pattern string.

### Fixed

- `screen_capture_monitor.cpp`: `ContentScanThread` now re-classifies the same window at most every 3 seconds instead of caching by identity forever, catching content typed/pasted into an already-focused window while still avoiding hammering Tesseract on a truly idle desktop.
- `dashboard/src/types/policy.ts` + `FileSystemPolicyForm.tsx`: added the same "Detection Patterns" section Clipboard Monitoring already has (predefined pattern toggles + custom regex builder with regex validation/testing) to File System Monitoring policies.
- `agent.cpp`: added `ExtractJsonObjectArrayField()` — a string-literal-aware parser for arrays of JSON objects — and switched `patterns.custom` parsing (both clipboard and file-system policies) to use it instead of the string-only `ExtractJsonArray()`, so custom regex patterns actually reach `rule.dataTypes` now.
- `agent.cpp`: `ExtractDataType()` gained a fallback case for any dataType name it doesn't recognize as a built-in type — tries it as a regex directly, falling back to a plain case-insensitive substring search if it isn't valid regex syntax (so simple keyword rules like "Study Report" work even without proper regex escaping).

### Verification

Not compiled locally (no Windows toolchain in this sandbox). Brace-balance check on `agent.cpp` unchanged (-5 baseline); `screen_capture_monitor.cpp` still balances to 0. Dashboard: `npm run build` (Vite) succeeds; `tsc --noEmit` shows no new errors in any changed file. Real verification is the next `build-windows-agent.yml` run plus a fresh dashboard deploy — after which the File System Monitoring policy needs its new Detection Patterns actually selected/added (existing policies won't have any until edited).

---

## 🖼️ Clipboard Image OCR — Malformed BMP for 16/32-bpp Captures (BI_BITFIELDS) (July 16, 2026)

### Summary

Real-world testing after the tessdata-dir fix showed foreground-window screen-capture OCR succeeding reliably (1000+ chars extracted, correct classification, blocking engaged), while clipboard-image OCR kept failing with the exact same "RunHiddenCommand returned 1" error, tessdata-dir included. Same Tesseract binary, same tessdata, same helper function (`RunTesseractOnFile`) — only the clipboard path failed, which ruled out tessdata as the cause for this specific failure.

### Root cause

`TryOcrClipboardImage()` reconstructs a standalone `.bmp` file from the clipboard's `CF_DIB` data by prepending a `BITMAPFILEHEADER`. It correctly accounted for a palette on ≤8bpp images, but never accounted for `BI_BITFIELDS` compression — the format Windows commonly uses for 16/32-bpp captures (very common for clipboard screenshots from Snipping Tool, browsers, etc.), which stores 3 DWORD color-channel masks immediately after the header instead of a palette. Without that adjustment, `bfOffBits` pointed into the mask table instead of the actual pixel data, producing a structurally invalid BMP that Tesseract/leptonica couldn't parse — exiting non-zero on every single clipboard-image OCR call. Foreground-window OCR was unaffected because it always builds its own plain 24-bit `BI_RGB` bitmap with no masks at all.

### Fixed

`TryOcrClipboardImage()` now adds `3 * sizeof(DWORD)` to `headerSize` when `biCompression == BI_BITFIELDS`, correctly positioning `bfOffBits` at the real start of pixel data regardless of bit depth.

### Verification

Not compiled locally (no Windows toolchain in this sandbox). Brace-balance check unchanged (still -5 baseline). Real verification is the next `build-windows-agent.yml` run, followed by a real clipboard-image-paste test checking `ocr_diagnostics.log` stays clean.

---

## 🖥️ Screen Capture — Only Checked 7 Hardcoded Patterns, Never Saw Custom Rules/Email/Phone (July 15, 2026)

### Summary

A screenshot containing a Study Report keyword match, an email address, and a mobile number only ever produced a plain "Screen capture" event with no detection, even with OCR working correctly (confirmed via `ocr_diagnostics.log` showing no failures). Root cause: screen-capture classification is architecturally isolated from every other detection path in this codebase.

### Root cause

`screenClassifier` in `agent.cpp` (used only for live screen-capture alerts) is a fully self-contained lambda with its own hardcoded, compiled-in regex list: AADHAAR, PAN, Credit Card, SSN, private keys, AWS keys, IFSC codes — 7 patterns total, no more, no less. Unlike file-write/clipboard/USB-transfer monitoring, it never calls `ContentClassifier::Classify()` against server-synced policies, and the OCR/window text it reads was never even sent to the server — the outgoing `screen_capture` event JSON had no `content`/text field at all. Two consequences: (1) common types like Email and Phone, which every other monitoring path already detects via `ExtractDataType()`, were silently absent from screen capture specifically; (2) anything relying on the server's full rule engine — custom rules like a user-defined "Study Report" keyword rule — had literally no way to ever see screen-capture content, since the text never left the agent.

### Fixed

- `screen_capture_monitor.h`/`.cpp`: `ClassifyCallback` now takes an `outExtractedText` out-parameter; added a mutex-guarded `m_lastScannedText` member so whichever thread last ran the classifier (the ~1Hz `ContentScanThread` poll loop, or `ProcessMonitorThread`'s capture-tool-launch check) can hand its text to `HandleCaptureAttempt()`. `ScreenCaptureEvent` gained a `detectedText` field.
- `agent.cpp`: `screenClassifier` now populates that out-parameter with whatever it read (WM_GETTEXT window text, or OCR output when window text wasn't available), and the outgoing event JSON now includes it as `"content"` (capped at 5000 chars, same convention used for file/clipboard event content). The server's existing `classify_event()` pipeline (`event_processor.py`) already classifies *any* event with a `content` field using the full database rule engine — no server-side changes were needed for this to start working end-to-end.
- Added `EMAIL` and `PHONE_IN` to `screenClassifier`'s own local pattern list (same regexes already used by `ExtractDataType` elsewhere), so those two common types are now detected immediately/locally, not just after a round trip to the server.

### Important caveat

Real-time *blocking* of the screenshot itself (the keyboard-hook swallow) is still decided purely by the agent's local classifier — now 9 patterns instead of 7, but still not custom server rules. The server-side rule match (which does include custom rules like Study Report) lands on the event shortly after it's emitted, populating `classification_metadata.classification_labels`/severity for alerting and dashboard/policy purposes — it does not retroactively stop a screenshot that already happened. Making custom rules block screen captures in real time would require syncing rule definitions to the agent for local evaluation, which hasn't been done here.

### Verification

Not compiled locally (no Windows toolchain in this sandbox). Verified structurally: brace-balance check unchanged for `agent.cpp` (still the known -5 baseline) and comes out to a clean 0 for both `screen_capture_monitor.h` and `.cpp`. Confirmed no other call sites still use the old 2-argument `ClassifyCallback` signature (`grep` across both files). Traced `event_processor.py`'s `classify_event()` to confirm it classifies any event with a `content` field regardless of `event_type`, so no server-side change was required. Real verification is the next `build-windows-agent.yml` run.

---

## 🚫 File System Monitoring — Two More "Detection-Only" Blockers Found (Frontend Validator + Linux Agent) (July 15, 2026)

### Summary

After the backend/dashboard-form fix below shipped, saving a File System Monitoring policy with action = Quarantine still failed with "File System Monitoring is Detection-only (alert/log)". The transformer fix wasn't the only place this restriction was enforced — it turned out to be duplicated in two more places that the previous pass missed.

### Root cause

1. `dashboard/src/utils/policyUtils.ts` — the client-side form validator for `file_system_monitoring` rejected any `action` other than `alert`/`log` before the request was even sent, with the exact error text the user saw.
2. `agents/endpoint/linux/agent.py` — the Linux agent's file-event handler had its own explicit `# File system monitoring is detection-only: ignore block/quarantine` guard that silently downgraded any `block`/`quarantine` policy action to `log`, same as the Windows agent's old backend-level restriction, just enforced agent-side instead.

### Fixed

- `policyUtils.ts`: validator now allows `quarantine`/`block`, only requiring a `quarantinePath` when action is `quarantine` (matching the existing USB Transfer / File Transfer validators).
- `agent.py` (Linux): the file-event handler now actually calls the existing `quarantine_file()` / `block_file_transfer()` helpers (already used by the file-transfer-destination handler) for `quarantine`/`block` actions, instead of forcing everything to `log`. Delete events still skip destructive actions (avoids quarantining/deleting a file that's already gone during a move/rename).
- `FileSystemPolicyForm.tsx`: updated the quarantine-path hint text to reflect that the path is now a real, required destination rather than an optional override.

### Verification

`python3 -m ast` parse check on `agent.py` (Linux) — no syntax errors. `npm run build` (Vite) succeeds. Not tested against a live Linux agent (no Linux endpoint in this environment) — logic directly mirrors the already-working `handle_transfer_destination_event()` quarantine/block path in the same file.

---

## 🚫 File System Monitoring — Add Quarantine/Block (was Alert-Only by Design) (July 15, 2026)

### Summary

After the OCR/tessdata fix below shipped, a Study Report screenshot saved to Downloads was correctly detected by File System Monitoring (confirmed via the fresh agent log — the policy fired, OCR read the file) but the file was never removed. Root cause turned out to be a deliberate, pre-existing restriction, not a bug in today's OCR work.

### Root cause

`_transform_file_system_config()` in `server/app/utils/policy_transformer.py` explicitly enforced "detection-only" semantics for the `file_system_monitoring` policy type: `if action not in {"alert", "log"}: action = "log"`, regardless of what was requested. The dashboard's `FileSystemPolicyForm.tsx` matched this — it only ever offered "Alert" and "Log Only" as options, with no way to select Quarantine or Block. Every other monitoring type (USB Transfer, File Transfer) already supported the full `alert | log | quarantine | block` set, and the agent's own enforcement code (`agent.cpp`, `ContentClassifier::Classify`) has always handled `quarantine`/`block` generically for any matched policy — this was the one policy type the backend deliberately withheld it from.

### Fixed

- `server/app/utils/policy_transformer.py`: `_transform_file_system_config()` now accepts `quarantine` and `block` (with an optional `quarantinePath`), mirroring the existing USB Transfer / File Transfer transformers. Falls back to `log` for anything unrecognized.
- `dashboard/src/types/policy.ts`: `FileSystemAction` widened to `'alert' | 'log' | 'quarantine' | 'block'`; `FileSystemConfig` gained an optional `quarantinePath`.
- `dashboard/src/components/policies/FileSystemPolicyForm.tsx`: added Block and Quarantine (with a quarantine-path input, defaulting to the agent's own quarantine folder if left blank) options alongside the existing Alert/Log Only choices.

### Also noted (not changed yet, flagging for awareness)

Screen Capture alerts use a **separate, hardcoded local classifier** (`screenClassifier` in `agent.cpp`) that only recognizes 7 fixed patterns — Aadhaar, PAN, Credit Card (Luhn-checked), SSN, private keys, AWS keys, IFSC codes. It does **not** know about custom rules created in the dashboard (like a "Study Report" keyword rule) or generic Email/phone patterns — so a screen-capture-only test with those data types will legitimately show "Public/low" even with working OCR. Only File System / Clipboard / USB Transfer monitoring consult the server-synced rule set (which does include custom rules, Email, etc.). Extending screen-capture to consult synced rules is a larger change and hasn't been done here.

### Verification

Backend change verified directly (`_transform_file_system_config` called in-sandbox with quarantine/block/invalid inputs, confirmed correct `actions` dict for each). Frontend verified with `npm run build` (Vite) — succeeds with no new errors; `tsc --noEmit` shows only pre-existing, unrelated errors in other files (confirmed absent from `FileSystemPolicyForm.tsx` specifically, both before and after this change).

---

## 🪵 Windows Agent — Log File Silently Stopped Updating + OCR Failures Were Invisible (July 15, 2026)

### Summary

After the quarantine fix above shipped, real-world retesting of the Study Report screenshot showed a new symptom: only the generic "Screen capture" event fired — the restricted-content detection that used to fire on the exact same test no longer did. Investigation was blocked by a second issue found along the way: the agent's log file hadn't been written to in 9 days, despite the agent process visibly running.

### Root cause (two separate bugs)

1. **Log file silently stopped writing.** `Logger`'s constructor defaults to a *relative* filename (`seceoknight_agent.log`) when `SECEOKNIGHT_LOG_DIR` isn't set — which it never was, since `install-agent.ps1` writes a `log_path` key into `agent_config.json` that the agent never actually reads. The relative path resolves against the process's current directory, which for the scheduled task is `C:\Program Files\SeceoKnight` — a UAC-protected folder the agent's normal, non-admin user (required for clipboard/screen hooks) can't write into. `OpenLogFile()`'s failure warning goes to `stderr`, which nobody sees in background mode, so this failed completely silently on every run. The only log content that ever existed was from a one-off run that happened to have write access.
2. **OCR failures were completely silent.** `RunTesseractOnFile()`, `ExtractPdfTextLayer()`, and `OcrScannedPdf()` (the free functions that shell out to `tesseract`/`pdftotext`/`pdftoppm` since the `RunHiddenCommand()` rewrite) return `""` on *any* failure — process launch failure, non-zero exit, or empty output — with zero logging anywhere. Combined with bug #1, there was no way to tell whether the screenshot regression was actually an OCR failure or a genuine "no restricted content found" result.

### Fixed

- `Logger`'s default (no `SECEOKNIGHT_LOG_DIR` set) now points at `C:\ProgramData\SeceoKnight\logs` — the same non-admin-writable location already proven to work for the quarantine folder — instead of a cwd-relative path, and creates the directory if missing.
- Added `ResolveOcrToolPath()`: prefers the Chocolatey shim (`C:\ProgramData\chocolatey\bin\<tool>.exe`, stable across package versions) or Tesseract's known install path, over handing `CreateProcess` a bare command name to resolve against PATH on its own. Falls back to the old bare-name behavior if neither is found.
- Added `LogOcrDiagnostic()`, writing timestamped one-liners to `C:\ProgramData\SeceoKnight\logs\ocr_diagnostics.log` whenever `RunHiddenCommand()` fails to launch/returns non-zero, or OCR produces no text, for all three OCR call sites. This is independent of the main `Logger` (a `DLPAgent` member the free OCR functions can't reach) and now gives real visibility into OCR failures in background mode, which previously had none.
- `install-agent.ps1`'s post-install output now points at the correct log location and lists the new OCR diagnostics file.

### Verification

Not compiled locally (no Windows toolchain in this sandbox). Verified structurally — brace-balance check across the whole file gives the same pre-existing offset (-5) before and after these edits. Real compiler verification is the next `build-windows-agent.yml` run. Next real-world test: reinstall, repeat the Study Report screenshot, and check both `C:\ProgramData\SeceoKnight\logs\seceoknight_agent.log` (should now update in real time) and `ocr_diagnostics.log` (should be empty if OCR succeeds, or show exactly why it didn't if not).

---

## 🔒 Windows Agent — Quarantine Silently Failed for Non-Admin User (July 15, 2026)

### Summary

During file-write OCR testing, a screenshot containing restricted content generated an alert correctly labeled "blocked" — but the file was never actually removed from Downloads.

### Root cause

`Config::LoadFromFile()` — the function that parses the real `agent_config.json` written by `install-agent.ps1` — only ever read 5 keys (`server_url`, `agent_name`, `agent_id`, `heartbeat_interval`, `policy_sync_interval`). The `quarantine_path` key that `install-agent.ps1` Step 7 writes (pointing at `C:\ProgramData\SeceoKnight\quarantine`, which Step 3 pre-creates) was silently ignored. The agent always fell back to a hardcoded `C:\Quarantine` — a path at the system drive root that a standard, non-elevated Windows user (which is exactly what the agent's scheduled task runs as, by design, since clipboard/screen hooks require non-admin "Interactive" logon) typically cannot create or write to. When the agent tried to `fs::rename()` the offending file there, it hit a permissions exception, which the surrounding `catch` block logged and silently swallowed — the classification/alert pipeline (which runs independently and had already correctly determined the content was restricted) still reported "blocked" as the *intended* action, but enforcement never actually happened.

### Fixed

- `agent.cpp`'s `LoadFromFile()` now reads `quarantine_path` via the existing `ExtractJsonValue()` helper, falling back to `C:\ProgramData\SeceoKnight\quarantine` (not `C:\Quarantine`) if the key is missing.
- Also corrected the constructor's own hardcoded default (used before any config file is loaded) to the same non-admin-writable path, for consistency.

### Verification

Not compiled locally (no Windows toolchain in this sandbox). Verified structurally (brace balance unchanged). Confirmed `C:\ProgramData\SeceoKnight\quarantine` is the exact path `install-agent.ps1` already creates and that a standard user can write to, so no install-script changes are needed — this is purely an agent-side fix to make it actually read the config it's already been given. Real verification is the next `build-windows-agent.yml` run.

---

## 🪟 Windows Agent — Fix Background Mode Actually Showing a Console (July 15, 2026)

### Summary

Reported after real-world testing: the Windows agent, installed via `install-agent.ps1` and launched through the "SeceoKnight DLP Agent" scheduled task with `--bg`, was still showing a visible cmd window streaming logs — and closing that window disconnected the agent entirely.

### Root cause

`agent.cpp` was compiled as a **console-subsystem** binary (`build.sh` / `build-windows-agent.yml` had no subsystem flag, which defaults to console). Windows creates and displays a console-subsystem process's console window the instant the process starts — before `main()` runs. The old `--bg` handling only *hid* that window after the fact (`GetConsoleWindow()` + `ShowWindow(SW_HIDE)`), which is inherently racy: there's always at least a brief window where it's visible, and longer if startup is slowed by antivirus or Task Scheduler's interactive-session launch. Because it genuinely was the process's own console, closing it fired `CTRL_CLOSE_EVENT`, which tore down the whole agent — exactly the reported symptom.

### Fixed

- **`build.sh`** / **`.github/workflows/build-windows-agent.yml`** — added `-mwindows` so the binary is built as a **GUI-subsystem** executable. The OS never auto-creates a console for it, in any launch mode.
- **`agent.cpp`** — replaced `HideConsoleWindow()` (reactive hide) with `AttachForegroundConsole()`, called only when running in foreground/manual mode (i.e. *not* `--bg`). It explicitly `AllocConsole()`s and redirects `stdout`/`stderr`/`stdin` so `std::cout` output is still visible when you deliberately want to watch it run. In `--bg` mode nothing calls this — no console is ever created, so there is no window for a user to see, and none to accidentally close and kill the agent. The existing `Logger::Log()` already only echoed to console `if (consoleWindow != NULL && IsWindowVisible(...))` and always wrote to the log file regardless, so background-mode file logging is unaffected.

### Verification

`agent.cpp` cannot be compiled in this Linux sandbox (no MinGW cross-toolchain, no root to install one) — this is Windows-specific C++ (`winsock2.h`, `windows.h`, `wbemidl.h`, etc.). Verified structurally instead: confirmed the edited `if`/`else` block's braces close correctly by direct inspection, and ran a brace-balance check across the whole file before and after the edit — both give the identical (pre-existing, parser-artifact) offset, confirming the edit introduces no imbalance. Real compiler verification will happen via `build-windows-agent.yml` (`windows-latest` + real MinGW) once this is pushed, since `agent.cpp` is in that workflow's trigger paths — check the Actions tab for a green run before re-deploying the agent.

### Follow-up: OCR helpers still flashed a console after the above fix (same day)

After the `-mwindows` change above shipped, real-world testing surfaced a second, related symptom: a cmd window would flash open and close briefly whenever a file was opened/saved or something was copied to the clipboard — i.e. whenever the OCR pipeline ran.

**Root cause:** `RunTesseractOnFile()`, `ExtractPdfTextLayer()`, and `OcrScannedPdf()` all shelled out via `system()` to run `tesseract`/`pdftotext`/`pdftoppm`. Before the GUI-subsystem change, `system()`'s child `cmd.exe` silently inherited the agent's own (hidden) console — no visible window. Once the agent became a GUI-subsystem process with *no* console at all, `system()` had nothing to inherit, so Windows had to create a brand-new — visible — console for every single OCR invocation, which fires on every file write, USB transfer, and clipboard image paste that reaches the OCR helpers.

**Fixed:** added `RunHiddenCommand()`, a `system()`-equivalent built on `CreateProcessA(..., CREATE_NO_WINDOW | DETACHED_PROCESS, ...)` — the same flag combination the existing auto-updater launch elsewhere in this file already used successfully. Replaced all three `system()` call sites with it. No other `system()` calls remain in `agent.cpp`.

**Verification:** same constraint as above (no Windows toolchain in this sandbox) — verified structurally (brace balance unchanged, `CreateProcessA`/`STARTUPINFOA`/`PROCESS_INFORMATION` already used correctly elsewhere in this exact file, `WaitForSingleObject`/`GetExitCodeProcess` are standard `<windows.h>` APIs). Real verification is the next `build-windows-agent.yml` run.

### Follow-up 2: continuous flashing on ordinary activity (select/copy) — real root cause found (same day)

After both fixes above shipped and were confirmed built (verified against the CI bot's binary-update commit timestamp), the user still reported near-continuous console flashing tied to ordinary activity like selecting text or copying — bad enough to make the machine hard to use.

**Root cause — a genuine pre-existing bug, not a console-suppression issue:** `ClipboardMonitor()` polls the clipboard every 2 seconds. Its text path already deduped correctly (`text != lastClipboard`), but its image path did not: whenever there was no *new* text that cycle, it unconditionally called `TryOcrClipboardImage()`, which reads whatever `CF_DIB` bitmap happens to be sitting on the clipboard and OCRs it — **every single 2-second cycle, for as long as that bitmap remains**, not just once when it first appears. Its own dedup check (`ocrText != lastClipboard`) only runs *after* Tesseract has already executed, so it prevented duplicate alerts but not duplicate OCR runs. Because many ordinary rich-text copies (Word, Outlook, browsers) leave a `CF_DIB` bitmap on the clipboard alongside the plain text as a paste-compatibility side effect, this meant Tesseract — and therefore a `RunHiddenCommand()` console launch — was firing every 2 seconds indefinitely, completely independent of any real user action. That's the "continuous" flashing: not activity-triggered at all, just a fixed timer, made to look activity-correlated because the user was actively working during those 2-second windows.

**Fixed:**
- `DLPAgent` gained a `lastClipboardSeq` member. `ClipboardMonitor()` now calls `GetClipboardSequenceNumber()` — the Windows-native "did the clipboard change at all, in any format" counter — at the top of each poll and skips the entire read-and-classify pass (both the text *and* image checks) unless it has advanced since the last pass. This closes the bug for good: OCR now only ever runs once per actual clipboard change, never on a repeat of the same still-there content.
- Hardened `RunHiddenCommand()` as defense-in-depth: added `STARTF_USESHOWWINDOW` + `SW_HIDE` in the `STARTUPINFO` alongside the existing `CREATE_NO_WINDOW | DETACHED_PROCESS` flags, since some environments (older Windows builds, certain AV/EDR hooks) have been reported to not fully honor `CREATE_NO_WINDOW` alone.

**Verification:** same sandbox constraint as the prior two entries — verified structurally (brace balance unchanged, `GetClipboardSequenceNumber` is a standard `<windows.h>` API, `STARTF_USESHOWWINDOW`/`SW_HIDE` are documented `STARTUPINFO` fields). Real verification is the next `build-windows-agent.yml` run — check its timestamp against the current time before reinstalling, the same way the previous two fixes were confirmed.

### Follow-up 3: flash confirmed on the verified-correct binary — CreateProcess flags weren't enough (same day)

The user confirmed, via `Get-FileHash`, they were genuinely running the binary containing all three fixes above — and the flash still occurred, console titled `tesseract "C:\Users\...`. This ruled out "stale binary" and meant the `CREATE_NO_WINDOW | DETACHED_PROCESS` + `STARTF_USESHOWWINDOW/SW_HIDE` flag combination was not fully suppressing the window in this environment (plausibly an AV/EDR hook on `CreateProcess`, or a Windows-build-specific timing quirk — a console-subsystem child's C runtime requests a console during startup whenever its inherited standard handles aren't valid, and that request can itself cause a flash before any hide flag is applied).

**Fixed — a fundamentally different, more robust approach:** `RunHiddenCommand()` no longer wraps commands in `cmd.exe /c` at all. It invokes `tesseract.exe` / `pdftotext.exe` / `pdftoppm.exe` directly (`CreateProcess` resolves the first token against `PATH` the same way `cmd.exe` would), and gives the child real, valid standard handles pointed at the `NUL` device via `STARTF_USESTDHANDLES` before it ever starts — so the child's C runtime has no reason to request a console in the first place, rather than requesting one and then trying to hide it after the fact. This removes cmd.exe as an intermediate process entirely and removes the two-step "create then hide" race that the previous three attempts were all still exposed to. The `2>nul` shell-redirection syntax was removed from all three call sites' command strings (no longer meaningful without a shell — stderr redirection is now handled via the real `hStdError` handle).

**Verification:** same sandbox constraint as all prior entries in this section. Verified structurally (brace balance unchanged); confirmed `CreateFileA("NUL", ...)`, `STARTF_USESTDHANDLES`, and `bInheritHandle`/`bInheritHandles` are all standard, correctly-paired `<windows.h>` APIs for this exact "redirect a child's stdio to NUL" pattern. Real verification is the next `build-windows-agent.yml` run.

---

## 📡 SIEM Syslog Forwarding (Wazuh / QRadar / ArcSight) + Connector Persistence (July 15, 2026)

### Summary

SeceoKnight's SIEM integration previously only supported Splunk (HEC) and ELK (Elasticsearch bulk API) — both HTTP-push connectors. There was no way to forward DLP events to syslog-based SIEMs such as Wazuh, QRadar, ArcSight, LogRhythm, Graylog, or plain rsyslog/syslog-ng, which is how most on-prem SOC tooling actually ingests logs. Registered connectors also lived only in memory and were lost on every restart, so any SIEM integration had to be manually re-registered via the API after each deploy. Both gaps are closed.

### Added

- **`server/app/integrations/siem/syslog_connector.py`** (new) — `SyslogConnector`, a write-only RFC 5424 syslog forwarder supporting UDP (fire-and-forget), TCP (RFC 6587 LF-framed), and TCP+TLS transport, with event payloads in CEF (ArcSight Common Event Format) or LEEF 2.0 (QRadar Log Event Extended Format). Per-connector minimum-severity filtering and syslog facility selection (local0–local7). Socket I/O is blocking and always dispatched via `asyncio.to_thread` so it never stalls the event loop.
- **`SIEMType.SYSLOG`** added to `server/app/integrations/siem/base.py`'s enum.
- **`server/app/models/siem_connector.py`** (new) — `SIEMConnectorConfigModel`, persists registered connector configuration (host/port/protocol/format/facility/severity threshold for syslog; index/source/sourcetype for Splunk/ELK). Secret fields (`password`, `api_key`, `hec_token`) are stored Fernet-encrypted (`app/core/crypto.py`) in a `secrets_enc` column, never in plaintext.
- **`server/app/integrations/siem/registry.py`** (new) — bridges the DB table and the in-memory `SIEMIntegrationService` registry: `build_connector()` (config → live connector), `persist_connector()` (encrypted upsert), `delete_persisted_connector()`, and `load_persisted_connectors()` which rebuilds and reconnects every enabled connector on server startup.
- **`server/alembic/versions/031_siem_connectors.py`** (new) — idempotent `CREATE TABLE IF NOT EXISTS siem_connectors` migration.
- **`server/app/main.py`** — wired `load_persisted_connectors()` into the startup lifespan, right after OpenSearch init, so previously-registered connectors reconnect automatically on every restart instead of silently vanishing.
- **`server/app/api/v1/siem.py`** — `POST /siem/connectors` now accepts `siem_type: "syslog"` plus `protocol`/`log_format`/`facility`/`min_severity`, and persists every registration (`db: AsyncSession` dependency added to the register/unregister routes). The SSRF host guard now has two modes: the existing strict `_BLOCKED_NETWORKS` list (loopback/RFC1918/link-local/metadata/multicast/IPv6-ULA) still applies to HTTP-push connectors (Splunk/ELK), while write-only syslog connectors use a relaxed `_ALWAYS_BLOCKED_NETWORKS` list that only blocks metadata/link-local/multicast/bogon ranges — on-prem SIEMs legitimately live on RFC1918/loopback addresses, and syslog is fire-and-forget with no response channel, so the SSRF exfiltration risk that justified the strict block for HTTP connectors doesn't apply here.
- **`server/app/integrations/siem/integration_service.py`** — `list_connectors()` now also returns `host`/`port`/`protocol`/`format`/`min_severity` per connector (previously only `name`/`siem_type`/`connected`/`active`), needed for the new dashboard connector table.
- **`dashboard/src/lib/api.ts`** — `getSiemConnectors`, `registerSyslogConnector`, `testSiemConnector`, `deleteSiemConnector`, and the `SiemConnector` type.
- **`dashboard/src/components/settings/SiemForwardingSection.tsx`** (new) — Settings → System panel (Super Admin only) listing registered connectors (destination, transport, format, min severity, live connected/down status) with test and delete actions, plus a form to register a new syslog connector.

### Fixed in passing

- `siem.py`'s structured-logging calls previously read `current_user.get("sub")`, but `require_role(...)` actually returns a `User` ORM object (not a dict) — every log call in this router would have raised `AttributeError` at runtime. Added a `_uid()` helper that handles both shapes and applied it throughout the file.

### Verification

All new/modified Python modules parse and import cleanly (`ast.parse` + live import smoke test with the FastAPI app's real dependency chain, isolating out unrelated sandbox-only missing packages). Confirmed `031_siem_connectors` chains correctly off the existing migration head (`030_retention_config`) with no competing branch. `npx tsc --noEmit` and `npm run build` show no new errors — the pre-existing ~27 TypeScript errors in the policy-form ecosystem are unchanged and untouched by this work.

---

## 📋 Compliance Report Templates — GDPR Art. 30 / HIPAA Breach / PCI Scope (July 14, 2026)

### Summary

Closed the "No Compliance Report Templates" gap from `ENTERPRISE_AUDIT.md` (was P2, 1 week estimate). The existing on-demand reporting pipeline (`POST /api/v1/reports/generate` → Celery task → branded PDF/CSV via `ExportService`) previously only produced generic summary/trends/violators-style analytics reports — nothing shaped for an actual regulatory filing. Three new report types close that gap.

### Added

- **`server/app/services/compliance_report_service.py`** (new) — `ComplianceReportService` with three data-fetching methods:
  - `get_gdpr_article_30_data()` — Records of Processing Activities: derives processing activities from active policies, categories of personal data from `DataLabel`, categories of data subjects from event department breakdowns, and retention periods from `RetentionConfig`. Controller identity, recipients, and third-country transfers are **not** in the schema and are returned explicitly flagged `manual_review_required: true` rather than fabricated.
  - `get_hipaa_breach_notification_data()` — surfaces candidate PHI-related incidents via keyword-matched classification labels, distinguishing `action=blocked/quarantined` (prevented) from `action=allowed/logged` (likely exposure). The legal risk-of-harm determination required by 45 CFR 164.402 is explicitly left for a privacy officer, not decided by the system.
  - `get_pci_dss_scope_data()` — DLP-visibility CDE scope: PCI-tagged policies, the endpoints they're applied to (via `PolicyAgent`), real cardholder-data-pattern detections in the period, and flagged `ClassifiedFile` rows. Framed throughout as DLP visibility, not a certified QSA scope determination.
- **`server/app/services/export_service.py`** — three new PDF content builders (`_create_gdpr_art30_pdf_content`, `_create_hipaa_breach_pdf_content`, `_create_pci_scope_pdf_content`) registered in the existing `export_to_pdf` dispatch table, plus matching CSV branches in `export_analytics_to_csv`. Added a shared `_manual_review_box()` helper that renders unanswerable legal/identity fields in an amber-bordered "REQUIRES MANUAL COMPLETION" callout so they can never be mistaken for a completed answer.
- **`server/app/api/v1/reports.py`** / **`server/app/tasks/reporting_tasks.py`** — new `report_type` slugs `gdpr_art30`, `hipaa_breach`, `pci_scope` threaded through the API's `valid_types` gate and the Celery task's `_fetch_report_data()` dispatch + PDF title map.
- **`dashboard/src/pages/Reports.tsx`** — three new entries in the report-type selection grid.
- **`server/tests/test_compliance_reports.py`** (new, 12 tests) — covers real-data population for all three report types, keyword-match filtering (PHI/PCI included vs. excluded), exposure-vs-prevented classification for HIPAA, and — the important half — that every field the schema can't answer comes back `None` + `manual_review_required: true` rather than guessed.

### Verification

Ran the 12 new tests against the in-memory SQLite test DB (all passing) and separately generated real PDF/CSV output for all three types — including empty-state (no matching policies/events/incidents) — via direct `ExportService` calls with data shaped exactly like each fetcher's real output, confirming valid non-empty PDFs (`%PDF` header) and correct CSV columns with no rendering exceptions.

### Caveat

Keyword-based PHI/PCI matching (`"phi"`, `"hipaa"`, `"pci"`, `"credit_card"`, etc. against `DataLabel.name`) is a best-effort filter, not a certified detector — it only catches what a DataLabel was actually named. No human compliance reviewer has looked at an actual generated report yet; have a DPO/privacy officer sanity-check the first real one before relying on it externally. See `ENTERPRISE_AUDIT.md` gap #8 for the full breakdown of what's automated versus what's flagged for manual completion.

---

## 📄 PDF Content Extraction (Text Layer + Scanned-Page OCR) (July 14, 2026)

### Summary

Extended the same-day file/USB OCR work to PDFs — the highest-value gap, since confidential contracts, HR records, and financial documents are routinely shared as PDFs, and a scanned/photographed PDF page previously had zero content visibility (raw binary bytes fed uselessly into the regex classifier).

### Added

- **`ExtractPdfTextLayer(pdfPath)`** — runs `pdftotext` (poppler-utils) to read a PDF's embedded text layer directly. Fast and exact for the common case: any PDF exported from Word, a browser, an e-signature tool, etc.
- **`OcrScannedPdf(pdfPath)`** — fallback for PDFs with no usable text layer (scans, photographed documents). Rasterizes up to 10 pages to PNG at 150 DPI via `pdftoppm`, then OCRs each page with the existing `RunTesseractOnFile()` helper and concatenates the results. Page count capped so a large scanned archive can't stall file/USB monitoring.
- **`ExtractPdfContent(pdfPath)`** — entry point: tries the text-layer path first, falls back to OCR only if that returns fewer than 20 non-whitespace characters (i.e. the PDF is essentially a scan).
- **`OcrImageFileIfApplicable`** now routes `.pdf` through `ExtractPdfContent` — no changes needed at the file-write or USB-transfer call sites, both already call this function for every monitored file.
- **`install-agent.ps1`** Step 4 now also installs `poppler` via Chocolatey (mirroring the existing `Install-Tesseract` pattern), alongside the already-auto-installed Tesseract.

### Scope

Clipboard image paste is unchanged — pasting a PDF isn't a `CF_DIB` bitmap operation on Windows, so it wasn't in scope here. File-write and USB-transfer monitoring are the two channels that matter for PDFs (someone saving or exfiltrating a document), and both are covered.

### ⚠️ Not yet verified

Same caveat as the file/USB/clipboard OCR work above: this C++ code has not been compiled or run on a real Windows machine. Test with an actual text-layer PDF, an actual scanned/photographed PDF, and confirm `poppler` installs cleanly via the updated `install-agent.ps1` before shipping to production.

---

## 🖥️ Extend Agent-Side OCR to File/USB/Clipboard Channels (July 14, 2026)

### Summary

Real-time OCR already existed on the Windows agent — `agent.cpp`'s screen-capture classifier captures the foreground window's pixels, shells out to `tesseract.exe`, and blocks the screenshot before it happens if the recognized text is sensitive, with `install-agent.ps1` Step 4 already auto-installing Chocolatey + Tesseract on every endpoint. This was missed in the same-day audit correction below (which only checked the Python server) and briefly, incorrectly reported as "genuinely absent." What actually *was* missing: that OCR path only covered screen captures, not file writes/saves, USB file transfers, or clipboard image paste.

### Added

- **`RunTesseractOnFile(imagePath)`** — new shared helper (`agents/endpoint/windows/agent.cpp`, near `ReadFileContent`) that shells out to `tesseract.exe` on an existing image file and returns the recognized text, or `""` on any failure (not installed, unreadable file, no text found). Never throws.
- **`OcrImageFileIfApplicable(filePath)`** — OCRs `filePath` if its extension is a raster image (`.png/.jpg/.jpeg/.bmp/.tiff/.tif/.gif`), no-ops for everything else so existing text-based file classification is unaffected.
- **`TryOcrClipboardImage()`** — reads a `CF_DIB` bitmap off an already-open clipboard, reconstructs it as a standalone `.bmp`, and OCRs it.
- Wired `OcrImageFileIfApplicable` into `HandleFileEvent` (file-write/save monitoring) and `EvaluatePolicyRealtime` (USB file transfer evaluation) — image files now get OCR'd instead of having their raw binary bytes fed into the regex classifier (which previously just turned them into a wall of spaces via the JSON-escaping step).
- Wired `TryOcrClipboardImage` into `ClipboardMonitor` — a pasted/copied image (e.g. a screenshot pasted into an email or chat app) is now OCR'd and run through the same `HandleClipboardEvent` classification path as typed/copied text.
- Refactored the original screen-capture Stage-4 OCR block to call the new shared `RunTesseractOnFile` instead of duplicating the "shell out + read result" logic inline — the pixel-capture (`BitBlt`/`GetDIBits`) portion is untouched.

### Scope / known limitation

Raster images only. Multi-page scanned PDFs are **not** covered — that needs a PDF rasterizer (e.g. poppler's `pdftoppm`) as an additional endpoint dependency, which is a separate, larger change (tracked as a P2 item in `ENTERPRISE_AUDIT.md`).

### ⚠️ Not yet verified

This C++ code was written and reviewed for correctness (each new/edited block was checked for local brace/paren balance) but **has not been compiled or run on a real Windows machine** — there is no Windows/C++ toolchain in the environment that wrote it. Build with the project's existing MSVC/CMake setup and test on a real endpoint (screen capture OCR, a saved `.png` with a fake SSN, a USB-copied scanned image, and a pasted screenshot) before shipping to production.

---

## 🔧 ML Classification Wiring + Enterprise Audit Correction (July 14, 2026)

### Summary

Verified five previously-questioned capabilities (MFA, ML/NLP classification, OCR, browser upload detection, email DLP) against the actual codebase rather than the stale `ENTERPRISE_AUDIT.md`. Two were already fully built and working (MFA, browser upload detection) but miscategorized as missing in the audit doc. One was fully built but never actually called (ML/NLP classification). Two are genuinely absent (OCR, email content-inspection DLP).

### Fixed

- **ML/NLP classification was dead code.** `app/services/ml_classification.py` (spaCy NER + TF-IDF/SGD sensitivity classifier) and `app/services/context_analyzer.py` (false-positive/true-positive phrase scoring) were fully implemented, `FEATURE_ML_CLASSIFICATION` already existed as a config flag, and the Docker image already installed spaCy (`requirements-ml.txt` + `python -m spacy download en_core_web_sm` in `server/Dockerfile`) — but the only "integration" was `classification_engine_ml_patch.py`, a set of copy-paste-me instructions that had never actually been applied. `ClassificationEngine.classify_content()` never called either service. Wired both in for real: `_apply_ml_classification` (200ms timeout, graceful fallback to rule-only on timeout/error), `_apply_context_analysis`, and `_combine_scores` (50% rule / 30% ML / 20% context, with a false-positive hard-cap) are now real methods called from Step 6b of the classification pipeline, gated behind `FEATURE_ML_CLASSIFICATION` so the rule-only path is unchanged when the flag is off. Retired `classification_engine_ml_patch.py`.
- Extended `_evaluate_regex_with_validation` / `_evaluate_keyword_rule` / `_evaluate_dictionary_rule` to also surface the actual matched substrings (capped at 10 per rule), so the context analyzer has real text to run its false-positive window analysis on instead of an empty list.
- Corrected `ENTERPRISE_AUDIT.md`: removed "No MFA" and "No ML/NLP Classification" as gaps (both were already done), reclassified "No Browser Extension" as a narrower "content-level payload inspection" gap (native file-selection detection already existed via `NetworkExfilMonitor::BrowserDetectorThread`), and confirmed OCR and Email DLP (content-inspection, as distinct from the existing SMTP *alert*-notification settings in `email_settings.py`) as the two gaps that are still genuinely open. Overall score revised 6.9/10 → 7.4/10.

### Test coverage

Added `test_ml_classification_wiring.py` (10 tests): `_combine_scores` weighting arithmetic, graceful degradation on ML service exception/timeout, and end-to-end `classify_content()` behavior with the feature flag on and off. All 81 previously-added tests (threat intel, domain RBAC, IP allowlist, retention) still pass — no regressions.

### Known pre-existing issue found (not fixed — separate scope)

`tests/test_detection_classification.py` calls `EventProcessor._classify_content()`, `EventProcessor._redact_content()`, and `EventProcessor.initialize()` — none of which exist on the current `EventProcessor` class (it only has `process_event()`). This test file was already broken before today's changes and is unrelated to the ML wiring fix; flagged for a separate pass if you want it repaired.

---

## 🚀 Threat Intel, Domain-Scoped RBAC, IP Allowlisting & Log Retention (July 14, 2026)

### Summary

Ported four capabilities from a sibling deployment's feature branch, backfilling test coverage and fixing two migration gaps found along the way.

### New features

- **Threat Intelligence (IOC / STIX 2.1 / TAXII 2.1)** — `iocs` and `taxii_feeds` tables, an in-memory IOC matcher (`app/services/ioc_service.py`), a TAXII 2.1 poller (`app/services/taxii_ingest.py`), an outbound TAXII 2.1 sharing server for opt-in indicators (`app/api/v1/taxii.py`), and a management API + dashboard page (`/threat-intel`) for manual/CSV/STIX import and feed polling.
- **Domain-scoped admin RBAC** — three new roles (`THREAT_ADMIN`, `DATA_PROTECTION_ADMIN`, `ACCESS_CONTROL_ADMIN`), each scoped to one policy domain (`app/core/domains.py`). Domain admins only see and manage the policies, events, alerts, and incidents within their domain; the global `ADMIN` is unrestricted. Policies are auto-tagged with a `domain` derived from their `type`.
- **IP allowlisting** — an admin-managed allowlist (`ip_allowlist` table) enforced by `IPAllowlistMiddleware`. Fail-open when empty, loopback always allowed, agent-ingestion and health endpoints always exempt so monitored machines keep reporting regardless of the portal restriction.
- **Log retention policy** — a dashboard-editable `retention_config` (event + OpenSearch index retention) with a hard 90-day compliance floor enforced both by the API and a DB `CHECK` constraint. The daily cleanup task now reads the effective value instead of a static env default.

### Fixed along the way

- Added Alembic migrations for `taxii_share_config` and `retention_config` — the source branch had model + API code for both but no migration, so a real `alembic upgrade head` deploy (as opposed to a fresh-install `create_all`) would have been missing the tables.
- Did **not** carry over `stix2`, `tensorflow`, `torch`, `transformers`, or `spacy` from the source branch's `requirements.txt` — none of them are imported anywhere; only `taxii2-client` is actually used for TAXII polling.
- Added the missing SQLite `JSONB`/`ARRAY` compiler shims to `tests/conftest.py` (pre-existing gap, not limited to the new tests — it also blocked the existing Google Drive model tests).

### Test coverage

Added `test_domain_service.py`, `test_ioc_taxii.py`, `test_ip_allowlist.py`, and `test_retention_service.py` (71 tests). The source branch shipped all four features with zero tests.

---

## 🚀 OneDrive Hybrid Modification Detection (December 25, 2025)

### Summary

- **Total Files Modified:** 2
- **New Features:** Hybrid modification detection using Redis file state tracking and ETag comparison
- **Problem Solved:** File modifications were incorrectly shown as create+delete pairs instead of modification events

### Highlights

#### Hybrid Modification Detection System
- **Problem:** Microsoft Graph API delta queries sometimes report file modifications as "created" + "deleted" events instead of a single "updated" event
- **Solution:** Implemented hybrid approach combining delta API with file metadata comparison
  - **Delta API for Deletions & Creations:** Uses delta API as-is for reliable `changeType="deleted"` and `changeType="created"` events
  - **Metadata Comparison for Modifications:** When delta reports "updated" OR when a file previously seen appears as "created", verifies by comparing file state (ETag, version, lastModifiedDateTime)

#### Redis File State Storage
- Stores file state in Redis: `onedrive:file_state:{connection_id}:{file_id}`
- State includes: ETag, lastModifiedDateTime, version
- 90-day TTL for automatic cleanup of old file states
- Gracefully handles Redis unavailability (falls back to delta-only mode)

#### File Metadata Fetching
- `_fetch_file_metadata()` method fetches current file ETag/version from Graph API
- Compares current state with stored state to detect real modifications
- Handles API errors gracefully (skips verification on errors)

#### Enhanced Delta Processing
- **Deletions:** Uses delta as-is, removes file state from Redis
- **Creations:** Checks if file exists in Redis; if yes, treats as modification
- **Updates:** Verifies with metadata comparison before logging as modification
- Stores file state after processing each file

#### Event Normalizer Updates
- Includes ETag and version in event details for debugging
- Modification events properly marked with `event_subtype="file_modified"`
- Event details include ETag/version information

#### Files Changed
- `server/app/services/onedrive_polling.py` - Added Redis helpers, metadata fetching, modification detection logic
- `server/app/services/onedrive_event_normalizer.py` - Added ETag/version extraction and event details

#### Testing Results
- ✅ File modifications now show as `file_modified` events (not create+delete)
- ✅ File creations still work correctly
- ✅ File deletions still work correctly
- ✅ System gracefully handles Redis/API failures
- ✅ Historical modifications correctly identified
- ✅ No performance degradation in normal operation

---

## 🐛 Alert Counter Bug Fix (January 5, 2026)

### Summary
- **Total Files Modified:** 2
- **Problem Solved:** Alert counter capped at 100, blank page on alerts route
- **Root Cause:** API returned limited list (100 items) and frontend calculated counts from array length; frontend called `.filter()` on response object instead of alerts array

### Highlights

#### Alert Counter Fix
- **Problem:** Alert counters on Alerts page were capped at 100 even when more alerts existed
- **Root Cause:** API endpoint `/api/v1/alerts` had hardcoded `.limit(100)` on MongoDB queries, and frontend calculated counts by filtering the returned array
- **Solution:** 
  - Modified API to return both alerts list (limited to 100 for performance) and total counts separately
  - API now returns `{alerts: [...], counts: {new: X, acknowledged: Y, resolved: Z, total: N}}`
  - Frontend uses API-provided counts instead of calculating from array length
  - Counters now display accurate totals above 100

#### Blank Page Fix
- **Problem:** Alerts page (`/alerts`) showed blank white page with console error `TypeError: e.filter is not a function`
- **Root Cause:** Frontend tried to call `.filter()` on the response object when API returned new format
- **Solution:**
  - Added defensive handling to ensure `alerts` is always an array
  - Proper type checking for both old format (array) and new format (object with alerts and counts)
  - Added null/undefined checks and type validation

#### Files Changed
- `server/app/api/v1/alerts.py` - Changed response from `List[Alert]` to `AlertsResponse` with separate counts
- `dashboard/src/pages/Alerts.tsx` - Updated to use API counts and added defensive response handling

#### Testing Results
- ✅ Alert counters display accurate totals above 100 (verified with 201 alerts)
- ✅ Alerts page loads correctly without blank page errors
- ✅ Backward compatible with both old and new API response formats
- ✅ List display still limited to 100 for performance while counts show accurate totals

---

## 🚀 Google Drive Cloud Integration (November 26, 2025)

### Summary

- **Total Files Modified:** 25+
- **New Features:** Google Drive OAuth integration, Activity API polling, protected folder monitoring, baseline management, manual refresh
- **New Components:** Google Drive policy forms, protected folder management UI, baseline reset controls

### Highlights

#### Google Drive OAuth & Connection Management
- Implemented OAuth 2.0 flow for Google Drive authentication
- Created `GoogleDriveConnection` and `GoogleDriveProtectedFolder` models in PostgreSQL
- Added connection management API endpoints (`/google-drive/connect`, `/google-drive/connections`)
- Protected folder selection UI with folder tree navigation
- Connection status tracking and token refresh handling

#### Google Drive Activity Polling
- Celery-based background polling service (`GoogleDrivePollingService`)
- Polls Google Drive Activity API every 5 minutes for protected folders
- Event normalization from Google Drive activity format to DLP event format
- Supports file operations: created, modified, deleted, moved, copied, downloaded
- Deterministic event ID generation to prevent duplicates
- Per-folder baseline timestamps (`last_seen_timestamp`) to prevent historical re-ingestion

#### Baseline Management System
- Per-folder `last_seen_timestamp` stored in PostgreSQL
- Polling only fetches events after baseline timestamp
- Baseline initialized to `datetime.utcnow()` when folder is added to policy
- API endpoints for viewing and resetting baselines (`/google-drive/connections/{id}/protected-folders`, `/google-drive/connections/{id}/baseline`)
- UI controls to reset individual folder baselines or entire connection baseline
- "Monitoring since" date display in policy forms

#### Manual Refresh & Event Display
- Manual refresh button in Events UI triggers immediate Google Drive poll
- API endpoint `/google-drive/poll` for on-demand polling
- Enhanced event display with Google Drive-specific fields:
  - `event_subtype`: file_created, file_deleted, file_modified, etc.
  - `description`: Human-readable activity description
  - `file_id`, `folder_id`, `folder_name`, `folder_path`: Google Drive metadata
  - `mime_type`: File MIME type
  - `details`: Raw Google Drive activity payload
- Event timestamps use actual Google Drive activity timestamp (not poll time)

#### Policy Integration
- Google Drive Cloud policy type in policy creation wizard
- Policy configuration includes:
  - Google Drive connection selection
  - Protected folder selection (multi-select)
  - Policy rules matching on `source`, `connection_id`, `folder_id`
- Policy sync updates protected folders when policy is created/updated
- Policy evaluation matches Google Drive events against configured rules

#### Database Schema
- Migration `caa6530e7d81_add_google_drive_tables.py`:
  - `google_drive_connections` table: OAuth tokens, user email, connection status
  - `google_drive_protected_folders` table: Folder metadata, baseline timestamps
- Foreign key relationships to `users` and `policies` tables

#### Files Changed
- `server/app/models/google_drive.py` - Database models
- `server/app/services/google_drive_oauth.py` - OAuth and connection management
- `server/app/services/google_drive_polling.py` - Activity polling service
- `server/app/services/google_drive_event_normalizer.py` - Event normalization
- `server/app/tasks/google_drive_polling_tasks.py` - Celery task wrapper
- `server/app/api/v1/google_drive.py` - API endpoints
- `server/app/api/v1/policies.py` - Policy sync integration
- `server/app/api/v1/events.py` - Event model updates for Google Drive fields
- `dashboard/src/components/policies/GoogleDriveCloudPolicyForm.tsx` - Policy form
- `dashboard/src/components/google-drive/` - OAuth and folder selection components
- `dashboard/src/lib/api.ts` - Google Drive API client functions
- `dashboard/src/pages/Events.tsx` - Manual refresh button
- `dashboard/src/app/dashboard/events/page.tsx` - Manual refresh button (App Router)

#### Testing Results
- ✅ OAuth flow completes successfully
- ✅ Protected folders are stored and synced with policies
- ✅ Polling service fetches new activities correctly
- ✅ Baseline system prevents historical event re-ingestion
- ✅ Events display with correct Google Drive timestamps
- ✅ Manual refresh triggers immediate polling
- ✅ Policy matching works for Google Drive events
- ✅ No duplicate events appear after baseline implementation

---

## 🚀 Unified Policy Distribution & Cleanup (November 20, 2025)

### Summary

- **Total Files Modified:** 112
- **Lines Changed:** +1,295 insertions / -35,281 deletions
- **New Artifacts:** `.cursorrules`, `archive/`, `server/app/policies/`, `server/app/utils/policy_transformer.py`, `server/tests/test_agent_policy_transformer.py`, `dashboard/src/types/policy.ts`
- **Removed Artifacts:** Legacy YAML configs, `policy_engine` module/tests, `agents/common/*`, deprecated Windows/Linux installers, and 40+ outdated documentation files

### Highlights

#### Unified Policy Schema + API
- Added `type`, `severity`, and `config` columns to the `Policy` ORM plus Alembic migration, enabling storage of UI-native configurations.
- Introduced `transform_frontend_config_to_backend()` so create/update flows accept wizard output while preserving backend condition/action logic.
- `/api/v1/policies` responses now include the new fields, enforce real `User` objects for auth, and expose a `/policies/stats/summary` endpoint with MongoDB-backed violation counts.

#### Agent Policy Bundles
- Created `AgentPolicyTransformer` and `/api/v1/agents/{id}/policies/sync`, caching bundles per platform/capability in Redis to minimize payload churn.
- Agents register/report capability flags plus policy sync metadata (`policy_version`, `policy_sync_status`, `policy_last_synced_at`, `policy_sync_error`) so operators can verify rollout status from the dashboard.

#### Windows & Linux Agent Runtime
- Agents now fetch bundles on startup and at `policy_sync_interval`, restart filesystem observers when monitored paths change, and include policy context in file/clipboard/USB events.
- USB transfer handling maps to per-policy actions (block/quarantine/log) and emits richer telemetry (source/destination paths, policy metadata, content snippets).
- Heartbeats inherit policy version/sync metadata, while event payloads include `policy_version`, `source_path`, and truncated `content` for downstream evaluation.

#### Event Pipeline Hardening
- `EventProcessor` now plugs into the database-backed evaluator/action executor, attaches `matched_policies` and `policy_action_summaries`, and preserves clipboard text for policy checks.
- Clipboard events automatically populate `clipboard_content`, and USB/file events carry additional metadata for evaluator rules.

#### Frontend & Docs
- `dashboard/src/lib/api.ts` hydrates auth tokens from persisted state and adds helpers for enable/disable/statistics calls; shared policy types live under `dashboard/src/types/policy.ts`.
- `README.md`, `INSTALLATION_GUIDE.md`, and `TESTING_COMMANDS.md` reference the new policy workflow, while the obsolete documentation tree was moved into `archive/` or removed entirely to keep the repo lean.

## Summary

- **Total Files Modified:** 53 files
- **Lines Changed:** +3,869 insertions, -826 deletions
- **New Files:** 2 (.env.example, Login page component)
- **Major Fixes:** Dashboard authentication, Dashboard overview page, Alerts page, Events API, Linux Agent connectivity, Windows Agent connectivity, Docker configuration, Configuration system (removed hardcoded paths/IPs), Windows Agent USB monitoring threading fix, Agent lifecycle management, Timezone display (IST), Heartbeat system improvements, File transfer blocking (Windows), Event display improvements

---

## 🎯 Latest Updates (December 2025)

### 18. Policy System & Agent Alignment (early December 2025)
- Backend: tightened policy bundle generation (`agent_policy_transformer`), agent policy sync API, and action execution paths to reflect updated policy schemas; added tests for transformer and Google Drive normalization/models.
- Agents: Linux agent classification and config defaults aligned; supports faster policy sync cadence and logs richer heartbeat/sync telemetry.
- Frontend: policy forms/types updated to current backend schema (actions, fields), details modal and table rows refreshed to reflect new policy shape.
- Data: Alembic migration for Google Drive tables kept in sync; sample test files expanded for new classifiers/policies.
- Note: Quarantine remains future work (tracked in `archive/FUTURE_TODO.md`); current actions focus on alert/log/block.

### 17. Installer Automation (Windows & Linux) - December 10, 2025
- Added scripted installers:
  - **Windows:** `scripts/install_windows_agent.ps1` clones the agent, builds a venv, templates config, and registers a SYSTEM AtStartup Scheduled Task with restart-on-failure. Docs include usage, args, and troubleshooting.
  - **Linux:** `scripts/install_linux_agent.sh` clones the agent, builds a venv, templates config, and installs a systemd service (boot autostart, restart on failure).
- Docs: `scripts/README.md` updated with arguments, examples, and post-install commands.
- Hardening: Linux installer skips empty configs, handles `--force` clean re-provisioning, and notes agent log location (`/root/seceoknight_agent.log` by default).
- Outcome: Both agents verified to auto-start after reboot; Linux logs surface 404 if manager is down (expected until registration).

### 16. India-Specific Detection & Clipboard Policy Alignment

#### Summary
- **Goal:** Align clipboard and file transfer detection with India-first identifiers and ensure agents strictly follow database policies as the single source of truth.

#### Highlights
- **India-Specific Patterns (Agents):**
  - Extended Windows agent content classifier to detect Aadhaar, PAN, IFSC, Indian bank accounts, Indian phone numbers, UPI IDs, MICR, and Indian-format dates of birth.
  - Added source code and secret patterns: generic code tokens, AWS access keys, GitHub tokens, generic API keys, and database connection strings (JDBC, MongoDB, Redis).
  - Reused the same classifier for clipboard, file events, and USB transfer events so all channels share a consistent label set.
- **Clipboard Monitoring (Windows):**
  - Switched clipboard capture to prefer `CF_UNICODETEXT` with fallback to `CF_TEXT`, fixing missing events from modern apps and standard `Ctrl+C` flows.
  - Introduced agent-side policy awareness: clipboard events are only sent when content is classified as sensitive **and** at least one active clipboard policy’s configured patterns match the detected labels.
  - Logged active clipboard/file/USB policy names on every policy bundle application to simplify debugging and manual validation.
- **Linux Agent:**
  - Confirmed filesystem monitoring pipeline and classification for sensitive content; added dedicated tests for Indian identifier and source code patterns.
  - Clarified that Linux currently performs **logical** blocking only (events marked as blocked by policies) and does not delete/move files on disk.
- **Quarantine Action Visibility:**
  - Temporarily removed `quarantine` from user-selectable actions in the dashboard (`File System` and `USB Transfer` policies) and from shared policy types.
  - Documented current limitation in `archive/FUTURE_TODO.md` – quarantine is tracked as future work and is not advertised as a working action in the UI.

#### Files Touched (Highlights)
- `agents/endpoint/windows/agent.py` – Unicode clipboard capture, India/source-code classifier, clipboard policy matching, USB transfer policy alignment.
- `agents/endpoint/linux/agent.py` – Classification confirmation and tests for new patterns.
- `dashboard/src/types/policy.ts` – Removed `quarantine` from active action enums; tightened policy types around `alert`, `log`, and `block`.
- `dashboard/src/components/policies/FileSystemPolicyForm.tsx` – Removed quarantine option and quarantine path field.
- `dashboard/src/components/policies/GoogleDriveLocalPolicyForm.tsx` – Removed quarantine option and quarantine path field.
- `dashboard/src/mocks/mockPolicies.ts` – Updated mock actions to use `block`/`alert` only.
- `dashboard/src/app/dashboard/settings/page.tsx` – Marked quarantine toggle as “coming soon”.
- `archive/FUTURE_TODO.md` – Captured end-to-end quarantine implementation as a tracked future enhancement.

---

## 🎯 Previous Updates (January 2025)

### 15. Policy Management UI Revamp

#### Problem
- Old policy tab showed YAML-based system (not actually implemented)
- No user-friendly way to create or manage policies
- Policies displayed as raw data without proper organization
- Missing features: edit, duplicate, toggle status, view details

#### Solution
- **Complete UI Redesign:**
  - Removed old YAML-based policy display
  - Created multi-step policy creation wizard (Type → Config → Review)
  - Added policy type selector with 4 types: Clipboard, File System, USB Device, USB Transfer
  - Implemented type-specific configuration forms with validation
  - Added Priority and Severity fields (customizable in step 2)
  - Created separate tables for Active and Inactive policies
  - Added 3-dots context menu for each policy row

- **Policy Creation Wizard:**
  - Step 1: Select policy type (2x2 card grid)
  - Step 2: Configure policy (Basic Info + Type-specific config)
    - Basic Info: Name, Description, Severity (Low/Medium/High/Critical), Priority (1-100), Enabled status
    - Type-specific: Patterns, directories, events, actions based on policy type
  - Step 3: Review and save (shows summary + JSON preview)

- **Policy Management Features:**
  - View Details: Read-only modal with full policy configuration, JSON toggle
  - Edit Policy: Opens creation modal pre-filled with existing policy data
  - Duplicate Policy: Creates copy and opens creation modal
  - Toggle Status: Activate/deactivate policy (moves between Active/Inactive tables)
  - Delete Policy: Removes policy with confirmation dialog

- **UI Components:**
  - `PolicyCreatorModal`: Multi-step wizard component
  - `PolicyTypeSelector`: 2x2 card grid for type selection
  - `ClipboardPolicyForm`: Pattern selection (predefined + custom regex)
  - `FileSystemPolicyForm`: Directory monitoring, file extensions, events
  - `USBDevicePolicyForm`: USB device events (connect, disconnect, file transfer)
  - `USBTransferPolicyForm`: Monitored directories, actions (block/quarantine)
  - `PolicyTable`: Reusable table component for Active/Inactive policies
  - `PolicyRow`: Individual policy row with icon, badges, metadata, 3-dots menu
  - `PolicyContextMenu`: Dropdown menu with all policy actions
  - `PolicyDetailsModal`: Read-only policy viewer with JSON toggle

- **Mock Data:**
  - Created `mockPolicies.ts` with 12 sample policies (9 active, 3 inactive)
  - Includes all 4 policy types with realistic configurations
  - Used for frontend development and testing

#### Files Changed
- `dashboard/src/app/dashboard/policies/page.tsx` - Complete rewrite with new UI
- `dashboard/src/components/policies/PolicyCreatorModal.tsx` - New multi-step wizard
- `dashboard/src/components/policies/PolicyTypeSelector.tsx` - New type selector
- `dashboard/src/components/policies/ClipboardPolicyForm.tsx` - New clipboard form
- `dashboard/src/components/policies/FileSystemPolicyForm.tsx` - New filesystem form
- `dashboard/src/components/policies/USBDevicePolicyForm.tsx` - New USB device form
- `dashboard/src/components/policies/USBTransferPolicyForm.tsx` - New USB transfer form
- `dashboard/src/components/policies/PolicyTable.tsx` - New table component
- `dashboard/src/components/policies/PolicyRow.tsx` - New row component
- `dashboard/src/components/policies/PolicyContextMenu.tsx` - New context menu
- `dashboard/src/components/policies/PolicyDetailsModal.tsx` - New details modal
- `dashboard/src/mocks/mockPolicies.ts` - New mock data file
- `dashboard/src/utils/policyUtils.ts` - New utility functions
- `dashboard/src/App.tsx` - Updated import for policies page

#### Current Status
- ✅ Frontend mock implementation complete
- ✅ All UI components built and tested
- ✅ Policy creation wizard working
- ✅ Active/Inactive tables displaying correctly
- ✅ Context menu actions functional (mock)
- ⏳ Backend integration pending (schema mismatch needs resolution)

#### Next Steps
- Integrate frontend with backend API
- Resolve schema mismatch between frontend form and backend API
- Implement actual policy CRUD operations
- Add policy evaluation engine integration

### 14. File Transfer Blocking Feature (Windows)

#### Problem
- No protection against copying sensitive files to removable drives (USB, external SSDs)
- Files could be copied to external storage without detection or blocking
- No visual feedback in dashboard for blocked transfers
- Event details showing raw JSON instead of user-friendly information

#### Solution
- **Windows Agent Transfer Blocking:**
  - Added removable drive monitoring with `watchdog` library
  - Detects files copied to removable drives (USB, external SSDs)
  - Compares file hash (SHA256) with files in monitored directories
  - Automatically deletes copied files from removable drives when match found
  - Sends blocked transfer events with `action: "blocked"` status
  - Handles file locking issues with retry mechanism (Windows Explorer locks files during copy)
  - Configurable via `transfer_blocking.enabled` in agent config

- **Backend Event Processing:**
  - Updated `EventCreate` model to accept `action`, `destination`, `blocked`, `event_subtype`, `description`, `user_email` fields
  - Backend now properly stores agent-provided `action` field (mapped to `action_taken`)
  - Fixed hardcoded `action_taken: "logged"` to use agent-provided action
  - Added debug logging for action field tracking

- **Dashboard Event Display:**
  - Created user-friendly `EventDetailModal` component for blocked transfers
  - Visual flow display: Source → Destination with file details
  - Shows file size, hash, transfer type, and action taken
  - Expandable raw JSON section for technical details
  - Improved standard event display with better formatting
  - Fixed `action_taken` field display (now shows "blocked" for blocked transfers, "logged" for others)

#### Configuration
```json
{
  "monitoring": {
    "transfer_blocking": {
      "enabled": true,
      "block_removable_drives": true,
      "poll_interval_seconds": 5
    }
  }
}
```

#### Files Changed
- `agents/endpoint/windows/agent.py` - Added transfer blocking logic, removable drive monitoring, file hash comparison
- `agents/endpoint/windows/agent_config.json` - Added transfer_blocking configuration section
- `server/app/api/v1/events.py` - Updated EventCreate model and event processing
- `dashboard/src/pages/Events.tsx` - Added EventDetailModal component and improved event display
- `dashboard/src/app/dashboard/events/page.tsx` - Added EventDetailModal component (app router version)

#### Testing Results
- ✅ Transfer blocking detects files copied to USB drives
- ✅ Files successfully deleted from removable drives when match found
- ✅ Blocked transfer events show `action_taken: "blocked"` in dashboard
- ✅ User-friendly event modal displays transfer details correctly
- ✅ File locking issues handled with retry mechanism
- ✅ Works with multiple monitored directories
- ✅ Handles path normalization (E:file.txt → E:\file.txt)

### 12. Agent Lifecycle Management and Heartbeat Improvements

#### Problem
- Agents didn't unregister cleanly on shutdown, leaving stale entries in dashboard
- Heartbeat timeout errors (5s timeout too short)
- Rate limiting middleware blocking agent heartbeats
- Agent names using hostname instead of friendly names
- "Last seen" timestamps not updating correctly
- Dashboard showing dead/inactive agents

#### Solution
- **Graceful Agent Shutdown:**
  - Added `unregister_agent()` method to both Linux and Windows agents
  - Agents now call `/agents/{agent_id}/unregister` endpoint on shutdown
  - Added signal handlers (SIGINT, SIGTERM) for clean shutdown
  - Added `atexit` handler as backup for cleanup

- **Heartbeat System Improvements:**
  - Increased heartbeat timeout from 5s to 30s (handles slow server responses)
  - Reduced heartbeat interval from 60s to 30s (more frequent updates)
  - Heartbeat now sends timestamp (ISO format with Z suffix) and IP address
  - Improved heartbeat logging (INFO level instead of DEBUG)
  - Fixed datetime timezone awareness in heartbeat endpoint

- **Rate Limiting Fix:**
  - Bypassed rate limiting for agent endpoints (heartbeat, registration)
  - Prevents Redis delays from blocking critical agent operations
  - Fixed datetime timezone comparison errors in rate limiting

- **Agent Name Standardization:**
  - Linux agent default name: "Linux-Agent" (was hostname)
  - Windows agent default name: "Windows-Agent" (configurable)
  - Updated config files with new default names

- **Backend Agent Management:**
  - Agents filtered by `last_seen` timestamp (only active within 5 minutes)
  - Dead agents automatically cleaned up in background
  - Removed `status` field (replaced with time-based filtering)
  - Backend converts datetime to ISO strings with 'Z' suffix for frontend

- **Frontend Improvements:**
  - Dashboard shows only active agents (filtered by backend)
  - Removed status indicators (no longer needed)
  - "Last seen" displays correctly with IST timezone
  - Auto-refresh every 10 seconds for real-time updates
  - Events page shows agent names instead of agent IDs

### 13. Timezone Display Fixes (IST)

#### Problem
- Dashboard timestamps displayed in UTC instead of IST
- Timezone conversion not working correctly
- "Last seen" times showing incorrect values

#### Solution
- **Frontend Timezone Conversion:**
  - Added `parseAsUTC()` function to handle dates without timezone info
  - All date formatting functions now use IST timezone (`Asia/Kolkata`)
  - Updated `formatDate()`, `formatRelativeTime()`, `formatTimeIST()`, `formatDateTimeIST()`
  - Fixed UTC date parsing (appends 'Z' if timezone missing)

- **Backend Timestamp Formatting:**
  - Backend explicitly converts datetime objects to ISO strings with 'Z' suffix
  - Ensures frontend receives properly formatted UTC timestamps
  - Fixed timezone awareness in heartbeat endpoint

- **Dashboard Components Updated:**
  - Events page: All timestamps display in IST
  - Agents page: "Last seen" and "Registered" times in IST
  - Dashboard charts: X-axis and tooltips show IST times
  - Recent events: Timestamps in IST format

---

## 🎯 Major Fixes

### 11. Configuration System - Removed Hardcoded Paths and IPs

#### Problem
- Hardcoded IP addresses (`172.23.19.78`) in `docker-compose.yml`
- Hardcoded server URLs in agent config files
- System-specific paths in installation guide
- No environment variable support for configuration
- Not portable across different systems

#### Solution
- **`.env.example`**: Created comprehensive environment variable template
  - Network configuration (`SERVER_IP`, `CORS_ORIGINS`, `VITE_API_URL`, `VITE_WS_URL`)
  - Database passwords and security keys
  - All configurable settings with sensible defaults

- **`docker-compose.yml`**: Updated to use environment variables
  - `CORS_ORIGINS` uses `${CORS_ORIGINS}` with localhost defaults
  - `VITE_API_URL` and `VITE_WS_URL` use environment variables with defaults
  - All values configurable via `.env` file

- **`agents/endpoint/linux/agent.py`**: Added environment variable support
  - Checks `SECEOKNIGHT_SERVER_URL` environment variable first
  - Falls back to config file, then defaults to `http://localhost:55000/api/v1`
  - Environment variable takes precedence over config file

- **`agents/endpoint/windows/agent.py`**: Added environment variable support
  - Checks `SECEOKNIGHT_SERVER_URL` environment variable first
  - Falls back to config file, then defaults to `http://localhost:55000/api/v1`
  - Environment variable expansion for `%USERNAME%` in monitored paths (via `os.path.expandvars()`)
  - Environment variable takes precedence over config file

- **`agents/endpoint/linux/agent_config.json`**: Updated default server URL
  - Changed from hardcoded IP to `http://localhost:55000/api/v1`

- **`agents/endpoint/windows/agent_config.json`**: Updated default server URL
  - Changed from hardcoded IP to `http://localhost:55000/api/v1`
  - Supports `%USERNAME%` in monitored paths (expanded at runtime)

- **`dashboard/Dockerfile`**: Fixed package manager issue
  - Changed `apk` (Alpine) to `apt-get` (Debian-based image)
  - Fixed curl installation order (before switching to non-root user)

- **`dashboard/src/lib/api.ts`**: Fixed duplicate exports
  - Removed duplicate function exports causing build errors
  - Cleaned up API client structure

- **`INSTALLATION_GUIDE.md`**: Updated with configurable paths
  - Removed hardcoded system-specific paths
  - Added instructions for `.env` file configuration
  - Updated agent configuration examples with environment variables

#### Files Changed
- `.env.example` (new file)
- `docker-compose.yml`
- `agents/endpoint/linux/agent.py`
- `agents/endpoint/linux/agent_config.json`
- `agents/endpoint/windows/agent.py`
- `agents/endpoint/windows/agent_config.json`
- `dashboard/Dockerfile`
- `dashboard/src/lib/api.ts`
- `INSTALLATION_GUIDE.md`

#### Testing Results
- ✅ Dashboard builds and runs with environment variables
- ✅ Linux agent connects using `localhost` default
- ✅ Windows agent connects using `localhost` default
- ✅ Environment variables override config file values
- ✅ Windows agent expands `%USERNAME%` in monitored paths correctly
- ✅ All hardcoded IPs removed
- ✅ System works out-of-the-box with sensible defaults

---

### 1. Dashboard Build and Runtime Issues

#### Problem
- Dashboard failed to build due to Next.js/Vite mismatch
- Missing dependencies (`react-router-dom`)
- Incorrect build commands in Dockerfile
- Environment variables not properly configured for Vite

#### Solution
- **`dashboard/Dockerfile`**: Migrated from Next.js to Vite build system
  - Changed base image to `node:20-slim`
  - Updated build commands to use `vite build` instead of Next.js
  - Fixed `CMD` to use `vite preview` for production
  - Added proper Vite environment variable handling via build args

- **`dashboard/package.json`**: Updated dependencies and scripts
  - Added `react-router-dom: ^6.20.0` to dependencies
  - Added `@vitejs/plugin-react` and `vite` to devDependencies
  - Updated scripts: `dev`, `build`, `start`, `preview` to use Vite

- **`dashboard/src/index.css`**: Fixed Tailwind CSS error
  - Changed `@apply border-border;` to `@apply border-gray-200;`

#### Files Changed
- `dashboard/Dockerfile`
- `dashboard/package.json`
- `dashboard/package-lock.json`
- `dashboard/src/index.css`

---

### 2. Dashboard Authentication System

#### Problem
- Dashboard had mock authentication
- No login page
- API calls failing with 401 Unauthorized
- Routes not protected

#### Solution
- **`dashboard/src/lib/store/auth.ts`**: Implemented real authentication
  - Replaced mock auth with actual API calls to `/auth/login` and `/auth/refresh`
  - Uses OAuth2PasswordRequestForm format (form-urlencoded)
  - Properly handles JWT tokens and refresh tokens
  - Stores authentication state in Zustand with persistence

- **`dashboard/src/pages/Login.tsx`**: Created new login page
  - Beautiful gradient UI with animated background
  - Form validation and error handling
  - Redirects to dashboard on successful login

- **`dashboard/src/components/Layout.tsx`**: Added route protection
  - Checks authentication status
  - Redirects unauthenticated users to login page
  - Handles client-side hydration

- **`dashboard/src/App.tsx`**: Added login route
  - New route `/login` pointing to Login component

#### Files Changed
- `dashboard/src/lib/store/auth.ts`
- `dashboard/src/components/Layout.tsx`
- `dashboard/src/components/auth/LoginForm.tsx`
- `dashboard/src/App.tsx`
- `dashboard/src/pages/Login.tsx` (new file)

---

### 3. Events API Response Format

#### Problem
- Events API returned 500 error
- Response format mismatch between API and frontend
- MongoDB `_id` fields causing validation errors
- Frontend expected nested structure but API returned flat structure

#### Solution
- **`server/app/api/v1/events.py`**: Fixed API response
  - Changed response model from `List[DLPEvent]` to `EventsResponse` with pagination
  - Added `EventsResponse` model with `events`, `total`, `skip`, `limit` fields
  - Removed MongoDB `_id` fields from response
  - Ensured all required fields have defaults
  - Fixed `current_user` access (changed from dict to User object)

- **`dashboard/src/pages/Events.tsx`**: Updated to match API structure
  - Changed from `event.event.severity` to `event.severity`
  - Changed from `event.event.type` to `event.event_type`
  - Updated field access: `event.timestamp`, `event.file_path`, `event.agent_id`
  - Fixed classification labels display

- **`dashboard/src/lib/api.ts`**: Updated Event type definition
  - Added all required fields: `classification_score`, `classification_labels`, `blocked`, `policy_id`, etc.
  - Updated `timestamp` to accept `string | Date`

#### Files Changed
- `server/app/api/v1/events.py`
- `dashboard/src/pages/Events.tsx`
- `dashboard/src/lib/api.ts`

---

### 4. Agent Configuration and Connectivity

#### Problem
- Linux agent couldn't connect to server
- Incorrect server URL in configuration
- Heartbeat endpoint mismatch (POST vs PUT)
- Permission errors for log/config files

#### Solution
- **`agents/endpoint/linux/agent.py`**: Multiple fixes
  - Updated default `server_url` to use correct port (55000) and path (`/api/v1`)
  - Changed `send_heartbeat` from `POST` to `PUT` to match server endpoint
  - Fixed log file location to use `~/seceoknight_agent.log` (user-writable)
  - Improved config loading with fallback to local config if `/etc/seceoknight` not writable
  - Better error handling for directory creation

- **`agents/endpoint/linux/agent_config.json`**: Updated configuration
  - Set `server_url` to `http://172.23.19.78:55000/api/v1` (WSL IP)
  - Updated `agent_id` to match registered agent

- **`agents/endpoint/windows/agent.py`**: Multiple fixes
  - Updated default `server_url` to use correct port (55000) and path (`/api/v1`)
  - Changed `send_heartbeat` from `POST` to `PUT` to match server endpoint
  - Added environment variable expansion in `start_file_monitoring()` using `os.path.expandvars()`
  - Added logging for file events to track monitoring activity
  - Fixed path expansion for `%USERNAME%` in monitored paths

- **`agents/endpoint/windows/agent_config.json`**: Updated for WSL compatibility
  - Set `server_url` to `http://localhost:55000/api/v1` for WSL2
  - Updated `agent_id` to `windows-agent-001` for testing

#### Files Changed
- `agents/endpoint/linux/agent.py`
- `agents/endpoint/linux/agent_config.json`
- `agents/endpoint/windows/agent.py`
- `agents/endpoint/windows/agent_config.json`

---

### 5. Docker Configuration

#### Problem
- CORS errors preventing dashboard from accessing API
- Server running on wrong port (8000 instead of 55000)
- OpenSearch healthcheck failing
- Environment variables not properly configured

#### Solution
- **`docker-compose.yml`**: Multiple fixes
  - Updated `CORS_ORIGINS` to include WSL IP: `http://172.23.19.78:3000`
  - Added `ALLOWED_HOSTS` with WSL IP
  - Fixed dashboard build args to pass Vite environment variables
  - Removed duplicate OpenSearch security settings
  - Added `DISABLE_SECURITY_PLUGIN=true` for OpenSearch

- **`server/Dockerfile`**: Fixed port configuration
  - Updated `EXPOSE` to port `55000`
  - Updated `HEALTHCHECK` to use correct port
  - Set `ENV PORT=55000`
  - Updated `CMD` to use port 55000

#### Files Changed
- `docker-compose.yml`
- `server/Dockerfile`

---

### 6. Database and Security Fixes

#### Problem
- User ID type mismatch (integer vs UUID)
- Role enum case mismatch (lowercase vs uppercase)
- Token blacklist failing incorrectly
- Database initialization errors

#### Solution
- **`server/init_db.py`**: Fixed database schema
  - Changed user `id` from `SERIAL PRIMARY KEY` to `UUID PRIMARY KEY DEFAULT gen_random_uuid()`
  - Updated default admin role to `'ADMIN'` (uppercase)
  - Added `policies` table creation
  - Updated default admin password to `"admin"`

- **`server/app/models/user.py`**: Fixed UserRole enum
  - Changed enum values to uppercase: `ADMIN`, `ANALYST`, `VIEWER`

- **`server/app/core/security.py`**: Fixed role comparison
  - Updated `role_hierarchy` to use uppercase keys
  - Added role conversion to uppercase for comparison

- **`server/app/services/blacklist_service.py`**: Fixed fail-safe logic
  - Changed error handling to return `False` (token valid) instead of `True` (token revoked)
  - Prevents all tokens from being rejected on Redis errors

#### Files Changed
- `server/init_db.py`
- `server/app/models/user.py`
- `server/app/core/security.py`
- `server/app/services/blacklist_service.py`

---

### 7. OpenSearch Configuration

#### Problem
- OpenSearch container unhealthy
- SSL connection errors
- Healthcheck authentication failures

#### Solution
- **`server/app/core/opensearch.py`**: Fixed client initialization
  - Conditionally add `http_auth` only if `OPENSEARCH_USE_SSL` is `True`
  - Fixed `exists_index_template` check using `get_index_template` with `NotFoundError` handling
  - Removed unnecessary `connection_class` parameter
  - Added error handling in `close_opensearch()`

- **`server/app/core/config.py`**: Updated OpenSearch settings
  - Set `OPENSEARCH_USE_SSL: bool = Field(default=False)`

#### Files Changed
- `server/app/core/opensearch.py`
- `server/app/core/config.py`

---

### 8. Frontend API Client Updates

#### Problem
- API client using wrong port (8000 instead of 55000)
- Environment variables not properly read (Next.js vs Vite)
- Missing exports for API functions

#### Solution
- **`dashboard/src/lib/api.ts`**: Multiple fixes
  - Updated `baseURL` to use `import.meta.env.VITE_API_URL` (Vite format)
  - Changed default port from 8000 to 55000
  - Fixed refresh token endpoint to use correct API URL
  - Exported all required functions: `getStats`, `getEventTimeSeries`, `getEventsByType`, `getEventsBySeverity`, `getAgents`, `deleteAgent`, `getAlerts`, `searchEvents`
  - Exported `Agent` and `Event` types
  - Fixed `getEventTimeSeries` function signature

#### Files Changed
- `dashboard/src/lib/api.ts`

---

### 9. Dashboard Overview Page Fix

#### Problem
- Dashboard overview page showing all zeros (0 agents, 0 events)
- Stats cards not displaying real data from database
- Charts not showing any data
- Dashboard data not synchronized with Agents and Events pages

#### Solution
- **`server/app/api/v1/dashboard.py`**: Fixed dashboard overview endpoint
  - Changed events collection from `db["events"]` to `db.dlp_events` (correct collection name)
  - Added agent queries from MongoDB `agents` collection
  - Updated response format to match frontend expectations:
    - `total_agents`: Count of all registered agents
    - `active_agents`: Count of agents with status "online"
    - `total_events`: Total count of all events
    - `critical_alerts`: Count of events with severity "critical"
    - `blocked_events`: Count of blocked events

- **`server/app/api/v1/events.py`**: Added missing stats endpoints
  - Added `/events/stats/by-type` endpoint for pie chart data
  - Added `/events/stats/by-severity` endpoint for bar chart data
  - Both endpoints aggregate data from `dlp_events` collection
  - Return data in format expected by chart components

- **`server/app/api/v1/dashboard.py`**: Fixed timeline endpoint
  - Updated to use `db.dlp_events` collection
  - Returns timeline data in correct format for line chart

#### Files Changed
- `server/app/api/v1/dashboard.py`
- `server/app/api/v1/events.py`

#### Testing
- Verified dashboard shows correct agent count (3 agents)
- Verified dashboard shows correct event count (362 events)
- Verified charts display data correctly:
  - Events Over Time: Line chart with hourly event counts
  - Events by Type: Pie chart showing file (99%), clipboard (1%)
  - Events by Severity: Bar chart showing critical, high, medium, low
- Verified data consistency across Dashboard, Agents, and Events pages

---

### 10. Alerts Page Fix

#### Problem
- Alerts page showing "0 alerts" even though dashboard showed 33 critical alerts
- Alerts API endpoint returning empty array
- `AttributeError: 'User' object has no attribute 'get'` when accessing current_user

#### Solution
- **`server/app/api/v1/alerts.py`**: Complete rewrite of alerts endpoint
  - Generates alerts dynamically from critical/high severity events in MongoDB
  - Checks for existing alerts in MongoDB collection first
  - If no alerts exist, creates alerts from events with severity "critical" or "high"
  - Formats alert titles and descriptions based on event type:
    - File events: "Sensitive Data Detected in File" with file path
    - Clipboard events: "Sensitive Data Copied to Clipboard"
    - USB events: "USB Device Connected"
  - Sets all generated alerts to status "new"
  - Added optional filtering by severity and status
  - Fixed `current_user` access: Changed `current_user.get("email")` to `getattr(current_user, "email", "unknown")`

#### Files Changed
- `server/app/api/v1/alerts.py`

#### Testing
- Verified alerts page displays 33 new alerts (matching dashboard critical alerts count)
- Verified stats cards show correct counts (33 New, 0 Acknowledged, 0 Resolved)
- Verified alerts list displays:
  - Severity badges (critical)
  - Alert titles and descriptions
  - File paths for file events
  - Agent IDs
  - Timestamps
  - Event IDs
  - Acknowledge/Resolve buttons
- Verified alerts are generated from critical/high severity events

---

### 12. Windows Agent USB Monitoring Threading Fix

#### Problem
- Windows agent throwing `wmi.x_wmi_uninitialised_thread` error
- USB monitoring failing with COM initialization error
- Error message: "WMI returned a syntax error: you're probably running inside a thread without first calling pythoncom.CoInitialize[Ex]"

#### Solution
- **`agents/endpoint/windows/agent.py`**: Fixed COM initialization in USB monitoring thread
  - Changed from `pythoncom.CoInitialize()` to `pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)` for better thread safety
  - Added fallback to `CoInitialize()` if `CoInitializeEx` is not available
  - Improved error handling with `exc_info=True` for better debugging
  - Added try/except around `CoUninitialize()` to prevent cleanup errors
  - USB monitoring now properly initializes COM in the separate thread

#### Files Changed
- `agents/endpoint/windows/agent.py`

#### Testing Results
- ✅ USB monitoring starts without errors
- ✅ No more `x_wmi_uninitialised_thread` exceptions
- ✅ USB device detection working correctly
- ✅ Windows agent runs cleanly without threading errors

---

### 11. Agents Page Display Fix

#### Problem
- Agents page showing white screen
- `RangeError: Invalid time value` in console
- Outdated Agent type definition

#### Solution
- **`dashboard/src/pages/Agents.tsx`**: Updated field names
  - Changed `agent.registered_at` to `agent.created_at`
  - Updated to use `agent.last_seen` instead of `agent.last_heartbeat`

- **`dashboard/src/lib/utils.ts`**: Improved date handling
  - Added null/undefined checks in `formatRelativeTime`
  - Added try-catch for invalid dates
  - Returns "Never" for null/undefined dates

- **`dashboard/src/lib/api.ts`**: Updated Agent type
  - Changed `last_heartbeat` to `last_seen`
  - Added `created_at` field
  - Updated field types to match API response

#### Files Changed
- `dashboard/src/pages/Agents.tsx`
- `dashboard/src/lib/utils.ts`
- `dashboard/src/lib/api.ts`

---

## 📝 Configuration Changes

### Environment Variables

#### Docker Compose
- Added `CORS_ORIGINS` with WSL IP support
- Added `ALLOWED_HOSTS` for server access
- Updated dashboard build args for Vite environment variables

#### Server Configuration
- Port changed from 8000 to 55000
- OpenSearch SSL disabled by default
- CORS origins include WSL IP addresses

#### Agent Configuration
- Server URL updated to use port 55000
- Path updated to `/api/v1`
- WSL-specific IP addresses configured

---

## 🧪 Testing Results

### Dashboard
- ✅ Login page working
- ✅ Authentication flow functional
- ✅ Events page displaying events correctly
- ✅ Agents page showing agent information
- ✅ Alerts page displaying alerts correctly (generated from critical/high events)
- ✅ API calls working with proper authentication
- ✅ Dashboard overview page fixed - now displays real-time stats
- ✅ Dashboard stats cards showing correct agent and event counts
- ✅ Charts displaying data (Events Over Time, Events by Type, Events by Severity)
- ✅ Dashboard data synchronized with Agents, Events, and Alerts pages

### Linux Agent
- ✅ Agent registration successful
- ✅ Heartbeat sending correctly
- ✅ File monitoring functional
- ✅ Events being sent to server
- ✅ Sensitive data classification working

### Windows Agent
- ✅ Agent registration successful
- ✅ Heartbeat endpoint fixed (POST → PUT)
- ✅ File monitoring functional with environment variable expansion
- ✅ Clipboard monitoring working (Windows-specific feature)
- ✅ USB device monitoring working (Windows-specific feature) - Fixed threading error
- ✅ Events being sent to server
- ✅ Sensitive data classification working
- ✅ Environment variable expansion in monitored paths (%USERNAME%)
- ✅ USB monitoring COM initialization fixed (CoInitializeEx with COINIT_MULTITHREADED)

### Server API
- ✅ Events API returning correct format
- ✅ Authentication endpoints working
- ✅ Agent endpoints functional
- ✅ Database operations successful

---

## 🔧 Technical Details

### Port Changes
- **Server API**: 8000 → 55000
- **Dashboard**: 3000 (unchanged)
- **PostgreSQL**: 5432 (unchanged)
- **MongoDB**: 27017 (unchanged)
- **Redis**: 6379 (unchanged)
- **OpenSearch**: 9200 (unchanged)

### Build System Changes
- **Dashboard**: Next.js → Vite
- **Node Version**: 18 → 20
- **Package Manager**: npm (unchanged)

### Database Schema Changes
- **User ID**: Integer → UUID
- **User Roles**: Lowercase → Uppercase
- **Policies Table**: Added

---

## 🚀 Deployment Notes

### WSL2 Specific Configuration
- Server IP: `172.23.19.78` (WSL2 dynamic IP)
- CORS origins include WSL IP
- Agent configs use WSL-compatible URLs

### Default Credentials
- **Email**: `admin`
- **Password**: `admin`
- **Role**: `ADMIN`

---

## 📋 Files Modified Summary

### Backend (Server)
1. `server/Dockerfile` - Port configuration
2. `server/app/api/v1/dashboard.py` - Overview endpoint, timeline endpoint, stats
3. `server/app/api/v1/events.py` - Response format, user access, stats endpoints
4. `server/app/api/v1/alerts.py` - Alerts generation from events, current_user fix
5. `server/app/core/config.py` - OpenSearch SSL, database paths
6. `server/app/core/opensearch.py` - Client initialization
7. `server/app/core/security.py` - Role comparison
8. `server/app/models/user.py` - Role enum values
9. `server/app/services/blacklist_service.py` - Error handling
10. `server/init_db.py` - Database schema and policies table

### Frontend (Dashboard)
1. `dashboard/Dockerfile` - Vite migration
2. `dashboard/package.json` - Dependencies and scripts
3. `dashboard/src/App.tsx` - Login route
4. `dashboard/src/components/Layout.tsx` - Route protection
5. `dashboard/src/components/auth/LoginForm.tsx` - Router update
6. `dashboard/src/index.css` - Tailwind fix
7. `dashboard/src/lib/api.ts` - API client updates
8. `dashboard/src/lib/store/auth.ts` - Real authentication
9. `dashboard/src/lib/utils.ts` - Date handling
10. `dashboard/src/pages/Agents.tsx` - Field names
11. `dashboard/src/pages/Events.tsx` - Event structure
12. `dashboard/src/pages/Login.tsx` - New file

### Agents
1. `agents/endpoint/linux/agent.py` - Connectivity and permissions
2. `agents/endpoint/linux/agent_config.json` - Server URL
3. `agents/endpoint/windows/agent.py` - Heartbeat endpoint, path expansion, logging, USB monitoring COM initialization fix
4. `agents/endpoint/windows/agent_config.json` - WSL compatibility

### Infrastructure
1. `docker-compose.yml` - CORS, environment variables, build args

---

## ✅ Verification Checklist

- [x] Dashboard builds successfully
- [x] Dashboard authentication working
- [x] Dashboard overview page displaying real-time stats
- [x] Dashboard charts displaying data correctly
- [x] Events page displaying events
- [x] Agents page showing agents
- [x] Alerts page displaying alerts (generated from critical/high events)
- [x] Linux agent connecting to server
- [x] Windows agent connecting to server
- [x] Agents sending heartbeats correctly
- [x] File monitoring functional (Linux and Windows)
- [x] Clipboard monitoring functional (Windows)
- [x] USB monitoring functional (Windows)
- [x] Events being stored in database
- [x] API endpoints responding correctly
- [x] CORS issues resolved
- [x] Database initialization working
- [x] OpenSearch connectivity fixed
- [x] Browser testing completed for all features

---

## 🔮 Known Issues / Future Improvements

1. **Policy Evaluation**: Policies are created but not evaluated when events are received (documented in removed `POLICY_TEST_RESULTS.md`)
2. **Agent-Side Policy Enforcement**: Not implemented - all events sent with `"action": "logged"`
3. **WSL IP**: Currently hardcoded - should use dynamic detection or environment variable
4. **Default Password**: Should be changed in production

---

## 📚 Related Documentation

- See `INSTALLATION_GUIDE.md` for updated installation instructions
- See `AGENT_DEPLOYMENT.md` for agent deployment details
- See `DEPLOYMENT_GUIDE.md` for production deployment

---

**End of Changelog**


