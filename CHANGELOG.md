# Changelog - Testing and Fixes

**Date:** November 14-26, 2025  
**Testing Environment:** WSL2 (Ubuntu on Windows)  
**Tested By:** Vansh-Raja

This document details all changes, fixes, and improvements made during testing and deployment of the SeceoKnight DLP platform.

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


