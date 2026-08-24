/*
 * SeceoKnight DLP - background service worker (MV3).
 *
 * Owns the Native Messaging connection to the endpoint agent
 * ("com.seceoknightdlp.dlp"). Relays classify requests and returns the agent's
 * allow/alert/block decision. Fail-open everywhere (a DLP outage must never
 * brick the browser) — but every failure is now LOGGED to this service
 * worker's console so setup problems are visible instead of silent.
 *
 * Debug it: chrome://extensions -> this extension -> "service worker" ->
 * Console. On browser start you should see "self-test: ping sent" and, if the
 * native host is correctly registered, "native host reachable (pong)". If you
 * instead see "could not connect to native host", the host manifest / registry
 * / extension-id is wrong (see INSTALL_WINDOWS.md).
 */
"use strict";

const NATIVE_HOST = "com.seceoknightdlp.dlp";
const AGENT_TIMEOUT_MS = 7000;
// GenAI / Web Activity Control (web-activity.js): a genai reply can be long
// and classification of it takes longer than a small upload decision does —
// separate, more generous timeout so a slow-but-legitimate response isn't
// mistaken for a hung agent.
const WEB_ACTIVITY_TIMEOUT_MS = 16000;

function log(...a) { console.log("[SK-DLP]", ...a); }
function warn(...a) { console.warn("[SK-DLP]", ...a); }

let port = null;
const waiters = new Map(); // requestId -> respond (fans out to every piggybacked caller, see inFlightByKey)
const requestKeys = new Map(); // requestId -> coalesce key, ONLY set for requests we're willing to cache

// GenAI / Web Activity Control (web-activity.js) requests. Originally a
// separate, simpler map from waiters/requestKeys/inFlightByKey above on the
// theory that a genai prompt/response isn't a chunked upload, so there was
// no equivalent need for cross-request coalescing/piggybacking here — each
// request just got its own waiter.
//
// That theory turned out to be wrong in the field (real endpoint, Aug 19
// 2026): ChatGPT's own SPA fires several background POST requests within
// the same second as a single real "send message" click — conversation
// metadata, moderation pre-checks, and similar internal calls, each of
// which independently satisfies web-activity.js's isWatchedHost() + 40-char
// gate. Without coalescing, one real user action was logging 4-6 near-
// duplicate medium-severity events instead of one, flooding the dashboard.
// waRecentDecisions below fixes this the same way recentDecisions above
// fixes it for chunked uploads — keyed on host+activity rather than
// content, since these background requests often carry DIFFERENT bodies
// for the same logical user action, so a content-based key wouldn't
// coalesce them.
const waWaiters = new Map(); // requestId -> respond
const waRequestKeys = new Map(); // requestId -> coalesce key, ONLY set for requests we're willing to cache
const waRecentDecisions = new Map(); // "host:activity" -> { decision, expiresAt }
const WA_COALESCE_WINDOW_MS = 4000; // matches COALESCE_WINDOW_MS's own reasoning below

function waCoalesceKeyFor(meta) {
  return ((meta && meta.host) || "") + ":" + ((meta && meta.activity) || "");
}

// In-flight requests, keyed the same way as recentDecisions. A completed
// decision only gets cached AFTER the native host responds — so two
// requests for the SAME file that both arrive before the first one's round
// trip finishes would previously both go out to the native host and both
// fire their own alert/event, even with the file-identity coalescing key
// above. This tracks the in-progress "leader" request per key so a second,
// concurrent request for the same key piggybacks on it instead of racing it.
const inFlightByKey = new Map(); // coalesce key -> { waiters: [sendResponse, ...] }

// Cross-frame decision cache. manifest.json injects inject.js into EVERY
// frame/iframe on the page ("all_frames": true), each with its own isolated
// JS global scope — so a per-frame cache in inject.js (see its own comment)
// cannot coalesce requests that originate from two different frames of the
// same page, which is exactly what a site like Gmail (built from several
// frames) triggers: a real content request from one frame and unrelated
// background traffic from another frame, a fraction of a second apart, each
// starting from a blank per-frame cache and getting classified independently.
// background.js is the one place every frame's "classify" message already
// converges on, so it's the correct layer for a TRUE cross-frame cache.
const recentDecisions = new Map(); // coalesce key -> { decision, expiresAt }
const COALESCE_WINDOW_MS = 4000;

// What identifies "this is the same upload" for coalescing purposes. Used to
// be destination host alone — but chunked/resumable upload protocols
// (Gmail, Google Drive) can split ONE file's bytes across MULTIPLE network
// requests that go to genuinely DIFFERENT hosts/subdomains, not just
// multiple requests to the same host. Before the real-file-capture fix in
// inject.js, those extra requests were misclassified as generic
// "upload.bin" with no content, so the duplication was mostly invisible;
// now that they carry the real captured file's name+content, every one of
// them classifies correctly (and fires its own alert) unless they're
// recognized as the same upload. So: key on the file's own identity
// (name+size) when we have a REAL name (not the "upload.bin" fallback) —
// that's what's actually stable across however many requests/hosts one
// upload produces. Falls back to destination host when there's no real
// filename to key on, same as the original behavior for that case.
function coalesceKeyFor(meta) {
  const fileName = meta && meta.fileName;
  const fileSize = meta && meta.fileSize;
  if (fileName && fileName !== "upload.bin" && typeof fileSize === "number") {
    return "file:" + fileName + ":" + fileSize;
  }
  return "host:" + ((meta && meta.host) || "");
}

// Admin-managed EXTRA cloud-upload destinations (dashboard-managed, additive
// only — see server/app/models/cloud_upload_hosts.py). Fetched from the
// native host, which itself fetches from the DLP server, and mirrored into
// chrome.storage.local so every tab's content.js can hand it to inject.js
// (MAIN world, no chrome.* API access) without a round trip per page load.
const HOSTS_REFRESH_ALARM = "skdlp-hosts-refresh";

function fetchExtraHosts() {
  if (!port) connect();
  if (!port) { warn("fetchExtraHosts: no native host available"); return; }
  try { port.postMessage({ type: "get_hosts" }); }
  catch (e) { warn("fetchExtraHosts: postMessage failed:", e && e.message); }
}

// Web Activity Control's watched-destination list + whether the feature is
// actually configured — see skdlp_host.py's fetch_app_catalog(). Refreshed
// on the same cadence as fetchExtraHosts (self-test triggers + the
// recurring alarm below).
function fetchAppCatalog() {
  if (!port) connect();
  if (!port) { warn("fetchAppCatalog: no native host available"); return; }
  try { port.postMessage({ type: "get_app_catalog" }); }
  catch (e) { warn("fetchAppCatalog: postMessage failed:", e && e.message); }
}

function failOpenAll(reason) {
  for (const [, respond] of waiters) { try { respond({ action: "allow", reason }); } catch (e) {} }
  waiters.clear();
  requestKeys.clear();
  // Also drop in-flight leaders — otherwise a key stuck here (its leader's
  // waiters map entry just got wiped above, so it will never resolve) would
  // permanently block every future request for that file from ever becoming
  // a new leader, silently fail-closed-by-omission forever after one
  // disconnect. Safe to drop: nothing here has a decision yet anyway.
  inFlightByKey.clear();
  for (const [, respond] of waWaiters) { try { respond({ action: "allow", reason }); } catch (e) {} }
  waWaiters.clear();
  waRequestKeys.clear();
}

function connect() {
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST);
    log("connectNative attempted for", NATIVE_HOST);
    port.onMessage.addListener((msg) => {
      if (msg && msg.type === "pong") { log("native host reachable (pong):", JSON.stringify(msg)); return; }
      if (msg && msg.type === "hosts") {
        const domains = Array.isArray(msg.domains) ? msg.domains : [];
        chrome.storage.local.set({ skdlpExtraHosts: domains });
        log("extra cloud hosts updated:", domains.length, domains.length ? "(" + domains.join(", ") + ")" : "");
        return;
      }
      if (msg && msg.type === "app_catalog") {
        const domains = Array.isArray(msg.domains) ? msg.domains : [];
        const enforced = !!msg.enforced;
        chrome.storage.local.set({ skdlpAppCatalog: domains, skdlpWebActivityEnforced: enforced });
        log("app catalog updated:", domains.length, "domains, web-activity enforced:", enforced);
        return;
      }
      if (msg && msg.requestId && waWaiters.has(msg.requestId)) {
        const respond = waWaiters.get(msg.requestId);
        waWaiters.delete(msg.requestId);
        const decision = {
          action: msg.action || "allow", appCategory: msg.appCategory,
          level: msg.level, reason: msg.reason, redactedContent: msg.redactedContent,
        };
        log("web-activity decision", msg.requestId, "->", decision.action, decision.appCategory || "");
        const waKey = waRequestKeys.get(msg.requestId);
        waRequestKeys.delete(msg.requestId);
        // Cache for coalescing (see waRecentDecisions' own comment) — EXCEPT
        // "redact", whose redactedContent is specific to THIS request's own
        // body. Reusing it for a different, later request within the
        // coalesce window would substitute the wrong redacted text into
        // that request instead of its own — silent data corruption, not
        // just a missed detection. allow/alert/block don't have that
        // problem: the action itself doesn't depend on which exact
        // background request triggered it.
        if (waKey && decision.action !== "redact") {
          waRecentDecisions.set(waKey, { decision, expiresAt: Date.now() + WA_COALESCE_WINDOW_MS });
        }
        respond(decision);
        return;
      }
      if (!msg || !msg.requestId) return;
      const respond = waiters.get(msg.requestId);
      if (respond) {
        waiters.delete(msg.requestId);
        const decision = { action: msg.action || "allow", level: msg.level, reason: msg.reason };
        log("decision", msg.requestId, "->", decision.action, decision.level || "");
        // This is the ONE place a genuine native-host decision arrives, so
        // it's the only place we cache — a timeout/send-failed/disconnect
        // fail-open never reaches here (see requestKeys.delete at each of
        // those sites below), so it can't poison the next real request.
        const coalesceKey = requestKeys.get(msg.requestId);
        requestKeys.delete(msg.requestId);
        if (coalesceKey) {
          recentDecisions.set(coalesceKey, { decision, expiresAt: Date.now() + COALESCE_WINDOW_MS });
          // Clear the leader marker now that a real decision exists — any
          // follower that piggybacked is fanned out via respond() below
          // (waiters.get returns the fan-out closure, not a single
          // sendResponse, once a request has become a leader; see the
          // classify handler). Future requests for this key are free to
          // become a new leader (or hit recentDecisions above instead).
          inFlightByKey.delete(coalesceKey);
        }
        respond(decision);
      }
    });
    port.onDisconnect.addListener(() => {
      const err = chrome.runtime.lastError;
      warn("native host disconnected:", err ? err.message : "(no lastError)");
      port = null;
      failOpenAll("agent-disconnected");
    });
    return true;
  } catch (e) {
    warn("connectNative threw:", e && e.message);
    port = null;
    return false;
  }
}

// Runs on browser start / extension load. Launches the native host (which logs
// "host started" to dlp-host.log the moment it runs) and round-trips a ping —
// so you can confirm the whole bridge WITHOUT needing an upload.
function selfTest() {
  log("self-test: connecting to native host…");
  if (!port) connect();
  if (port) {
    try { port.postMessage({ type: "ping" }); log("self-test: ping sent (expect a pong + a dlp-host.log entry)"); }
    catch (e) { warn("self-test: ping failed:", e && e.message); }
  } else {
    warn("self-test: COULD NOT CONNECT to native host — check the host manifest, registry key, and that allowed_origins matches this extension id.");
  }
}

chrome.runtime.onStartup.addListener(selfTest);
chrome.runtime.onInstalled.addListener(selfTest);
selfTest(); // also fires when the service worker first spins up

// Refresh the admin-managed extra-hosts list on every self-test trigger, plus
// on a recurring alarm — MV3 service workers can be terminated between page
// loads, so a plain setInterval isn't reliable; chrome.alarms survives that.
fetchExtraHosts();
fetchAppCatalog();
chrome.runtime.onStartup.addListener(fetchExtraHosts);
chrome.runtime.onStartup.addListener(fetchAppCatalog);
chrome.runtime.onInstalled.addListener(fetchExtraHosts);
chrome.runtime.onInstalled.addListener(fetchAppCatalog);
try {
  chrome.alarms.create(HOSTS_REFRESH_ALARM, { periodInMinutes: 15 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === HOSTS_REFRESH_ALARM) { fetchExtraHosts(); fetchAppCatalog(); }
  });
} catch (e) {
  warn("chrome.alarms unavailable, extra-hosts/app-catalog lists will only refresh on browser/extension restart:", e && e.message);
}

// Extension self-update (gap-scan of CyberSentinel-DLP, August 19, 2026):
// ExtensionInstallForcelist only guarantees the extension is PRESENT, not
// current. Chrome/Edge check the update feed (update.xml) on their own
// multi-hour timer, independent of restarts -- CyberSentinel's own installer
// spent several rounds on exactly this before finding it: an endpoint sat on
// a stale force-installed version for DAYS with a newer one published and
// reachable, because nothing was ever telling the browser to look sooner.
// requestUpdateCheck() is the browser's own supported "check my update URL
// now"; onUpdateAvailable fires once a newer version has actually been
// downloaded but Chrome is waiting for the extension to go idle before
// swapping it in underneath itself -- reload() immediately instead, since a
// DLP control silently staying on a known-stale build is worse than one
// reload interruption.
//
// Declared here, before first use, deliberately -- CyberSentinel's own fix
// for this hit a temporal-dead-zone bug from declaring the alarm name after
// the function that referenced it.
const UPDATE_CHECK_ALARM = "skdlp-update-check";

// Dotted-integer version comparator ("1.0.4" vs "1.0.5") -- good enough for
// this extension's manifest versions (always plain dotted integers, no
// pre-release suffixes), not a general semver parser. Returns negative/0/
// positive like a normal comparator.
function compareVersions(a, b) {
  const pa = String(a || "0").split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b || "0").split(".").map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function checkForUpdate(reason) {
  try {
    chrome.runtime.requestUpdateCheck((status) => {
      // "throttled" is Chrome's own rate limit on how often this can be
      // called, not a failure -- logging it here (instead of silence) is
      // what would have saved CyberSentinel days of chasing the server for
      // an explanation, per their own commit message.
      log("requestUpdateCheck (" + (reason || "?") + "):", status);
    });
  } catch (e) {
    warn("requestUpdateCheck failed:", e && e.message);
  }
}

// Gap-scan of CyberSentinel-DLP 2.9.1 (August 24, 2026): two refinements on
// top of the plain hourly/on-start check above, both riding on "wantVersion"
// -- the currently-published version, written into chrome.storage.managed
// by agent.cpp's Browser Extension Guard task the SAME safe way serverUrl/
// agentId already are (NOT the ExtensionSettings mechanism that broke Edge
// and was reverted the same day it shipped -- see agent.cpp's comment).
//
// 1. requestUpdateCheck() is throttled by Chrome itself (a limited number of
//    calls per time window) -- calling it unconditionally from every alarm
//    tick, browser start, AND install wastes that budget on checks that
//    find nothing, the same mistake CyberSentinel's own first pass at this
//    made. wantVersion is a cheap, unthrottled comparison: skip the real
//    check entirely when the installed version already matches what the
//    server has published.
// 2. Reacting to wantVersion CHANGING via chrome.storage.onChanged means a
//    freshly-published version reaches an already-running browser within
//    about 2 minutes (the guard task's own tick) instead of up to an hour
//    later on the alarm. This can only ever ASK Chrome to check for an
//    update -- unlike ExtensionSettings' minimum_version_required, it has
//    no way to force anything about how the browser itself starts, so it
//    can't repeat that failure.
function maybeCheckForUpdate(reason) {
  try {
    chrome.storage.managed.get(["wantVersion"], (managed) => {
      if (chrome.runtime.lastError) {
        // No managed policy at all (unmanaged/standalone install) -- fall
        // back to always checking, same as before this refinement existed.
        checkForUpdate(reason);
        return;
      }
      const wantVersion = managed && managed.wantVersion;
      const currentVersion = chrome.runtime.getManifest().version;
      if (!wantVersion || compareVersions(wantVersion, currentVersion) > 0) {
        checkForUpdate(reason);
      } else {
        log("skipping update check (" + reason + "): already at", currentVersion, "server wants", wantVersion || "(unset)");
      }
    });
  } catch (e) {
    // chrome.storage.managed itself unavailable for some reason -- fail
    // open to the unconditional check rather than never checking at all.
    checkForUpdate(reason);
  }
}

try {
  chrome.runtime.onUpdateAvailable.addListener((details) => {
    log("update available (" + (details && details.version) + ") -- reloading now to apply it");
    chrome.runtime.reload();
  });
} catch (e) {
  warn("onUpdateAvailable unavailable:", e && e.message);
}

try {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "managed" && changes.wantVersion) {
      log("wantVersion changed ->", changes.wantVersion.newValue, "-- checking immediately");
      maybeCheckForUpdate("wantVersion-changed");
    }
  });
} catch (e) {
  warn("chrome.storage.onChanged unavailable:", e && e.message);
}

maybeCheckForUpdate("startup");
chrome.runtime.onStartup.addListener(() => maybeCheckForUpdate("onStartup"));
chrome.runtime.onInstalled.addListener(() => maybeCheckForUpdate("onInstalled"));
try {
  chrome.alarms.create(UPDATE_CHECK_ALARM, { periodInMinutes: 60 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === UPDATE_CHECK_ALARM) maybeCheckForUpdate("alarm");
  });
} catch (e) {
  warn("chrome.alarms unavailable, update checks will only run on browser/extension restart:", e && e.message);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message && message.kind === "webActivity") {
    // GenAI / Web Activity Control path — see waRecentDecisions' own
    // comment above for why this now coalesces the same way "classify"
    // below does, instead of hitting the native host (and logging a new
    // event) for every qualifying background request a genai SPA fires
    // within the same burst of real user activity.
    const waKey = waCoalesceKeyFor(message.meta);
    const waCached = waRecentDecisions.get(waKey);
    if (waCached && waCached.expiresAt > Date.now()) {
      log("reusing cached web-activity decision for", waKey, "->", waCached.decision.action);
      sendResponse(waCached.decision);
      return false;
    }

    if (!port) connect();
    if (!port) {
      warn("webActivity: no native host available → allow (fail-open)");
      sendResponse({ action: "allow", reason: "agent-unavailable" });
      return false;
    }
    waWaiters.set(message.requestId, sendResponse);
    waRequestKeys.set(message.requestId, waKey);
    try {
      port.postMessage(Object.assign({ type: "web_activity", requestId: message.requestId }, message.meta));
    } catch (e) {
      waWaiters.delete(message.requestId);
      waRequestKeys.delete(message.requestId);
      warn("webActivity postMessage to host failed:", e && e.message);
      sendResponse({ action: "allow", reason: "send-failed" });
      return false;
    }
    setTimeout(() => {
      if (waWaiters.has(message.requestId)) {
        const respond = waWaiters.get(message.requestId);
        waWaiters.delete(message.requestId);
        waRequestKeys.delete(message.requestId);
        warn("webActivity agent timeout for", message.requestId);
        respond({ action: "allow", reason: "agent-timeout" });
      }
    }, WEB_ACTIVITY_TIMEOUT_MS);
    return true; // async response
  }

  if (!message || message.kind !== "classify") return false;
  const destHost = (message.meta && message.meta.host) || "";
  const coalesceKey = coalesceKeyFor(message.meta);
  log("classify:", (message.meta && message.meta.fileName) || "?", "→", destHost || "?", "| key:", coalesceKey);

  // Reuse a recent real decision for the same upload instead of hitting the
  // native host (and re-logging an event) for every chunk/request of it.
  const cached = recentDecisions.get(coalesceKey);
  if (cached && cached.expiresAt > Date.now()) {
    log("reusing cached decision for", coalesceKey, "->", cached.decision.action);
    sendResponse(cached.decision);
    return false;
  }

  // A "leader" request for this exact file is already in flight (its
  // round-trip to the native host hasn't completed, so recentDecisions above
  // is still empty for it) — piggyback on the leader instead of racing it
  // with a second independent classify call to the native host. This closes
  // the race-condition gap the cache alone can't: recentDecisions only gets
  // populated once the leader's decision actually arrives (see port.onMessage
  // below), so a follower arriving BEFORE that point needs this separate
  // in-flight registry.
  const inFlight = inFlightByKey.get(coalesceKey);
  if (inFlight) {
    log("piggybacking on in-flight request for", coalesceKey);
    inFlight.waiters.push(sendResponse);
    return true; // async — answered when the leader's decision arrives
  }

  if (!port) connect();
  if (!port) { warn("no native host available → allow (fail-open)"); sendResponse({ action: "allow", reason: "agent-unavailable" }); return false; }

  // Become the leader for this key. leaderEntry.waiters starts with just
  // this caller, and grows if other requests for the same key piggyback
  // before the native host responds.
  const leaderEntry = { waiters: [sendResponse] };
  inFlightByKey.set(coalesceKey, leaderEntry);
  const fanOut = (decision) => {
    for (const respond of leaderEntry.waiters) { try { respond(decision); } catch (e) {} }
  };
  waiters.set(message.requestId, fanOut);
  requestKeys.set(message.requestId, coalesceKey); // eligible to be cached if a real decision arrives
  try {
    port.postMessage(Object.assign({ type: "classify", requestId: message.requestId }, message.meta));
  } catch (e) {
    waiters.delete(message.requestId);
    requestKeys.delete(message.requestId);
    inFlightByKey.delete(coalesceKey);
    warn("postMessage to host failed:", e && e.message);
    fanOut({ action: "allow", reason: "send-failed" });
    return false;
  }

  setTimeout(() => {
    const respond = waiters.get(message.requestId);
    if (respond) {
      waiters.delete(message.requestId);
      requestKeys.delete(message.requestId); // fail-open — never cache this as a real decision
      inFlightByKey.delete(coalesceKey);
      warn("agent timeout for", message.requestId);
      respond({ action: "allow", reason: "agent-timeout" }); // fans out to every piggybacked waiter too
    }
  }, AGENT_TIMEOUT_MS);

  return true; // async response
});
