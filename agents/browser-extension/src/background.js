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

function log(...a) { console.log("[SK-DLP]", ...a); }
function warn(...a) { console.warn("[SK-DLP]", ...a); }

let port = null;
const waiters = new Map(); // requestId -> sendResponse
const requestKeys = new Map(); // requestId -> coalesce key, ONLY set for requests we're willing to cache

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

function failOpenAll(reason) {
  for (const [, respond] of waiters) { try { respond({ action: "allow", reason }); } catch (e) {} }
  waiters.clear();
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
chrome.runtime.onStartup.addListener(fetchExtraHosts);
chrome.runtime.onInstalled.addListener(fetchExtraHosts);
try {
  chrome.alarms.create(HOSTS_REFRESH_ALARM, { periodInMinutes: 15 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === HOSTS_REFRESH_ALARM) fetchExtraHosts();
  });
} catch (e) {
  warn("chrome.alarms unavailable, extra-hosts list will only refresh on browser/extension restart:", e && e.message);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
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

  if (!port) connect();
  if (!port) { warn("no native host available → allow (fail-open)"); sendResponse({ action: "allow", reason: "agent-unavailable" }); return false; }

  waiters.set(message.requestId, sendResponse);
  requestKeys.set(message.requestId, coalesceKey); // eligible to be cached if a real decision arrives
  try {
    port.postMessage(Object.assign({ type: "classify", requestId: message.requestId }, message.meta));
  } catch (e) {
    waiters.delete(message.requestId);
    requestKeys.delete(message.requestId);
    warn("postMessage to host failed:", e && e.message);
    sendResponse({ action: "allow", reason: "send-failed" });
    return false;
  }

  setTimeout(() => {
    const respond = waiters.get(message.requestId);
    if (respond) {
      waiters.delete(message.requestId);
      requestKeys.delete(message.requestId); // fail-open — never cache this as a real decision
      warn("agent timeout for", message.requestId);
      respond({ action: "allow", reason: "agent-timeout" });
    }
  }, AGENT_TIMEOUT_MS);

  return true; // async response
});
