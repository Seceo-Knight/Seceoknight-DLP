/*
 * SeceoKnight DLP — content script (ISOLATED world).
 *
 * Bridges the page-context interceptor (inject.js) to the extension
 * background service worker. inject.js cannot use chrome.* APIs, so it posts
 * classify requests here via window.postMessage; we relay to the background
 * (which talks to the native agent) and post the decision back to the page.
 * Also renders the on-page "blocked" banner.
 */
(function () {
  "use strict";

  // Admin-managed EXTRA cloud-upload destinations (dashboard-managed, on top
  // of inject.js's own hardcoded baseline). background.js keeps
  // chrome.storage.local's "skdlpExtraHosts" fresh; this content script
  // (ISOLATED world, has chrome.storage access) reads it and hands it to
  // inject.js (MAIN world, no chrome.* access) via postMessage.
  function pushExtraHosts(domains) {
    window.postMessage({ __skdlp: 1, dir: "toPage", kind: "extraHosts", domains: domains || [] }, "*");
  }

  // Web Activity Control's watched-destination list + whether the feature
  // is actually configured — mirrors pushExtraHosts above, feeds
  // web-activity.js's isWatchedHost()/webActivityEnforced instead of
  // inject.js's CLOUD_HOSTS.
  function pushAppCatalog(domains, enforced) {
    window.postMessage({ __skdlp: 1, dir: "toPage", kind: "appCatalog", domains: domains || [], enforced: !!enforced }, "*");
  }

  try {
    chrome.storage.local.get(["skdlpExtraHosts", "skdlpAppCatalog", "skdlpWebActivityEnforced"], function (res) {
      pushExtraHosts(res && res.skdlpExtraHosts);
      pushAppCatalog(res && res.skdlpAppCatalog, res && res.skdlpWebActivityEnforced);
    });
    chrome.storage.onChanged.addListener(function (changes, area) {
      if (area !== "local") return;
      if (changes.skdlpExtraHosts) {
        pushExtraHosts(changes.skdlpExtraHosts.newValue);
      }
      if (changes.skdlpAppCatalog || changes.skdlpWebActivityEnforced) {
        chrome.storage.local.get(["skdlpAppCatalog", "skdlpWebActivityEnforced"], function (res2) {
          pushAppCatalog(res2 && res2.skdlpAppCatalog, res2 && res2.skdlpWebActivityEnforced);
        });
      }
    });
  } catch (e) {
    // Extension context invalidated or storage unavailable — inject.js and
    // web-activity.js just keep using their last-known lists, fail-open by
    // omission (an empty appCatalogHosts means web-activity.js simply
    // never intercepts anything, same fail-open posture as everywhere else).
  }

  window.addEventListener("message", function (e) {
    if (e.source !== window) return;
    var d = e.data;
    if (!d || d.__skdlp !== 1 || d.dir !== "toContent") return;

    if (d.kind === "classify") {
      try {
        chrome.runtime.sendMessage({ kind: "classify", requestId: d.requestId, meta: d.meta }, function (resp) {
          var dec = (resp && resp.action) ? resp : { action: "allow", reason: "no-agent" };
          window.postMessage({
            __skdlp: 1, dir: "toPage", kind: "decision", requestId: d.requestId,
            action: dec.action, level: dec.level, reason: dec.reason
          }, "*");
        });
      } catch (err) {
        // Extension context invalidated → fail open.
        window.postMessage({ __skdlp: 1, dir: "toPage", kind: "decision", requestId: d.requestId, action: "allow", reason: "bridge-error" }, "*");
      }
    } else if (d.kind === "webActivity") {
      // GenAI / Web Activity Control path — separate message kind from
      // "classify" above so the two flows (and their native-host handlers)
      // can never cross-wire. See web-activity.js.
      try {
        chrome.runtime.sendMessage({ kind: "webActivity", requestId: d.requestId, meta: d.meta }, function (resp) {
          var dec = (resp && resp.action) ? resp : { action: "allow", reason: "no-agent" };
          window.postMessage({
            __skdlp: 1, dir: "toPage", kind: "webActivityDecision", requestId: d.requestId,
            action: dec.action, appCategory: dec.appCategory, level: dec.level,
            reason: dec.reason, redactedContent: dec.redactedContent,
          }, "*");
        });
      } catch (err) {
        window.postMessage({
          __skdlp: 1, dir: "toPage", kind: "webActivityDecision", requestId: d.requestId,
          action: "allow", reason: "bridge-error",
        }, "*");
      }
    } else if (d.kind === "blocked") {
      showBanner(d);
      try { chrome.runtime.sendMessage({ kind: "blocked-log", meta: d }); } catch (err) {}
    } else if (d.kind === "webActivityNotice") {
      showWebActivityBanner(d);
    }
  });

  function showBanner(d) {
    try {
      var id = "skdlp-blocked-banner";
      if (document.getElementById(id)) return;
      var el = document.createElement("div");
      el.id = id;
      el.textContent = "⛔  Upload blocked — this file is classified " +
        (d.level || "Sensitive") + " and may not be uploaded to cloud apps. (SeceoKnight DLP)";
      el.style.cssText = [
        "position:fixed", "z-index:2147483647", "top:16px", "left:50%",
        "transform:translateX(-50%)", "max-width:540px", "background:#b3261e",
        "color:#fff", "font:600 13px/1.4 system-ui,-apple-system,sans-serif",
        "padding:12px 18px", "border-radius:10px",
        "box-shadow:0 10px 34px rgba(0,0,0,.35)"
      ].join(";");
      (document.body || document.documentElement).appendChild(el);
      setTimeout(function () { try { el.remove(); } catch (e) {} }, 6000);
    } catch (e) {}
  }

  function showWebActivityBanner(d) {
    try {
      var id = "skdlp-webactivity-banner";
      var existing = document.getElementById(id);
      if (existing) existing.remove();
      var el = document.createElement("div");
      el.id = id;
      var color = d.noticeKind === "blocked" ? "#b3261e" : "#8a5a00"; // red for block, amber for redact/alert
      var msg = d.noticeKind === "blocked"
        ? "⛔  Blocked — this content is classified " + (d.level || "Sensitive") + " and may not be sent. (SeceoKnight DLP)"
        : d.noticeKind === "redacted"
          ? "✏️  Sensitive values were removed before this was sent/received. (SeceoKnight DLP)"
          : "⚠️  This activity involved " + (d.level || "sensitive") + " content and has been logged. (SeceoKnight DLP)";
      el.textContent = msg;
      el.style.cssText = [
        "position:fixed", "z-index:2147483647", "top:16px", "left:50%",
        "transform:translateX(-50%)", "max-width:540px", "background:" + color,
        "color:#fff", "font:600 13px/1.4 system-ui,-apple-system,sans-serif",
        "padding:12px 18px", "border-radius:10px",
        "box-shadow:0 10px 34px rgba(0,0,0,.35)"
      ].join(";");
      (document.body || document.documentElement).appendChild(el);
      setTimeout(function () { try { el.remove(); } catch (e) {} }, 6000);
    } catch (e) {}
  }
})();
