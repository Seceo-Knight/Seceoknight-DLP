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
    } else if (d.kind === "blocked") {
      showBanner(d);
      try { chrome.runtime.sendMessage({ kind: "blocked-log", meta: d }); } catch (err) {}
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
})();
