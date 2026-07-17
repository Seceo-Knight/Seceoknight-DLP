/*
 * SeceoKnight DLP — page-context upload interceptor (MAIN world).
 *
 * Wraps XMLHttpRequest.send / window.fetch so that any request carrying a
 * File/Blob (a file upload) to a known cloud host is PAUSED until the DLP
 * agent returns a decision. On "block" the request is aborted before any
 * bytes reach the network; on "allow"/"alert" it proceeds untouched.
 *
 * This runs in the page's own JS context (MAIN world) because it must patch
 * the same fetch/XHR the page uses. It cannot use chrome.* APIs, so it talks
 * to the ISOLATED content script (content.js) via window.postMessage, which
 * relays to the extension background and on to the native agent.
 *
 * Fail-open: any error or timeout lets the upload proceed (never break the
 * user's browser because DLP had a hiccup) — enforcement is best-effort at
 * this layer and backed by server-side + agent telemetry.
 */
(function () {
  "use strict";

  // Cloud upload destinations. Bytes going to these hosts get inspected.
  // Kept in sync with the agent's host list; broad on purpose (subdomains too).
  var CLOUD_HOSTS = [
    "google.com", "googleapis.com", "googleusercontent.com", "gmail.com",
    "drive.google.com", "docs.google.com", "mail.google.com",
    "dropbox.com", "dropboxapi.com", "dropboxusercontent.com",
    "onedrive.live.com", "1drv.ms", "sharepoint.com", "live.com", "office.com",
    "box.com", "boxcloud.com", "app.box.com",
    "wetransfer.com", "mega.nz", "mediafire.com", "icloud.com",
    "slack.com", "files.slack.com", "amazonaws.com", "wasabisys.com",
    "sendgrid.net", "s3.amazonaws.com"
  ];

  var MAX_CLASSIFY_BYTES = 10 * 1024 * 1024; // cap content sent for classification
  var DECISION_TIMEOUT_MS = 8000;

  var pending = new Map(); // requestId -> resolve()
  var seq = 0;

  function isCloudUrl(url) {
    try {
      var host = new URL(url, location.href).hostname.toLowerCase();
      return CLOUD_HOSTS.some(function (s) { return host === s || host.endsWith("." + s); });
    } catch (e) { return false; }
  }

  function requestDecision(meta) {
    return new Promise(function (resolve) {
      var requestId = Date.now() + "-" + (seq++);
      pending.set(requestId, resolve);
      window.postMessage({ __skdlp: 1, dir: "toContent", kind: "classify", requestId: requestId, meta: meta }, "*");
      setTimeout(function () {
        if (pending.has(requestId)) { pending.delete(requestId); resolve({ action: "allow", reason: "decision-timeout" }); }
      }, DECISION_TIMEOUT_MS);
    });
  }

  window.addEventListener("message", function (e) {
    var d = e.data;
    if (!d || d.__skdlp !== 1 || d.dir !== "toPage" || d.kind !== "decision") return;
    var r = pending.get(d.requestId);
    if (r) { pending.delete(d.requestId); r({ action: d.action, level: d.level, reason: d.reason }); }
  });

  function asFile(bytes, name, type) {
    return new File([bytes], name || "upload.bin", { type: type || "application/octet-stream" });
  }

  function collectFiles(body) {
    var files = [];
    if (body instanceof File) files.push(body);
    else if (body instanceof Blob) files.push(asFile(body, "upload.bin", body.type));
    // Resumable uploads (Google Drive, etc.) send raw bytes, not File/Blob.
    else if (body instanceof ArrayBuffer) files.push(asFile(body, "upload.bin"));
    else if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(body)) {
      files.push(asFile(body.buffer ? body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) : body, "upload.bin"));
    }
    else if (typeof FormData !== "undefined" && body instanceof FormData) {
      try {
        body.forEach(function (v) {
          if (v instanceof File) files.push(v);
          else if (v instanceof Blob) files.push(asFile(v, "upload.bin", v.type)); // bare Blob part (no filename)
        });
      } catch (e) {}
    }
    return files;
  }

  function fileToBase64(file) {
    var slice = file.slice(0, MAX_CLASSIFY_BYTES);
    return slice.arrayBuffer().then(function (buf) {
      var bytes = new Uint8Array(buf), bin = "", chunk = 0x8000;
      for (var i = 0; i < bytes.length; i += chunk) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
      }
      return btoa(bin);
    });
  }

  // Returns the strictest decision across all files in the body.
  function decideForBody(url, body) {
    if (!isCloudUrl(url) || body == null) return Promise.resolve({ action: "allow" });
    var files = collectFiles(body);
    // Diagnostic (page console): shows every cloud-host request this page realm
    // sees. If a Drive upload produces NO such line, the upload ran in a worker
    // the page hook can't reach — the known limitation.
    try {
      console.debug("[SK-DLP] cloud request →", new URL(url, location.href).hostname,
        "| bodyType:", body && body.constructor && body.constructor.name, "| files:", files.length);
    } catch (e) {}
    if (!files.length) return Promise.resolve({ action: "allow" });

    var worst = { action: "allow" };
    var chain = Promise.resolve();
    files.forEach(function (f) {
      chain = chain.then(function (blocked) {
        if (blocked) return blocked; // short-circuit once a block is decided
        return fileToBase64(f).then(function (b64) {
          return requestDecision({
            host: location.hostname, url: String(url),
            fileName: f.name || "upload.bin", fileSize: f.size,
            mimeType: f.type || "application/octet-stream", contentB64: b64
          }).then(function (dec) {
            if (dec.action === "block") return dec;
            if (dec.action === "alert" && worst.action === "allow") worst = dec;
            return null;
          });
        });
      });
    });
    return chain.then(function (blocked) { return blocked || worst; });
  }

  function announceBlock(dec, fileName) {
    window.postMessage({ __skdlp: 1, dir: "toContent", kind: "blocked", level: dec.level, reason: dec.reason, fileName: fileName }, "*");
  }

  // ---- patch XMLHttpRequest ----
  var XHRopen = XMLHttpRequest.prototype.open;
  var XHRsend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__skdlpUrl = url;
    return XHRopen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    var url = this.__skdlpUrl || "";
    if (!isCloudUrl(url) || body == null) return XHRsend.apply(this, arguments);
    var xhr = this, args = arguments;
    decideForBody(url, body).then(function (dec) {
      if (dec.action === "block") {
        announceBlock(dec, "");
        // Make the page observe a failed upload without any bytes leaving.
        try { Object.defineProperty(xhr, "status", { value: 403, configurable: true }); } catch (e) {}
        try { xhr.dispatchEvent(new ProgressEvent("error")); } catch (e) {}
        try { xhr.dispatchEvent(new Event("loadend")); } catch (e) {}
      } else {
        XHRsend.apply(xhr, args);
      }
    }, function () { XHRsend.apply(xhr, args); }); // fail-open
  };

  // ---- patch fetch ----
  var origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function (input, init) {
      var url = (typeof input === "string") ? input : (input && input.url) || "";
      var body = init && init.body;
      if (!isCloudUrl(url) || body == null) return origFetch.apply(this, arguments);
      return decideForBody(url, body).then(function (dec) {
        if (dec.action === "block") {
          announceBlock(dec, "");
          return new Response("", { status: 403, statusText: "Blocked by SeceoKnight DLP" });
        }
        return origFetch.call(window, input, init);
      }, function () { return origFetch.call(window, input, init); });
    };
  }
})();
