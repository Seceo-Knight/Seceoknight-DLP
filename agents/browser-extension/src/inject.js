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
    // Outlook web mail runs on domains of its own that "office.com"/"live.com"
    // don't cover ("outlook.office365.com" does NOT end with ".office.com" —
    // office365.com is a different root domain; bare "outlook.com" doesn't
    // end with ".live.com" either) — found missing entirely after a real
    // Outlook test never triggered a single interception. Enterprise-grade
    // support for Outlook (explicitly required alongside Gmail) needs these.
    "outlook.com", "outlook.office.com", "outlook.office365.com",
    "outlook.cloud.microsoft", "microsoftonline.com",
    "box.com", "boxcloud.com", "app.box.com",
    "wetransfer.com", "mega.nz", "mediafire.com", "icloud.com",
    "slack.com", "files.slack.com", "amazonaws.com", "wasabisys.com",
    "sendgrid.net", "s3.amazonaws.com"
  ];

  var MAX_CLASSIFY_BYTES = 10 * 1024 * 1024; // cap content sent for classification
  var DECISION_TIMEOUT_MS = 8000;

  var pending = new Map(); // requestId -> resolve()
  var seq = 0;

  // Chunked/resumable upload protocols (Gmail, Google Drive, etc.) split ONE
  // logical file the user attaches into several separate network requests
  // (an init call, one or more byte-range chunks, progress pings, ...). Each
  // request used to be classified and logged completely independently, which
  // is why attaching a single file could flood the dashboard with many
  // near-identical events, all showing the generic "upload.bin" name (none
  // of those individual chunk requests are real File objects with a name —
  // same underlying cause as the filename issue).
  //
  // Coalesce: reuse the most recent decision for a destination host for a
  // short window instead of re-classifying + re-logging every chunk.
  // Deliberate trade-off, not a full fix: a block decision is always reused
  // as block (never weakens), but a genuinely different file uploaded to the
  // SAME host within the window would inherit the earlier decision rather
  // than being freshly classified. Kept short to bound that risk.
  var recentDecisions = new Map(); // host -> { promise, expiresAt }
  var COALESCE_WINDOW_MS = 4000;

  // Admin-managed EXTRA cloud-upload destinations, added from the dashboard
  // (server/app/models/cloud_upload_hosts.py) on top of the CLOUD_HOSTS
  // baseline above — lets an admin start monitoring a new destination
  // without redeploying this file to every machine. Populated by content.js
  // (this file can't use chrome.* APIs directly, since it runs in the page's
  // MAIN world) and kept fresh in the background as the admin edits the list.
  var extraHosts = [];
  window.addEventListener("message", function (e) {
    var d = e.data;
    if (!d || d.__skdlp !== 1 || d.dir !== "toPage" || d.kind !== "extraHosts") return;
    extraHosts = Array.isArray(d.domains) ? d.domains : [];
  });

  function isCloudUrl(url) {
    try {
      var host = new URL(url, location.href).hostname.toLowerCase();
      var matches = function (s) { return host === s || host.endsWith("." + s); };
      return CLOUD_HOSTS.some(matches) || extraHosts.some(matches);
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

  // Real file capture (fixes the Gmail/Drive filename+content problem at the
  // source instead of guessing at it downstream).
  //
  // Chunked/resumable upload protocols (Gmail, Google Drive) send the file's
  // actual bytes to an opaque session URI with no filename anywhere in that
  // specific request — the real name only exists in an earlier, separate
  // metadata-initiation call this code never sees. Worse: because the server
  // picks how to parse a file BY ITS EXTENSION, an unrecoverable filename
  // doesn't just mean an ugly "upload.bin" in the dashboard — the server logs
  // "binary/unknown format .bin" and extracts NO content at all, so nothing
  // ever gets classified and everything defaults to Public/allow. That is a
  // real detection bypass, not a cosmetic issue (confirmed via the manager's
  // own "Content not extractable" / "matched_rules_count: 0" logs).
  //
  // Fix: capture the REAL File object the moment the user selects it (via a
  // <input type=file> change event) or drops it onto the page — both fire
  // BEFORE the site's own JS reads/repackages the bytes into whatever upload
  // request(s) it sends. That gives us the true name AND untouched original
  // bytes, sidestepping Gmail's chunking entirely: even if a later network
  // request only carries a fragment/byte-range of the file, we substitute
  // the complete originally-selected File for classification instead of
  // trying to parse that fragment.
  //
  // This never fires more classify/log requests than before: it only swaps
  // WHICH bytes+name get sent into the exact same per-request classify flow
  // that already runs in decideForBody(). No capture -> identical behavior
  // to before (fail-open by construction, not just by exception handling).
  var capturedFiles = []; // { file, capturedAt } newest first
  var CAPTURE_MAX_AGE_MS = 60000;

  function captureFileList(list) {
    try {
      if (!list || !list.length) return;
      for (var i = 0; i < list.length; i++) {
        var f = list[i];
        if (f && typeof File !== "undefined" && f instanceof File && f.size > 0) {
          capturedFiles.unshift({ file: f, capturedAt: Date.now() });
          try { console.debug("[SK-DLP] captured file selection:", f.name, "(" + f.size + " bytes)"); } catch (e) {}
        }
      }
      if (capturedFiles.length > 8) capturedFiles.length = 8;
    } catch (e) {}
  }

  document.addEventListener("change", function (e) {
    var t = e.target;
    if (t && t.files) captureFileList(t.files);
  }, true);
  document.addEventListener("drop", function (e) {
    try { if (e.dataTransfer && e.dataTransfer.files) captureFileList(e.dataTransfer.files); } catch (err) {}
  }, true);

  // Best-effort match: prefer a captured file whose size exactly matches the
  // network body we're about to classify (covers simple single-request
  // uploads exactly); otherwise fall back to the most recent capture (covers
  // chunked uploads, where no individual chunk equals the full file size —
  // still correct, since it's the same file, just a different byte range of
  // the request that triggered classification).
  function pickCapturedFile(byteLength) {
    var now = Date.now();
    capturedFiles = capturedFiles.filter(function (c) { return (now - c.capturedAt) <= CAPTURE_MAX_AGE_MS; });
    if (!capturedFiles.length) return null;
    if (typeof byteLength === "number") {
      for (var i = 0; i < capturedFiles.length; i++) {
        if (capturedFiles[i].file.size === byteLength) return capturedFiles[i].file;
      }
    }
    return capturedFiles[0].file;
  }

  // Best-effort filename recovery for raw Blob/ArrayBuffer bodies, which the
  // Fetch/XHR APIs never attach a name to (only a real File object has one —
  // see the module-level comment in decideForBody for the full explanation).
  // Some services put the filename in the request URL as a query parameter;
  // this catches that case. It does NOT catch Google's resumable-upload
  // pattern (Gmail/Drive), where the byte-content request goes to an opaque
  // session URI with no filename anywhere in that specific request — the
  // real name lives only in an earlier, separate metadata-initiation call.
  // Fixing that fully would need correlating two distinct network requests
  // per upload, which isn't safe to build without being able to inspect the
  // actual live traffic — so for Gmail/Drive specifically, "upload.bin" is a
  // known, documented limitation for now, not something this function fixes.
  // A path segment "looks like" a filename if it ends in a short extension —
  // filters out opaque upload-session IDs/tokens (e.g. S3 object keys,
  // UUIDs) that happen to be the last path segment but aren't a real name.
  function looksLikeFileName(segment) {
    return /\.[A-Za-z0-9]{1,8}$/.test(segment) && segment.length <= 120;
  }

  function guessFileNameFromUrl(url) {
    try {
      var parsed = new URL(url, location.href);
      var candidates = ["filename", "fileName", "name", "title", "upload_name"];
      for (var i = 0; i < candidates.length; i++) {
        var v = parsed.searchParams.get(candidates[i]);
        if (v) return decodeURIComponent(v);
      }
      // Some services (S3-backed uploaders, filebin-style services, ...)
      // encode the filename as the LAST PATH SEGMENT instead of a query
      // param, e.g. PUT /uploads/abc123/report.pdf. Only trust it if it
      // looks like a real filename (has an extension), not an opaque
      // session/object id.
      var parts = parsed.pathname.split("/").filter(Boolean);
      var last = parts.length ? decodeURIComponent(parts[parts.length - 1]) : "";
      if (last && looksLikeFileName(last)) return last;
    } catch (e) {}
    return null;
  }

  function collectFiles(body, url) {
    var files = [];
    var urlHint = url ? guessFileNameFromUrl(url) : null;
    if (body instanceof File) files.push(body);
    else if (body instanceof Blob) {
      var capturedB = pickCapturedFile(body.size);
      files.push(capturedB || asFile(body, urlHint || "upload.bin", body.type));
    }
    // Resumable uploads (Google Drive, etc.) send raw bytes, not File/Blob.
    else if (body instanceof ArrayBuffer) {
      var capturedAB = pickCapturedFile(body.byteLength);
      files.push(capturedAB || asFile(body, urlHint || "upload.bin"));
    }
    else if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(body)) {
      var capturedTB = pickCapturedFile(body.byteLength);
      files.push(capturedTB || asFile(body.buffer ? body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) : body, urlHint || "upload.bin"));
    }
    else if (typeof FormData !== "undefined" && body instanceof FormData) {
      try {
        body.forEach(function (v) {
          if (v instanceof File) files.push(v);
          else if (v instanceof Blob) {
            var capturedFD = pickCapturedFile(v.size);
            files.push(capturedFD || asFile(v, urlHint || "upload.bin", v.type)); // bare Blob part (no filename)
          }
        });
      } catch (e) {}
    }
    try {
      var usedCapture = files.length && files[0] && capturedFiles.some(function (c) { return c.file === files[0]; });
      if (usedCapture) console.debug("[SK-DLP] using captured file selection for classification:", files[0].name, "(" + files[0].size + " bytes)");
    } catch (e) {}
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

    var destHost;
    try { destHost = new URL(url, location.href).hostname.toLowerCase(); } catch (e) { destHost = ""; }

    // Reuse an in-flight/recent decision for this destination instead of
    // re-classifying + re-logging every chunk of the same upload.
    if (destHost) {
      var cached = recentDecisions.get(destHost);
      if (cached && cached.expiresAt > Date.now()) return cached.promise;
    }

    var files = collectFiles(body, url);
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
    var resultPromise = chain.then(function (blocked) { return blocked || worst; });

    // Only cache when we actually found file-like content to classify — an
    // empty/metadata-only request shouldn't suppress classification of the
    // real content request that follows it.
    if (destHost) {
      recentDecisions.set(destHost, { promise: resultPromise, expiresAt: Date.now() + COALESCE_WINDOW_MS });
    }
    return resultPromise;
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
