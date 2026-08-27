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
  var recentDecisions = new Map(); // coalesce key -> { promise, expiresAt }
  var COALESCE_WINDOW_MS = 4000;

  // Cheap, no-collectFiles()-call identity for a request body, used ONLY to
  // build the recentDecisions coalesce key below — NOT a full file match
  // (that's collectFiles()/pickCapturedFile()'s job, and is deliberately
  // NOT run here, since the whole point of this cache is to skip that
  // heavier work for repeat chunks of the same upload).
  //
  // Originally this cache was keyed on destHost alone. That's wrong: if two
  // DIFFERENT files are uploaded to the SAME host within one
  // COALESCE_WINDOW_MS (4s) — e.g. a sensitive file, then an unrelated
  // public one, both to Drive — the second upload would silently inherit
  // the first file's decision instead of being classified on its own
  // merits. For an allow-cached-then-reused case that's a false NEGATIVE:
  // a sensitive second file could ride through on an earlier "allow"
  // without ever being inspected — the kind of gap that matters most in an
  // enterprise DLP product, not just noise. Including a body-identity
  // component in the key (file name+size when available, otherwise a
  // Blob/ArrayBuffer's byte length) means only genuine repeat chunks of the
  // SAME body still coalesce; two different files/bodies to the same host
  // now get their own cache entries and are classified independently.
  function bodyIdentityKey(body) {
    try {
      if (body instanceof File) return "f:" + body.name + ":" + body.size;
      if (body instanceof Blob) return "b:" + body.size;
      if (body instanceof ArrayBuffer) return "ab:" + body.byteLength;
      if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(body)) return "tb:" + body.byteLength;
    } catch (e) {}
    return ""; // FormData or unrecognized body type — falls back to host-only coalescing, same as before
  }

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
  // Paste (Cmd/Ctrl+V) is a real upload vector this hook previously had no
  // capture for at all -- screenshotting something sensitive and pasting it
  // into Gmail/Slack/a Drive comment is a completely ordinary way to exfil
  // data, and until now that Blob would fall straight through to the generic
  // "no captured file -> upload.bin" path below with no real name and (after
  // the fix in collectFiles()) would now be SKIPPED entirely rather than
  // classified. Capturing it here closes that gap instead of opening one.
  document.addEventListener("paste", function (e) {
    try { if (e.clipboardData && e.clipboardData.files) captureFileList(e.clipboardData.files); } catch (err) {}
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

  // Whether a raw Blob/ArrayBuffer body without a matching captured file is
  // still worth treating as "some file, name unknown" (old behavior) or
  // should be skipped as not-actually-a-file (new behavior).
  //
  // Before this fix, ANY binary-bodied fetch/XHR to a matched host was
  // treated as a file upload, fabricating a generic File named "upload.bin"
  // for it. That's wrong: plenty of ordinary web-platform traffic to these
  // same domains carries binary bodies that are not file uploads at all --
  // confirmed live on a real deployment where a Google Docs/Sheets tab just
  // sitting open, untouched, in the background produced a NEW "Cloud Upload
  // Allowed" event with filename "upload.bin" every 7-15 seconds indefinitely
  // (Google's client-side sync protocol periodically flushes small binary
  // state deltas via fetch() to docs.google.com even with zero user activity).
  // Each one got independently classified and logged, flooding the Events
  // table with thousands of meaningless, always-Public, always-allowed rows
  // that made genuinely interesting alerts harder to find in a busy tenant --
  // a real logging-noise bug, not a detection gap (nothing sensitive was
  // ever actually let through; the noise was itself the problem).
  //
  // Fix: a bare Blob/ArrayBuffer is now only treated as a real file when it
  // correlates to something the user actually selected or pasted (via
  // captureFileList() above, fed by the change/drop/paste listeners). If
  // there's no captured file within the last CAPTURE_MAX_AGE_MS, this is
  // background/protocol chatter, not a user-driven upload -- skip it rather
  // than logging a phantom "upload.bin". This does trade away visibility
  // into the narrow case of a page generating file-like bytes entirely in
  // JS with no user selection/paste event at all (e.g. canvas.toBlob()) --
  // accepted as a reasonable trade given that scenario doesn't correspond to
  // an existing sensitive FILE being exfiltrated in the first place, and it
  // is far outweighed by no longer drowning real signal in fabricated noise.
  function collectFiles(body, url) {
    var files = [];
    if (body instanceof File) files.push(body);
    else if (body instanceof Blob) {
      var capturedB = pickCapturedFile(body.size);
      if (capturedB) files.push(capturedB);
    }
    // Resumable uploads (Google Drive, etc.) send raw bytes, not File/Blob --
    // but so does a lot of non-upload background traffic to the same hosts
    // (see comment above). Only trust it when it matches a real capture.
    else if (body instanceof ArrayBuffer) {
      var capturedAB = pickCapturedFile(body.byteLength);
      if (capturedAB) files.push(capturedAB);
    }
    else if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(body)) {
      var capturedTB = pickCapturedFile(body.byteLength);
      if (capturedTB) files.push(capturedTB);
    }
    else if (typeof FormData !== "undefined" && body instanceof FormData) {
      try {
        body.forEach(function (v) {
          if (v instanceof File) files.push(v);
          else if (v instanceof Blob) {
            // A named File part in FormData is unambiguous; a bare Blob part
            // is the same "is this really a file?" question as above.
            var capturedFD = pickCapturedFile(v.size);
            if (capturedFD) files.push(capturedFD);
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
    var coalesceKey = destHost ? (destHost + "|" + bodyIdentityKey(body)) : "";

    // Reuse an in-flight/recent decision for this destination+body instead
    // of re-classifying + re-logging every chunk of the same upload (see
    // bodyIdentityKey's comment for why the key includes the body, not just
    // the host).
    if (coalesceKey) {
      var cached = recentDecisions.get(coalesceKey);
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
    if (coalesceKey) {
      recentDecisions.set(coalesceKey, { promise: resultPromise, expiresAt: Date.now() + COALESCE_WINDOW_MS });
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
