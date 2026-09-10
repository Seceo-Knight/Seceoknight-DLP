/*
 * SeceoKnight DLP — GenAI / Web Activity Control interceptor (MAIN world).
 *
 * New capability, separate from inject.js's Cloud Upload Guard (left
 * completely untouched to avoid regression risk to that mature, already
 * heavily-tested path). Loads AFTER inject.js in manifest.json, so
 * window.fetch here is inject.js's own wrapper — the two compose safely,
 * each only acting on the destinations/bodies it cares about and calling
 * through to the other otherwise.
 *
 * Covers, end to end (server-side matrix in app/core/web_activity.py):
 *   - "post"        a text prompt sent TO a genai destination (ChatGPT,
 *                    Copilot, Gemini, Claude, ...)
 *   - "send"        a substantial composed-message text body sent to a
 *                    webmail/collaboration destination (best-effort: see
 *                    MIN_SEND_TEXT_LENGTH below — there's no reliable way
 *                    to distinguish "the user hit Send" from any other
 *                    JSON-bearing request purely from network traffic)
 *   - "ai_response"  the reply streaming back FROM a genai destination —
 *                    the actual headline capability this feature exists
 *                    for. Only engaged when the server reports Web
 *                    Activity Control is actually configured
 *                    (webActivityEnforced), so an installation that never
 *                    touches this feature pays zero streaming-latency cost.
 *
 * NOT covered by this script (documented scope, not a silent gap):
 *   - "upload"/"attach"/"download" — file-bearing transfers still go
 *     through inject.js's OLDER, separate CLOUD_HOSTS/native-host
 *     "classify" path (event_type=cloud_upload), not this one, so the same
 *     upload is never double-submitted/double-logged through two
 *     different classifiers. A dashboard matrix cell for these activities
 *     currently has nothing wired up to reach it — unifying the two
 *     upload paths is future work.
 *   - XHR-based ai_response streaming — genai chat UIs overwhelmingly use
 *     fetch()+ReadableStream today; XHR response-body redaction would need
 *     a materially different (readyState-polling) implementation this
 *     pass doesn't add.
 */
(function () {
  "use strict";

  var appCatalogHosts = [];      // domains from the server's app_catalog — populated via content.js
  var webActivityEnforced = false;
  window.addEventListener("message", function (e) {
    var d = e.data;
    if (!d || d.__skdlp !== 1 || d.dir !== "toPage" || d.kind !== "appCatalog") return;
    appCatalogHosts = Array.isArray(d.domains) ? d.domains : [];
    webActivityEnforced = !!d.enforced;
  });

  function isWatchedHost(url) {
    try {
      var host = new URL(url, location.href).hostname.toLowerCase();
      return appCatalogHosts.some(function (d) { return host === d || host.endsWith("." + d); });
    } catch (e) { return false; }
  }

  var MAX_TEXT_CHARS = 200000;      // cap for prompt/message/response text sent for classification
  // Raised from 40 (September 2026): 40 chars is trivially exceeded by a
  // huge amount of routine SPA background traffic that isn't a real
  // composed prompt/message at all — a JSON array with two or three short
  // fields (conversation-list refresh, model list, a telemetry beacon)
  // clears 40 chars easily. Every one of those was spending a full
  // server decision round trip just to (almost always) come back "allow" —
  // wasted latency/load even after the native-host side stopped logging
  // "allow" outcomes as events. 150 is still short enough to catch a real
  // one-line sensitive prompt/message, just no longer trivially matched by
  // near-empty structured payloads. Same trade-off as before, just tuned:
  // a genuinely short sensitive prompt under the threshold still isn't
  // inspected — accepted because it's outweighed by not drowning real
  // signal (and the server) in background chatter.
  var MIN_SEND_TEXT_LENGTH = 150;    // best-effort filter — see module docstring on "send"
  var MIN_RESPONSE_TEXT_LENGTH = 150; // same reasoning as MIN_SEND_TEXT_LENGTH, applied to responses —
                                       // see maybeRedactResponse for why this exists
  var DECISION_TIMEOUT_MS = 15000;  // generous: a genai reply can take longer to classify than a small upload
  var pending = new Map();
  var seq = 0;

  function requestDecision(meta) {
    return new Promise(function (resolve) {
      var requestId = "wa-" + Date.now() + "-" + (seq++);
      pending.set(requestId, resolve);
      window.postMessage({ __skdlp: 1, dir: "toContent", kind: "webActivity", requestId: requestId, meta: meta }, "*");
      setTimeout(function () {
        if (pending.has(requestId)) { pending.delete(requestId); resolve({ action: "allow", reason: "decision-timeout" }); }
      }, DECISION_TIMEOUT_MS);
    });
  }

  window.addEventListener("message", function (e) {
    var d = e.data;
    if (!d || d.__skdlp !== 1 || d.dir !== "toPage" || d.kind !== "webActivityDecision") return;
    var r = pending.get(d.requestId);
    if (r) {
      pending.delete(d.requestId);
      r({ action: d.action, appCategory: d.appCategory, level: d.level, reason: d.reason, redactedContent: d.redactedContent });
    }
  });

  // Best-effort plain-text extraction from a fetch/XHR request body, for
  // classification only — doesn't need to perfectly represent the wire
  // format; the classifier's rules match substrings anywhere in the text,
  // JSON structure included, same reasoning document_extract.py uses
  // server-side for treating a whole extracted blob as one unit.
  function requestBodyToText(body) {
    if (body == null) return null;
    if (typeof body === "string") return body.slice(0, MAX_TEXT_CHARS);
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
      return body.toString().slice(0, MAX_TEXT_CHARS);
    }
    return null; // File/Blob/FormData/ArrayBuffer bodies are inject.js's concern, not this script's
  }

  // Resolves request body text for BOTH calling conventions apps use:
  //   fetch(url, { body })                 -- body lives on init, synchronous read
  //   fetch(new Request(url, { body }))     -- body lives inside the Request
  //                                            object itself (a stream), and
  //                                            is only reachable async via
  //                                            .clone().text(). Many bundled/
  //                                            instrumented apps (ChatGPT
  //                                            included) use this single-
  //                                            argument form, and previously
  //                                            this script had no path to
  //                                            it at all: init was
  //                                            undefined, body resolved to
  //                                            undefined, and the request
  //                                            silently fell through to
  //                                            "allow" with no server round
  //                                            trip and no error — a
  //                                            complete, silent miss on the
  //                                            exact traffic this feature
  //                                            exists to inspect.
  // Always resolves (never rejects) — a body we can't read is treated as
  // "no text", same as the synchronous path.
  function resolveBodyText(input, init) {
    var syncText = requestBodyToText(init && init.body);
    if (syncText !== null) return Promise.resolve(syncText);
    if (typeof Request !== "undefined" && input instanceof Request && (!init || init.body == null)) {
      try {
        return input.clone().text().then(
          function (t) { return t ? t.slice(0, MAX_TEXT_CHARS) : null; },
          function () { return null; }
        );
      } catch (e) { return Promise.resolve(null); }
    }
    return Promise.resolve(null);
  }

  function announce(dec, kind) {
    window.postMessage({
      __skdlp: 1, dir: "toContent", kind: "webActivityNotice",
      noticeKind: kind, level: dec.level, category: dec.appCategory,
    }, "*");
  }

  // Headers minus content-length/content-encoding — a redacted body is a
  // different byte length than the original, and any encoding
  // (gzip/br/...) the original bytes had no longer applies to plain
  // substituted text, so both must be dropped rather than copied verbatim
  // from the original response.
  function headersForReplacementBody(original) {
    var h = new Headers(original);
    try { h.delete("content-length"); } catch (e) {}
    try { h.delete("content-encoding"); } catch (e) {}
    return h;
  }

  // Best-effort method resolution for BOTH fetch() calling conventions —
  // mirrors resolveBodyText's two-path handling above. fetch()'s own
  // default when no method is given anywhere is GET.
  function resolveMethod(input, init) {
    if (init && init.method) return String(init.method).toUpperCase();
    if (typeof Request !== "undefined" && input instanceof Request && input.method) {
      return String(input.method).toUpperCase();
    }
    return "GET";
  }

  // Methods that never carry a request body in normal use — i.e. "read"
  // calls, not "send/submit" calls. A genai web app's OWN startup/navigation
  // traffic (reloading an existing conversation's messages when the tab is
  // opened, fetching the conversation list, model/account config, ...) is
  // fetched this way. Confirmed live (September 10, 2026, CYBER-SEC 001):
  // simply opening chatgpt.com to an existing conversation -- no prompt
  // typed, no message sent -- produced a MEDIUM "Web Activity AI Response"
  // alert (classified Internal at only 31% confidence, itself a sign this
  // was generic conversation/app JSON, not an actual model reply). A real
  // chat completion is always requested with a body-bearing method (POST,
  // occasionally PUT/PATCH for some vendors' APIs); simply reloading
  // already-generated content on page load is not.
  var NON_SUBMIT_METHODS = { GET: 1, HEAD: 1, OPTIONS: 1 };

  // Reads a Response's CLONE to text for classification, leaving the
  // original Response's body untouched and still consumable by whatever
  // this function ultimately returns to the caller — see maybeRedactResponse.
  function maybeRedactResponse(resp, destHost, method) {
    if (!webActivityEnforced || !resp || !resp.body || typeof resp.clone !== "function") return resp;
    if (NON_SUBMIT_METHODS[method]) return resp; // see NON_SUBMIT_METHODS above -- not a real send/reply exchange
    var ct = "";
    try { ct = (resp.headers && resp.headers.get && resp.headers.get("content-type")) || ""; } catch (e) {}
    // Only text-ish responses are worth buffering+inspecting (SSE streams,
    // JSON chat-completion payloads). Binary/media responses pass through
    // untouched via this early return, at effectively zero extra cost.
    if (!/text|json|event-stream/i.test(ct)) return resp;

    return resp.clone().text().then(function (text) {
      // Content-type alone (checked above) isn't a strong enough signal —
      // real genai chat UIs fire plenty of small, unrelated JSON/text
      // fetches to the same watched host alongside the actual completion
      // call: conversation-list refreshes, model lists, telemetry beacons,
      // moderation pre-checks, keep-alive pings, etc. Before this gate,
      // EVERY one of those got buffered, classified, and logged as a
      // distinct "ai_response" event — the same class of flooding bug fixed
      // in inject.js's collectFiles() for cloud uploads, just on the
      // response side instead of the request side. Mirror that fix's
      // request-side MIN_SEND_TEXT_LENGTH gate here: skip the classify
      // round trip (and the log entry it would produce) for anything too
      // short to plausibly be a real completion payload. Same trade-off as
      // the request side — a one-word AI reply under the threshold isn't
      // inspected — accepted for the same reason: it's far outweighed by no
      // longer drowning real signal in noise from background API chatter.
      if (!text || text.length < MIN_RESPONSE_TEXT_LENGTH) return resp;
      return requestDecision({
        host: destHost, activity: "ai_response", content: text.slice(0, MAX_TEXT_CHARS),
      }).then(function (dec) {
        if (dec.action === "block") {
          announce(dec, "blocked");
          return new Response("", { status: resp.status, statusText: "Blocked by SeceoKnight DLP", headers: headersForReplacementBody(resp.headers) });
        }
        if (dec.action === "redact" && dec.redactedContent != null) {
          announce(dec, "redacted");
          return new Response(dec.redactedContent, { status: resp.status, statusText: resp.statusText, headers: headersForReplacementBody(resp.headers) });
        }
        return resp; // allow/alert — original response, unmodified, whatever streaming behavior it had is preserved
      });
    }, function () { return resp; }); // couldn't read the clone — fail open, return the untouched original
  }

  // ---- patch fetch a second time (composes with inject.js's own patch —
  // see module docstring) ----
  var origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function (input, init) {
      var url = (typeof input === "string") ? input : (input && input.url) || "";
      if (!isWatchedHost(url)) return origFetch.apply(this, arguments);

      var destHost;
      try { destHost = new URL(url, location.href).hostname.toLowerCase(); } catch (e) { destHost = ""; }
      var method = resolveMethod(input, init);

      return resolveBodyText(input, init).then(function (text) {
        var reqDecisionPromise;
        if (!text || text.length < MIN_SEND_TEXT_LENGTH) {
          // Too short to be a real composed message/prompt (or not a
          // text-ish body at all, e.g. a File — inject.js's concern) — skip
          // straight to allow without spending a round trip on it. GenAI
          // prompts under 40 chars ("hi", "continue", ...) are also skipped
          // by this same threshold; a deliberate trade-off against spamming
          // the classifier on every keystroke-adjacent request some sites
          // make, not a claim that short prompts can never carry sensitive
          // data.
          reqDecisionPromise = Promise.resolve({ action: "allow" });
        } else {
          // This client only has a flat watched-domain list (appCatalogHosts
          // above), not a per-domain category, so it can't cheaply tell "a
          // prompt to a genai host" apart from "a composed message to a
          // webmail/collaboration host" before making the call — "post" is
          // sent unconditionally for every request-side hit here. The
          // server resolves the AUTHORITATIVE (category, activity) cell
          // itself from the host (see MEANINGFUL_CELLS in web_activity.py)
          // and re-derives "send" from "post" for webmail/collaboration
          // hosts server-side — see evaluate_web_activity() in agents.py.
          // (An earlier version of this comment claimed a non-genai host
          // sending "post" "just means the server's lookup misses and
          // returns allow" — that was true, but it also meant the
          // "Webmail Send"/"Collaboration Send" matrix cells could never be
          // reached by anything this client ever sent, silently, no matter
          // what an admin configured. Fixed server-side rather than by
          // teaching this client per-domain categories, so the fix took
          // effect immediately without an extension redeploy.)
          reqDecisionPromise = requestDecision({ host: destHost, url: String(url), activity: "post", content: text });
        }

        return reqDecisionPromise.then(function (dec) {
          var finalInit = init;
          if (dec.action === "block") {
            announce(dec, "blocked");
            return new Response("", { status: 403, statusText: "Blocked by SeceoKnight DLP" });
          }
          if (dec.action === "redact" && dec.redactedContent != null) {
            announce(dec, "redacted");
            // Works for both calling conventions: when input is a plain
            // URL string, finalInit.body is all that matters. When input
            // is a Request object, passing an init with body set here
            // still overrides the Request's own (already-cloned-from)
            // body per the Fetch spec, so redaction reaches the wire
            // either way.
            finalInit = Object.assign({}, init, { body: dec.redactedContent });
          } else if (dec.action === "alert") {
            announce(dec, "alerted");
          }
          return origFetch.call(window, input, finalInit).then(function (resp) {
            return maybeRedactResponse(resp, destHost, method);
          });
        }, function () {
          // Decision round trip itself failed — fail open, but the response
          // still passes through maybeRedactResponse so ai_response
          // inspection isn't silently skipped just because the REQUEST
          // side's decision errored.
          return origFetch.call(window, input, init).then(function (resp) {
            return maybeRedactResponse(resp, destHost, method);
          });
        });
      });
    };
  }
})();
