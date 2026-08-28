// messaging_text_monitor.h
// Typed-message DLP for desktop messaging apps — SeceoKnight DLP Windows Agent
//
// Ported from CyberSentinel-DLP. First taken August 26 2026 (gap-scan of
// their then-HEAD, 558 -> 1355 lines in the .cpp); re-synced August 27 2026
// to their HEAD as of that date (1355 -> 1762 lines), after a real,
// production-blocking bug they found and fixed on WhatsApp for Windows: the
// original hold-and-read design called UI Automation's window-wide sweep
// while the Enter keystroke was still held, and on WhatsApp's WebView2
// composer that single call measured SEVEN SECONDS -- ten times past the
// watchdog's timeout, so every send on that app was released uninspected,
// silently, with no error. The fix restructures the module so a background
// sampler locates the composer ELEMENT once (the expensive FindAll walk,
// done between keystrokes, never while one is held) and BLOCK mode decides
// primarily on the sampler's last snapshot -- the same architecture ALERT
// mode always used, now shared by both. Also folds in: a UI Automation
// acquisition retry loop (a COM failure at agent boot previously disabled
// the whole feature until a restart, silently), definite-vs-guessed
// editability tracking (so an ambiguous focused-subtree read no longer
// picks whichever candidate happened to sort first, which could mean
// reading and shipping the chat history instead of the message), a
// classifier self-test logged on every Start() (so "the classifier is not
// wired up" and "we read the wrong box" stop producing the identical
// "every message is clean" symptom), and clean-verdict logging that
// explains WHAT was read and WHY it did not count, not just that it did
// not. Taken as their current, iterated implementation rather than
// re-derived from the written description each time, deliberately --
// re-deriving low-level keyboard-hook + UI Automation logic from a
// description is exactly how bugs like the seven-second stall get
// reintroduced a second time instead of staying fixed.
//
// THE GAP THIS CLOSES
// -------------------
// Messaging App Attachment Control watches the file picker: it sees a file
// chosen through the app's Open dialog and can block it. It never sees the far
// more common case — somebody TYPING sensitive data straight into the chat box.
// An operator who switched that policy to Block reasonably believed sensitive
// data could no longer leave over WhatsApp. It could, and did: a pasted or typed
// Aadhaar number went out with nothing logged, because no file dialog ever
// opened and so no code path ran at all.
//
// This module covers the typed path, in two modes.
//
// BLOCK MODE — hold, inspect, then release
// ----------------------------------------
// A low-level keyboard hook (WH_KEYBOARD_LL — no DLL injection, no code inside
// the target app) watches for the send gesture: Enter, or Ctrl+Enter, in a
// window owned by a managed messaging app. The keystroke is swallowed and a
// worker thread:
//
//   1. reads the composer text through UI Automation,
//   2. classifies it with the agent's local classifier (regex + Luhn,
//      sub-millisecond — no server round trip, works offline),
//   3. re-injects the keystroke if the message is clean, or drops it and
//      raises an event if it is not.
//
// The hold is typically 10-100ms and imperceptible in a chat window.
//
// ALERT MODE — sample, and never touch input
// ------------------------------------------
// Alert mode does not hold anything, so it cannot read the composer at send
// time: by the time the worker looks, the app has cleared the box. It therefore
// keeps a light sampler on the focused composer while a managed app is in the
// foreground, and on Enter classifies the most recent snapshot.
//
// That is exactly the sampling gap the block path refuses (see below), and it
// is accepted here because the two modes are answering different questions.
// Block mode is asked to GUARANTEE that nothing sensitive leaves, and a
// guarantee with a 500ms hole in it is not one. Alert mode is asked to tell an
// operator what their fleet is doing before they turn enforcement on, and a
// sampler answers that honestly. What alert mode must never do is silently
// record NOTHING, which is what it did before this: the hook returned early
// unless the action was Block, so an operator auditing first saw an empty
// dashboard and concluded the channel was quiet.
//
// WHY HOLD-AND-RELEASE, AND NOT THE SCREENSHOT MODULE'S PRECOMPUTED FLAG
// ----------------------------------------------------------------------
// ScreenCaptureMonitor keeps a background thread scoring the screen and has the
// hook read one atomic bool, because OCR is far too slow to run inside a hook
// and a screenshot cannot be meaningfully "replayed" later.
//
// Neither constraint applies here. Classifying a chat message is a regex sweep,
// and an Enter key CAN be replayed — perfectly, a few milliseconds later, with
// SendInput. Holding it means the verdict is computed against the text that is
// actually in the box at the moment of sending, instead of whatever a sampler
// last happened to see. A sampled flag would leave a real hole: type or paste a
// number and hit Enter inside the sampling gap and it ships uninspected. That
// hole is the entire bug this module exists to close, so it is not reintroduced
// as an implementation detail on the path that promises to close it.
//
// FINDING THE APP, AND FINDING THE BOX
// ------------------------------------
// Two things that look like implementation detail decide whether this module
// does anything at all, and both were wrong in the first cut:
//
//   * A packaged (MSIX/UWP) app such as the Store build of WhatsApp does not
//     own its own top-level window. The foreground HWND is an
//     ApplicationFrameWindow belonging to ApplicationFrameHost.exe, and the app
//     itself owns a child CoreWindow. Resolving the process from the foreground
//     window alone therefore yields "applicationframehost.exe", which is in no
//     managed-app list, so the hook passes every keystroke through and the
//     feature silently does nothing. We step through the frame host to the
//     child window's process.
//
//   * The composer must be located by FOCUS, never by size. Current WhatsApp
//     builds for Windows are a WebView2/Chromium wrapper, where the entire
//     conversation is one Document node — so "take the longest Edit/Document in
//     the window", which is safe in a native XAML app, picks the chat HISTORY.
//     That blocks every send on something said last month and ships the whole
//     conversation off the endpoint as evidence. Everything here is scoped to
//     the focused element and its subtree; the window-wide sweep survives only
//     as a last resort, restricted to editable nodes and size-capped.
//
// SAFETY RULES, and they matter more than coverage here
// -----------------------------------------------------
//   * ALERT mode never touches input. Keystrokes are only ever held when an
//     admin has explicitly chosen Block, so the audit-first rollout the rest of
//     the product follows costs the user nothing.
//   * Every failure path RELEASES the keystroke, including the one where the
//     inspection never finishes: a watchdog releases anything held longer than
//     decisionTimeoutMs. Without it a wedged UI Automation call — and Chromium
//     enabling its accessibility tree on first query is exactly that call —
//     holds the Enter forever AND keeps swallowing the matching key-ups, so the
//     key reads as stuck down inside the app. A DLP agent that appears to break
//     the keyboard gets uninstalled.
//   * Injected keystrokes are ignored (LLKHF_INJECTED), so our own replay
//     cannot re-enter the hook and loop.
//   * The hook holds no locks and does no I/O — it flips an atomic and signals
//     a worker, so it can never approach the LowLevelHooksTimeout that would
//     make Windows silently evict it.
//   * Exactly one of {worker, watchdog} resolves any given keystroke, decided
//     by an atomic claim. Both releasing would send the message twice.
//
// SCOPE — what this does NOT cover
//   * Sending by CLICKING the send button. Deciding whether a click lands on
//     that button needs a UI Automation hit-test, which cannot run inside a
//     mouse hook, and swallowing clicks globally to find out is not a risk
//     worth taking for the minority gesture.
//   * Apps that send on a key this doesn't know about.
//   * Text pasted and sent inside one sampling-free instant is still caught in
//     BLOCK mode, because the text is read at send time — but the paste itself
//     is Clipboard control's job and remains so.
//
// ROLLOUT NOTE (SeceoKnight, August 26 2026): inspect_messages defaults to
// FALSE and does not inherit from Messaging App Attachment Control -- this
// sits in front of the keyboard, and that is a decision an operator should
// make on purpose. Strongly recommend enabling in ALERT mode first on any
// fleet, confirming detections look right on the dashboard, before ever
// switching a policy to BLOCK -- alert mode never touches input at all, so
// it carries none of the risk block mode does.

#pragma once

#include <string>
#include "network_exfil_monitor.h"

namespace MessagingTextMonitor {

struct Config {
    std::string agentId;
    std::string agentName;
    std::string username;
    std::string hostname;

    // Reused verbatim from NetworkExfilMonitor so both messaging paths classify,
    // report and resolve policy through exactly one implementation each.
    NetworkExfilMonitor::ClassifyFn         classify;        // MUST be set
    NetworkExfilMonitor::SendEventFn        sendEvent;       // MUST be set
    NetworkExfilMonitor::LogFn              log;             // MUST be set
    NetworkExfilMonitor::MessagingPolicyFn  messagingPolicy; // MUST be set

    // Longest composer text inspected. A chat message is small; the cap only
    // bounds the cost of someone pasting a novel into the box.
    size_t maxTextBytes = 64 * 1024;

    // Cap for the LAST-RESORT window-wide sweep only. The focused element is
    // trusted at full size, because a large paste into the composer is a real
    // case we must inspect. An unfocused node this big, on the other hand, is
    // far more likely to be the conversation than the message.
    size_t maxFallbackTextBytes = 16 * 1024;

    // How long a held keystroke may wait for a verdict before the watchdog
    // releases it anyway. Sized for "UI Automation is wedged", not for normal
    // operation, where the whole decision is single-digit milliseconds.
    unsigned decisionTimeoutMs = 1200;

    // Alert mode only: how often the composer is snapshotted while a managed
    // app is in the foreground. Costs one UIA focused-element read per tick,
    // and only inside a managed app with alert-mode inspection on.
    unsigned sampleIntervalMs = 250;

    // An app whose composer UI Automation cannot read at all is reported once,
    // then not again for this long — it is a deployment fact worth surfacing,
    // not something to log on every Enter.
    unsigned uninspectableCooldownSec = 600;
};

// Installs the hook and starts the worker. Returns false if the hook could not
// be installed; the agent keeps running with typed-message coverage off.
bool Start(const Config& cfg);

void Stop();

// True while the hook is installed.
bool IsRunning();

} // namespace MessagingTextMonitor
