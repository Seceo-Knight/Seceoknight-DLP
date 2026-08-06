// network_exfil_monitor.h
// Process-Based Network Exfiltration Monitor for CyberSentinel DLP Windows Agent
//
// ISOLATED MODULE - does not modify or depend on clipboard/USB/screenshot logic.
// Communicates with the main agent strictly through the callback interface below.
//
// Scope (per approved spec):
//   1. curl / wget / PowerShell / bitsadmin / certutil interception (FULL BLOCKING)
//   2. Python-based transfers (BEST EFFORT via script content heuristics)
//   3. Browser file-selection detection (DETECTION + ALERT ONLY, never blocks)
//   4. Bluetooth: INTENTIONALLY DEFERRED
//
// Blocking mechanism: WMI process-creation events -> NtSuspendProcess ->
// classify file content -> TerminateProcess if Confidential/Restricted.

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstddef>

namespace NetworkExfilMonitor {

// Minimal view of a classification result the monitor cares about.
// Callers translate their richer internal result into this shape.
struct ClassifyResult {
    std::string category;                 // "Public" / "Internal" / "Confidential" / "Restricted" / ""
    double      score        = 0.0;
    std::string matchedRule;              // Name of first matched policy, if any
    std::vector<std::string> labels;      // Matched data-type labels
};

// Callbacks the host agent provides. All must be thread-safe.
using ClassifyFn  = std::function<ClassifyResult(const std::string& content,
                                                 const std::string& eventType)>;
using SendEventFn = std::function<void(const std::string& jsonPayload)>;
using LogFn       = std::function<void(const std::string& level,
                                       const std::string& message)>;
// Optional: managed-application file control. Given the acting process exe, the
// target file path and its extension, return TRUE to BLOCK the transfer regardless
// of content. Unset (or returning false) => no app-based block. Additive -- leaves
// the content-classification block path (ClassifyFn above) completely intact.
// Ported from CyberSentinel-DLP.
using AppActionFn = std::function<bool(const std::string& processName,
                                       const std::string& filePath,
                                       const std::string& fileExt)>;

// Optional: managed messaging / thick-client app control. For a file-open
// dialog owned by process `exeLower` (already lowercased) run by `userName`,
// the host returns whether that app is a managed messaging client (Teams /
// WhatsApp / Telegram / Slack / Discord / Signal / ...), whether a sensitive
// attachment must be BLOCKED (true, terminates the app) or only ALERTED
// (false, the audit-first default), and any file extensions to exempt.
// Driving the app list + action through a callback lets the host refresh
// them from server policy each sync without restarting the monitor.
// SCOPE: only file-picker attachments are seen here -- drag-and-drop into
// the app window bypasses the common dialog and would need a filesystem
// minifilter (out of scope for this user-mode module). Ported from
// CyberSentinel-DLP; reuses this module's EXISTING WinEvent-hook-based
// dialog detector (not CyberSentinel's separate UIA event handler) since
// that detector was independently hardened through several real-world
// browser-upload bugs already fixed in this codebase.
struct MessagingVerdict {
    bool managed = false;                       // is exeLower a managed messaging app?
    bool block   = false;                       // sensitive attach: true = block, false = alert
    std::vector<std::string> exemptExtensions;  // lowercased, no leading dot
};
using MessagingPolicyFn = std::function<MessagingVerdict(const std::string& exeLower,
                                                         const std::string& userName)>;

struct Config {
    // Identity fields copied into every emitted event
    std::string agentId;
    std::string agentName;
    std::string username;       // e.g., "alice"
    std::string hostname;       // e.g., "DESKTOP-XYZ"

    // Host-provided integrations
    ClassifyFn  classify;       // MUST be set
    SendEventFn sendEvent;      // MUST be set
    LogFn       log;            // MUST be set (level: "INFO"/"WARNING"/"ERROR"/"DEBUG")
    AppActionFn appAction;      // optional -- managed-application file control (by acting exe)
    MessagingPolicyFn messagingPolicy;  // optional -- managed messaging-app attachment control

    // Safety caps
    size_t maxFileBytes = 50ull * 1024 * 1024;   // Do not read files larger than this
    size_t maxScriptBytes = 2ull * 1024 * 1024;  // For Python/PS script heuristic scans

    // Feature toggles (useful for incremental rollout / kill switch)
    bool enableCliMonitor      = true;
    bool enableBrowserDetector = true;
    // Reuse the browser dialog detector to also watch managed messaging apps.
    // Only fires when messagingPolicy is set AND reports an app as managed,
    // so leaving this on with no policy configured is a no-op.
    bool enableMessagingDetector = true;
};

// Start the monitor. Launches background threads and returns immediately.
// Calling Start() twice is a no-op; stop first if you need to reconfigure.
// Returns true on successful init of at least one subsystem.
bool Start(const Config& cfg);

// Signals shutdown of all worker threads. Non-blocking. Safe to call multiple times.
// Intended to be invoked during agent shutdown.
void Stop();

// True if Start() has been called and Stop() has not yet been invoked.
bool IsRunning();

// -----------------------------------------------------------------------------
// Dedicated classifier for network-exfil content.
//
// DOES NOT depend on the shared ContentClassifier / ExtractDataType engine.
// Has its own regex patterns, Luhn validation, and severity mapping so we
// cannot affect clipboard / USB / screen-capture / file-monitor logic.
//
// Produces specific canonical labels (AADHAAR, CREDIT_CARD, PAN, SSN,
// INDIAN_PHONE, US_PHONE, IFSC, EMAIL, AWS_KEY, PRIVATE_KEY, JWT_TOKEN,
// UPI_ID) so the dashboard displays the right data type.
// -----------------------------------------------------------------------------
ClassifyResult ClassifyNetworkContent(const std::string& content);

} // namespace NetworkExfilMonitor
