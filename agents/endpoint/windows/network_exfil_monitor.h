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

    // Safety caps
    size_t maxFileBytes = 50ull * 1024 * 1024;   // Do not read files larger than this
    size_t maxScriptBytes = 2ull * 1024 * 1024;  // For Python/PS script heuristic scans

    // Feature toggles (useful for incremental rollout / kill switch)
    bool enableCliMonitor      = true;
    bool enableBrowserDetector = true;
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
