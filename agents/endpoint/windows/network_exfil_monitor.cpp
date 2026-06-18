// network_exfil_monitor.cpp
// Process-Based Network Exfiltration Monitor - isolated implementation.
// See header for scope and rationale.
//
// Threads launched:
//   1. CLI process monitor (WMI __InstanceCreationEvent consumer)
//   2. Browser file-dialog detector (UIAutomation WindowOpenedEvent consumer)
//
// Blocking sequence on hit:
//   WMI event -> open process (terminate+suspend+read) -> NtSuspendProcess ->
//   parse cmdline -> read file(s) -> classify -> if sensitive: TerminateProcess
//   else: NtResumeProcess.
//
// NO HOOKS are installed in other processes. Everything happens inside our own
// agent process. We do not touch the network stack.

#include "network_exfil_monitor.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601      // Windows 7+, matches agent.cpp
#endif
#define _WIN32_DCOM
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winternl.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>

// UIAutomation
#include <UIAutomation.h>

#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <regex>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <cctype>
#include <filesystem>

// Note: libs are provided via build.sh (-lwbemuuid -lole32 -loleaut32
// -luiautomationcore -ladvapi32 -lshell32 -luser32 -lpsapi). MSVC #pragma
// comment(lib,...) pragmas are intentionally omitted to stay MinGW-friendly.

// -----------------------------------------------------------------------------
// UIAutomation GUID definitions for MinGW-w64.
//
// MinGW's libuiautomationcore.a only contains function stubs - the CLSID/IID
// constants for UIAutomation are declared via `EXTERN_C const IID ...;` in the
// headers but NOT defined in any MinGW-provided library (unlike MSVC, where
// uiautomationcore.lib provides them). Providing them here lets our TU link
// cleanly. The GUIDs are stable Microsoft-published values.
// -----------------------------------------------------------------------------
extern "C" {
    const CLSID CLSID_CUIAutomation =
        { 0xFF48DBA4, 0x60EF, 0x4201,
          { 0xAA, 0x87, 0x54, 0x10, 0x3E, 0xEF, 0x59, 0x4E } };
    const IID   IID_IUIAutomation =
        { 0x30CBE57D, 0xD9D0, 0x452A,
          { 0xAB, 0x13, 0x7A, 0xC5, 0xAC, 0x48, 0x25, 0xEE } };
    const IID   IID_IUIAutomationEventHandler =
        { 0x146C3C17, 0xF12E, 0x4E22,
          { 0x8C, 0x27, 0xF8, 0x94, 0xB9, 0xB7, 0x9C, 0x69 } };
    const IID   IID_IUIAutomationValuePattern =
        { 0xA94CD8FE, 0x0D17, 0x4D8F,
          { 0xBD, 0xB2, 0x0B, 0x4F, 0x99, 0x5F, 0x82, 0x2F } };
}

namespace fs = std::filesystem;

namespace NetworkExfilMonitor {

// =============================================================================
// Module-level state
// =============================================================================
namespace {

std::atomic<bool> g_running{false};
std::atomic<bool> g_stopRequested{false};

Config g_cfg;                     // Snapshot of config (callbacks kept live)
std::mutex g_cfgMutex;            // Protects g_cfg reads after Start()

std::thread g_cliThread;
std::thread g_browserThread;

// Dedup: avoid classifying the same pid twice (WMI can flap)
std::mutex g_seenMutex;
std::unordered_set<DWORD> g_seenPids;

// Thin logging helpers. Never throws. Never blocks.
void LogInfo (const std::string& m) { if (g_cfg.log) g_cfg.log("INFO",    m); }
void LogWarn (const std::string& m) { if (g_cfg.log) g_cfg.log("WARNING", m); }
void LogErr  (const std::string& m) { if (g_cfg.log) g_cfg.log("ERROR",   m); }
void LogDbg  (const std::string& m) { if (g_cfg.log) g_cfg.log("DEBUG",   m); }

} // anonymous namespace


// =============================================================================
// Utility helpers
// =============================================================================
namespace {

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(needed, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), needed);
    return out;
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}

// Strip surrounding quotes from a path token.
std::string StripQuotes(std::string s) {
    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') ||
                          (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

// Expand %VAR% environment variables. Returns input if expansion fails.
std::string ExpandEnvVars(const std::string& in) {
    if (in.find('%') == std::string::npos) return in;
    std::wstring wIn = Utf8ToWide(in);
    wchar_t buf[MAX_PATH * 4] = {0};
    DWORD n = ExpandEnvironmentStringsW(wIn.c_str(), buf, sizeof(buf)/sizeof(buf[0]));
    if (n == 0 || n >= sizeof(buf)/sizeof(buf[0])) return in;
    return WideToUtf8(buf);
}

// Given argv-style tokens extracted from a command line, return the index of
// first token that looks like an existing file path. Returns -1 if none.
std::string ResolveExistingPath(const std::string& candidate) {
    std::string s = ExpandEnvVars(StripQuotes(candidate));
    if (s.empty()) return {};
    // Reject URL-looking tokens
    std::string lc = ToLower(s);
    if (lc.rfind("http://", 0) == 0 || lc.rfind("https://", 0) == 0 ||
        lc.rfind("ftp://", 0) == 0  || lc.rfind("file://", 0) == 0) {
        return {};
    }
    try {
        fs::path p(s);
        if (p.is_relative()) {
            // We don't know the child process's CWD reliably; try current dir
            // as a best-effort. If it doesn't exist, skip (we won't guess).
            fs::path abs = fs::absolute(p);
            if (fs::exists(abs) && fs::is_regular_file(abs)) return abs.string();
        } else {
            if (fs::exists(p) && fs::is_regular_file(p)) return p.string();
        }
    } catch (...) {}
    return {};
}

// Forward declarations (definitions appear later in this anonymous namespace).
std::string Utf16LeToUtf8(const std::string& raw);

// Normalize a byte buffer to UTF-8 text suitable for regex-based classifiers.
// Handles UTF-16LE (common from PowerShell Out-File), UTF-16BE, UTF-8 BOM.
// Falls through untouched for plain ASCII / UTF-8.
//
// This is essential on Windows because PowerShell's Out-File defaults to
// UTF-16LE, which stores ASCII regex targets with a null byte between every
// character - the classifier's patterns would never match.
std::string NormalizeToUtf8(const std::string& raw) {
    if (raw.size() >= 3 &&
        (unsigned char)raw[0] == 0xEF &&
        (unsigned char)raw[1] == 0xBB &&
        (unsigned char)raw[2] == 0xBF) {
        // UTF-8 BOM - strip it
        return raw.substr(3);
    }
    if (raw.size() >= 2 &&
        (unsigned char)raw[0] == 0xFF &&
        (unsigned char)raw[1] == 0xFE) {
        // UTF-16LE BOM
        std::string payload = raw.substr(2);
        std::string converted = Utf16LeToUtf8(payload);
        return converted.empty() ? raw : converted;
    }
    if (raw.size() >= 2 &&
        (unsigned char)raw[0] == 0xFE &&
        (unsigned char)raw[1] == 0xFF) {
        // UTF-16BE BOM - swap bytes then treat as LE
        std::string swapped;
        swapped.reserve(raw.size());
        for (size_t i = 2; i + 1 < raw.size(); i += 2) {
            swapped.push_back(raw[i + 1]);
            swapped.push_back(raw[i]);
        }
        std::string converted = Utf16LeToUtf8(swapped);
        return converted.empty() ? raw : converted;
    }

    // Heuristic UTF-16LE without BOM: many ASCII-looking bytes at even
    // offsets with null bytes at odd offsets. Common in Windows exports
    // that skip the BOM.
    if (raw.size() >= 16 && (raw.size() % 2 == 0)) {
        size_t nulOdd = 0;
        size_t checked = std::min<size_t>(raw.size(), 256);
        for (size_t i = 1; i < checked; i += 2) {
            if (raw[i] == '\0') nulOdd++;
        }
        if (nulOdd * 4 >= checked) {         // >= ~50% null at odd offsets
            std::string converted = Utf16LeToUtf8(raw);
            if (!converted.empty()) return converted;
        }
    }

    return raw;
}

// Read up to maxBytes from a file and normalize to UTF-8. Returns empty on failure.
std::string ReadFileSafely(const std::string& path, size_t maxBytes) {
    try {
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open()) return {};
        f.seekg(0, std::ios::end);
        std::streamoff size = f.tellg();
        f.seekg(0, std::ios::beg);
        if (size < 0) return {};
        size_t toRead = (size_t)std::min<std::streamoff>(size, (std::streamoff)maxBytes);
        std::string buf;
        buf.resize(toRead);
        if (toRead > 0) f.read(buf.data(), toRead);
        return NormalizeToUtf8(buf);
    } catch (...) {
        return {};
    }
}

// Detect whether a content buffer looks like a ZIP (PK\x03\x04) or a base64
// blob. Used for NETWORK_EVASION_ATTEMPT_DETECTED logging.
bool LooksLikeZip(const std::string& buf) {
    return buf.size() >= 4 && buf[0] == 'P' && buf[1] == 'K' &&
           (unsigned char)buf[2] == 0x03 && (unsigned char)buf[3] == 0x04;
}

bool LooksMostlyBase64(const std::string& buf) {
    if (buf.size() < 128) return false;
    size_t ok = 0;
    size_t checked = std::min<size_t>(buf.size(), 1024);
    for (size_t i = 0; i < checked; ++i) {
        unsigned char c = (unsigned char)buf[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
            c == '\r' || c == '\n') ok++;
    }
    return ok * 100 / checked >= 95;
}

// Attempt to base64-decode (best effort). Returns empty on failure.
std::string TryBase64Decode(const std::string& in) {
    static const int8_t tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    std::string out;
    out.reserve(in.size() * 3 / 4);
    int val = 0, bits = 0;
    for (unsigned char c : in) {
        if (c > 127) return {};
        if (std::isspace(c)) continue;
        int8_t d = tbl[c];
        if (d == -2) break;  // padding
        if (d == -1) return {};
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((val >> bits) & 0xFF));
        }
    }
    return out;
}

// UTF-16LE detection (PowerShell -EncodedCommand uses UTF-16LE before base64).
// Convert UTF-16LE string to UTF-8 for scanning.
std::string Utf16LeToUtf8(const std::string& raw) {
    if (raw.size() < 2 || raw.size() % 2 != 0) return {};
    std::wstring w;
    w.reserve(raw.size() / 2);
    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
        wchar_t c = (wchar_t)((unsigned char)raw[i] | ((unsigned char)raw[i+1] << 8));
        w.push_back(c);
    }
    return WideToUtf8(w);
}

// Simple ISO 8601 UTC timestamp.
std::string NowIso8601() {
    std::time_t t = std::time(nullptr);
    std::tm gm{};
    gmtime_s(&gm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &gm);
    return buf;
}

std::string GenerateUuidLike() {
    // Lightweight uuid-ish identifier (no crypto strength required for event IDs;
    // backend will treat it as a string).
    GUID g; CoCreateGuid(&g);
    wchar_t wbuf[40] = {0};
    StringFromGUID2(g, wbuf, 40);
    std::string s = WideToUtf8(wbuf);
    // Strip braces
    if (!s.empty() && s.front() == '{') s.erase(s.begin());
    if (!s.empty() && s.back()  == '}') s.pop_back();
    return s;
}

} // anonymous namespace


// =============================================================================
// ntdll dynamic bindings: NtSuspendProcess / NtResumeProcess
// These are undocumented but have been stable since Windows XP.
// =============================================================================
namespace {

using NtSuspendProcess_t = NTSTATUS (NTAPI*)(HANDLE);
using NtResumeProcess_t  = NTSTATUS (NTAPI*)(HANDLE);

NtSuspendProcess_t pNtSuspendProcess = nullptr;
NtResumeProcess_t  pNtResumeProcess  = nullptr;
std::once_flag     g_ntdllInitOnce;

void InitNtdllBindings() {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) h = LoadLibraryW(L"ntdll.dll");
    if (!h) { LogWarn("ntdll.dll unavailable; suspend/resume disabled"); return; }
    pNtSuspendProcess = (NtSuspendProcess_t)GetProcAddress(h, "NtSuspendProcess");
    pNtResumeProcess  = (NtResumeProcess_t) GetProcAddress(h, "NtResumeProcess");
    if (!pNtSuspendProcess || !pNtResumeProcess) {
        LogWarn("NtSuspendProcess/NtResumeProcess not resolvable");
    }
}

bool SuspendPid(DWORD pid) {
    std::call_once(g_ntdllInitOnce, InitNtdllBindings);
    if (!pNtSuspendProcess) return false;
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, pid);
    if (!h) return false;
    NTSTATUS st = pNtSuspendProcess(h);
    CloseHandle(h);
    return st == 0;
}

bool ResumePid(DWORD pid) {
    std::call_once(g_ntdllInitOnce, InitNtdllBindings);
    if (!pNtResumeProcess) return false;
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, pid);
    if (!h) return false;
    NTSTATUS st = pNtResumeProcess(h);
    CloseHandle(h);
    return st == 0;
}

bool TerminatePid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return false;
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok == TRUE;
}

} // anonymous namespace


// =============================================================================
// Event emission - follows existing agent event format (event_type + event_subtype)
// =============================================================================
namespace {

struct EventFields {
    std::string eventSubtype;             // e.g., "cli_upload" / "browser_file_selection"
    std::string channel;                  // "CLI" / "BROWSER"
    std::string processName;              // e.g., "curl.exe"
    DWORD       pid = 0;
    std::string commandLine;
    std::string fileName;
    std::string filePath;
    size_t      fileSize = 0;
    std::string action;                   // "BLOCK" / "ALERT" / "ALLOW"
    std::string severity;                 // "high" / "medium" / "low"
    std::string category;                 // "Public" / "Internal" / "Confidential" / "Restricted"
    double      classificationScore = 0.0;
    std::string matchedRule;
    std::vector<std::string> labels;
    std::string reason;                   // human-readable explanation
    std::string evasion;                  // set if evasion detected
};

std::string EscapeJson(const std::string& s) {
    std::string out; out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if ((unsigned char)c < 32) {
                    char buf[8]; sprintf_s(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

void EmitEvent(const EventFields& f) {
    if (!g_cfg.sendEvent) return;

    // Build JSON matching the agent's existing event schema (see USB transfer
    // events for the reference shape).
    std::ostringstream j;
    j << "{";
    j << "\"event_id\":\""       << EscapeJson(GenerateUuidLike())      << "\",";
    j << "\"event_type\":\""     << "network_exfil"                     << "\",";
    j << "\"event_subtype\":\""  << EscapeJson(f.eventSubtype)          << "\",";
    j << "\"agent_id\":\""       << EscapeJson(g_cfg.agentId)           << "\",";
    j << "\"source_type\":\""    << "agent"                             << "\",";
    j << "\"user_email\":\""     << EscapeJson(g_cfg.username + "@" + g_cfg.hostname) << "\",";
    j << "\"severity\":\""       << EscapeJson(f.severity)              << "\",";
    j << "\"action\":\""         << EscapeJson(f.action)                << "\",";
    j << "\"channel\":\""        << EscapeJson(f.channel)               << "\",";
    j << "\"process_name\":\""   << EscapeJson(f.processName)           << "\",";
    j << "\"process_id\":"       << f.pid                               << ",";
    j << "\"command_line\":\""   << EscapeJson(f.commandLine)           << "\",";
    if (!f.fileName.empty()) {
        j << "\"file_name\":\""  << EscapeJson(f.fileName)              << "\",";
    }
    if (!f.filePath.empty()) {
        j << "\"file_path\":\""  << EscapeJson(f.filePath)              << "\",";
    }
    j << "\"file_size\":"        << f.fileSize                          << ",";
    if (!f.category.empty()) {
        j << "\"classification_level\":\"" << EscapeJson(f.category)    << "\",";
        j << "\"classification_score\":"   << f.classificationScore     << ",";
    }
    if (!f.matchedRule.empty()) {
        j << "\"classification_rule_matched\":\"" << EscapeJson(f.matchedRule) << "\",";
    }
    if (!f.labels.empty()) {
        j << "\"classification_labels\":[";
        for (size_t i = 0; i < f.labels.size(); ++i) {
            if (i) j << ",";
            j << "\"" << EscapeJson(f.labels[i]) << "\"";
        }
        j << "],";
    }
    if (!f.evasion.empty()) {
        j << "\"evasion\":\""    << EscapeJson(f.evasion)               << "\",";
    }
    if (!f.reason.empty()) {
        j << "\"description\":\"" << EscapeJson(f.reason)               << "\",";
    }
    j << "\"timestamp\":\""      << NowIso8601()                        << "\"";
    j << "}";

    try { g_cfg.sendEvent(j.str()); }
    catch (...) { LogErr("EmitEvent: sendEvent callback threw"); }
}

} // anonymous namespace


// =============================================================================
// Command-line parsing
// =============================================================================
namespace {

// Split a command line into tokens, honoring double-quotes. Good enough for
// the common cmdline styles we care about. Not perfect POSIX shell quoting.
std::vector<std::string> SplitCmdLine(const std::string& in) {
    std::vector<std::string> out;
    std::string cur;
    bool inQuote = false;
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '"') { inQuote = !inQuote; cur += c; continue; }
        if (!inQuote && (c == ' ' || c == '\t')) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// Extract one or more file paths referenced on a cmdline. Returns resolved
// absolute paths for files that exist at the moment of inspection.
std::vector<std::string> ExtractFilePathsFromCmdline(const std::string& exeLower,
                                                     const std::string& cmdLine) {
    std::vector<std::string> results;
    auto tokens = SplitCmdLine(cmdLine);

    auto pushIfExists = [&](const std::string& cand) {
        std::string resolved = ResolveExistingPath(cand);
        if (!resolved.empty() &&
            std::find(results.begin(), results.end(), resolved) == results.end()) {
            results.push_back(resolved);
        }
    };

    // --- curl ------------------------------------------------------------
    //   curl -F "file=@path" / --form name=@path
    //   curl --data-binary @path / -d @path / --data @path
    //   curl -T path / --upload-file path
    //   curl --data-urlencode @path
    if (exeLower == "curl.exe" || exeLower == "curl") {
        for (size_t i = 1; i < tokens.size(); ++i) {
            std::string t = StripQuotes(tokens[i]);
            std::string lc = ToLower(t);

            // @path embedded in value (for -F / --form / --data*)
            auto at = t.find('@');
            if (at != std::string::npos && at + 1 < t.size()) {
                std::string after = t.substr(at + 1);
                // Strip field=@path -> path
                pushIfExists(after);
            }

            // -T / --upload-file <next token>
            if ((lc == "-t" || lc == "--upload-file") && i + 1 < tokens.size()) {
                pushIfExists(tokens[i + 1]);
            }
        }
    }

    // --- wget ------------------------------------------------------------
    //   wget --post-file=path  / --body-file=path
    if (exeLower == "wget.exe" || exeLower == "wget") {
        for (const auto& tok : tokens) {
            std::string t = StripQuotes(tok);
            std::string lc = ToLower(t);
            const char* keys[] = {"--post-file=", "--body-file=", "--input-file="};
            for (const char* k : keys) {
                if (lc.rfind(k, 0) == 0) {
                    pushIfExists(t.substr(strlen(k)));
                }
            }
        }
    }

    // --- PowerShell ------------------------------------------------------
    //   -InFile path     (Invoke-WebRequest / Invoke-RestMethod)
    //   -OutFile path    (download; still worth classifying if it's an upload
    //                     wrapped inside; we skip OutFile here — it's a sink)
    if (exeLower == "powershell.exe" || exeLower == "pwsh.exe" ||
        exeLower == "powershell_ise.exe") {
        for (size_t i = 0; i + 1 < tokens.size(); ++i) {
            std::string lc = ToLower(StripQuotes(tokens[i]));
            if (lc == "-infile") {
                pushIfExists(tokens[i + 1]);
            }
        }

        // Scan entire cmdline text for literal path patterns after
        // -InFile / Get-Content etc. (the token splitter can miss
        // script-block internal quoting).
        // Custom raw-string delimiter X(...)X to avoid early termination
        // from the ')"' sequence inside the pattern.
        std::regex re(R"X((?:-InFile|Get-Content|ReadAllBytes|ReadAllText)\s+"?([A-Za-z]:\\[^"\s;]+|\.\.?\\[^"\s;]+)"?)X",
                      std::regex::icase);
        auto begin = std::sregex_iterator(cmdLine.begin(), cmdLine.end(), re);
        auto end   = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            if (it->size() > 1) pushIfExists((*it)[1].str());
        }
    }

    // --- bitsadmin --------------------------------------------------------
    //   bitsadmin /transfer <name> <url> <local_path>
    //   bitsadmin /addfile <job> <url> <local_path>
    if (exeLower == "bitsadmin.exe") {
        // Last token is often the local path.
        for (size_t i = 0; i < tokens.size(); ++i) {
            pushIfExists(tokens[i]);
        }
    }

    // --- certutil ---------------------------------------------------------
    //   certutil -encode <src> <dst>     (staging for exfil)
    //   certutil -urlcache -split -f <url> <local_path>
    if (exeLower == "certutil.exe") {
        for (size_t i = 0; i < tokens.size(); ++i) {
            pushIfExists(tokens[i]);
        }
    }

    // --- python ----------------------------------------------------------
    //   python script.py  ->  the script itself is the evidence (heuristic)
    //   python -c "import requests; requests.post(...)"  -> inline code
    if (exeLower == "python.exe" || exeLower == "python3.exe" ||
        exeLower == "py.exe" || exeLower == "pythonw.exe") {
        for (size_t i = 1; i < tokens.size(); ++i) {
            std::string t = StripQuotes(tokens[i]);
            if (!t.empty() && t[0] != '-') {
                pushIfExists(t);
            }
        }
    }

    return results;
}

// Decode PowerShell -EncodedCommand <base64>.  Evasion marker if present.
// Returns decoded UTF-8 text. Empty on failure.
std::string DecodePowerShellEncodedCommand(const std::string& cmdLine) {
    std::regex re(R"((?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]{16,}))",
                  std::regex::icase);
    std::smatch m;
    if (!std::regex_search(cmdLine, m, re)) return {};
    std::string decoded = TryBase64Decode(m[1].str());
    if (decoded.empty()) return {};
    // PowerShell uses UTF-16LE for -EncodedCommand
    std::string asUtf8 = Utf16LeToUtf8(decoded);
    if (!asUtf8.empty()) return asUtf8;
    return decoded;  // fallback: treat as-is
}

// Heuristic inspection of a Python script to determine if it's doing
// network upload. Returns true if we see suspicious patterns.
bool PythonScriptLooksLikeUploader(const std::string& script) {
    static const std::regex patterns[] = {
        std::regex(R"(import\s+requests)",            std::regex::icase),
        std::regex(R"(from\s+requests\b)",            std::regex::icase),
        std::regex(R"(requests\.(post|put|patch))",   std::regex::icase),
        std::regex(R"(urllib\.(request|urlopen))",    std::regex::icase),
        std::regex(R"(urllib2\.urlopen)",             std::regex::icase),
        std::regex(R"(httpx\.(post|put|AsyncClient))",std::regex::icase),
        std::regex(R"(http\.client\.HTTPSConnection)",std::regex::icase),
        std::regex(R"(paramiko\.|pysftp\.)",          std::regex::icase),
        std::regex(R"(smtplib\.SMTP)",                std::regex::icase),
        std::regex(R"(boto3\.client\s*\(\s*['"]s3)",  std::regex::icase),
        std::regex(R"(socket\.socket\s*\(.*SOCK_STREAM)", std::regex::icase),
    };
    for (const auto& p : patterns) {
        if (std::regex_search(script, p)) return true;
    }
    return false;
}

} // anonymous namespace


// =============================================================================
// Enforcement core: decide on a captured process
// =============================================================================
namespace {

// Set of executables we actively monitor.
bool IsMonitoredExe(const std::string& exeLower) {
    static const std::unordered_set<std::string> targets = {
        "curl.exe", "wget.exe",
        "powershell.exe", "pwsh.exe", "powershell_ise.exe",
        "python.exe", "python3.exe", "pythonw.exe", "py.exe",
        "bitsadmin.exe", "certutil.exe"
    };
    return targets.count(exeLower) > 0;
}

void HandleCandidateProcess(DWORD pid,
                            const std::string& exeName,
                            const std::string& cmdLine) {
    if (pid == 0) return;

    // Dedup (WMI sometimes double-fires on fast processes)
    {
        std::lock_guard<std::mutex> lk(g_seenMutex);
        if (!g_seenPids.insert(pid).second) return;
        if (g_seenPids.size() > 4096) {
            // Simple trim; we don't need perfect history
            g_seenPids.clear();
            g_seenPids.insert(pid);
        }
    }

    const std::string exeLower = ToLower(exeName);
    if (!IsMonitoredExe(exeLower)) return;

    LogInfo("NETWORK_REQUEST_DETECTED pid=" + std::to_string(pid) +
            " exe=" + exeName);
    LogDbg("cmdline: " + cmdLine);

    // --- 1. Suspend the process IMMEDIATELY to beat the race ----------------
    // If suspend fails (e.g., process already exited) we still do our best.
    bool suspended = SuspendPid(pid);
    if (!suspended) LogDbg("Suspend failed (process may have exited) pid=" +
                            std::to_string(pid));

    // --- 2. Evasion detection: PowerShell -EncodedCommand -------------------
    std::string expandedCmd = cmdLine;
    std::string evasionMarker;
    if (exeLower == "powershell.exe" || exeLower == "pwsh.exe") {
        std::string decoded = DecodePowerShellEncodedCommand(cmdLine);
        if (!decoded.empty()) {
            evasionMarker = "powershell_encoded_command";
            LogWarn("NETWORK_EVASION_ATTEMPT_DETECTED pid=" +
                    std::to_string(pid) + " technique=EncodedCommand");
            expandedCmd += "  <<decoded>> " + decoded;
        }
    }

    // --- 3. Extract referenced file paths ----------------------------------
    auto paths = ExtractFilePathsFromCmdline(exeLower, expandedCmd);

    // --- 4. Read content + classify -----------------------------------------
    std::string aggregate;
    std::string firstPath;
    size_t      firstSize = 0;

    if (!paths.empty()) {
        for (const auto& p : paths) {
            size_t cap = g_cfg.maxFileBytes;
            // Python scripts: use the smaller script cap & heuristic scan
            if ((exeLower.find("python") != std::string::npos) &&
                (ToLower(p).size() >= 3 &&
                 p.substr(p.size() - 3) == ".py")) {
                cap = g_cfg.maxScriptBytes;
            }
            std::string content = ReadFileSafely(p, cap);
            if (!content.empty()) {
                if (firstPath.empty()) {
                    firstPath = p;
                    try { firstSize = (size_t)fs::file_size(p); } catch(...) {}
                }
                // Evasion: ZIP content -> extraction is out of scope, but flag
                if (LooksLikeZip(content) && evasionMarker.empty()) {
                    evasionMarker = "zip_compressed_payload";
                    LogWarn("NETWORK_EVASION_ATTEMPT_DETECTED pid=" +
                            std::to_string(pid) + " technique=ZIP");
                }
                // Evasion: pure base64 blob
                if (LooksMostlyBase64(content) && evasionMarker.empty()) {
                    std::string decoded = TryBase64Decode(content);
                    if (!decoded.empty()) {
                        evasionMarker = "base64_encoded_payload";
                        LogWarn("NETWORK_EVASION_ATTEMPT_DETECTED pid=" +
                                std::to_string(pid) + " technique=Base64");
                        // Scan the decoded form too
                        aggregate += decoded;
                        aggregate.push_back('\n');
                    }
                }
                aggregate += content;
                aggregate.push_back('\n');

                LogDbg("FILE_CAPTURED_BEFORE_SEND pid=" + std::to_string(pid) +
                       " path=" + p + " bytes=" + std::to_string(content.size()));
            } else {
                LogWarn("CONTENT_EXTRACTION_FAILED path=" + p);
            }
        }
    }

    // Python heuristic: if the referenced .py looks like an uploader, we still
    // proceed even if no *data file* was extracted, because the script itself
    // is the indicator.
    if (aggregate.empty() && exeLower.find("python") != std::string::npos) {
        for (const auto& p : paths) {
            std::string sc = ReadFileSafely(p, g_cfg.maxScriptBytes);
            if (!sc.empty() && PythonScriptLooksLikeUploader(sc)) {
                aggregate = sc;  // classify the script content itself
                if (firstPath.empty()) {
                    firstPath = p;
                    try { firstSize = (size_t)fs::file_size(p); } catch(...) {}
                }
                LogInfo("Python script heuristic: uploader pattern detected in " + p);
                break;
            }
        }
    }

    // Inline PowerShell / curl data: scan the cmdline itself as last resort
    if (aggregate.empty()) {
        aggregate = expandedCmd;
    }

    // --- 5. Classify --------------------------------------------------------
    ClassifyResult cls;
    try {
        cls = g_cfg.classify(aggregate, "network_exfil");
    } catch (...) {
        LogErr("classify callback threw for pid=" + std::to_string(pid));
    }

    std::string catLower = ToLower(cls.category);
    bool sensitive = (catLower == "confidential" || catLower == "restricted");

    LogInfo("CLASSIFICATION_RESULT pid=" + std::to_string(pid) +
            " category=" + (cls.category.empty() ? "none" : cls.category) +
            " score=" + std::to_string(cls.score) +
            " rule=" + cls.matchedRule);

    // --- 6. Enforce ---------------------------------------------------------
    EventFields f;
    f.eventSubtype = "cli_upload";
    f.channel = "CLI";
    f.processName = exeName;
    f.pid = pid;
    f.commandLine = cmdLine;
    f.fileName = firstPath.empty() ? "" : fs::path(firstPath).filename().string();
    f.filePath = firstPath;
    f.fileSize = firstSize;
    f.category = cls.category;
    f.classificationScore = cls.score;
    f.matchedRule = cls.matchedRule;
    f.labels = cls.labels;
    f.evasion = evasionMarker;

    if (sensitive) {
        // BLOCK: terminate and emit
        bool killed = TerminatePid(pid);
        f.action   = "BLOCK";
        f.severity = (catLower == "restricted") ? "critical" : "high";
        f.reason   = "Blocked " + exeName + " transfer of sensitive data ("
                   + cls.category + ")" + (killed ? "" : " [terminate failed]");
        LogWarn("NETWORK_BLOCKED pid=" + std::to_string(pid) +
                " exe=" + exeName + " category=" + cls.category);
        LogInfo("POLICY_DECISION pid=" + std::to_string(pid) + " decision=BLOCK");
        EmitEvent(f);
    } else if (!cls.category.empty()) {
        // Non-sensitive classification returned: allow and resume.
        if (suspended) ResumePid(pid);
        f.action   = "ALLOW";
        f.severity = "low";
        f.reason   = "Transfer allowed - classification=" + cls.category;
        LogInfo("POLICY_DECISION pid=" + std::to_string(pid) + " decision=ALLOW");
        // Only emit ALLOW events for transparency when a file was actually
        // captured (reduces noise from benign invocations).
        if (!firstPath.empty()) EmitEvent(f);
    } else {
        // No classification match at all: resume and stay silent.
        if (suspended) ResumePid(pid);
        LogDbg("No classification match; process resumed pid=" +
               std::to_string(pid));
    }
}

} // anonymous namespace


// =============================================================================
// WMI process-creation event consumer (CLI monitor)
// =============================================================================
namespace {

class WmiEventSink : public IWbemObjectSink {
    LONG m_ref = 0;
public:
    WmiEventSink() = default;
    virtual ~WmiEventSink() = default;

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_ref);
    }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = static_cast<IWbemObjectSink*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    HRESULT STDMETHODCALLTYPE Indicate(LONG objCount,
                                       IWbemClassObject** apObj) override {
        if (g_stopRequested.load()) return WBEM_S_NO_ERROR;

        for (LONG i = 0; i < objCount; ++i) {
            IWbemClassObject* evt = apObj[i];
            if (!evt) continue;
            VARIANT v; VariantInit(&v);

            // TargetInstance is an embedded object (Win32_Process)
            HRESULT hr = evt->Get(L"TargetInstance", 0, &v, nullptr, nullptr);
            if (FAILED(hr) || v.vt != VT_UNKNOWN || !v.punkVal) {
                VariantClear(&v);
                continue;
            }

            IWbemClassObject* proc = nullptr;
            hr = v.punkVal->QueryInterface(IID_IWbemClassObject, (void**)&proc);
            VariantClear(&v);
            if (FAILED(hr) || !proc) continue;

            // Extract Name, ProcessId, CommandLine
            std::string exeName, cmdLine;
            DWORD pid = 0;

            VARIANT vname; VariantInit(&vname);
            if (SUCCEEDED(proc->Get(L"Name", 0, &vname, nullptr, nullptr)) &&
                vname.vt == VT_BSTR && vname.bstrVal) {
                exeName = WideToUtf8(vname.bstrVal);
            }
            VariantClear(&vname);

            VARIANT vcmd; VariantInit(&vcmd);
            if (SUCCEEDED(proc->Get(L"CommandLine", 0, &vcmd, nullptr, nullptr)) &&
                vcmd.vt == VT_BSTR && vcmd.bstrVal) {
                cmdLine = WideToUtf8(vcmd.bstrVal);
            }
            VariantClear(&vcmd);

            VARIANT vpid; VariantInit(&vpid);
            if (SUCCEEDED(proc->Get(L"ProcessId", 0, &vpid, nullptr, nullptr))) {
                if (vpid.vt == VT_I4)      pid = (DWORD)vpid.lVal;
                else if (vpid.vt == VT_UI4) pid = vpid.ulVal;
                else if (vpid.vt == VT_I2)  pid = (DWORD)vpid.iVal;
            }
            VariantClear(&vpid);
            proc->Release();

            if (pid == 0 || exeName.empty()) continue;

            // Hand off to the enforcement path on a detached worker so the
            // WMI callback thread returns quickly. This is critical - blocking
            // here would starve the WMI event pump.
            try {
                std::thread([pid, exeName, cmdLine]() {
                    try { HandleCandidateProcess(pid, exeName, cmdLine); }
                    catch (const std::exception& e) {
                        LogErr(std::string("HandleCandidateProcess threw: ") + e.what());
                    } catch (...) {
                        LogErr("HandleCandidateProcess threw unknown exception");
                    }
                }).detach();
            } catch (...) {
                LogErr("Failed to spawn handler thread");
            }
        }
        return WBEM_S_NO_ERROR;
    }

    HRESULT STDMETHODCALLTYPE SetStatus(LONG /*flags*/, HRESULT /*hr*/,
                                        BSTR /*param*/,
                                        IWbemClassObject* /*objParam*/) override {
        return WBEM_S_NO_ERROR;
    }
};

void CliMonitorThread() {
    LogInfo("NetworkExfilMonitor: CLI monitor thread starting");

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool comInitialized = (hr == S_OK || hr == S_FALSE);
    if (!comInitialized) {
        LogErr("CoInitializeEx failed hr=0x" +
               std::to_string((unsigned)hr));
        return;
    }

    // Security for WMI
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE, nullptr);
    // S_OK or RPC_E_TOO_LATE (already set by host) are both fine.
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        LogErr("CoInitializeSecurity failed hr=0x" +
               std::to_string((unsigned)hr));
        CoUninitialize();
        return;
    }

    IWbemLocator*  pLoc  = nullptr;
    IWbemServices* pSvc  = nullptr;
    IUnsecuredApartment* pUnsec = nullptr;
    IWbemObjectSink* pStub = nullptr;
    WmiEventSink*    pSink = nullptr;

    auto cleanup = [&]() {
        if (pStub)  { pStub->Release();  pStub = nullptr; }
        if (pUnsec) { pUnsec->Release(); pUnsec = nullptr; }
        if (pSvc)   { pSvc->Release();   pSvc = nullptr; }
        if (pLoc)   { pLoc->Release();   pLoc = nullptr; }
        // pSink is released via pStub/unsecured-apartment pathway
        if (comInitialized) CoUninitialize();
    };

    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr) || !pLoc) {
        LogErr("CoCreateInstance(WbemLocator) failed");
        cleanup(); return;
    }

    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    hr = pLoc->ConnectServer(ns, nullptr, nullptr, nullptr,
                             WBEM_FLAG_CONNECT_USE_MAX_WAIT,
                             nullptr, nullptr, &pSvc);
    SysFreeString(ns);
    if (FAILED(hr) || !pSvc) {
        LogErr("WMI ConnectServer failed");
        cleanup(); return;
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        LogErr("CoSetProxyBlanket failed");
        cleanup(); return;
    }

    hr = CoCreateInstance(CLSID_UnsecuredApartment, nullptr, CLSCTX_LOCAL_SERVER,
                          IID_IUnsecuredApartment, (void**)&pUnsec);
    if (FAILED(hr) || !pUnsec) {
        LogErr("CoCreateInstance(UnsecuredApartment) failed");
        cleanup(); return;
    }

    pSink = new WmiEventSink();
    pSink->AddRef();

    IUnknown* pSinkUnk = nullptr;
    hr = pUnsec->CreateObjectStub(pSink, &pSinkUnk);
    if (FAILED(hr) || !pSinkUnk) {
        LogErr("CreateObjectStub failed");
        pSink->Release();
        cleanup(); return;
    }

    hr = pSinkUnk->QueryInterface(IID_IWbemObjectSink, (void**)&pStub);
    pSinkUnk->Release();
    if (FAILED(hr) || !pStub) {
        LogErr("QueryInterface(IWbemObjectSink) failed");
        pSink->Release();
        cleanup(); return;
    }

    // WITHIN 0.5 -> poll every 500ms; good balance of latency vs CPU
    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(
        L"SELECT * FROM __InstanceCreationEvent WITHIN 0.5 "
        L"WHERE TargetInstance ISA 'Win32_Process'");

    hr = pSvc->ExecNotificationQueryAsync(lang, query, 0, nullptr, pStub);
    SysFreeString(lang);
    SysFreeString(query);

    if (FAILED(hr)) {
        LogErr("ExecNotificationQueryAsync failed hr=0x" +
               std::to_string((unsigned)hr));
        pSink->Release();
        cleanup(); return;
    }

    LogInfo("NetworkExfilMonitor: WMI subscription active");

    // Idle loop until shutdown requested
    while (!g_stopRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    LogInfo("NetworkExfilMonitor: CLI monitor shutting down");
    pSvc->CancelAsyncCall(pStub);

    if (pSink) pSink->Release();
    cleanup();
}

} // anonymous namespace


// =============================================================================
// Browser file-dialog detector (UIAutomation)
// =============================================================================
namespace {

// Returns the image name (lowercased) for a PID.
std::string ProcessImageName(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH] = {0};
    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameW(h, 0, buf, &sz);
    CloseHandle(h);
    std::string full = WideToUtf8(buf);
    try { return ToLower(fs::path(full).filename().string()); } catch (...) { return {}; }
}

bool IsBrowserExe(const std::string& exeLower) {
    static const std::unordered_set<std::string> browsers = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"
    };
    return browsers.count(exeLower) > 0;
}

// Walk up the UIA subtree looking for the Edit control that contains the
// currently-typed file name. Depth-limited to avoid runaway traversal.
std::string FindFileNameFromDialog(IUIAutomation* uia, IUIAutomationElement* root) {
    if (!uia || !root) return {};
    IUIAutomationCondition* cond = nullptr;
    VARIANT v; VariantInit(&v);
    v.vt = VT_I4; v.lVal = UIA_EditControlTypeId;
    uia->CreatePropertyCondition(UIA_ControlTypePropertyId, v, &cond);

    std::string result;
    if (cond) {
        IUIAutomationElementArray* arr = nullptr;
        root->FindAll(TreeScope_Descendants, cond, &arr);
        if (arr) {
            int count = 0; arr->get_Length(&count);
            for (int i = 0; i < count && result.empty(); ++i) {
                IUIAutomationElement* el = nullptr;
                arr->GetElement(i, &el);
                if (!el) continue;
                BSTR name = nullptr;
                if (SUCCEEDED(el->get_CurrentName(&name)) && name) {
                    std::string n = WideToUtf8(name);
                    SysFreeString(name);
                    // Skip empty / generic labels
                    if (!n.empty()) {
                        // Pattern heuristic: if it contains a path separator
                        // or a common file extension, treat as filename.
                        if (n.find('\\') != std::string::npos ||
                            n.find(':') != std::string::npos  ||
                            n.find('.') != std::string::npos) {
                            result = n;
                        }
                    }
                }
                // Also try Value pattern (portable form: GetCurrentPattern + QI)
                if (result.empty()) {
                    IUnknown* pat = nullptr;
                    if (SUCCEEDED(el->GetCurrentPattern(UIA_ValuePatternId, &pat)) && pat) {
                        IUIAutomationValuePattern* vp = nullptr;
                        pat->QueryInterface(IID_IUIAutomationValuePattern,
                                            (void**)&vp);
                        pat->Release();
                        if (vp) {
                            BSTR val = nullptr;
                            if (SUCCEEDED(vp->get_CurrentValue(&val)) && val) {
                                std::string s = WideToUtf8(val);
                                SysFreeString(val);
                                if (!s.empty()) result = s;
                            }
                            vp->Release();
                        }
                    }
                }
                el->Release();
            }
            arr->Release();
        }
        cond->Release();
    }
    return result;
}

class BrowserDialogHandler : public IUIAutomationEventHandler {
    LONG m_ref = 0;
    IUIAutomation* m_uia = nullptr;
public:
    explicit BrowserDialogHandler(IUIAutomation* uia) : m_uia(uia) {
        if (m_uia) m_uia->AddRef();
    }
    virtual ~BrowserDialogHandler() { if (m_uia) m_uia->Release(); }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_ref);
    }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IUIAutomationEventHandler) {
            *ppv = static_cast<IUIAutomationEventHandler*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    HRESULT STDMETHODCALLTYPE HandleAutomationEvent(
        IUIAutomationElement* sender, EVENTID eventId) override {
        if (g_stopRequested.load() || !sender ||
            eventId != UIA_Window_WindowOpenedEventId) return S_OK;

        // Filter: owning process must be a browser
        int pid = 0;
        sender->get_CurrentProcessId(&pid);
        if (pid <= 0) return S_OK;
        std::string exe = ProcessImageName((DWORD)pid);
        if (!IsBrowserExe(exe)) return S_OK;

        // Filter: window is a dialog (class #32770) or name indicates file picker
        BSTR className = nullptr;
        sender->get_CurrentClassName(&className);
        std::string cls = className ? WideToUtf8(className) : std::string{};
        if (className) SysFreeString(className);

        BSTR name = nullptr;
        sender->get_CurrentName(&name);
        std::string winName = name ? WideToUtf8(name) : std::string{};
        if (name) SysFreeString(name);

        std::string nlc = ToLower(winName);
        bool isFileDialog =
            cls == "#32770" ||
            nlc.find("open") != std::string::npos ||
            nlc.find("upload") != std::string::npos ||
            nlc.find("choose file") != std::string::npos ||
            nlc.find("select file") != std::string::npos;
        if (!isFileDialog) return S_OK;

        LogDbg("Browser file dialog opened exe=" + exe +
               " class=" + cls + " title=" + winName);

        // We don't know the selected file yet (user hasn't clicked Open).
        // Poll the dialog for up to 60 seconds looking for a filename and
        // dialog-close signal. Detached thread so we don't block UIA.
        IUIAutomation* uia = m_uia;
        if (uia) uia->AddRef();
        IUIAutomationElement* senderCopy = sender;
        senderCopy->AddRef();

        std::thread([uia, senderCopy, exe, pid]() {
            std::unique_ptr<IUIAutomationElement,
                            void(*)(IUIAutomationElement*)>
                elGuard(senderCopy, [](IUIAutomationElement* p){ if (p) p->Release(); });
            std::unique_ptr<IUIAutomation,
                            void(*)(IUIAutomation*)>
                uiaGuard(uia, [](IUIAutomation* p){ if (p) p->Release(); });

            std::string captured;
            for (int i = 0; i < 120; ++i) {     // 120 * 500ms = 60s
                if (g_stopRequested.load()) return;
                std::this_thread::sleep_for(std::chrono::milliseconds(500));

                // Dialog closed?
                BOOL offscreen = FALSE;
                HRESULT hr = senderCopy->get_CurrentIsOffscreen(&offscreen);
                if (FAILED(hr)) break;  // window invalid -> closed
                std::string fn = FindFileNameFromDialog(uia, senderCopy);
                if (!fn.empty()) captured = fn;
                if (offscreen) break;
            }

            if (captured.empty()) return;

            // Resolve to full path (the Edit control often has just a name)
            std::string resolved = ResolveExistingPath(captured);
            if (resolved.empty()) {
                // Try common download / doc locations
                wchar_t pathBuf[MAX_PATH] = {0};
                if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr,
                                               0, pathBuf))) {
                    std::string home = WideToUtf8(pathBuf);
                    for (const char* sub : {"\\Downloads\\", "\\Documents\\",
                                            "\\Desktop\\", "\\"}) {
                        std::string attempt = home + sub + captured;
                        if (fs::exists(attempt)) { resolved = attempt; break; }
                    }
                }
            }
            if (resolved.empty()) resolved = captured;

            // Read + classify (BEST EFFORT - we don't block browsers)
            std::string content;
            size_t      sz = 0;
            try {
                content = ReadFileSafely(resolved, g_cfg.maxFileBytes);
                sz = fs::exists(resolved) ? (size_t)fs::file_size(resolved) : 0;
            } catch (...) {}

            if (content.empty()) {
                LogWarn("CONTENT_EXTRACTION_FAILED browser path=" + resolved);
                // Still emit a low-severity ALERT for visibility
                EventFields f;
                f.eventSubtype = "browser_file_selection";
                f.channel = "BROWSER";
                f.processName = exe;
                f.pid = (DWORD)pid;
                f.fileName = fs::path(resolved).filename().string();
                f.filePath = resolved;
                f.fileSize = sz;
                f.action = "ALERT";
                f.severity = "low";
                f.reason = "Browser file selection detected (content not readable)";
                EmitEvent(f);
                return;
            }

            ClassifyResult cls;
            try { cls = g_cfg.classify(content, "network_exfil"); } catch(...) {}

            LogInfo("CLASSIFICATION_RESULT browser pid=" + std::to_string(pid) +
                    " category=" + (cls.category.empty() ? "none" : cls.category));

            std::string catLower = ToLower(cls.category);
            bool sensitive = (catLower == "confidential" || catLower == "restricted");

            EventFields f;
            f.eventSubtype = "browser_file_selection";
            f.channel = "BROWSER";
            f.processName = exe;
            f.pid = (DWORD)pid;
            f.fileName = fs::path(resolved).filename().string();
            f.filePath = resolved;
            f.fileSize = sz;
            f.category = cls.category;
            f.classificationScore = cls.score;
            f.matchedRule = cls.matchedRule;
            f.labels = cls.labels;

            if (sensitive) {
                f.action   = "ALERT";            // Per spec: never block browsers
                f.severity = (catLower == "restricted") ? "critical" : "high";
                f.reason   = "Sensitive file selected for upload in " + exe +
                             " (" + cls.category + "). Alert only - not blocked.";
                LogWarn("POLICY_DECISION browser decision=ALERT category=" +
                        cls.category);
                EmitEvent(f);
            } else if (!cls.category.empty()) {
                LogDbg("Browser file selection non-sensitive; no event emitted");
            }
        }).detach();

        return S_OK;
    }
};

void BrowserDetectorThread() {
    LogInfo("NetworkExfilMonitor: browser detector thread starting");

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool comInitialized = (hr == S_OK || hr == S_FALSE);
    if (!comInitialized) {
        LogErr("Browser detector: CoInitializeEx failed");
        return;
    }

    IUIAutomation* uia = nullptr;
    hr = CoCreateInstance(CLSID_CUIAutomation, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IUIAutomation, (void**)&uia);
    if (FAILED(hr) || !uia) {
        LogWarn("UIAutomation unavailable; browser detection disabled");
        CoUninitialize();
        return;
    }

    IUIAutomationElement* rootEl = nullptr;
    uia->GetRootElement(&rootEl);
    if (!rootEl) {
        LogWarn("UIA root element unavailable");
        uia->Release(); CoUninitialize(); return;
    }

    BrowserDialogHandler* handler = new BrowserDialogHandler(uia);
    handler->AddRef();

    hr = uia->AddAutomationEventHandler(UIA_Window_WindowOpenedEventId,
                                        rootEl, TreeScope_Subtree,
                                        nullptr, handler);
    if (FAILED(hr)) {
        LogWarn("AddAutomationEventHandler failed; browser detection disabled");
        handler->Release();
        rootEl->Release(); uia->Release(); CoUninitialize();
        return;
    }

    LogInfo("NetworkExfilMonitor: browser dialog detector active");

    // Pump a message loop - UIA events are delivered on MTA threads but some
    // implementations still rely on a message pump for child windows.
    while (!g_stopRequested.load()) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    uia->RemoveAutomationEventHandler(UIA_Window_WindowOpenedEventId,
                                      rootEl, handler);
    handler->Release();
    rootEl->Release();
    uia->Release();
    CoUninitialize();

    LogInfo("NetworkExfilMonitor: browser detector stopped");
}

} // anonymous namespace


// =============================================================================
// Public API
// =============================================================================

bool Start(const Config& cfg) {
    if (g_running.exchange(true)) {
        LogWarn("NetworkExfilMonitor::Start called twice - ignoring");
        return true;
    }
    g_stopRequested.store(false);

    if (!cfg.classify || !cfg.sendEvent || !cfg.log) {
        // Config callbacks are required
        g_running.store(false);
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(g_cfgMutex);
        g_cfg = cfg;
    }

    bool started = false;
    if (cfg.enableCliMonitor) {
        try {
            g_cliThread = std::thread(CliMonitorThread);
            started = true;
        } catch (...) {
            LogErr("Failed to launch CLI monitor thread");
        }
    }
    if (cfg.enableBrowserDetector) {
        try {
            g_browserThread = std::thread(BrowserDetectorThread);
            started = true;
        } catch (...) {
            LogErr("Failed to launch browser detector thread");
        }
    }

    if (!started) g_running.store(false);
    return started;
}

void Stop() {
    if (!g_running.load()) return;
    g_stopRequested.store(true);

    // Give threads time to notice and exit cleanly
    if (g_cliThread.joinable())     { try { g_cliThread.join();     } catch(...) {} }
    if (g_browserThread.joinable()) { try { g_browserThread.join(); } catch(...) {} }

    g_running.store(false);
}

bool IsRunning() {
    return g_running.load();
}

// =============================================================================
// Dedicated Network-Exfil Content Classifier
//
// Independent from ContentClassifier / ExtractDataType. Has its own regex
// patterns, its own Luhn validation for credit cards, its own severity map.
// Designed so that clipboard / USB / file / screen-capture detection remains
// absolutely unchanged (zero shared state, zero shared regex).
//
// Precedence: credit card is evaluated BEFORE Aadhaar, and Aadhaar only
// matches when NOT part of a longer digit sequence (negative lookahead).
// This resolves the historical aadhaar/credit-card collision locally
// without touching the shared engine used by other modules.
// =============================================================================
namespace {

// Luhn checksum validator (credit cards).
bool NxLuhn(const std::string& s) {
    std::string d;
    for (char c : s) if (c >= '0' && c <= '9') d += c;
    if (d.size() < 13 || d.size() > 19) return false;
    int sum = 0; bool alt = false;
    for (int i = (int)d.size() - 1; i >= 0; --i) {
        int x = d[i] - '0';
        if (alt) { x *= 2; if (x > 9) x -= 9; }
        sum += x;
        alt = !alt;
    }
    return (sum % 10) == 0;
}

// Returns the first N bytes of s, for safe logging / preview.
std::string NxTrim(const std::string& s, size_t n = 64) {
    return s.size() <= n ? s : s.substr(0, n) + "...";
}

// Run all detectors, return list of {type, sample} pairs.
struct NxItem { std::string type; std::string sample; };

std::vector<NxItem> NxDetectAll(const std::string& content) {
    std::vector<NxItem> items;
    if (content.empty()) return items;

    auto pushUnique = [&](const std::string& type, const std::string& sample) {
        for (const auto& it : items) if (it.type == type) return;
        items.push_back({type, NxTrim(sample)});
    };

    // ---- CREDIT_CARD (evaluated first; Luhn-validated) --------------------
    try {
        std::regex rx(R"(\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        for (; it != end; ++it) {
            std::string m = it->str();
            std::string d; for (char c : m) if (c >= '0' && c <= '9') d += c;
            if (d.size() == 16 && NxLuhn(m)) {
                pushUnique("CREDIT_CARD", m);
                break;
            }
        }
    } catch (...) {}

    // ---- AADHAAR (negative lookahead + manual lookbehind) -----------------
    // A real Aadhaar is a standalone 4-4-4 digit string. We must reject the
    // match when it is actually the head OR the tail of a longer digit run
    // (e.g. a 16-digit credit card that failed Luhn).
    //
    // Negative lookahead ?![\s-]?\d  handles the HEAD-of-a-longer-number case.
    // std::regex does not support lookbehind, so the TAIL-of-a-longer-number
    // case is handled manually below by inspecting the bytes immediately
    // before the match position.
    try {
        std::regex rx(R"(\b\d{4}[\s-]\d{4}[\s-]\d{4}\b(?![\s-]?\d))");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        for (; it != end; ++it) {
            std::string m = it->str();
            std::string d; for (char c : m) if (c >= '0' && c <= '9') d += c;
            if (d.size() != 12) continue;

            // Manual lookbehind: reject if preceded by  <digit>  or
            // <digit><sep>  -- i.e. we are sitting inside a larger run like a
            // 16-digit card number. \b in the regex guarantees the byte at
            // pos-1 (if any) is non-word, so we only need to handle:
            //   pos-1 = separator AND pos-2 = digit  -> reject.
            size_t pos = static_cast<size_t>(it->position());
            if (pos >= 2) {
                char c1 = content[pos - 1];
                if (c1 == '-' || c1 == ' ' || c1 == '\t' || c1 == '.') {
                    char c2 = content[pos - 2];
                    if (c2 >= '0' && c2 <= '9') continue;   // REJECT
                }
            }
            pushUnique("AADHAAR", m);
            break;
        }
    } catch (...) {}

    // ---- PAN (Indian Permanent Account Number: 5 letters, 4 digits, 1 letter)
    try {
        std::regex rx(R"(\b[A-Z]{5}\d{4}[A-Z]\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("PAN", it->str());
    } catch (...) {}

    // ---- IFSC (Indian bank branch code: 4 letters, 0, 6 alnum) ------------
    try {
        std::regex rx(R"(\b[A-Z]{4}0[A-Z0-9]{6}\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("IFSC", it->str());
    } catch (...) {}

    // ---- SSN (US Social Security Number) ----------------------------------
    try {
        std::regex rx(R"(\b\d{3}-\d{2}-\d{4}\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("SSN", it->str());
    } catch (...) {}

    // ---- INDIAN_PHONE (+91, leading 0, or bare 10 digits 6-9) ------------
    try {
        std::regex rx(R"((?:\+91[\s.-]?|0)?[6-9]\d{4}[\s.-]?\d{5})");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        for (; it != end; ++it) {
            std::string m = it->str();
            std::string d; for (char c : m) if (c >= '0' && c <= '9') d += c;
            if (d.size() >= 10 && d.size() <= 12) {
                pushUnique("INDIAN_PHONE", m);
                break;
            }
        }
    } catch (...) {}

    // ---- US_PHONE (requires separators to avoid matching random 10 digits)
    try {
        std::regex rx(R"((?:\+?1[\s.-])?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4})");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        for (; it != end; ++it) {
            std::string m = it->str();
            std::string d; for (char c : m) if (c >= '0' && c <= '9') d += c;
            if (d.size() >= 10 && d.size() <= 11) {
                pushUnique("US_PHONE", m);
                break;
            }
        }
    } catch (...) {}

    // ---- EMAIL -------------------------------------------------------------
    try {
        std::regex rx(R"(\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("EMAIL", it->str());
    } catch (...) {}

    // ---- AWS_KEY (access key id: AKIA / ASIA / AIDA / AROA + 16 alnum) ----
    try {
        std::regex rx(R"(\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("AWS_KEY", it->str());
    } catch (...) {}

    // ---- PRIVATE_KEY (PEM header) -----------------------------------------
    try {
        std::regex rx(R"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("PRIVATE_KEY", "<PEM private key header>");
    } catch (...) {}

    // ---- JWT_TOKEN (header.payload.signature, base64url segments) --------
    try {
        std::regex rx(R"(\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("JWT_TOKEN", "<jwt>");
    } catch (...) {}

    // ---- UPI_ID (Indian UPI handle - PSP-scoped only to avoid email FPs) -
    try {
        std::regex rx(
            R"(\b[a-zA-Z0-9._\-]{3,}@(?:okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|ibl|axl|upi|apl|airtel|fam|jupiteraxis|idfcbank|yesbank|kotak|federal|timecosmos|sbi)\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("UPI_ID", it->str());
    } catch (...) {}

    // ---- INDIAN_PASSPORT (one letter + 7 digits) --------------------------
    try {
        std::regex rx(R"(\b[A-PR-WYa-pr-wy][0-9]{7}\b)");
        std::sregex_iterator it(content.begin(), content.end(), rx), end;
        if (it != end) pushUnique("INDIAN_PASSPORT", it->str());
    } catch (...) {}

    return items;
}

// Map a detected type to our four-level category.
int NxTypeSeverity(const std::string& type) {   // 0=Public, 3=Restricted
    static const std::unordered_map<std::string, int> sev = {
        // Critical PII / credentials - Restricted
        {"CREDIT_CARD",     3}, {"AADHAAR",      3}, {"PAN",             3},
        {"SSN",             3}, {"AWS_KEY",      3}, {"PRIVATE_KEY",     3},
        {"INDIAN_PASSPORT", 3},
        // Sensitive but less critical - Confidential
        {"JWT_TOKEN",       2}, {"IFSC",         2}, {"INDIAN_PHONE",    2},
        {"UPI_ID",          2},
        // Lower sensitivity - Internal
        {"US_PHONE",        1}, {"EMAIL",        1},
    };
    auto it = sev.find(type);
    return it == sev.end() ? 0 : it->second;
}

} // anonymous namespace

ClassifyResult ClassifyNetworkContent(const std::string& content) {
    ClassifyResult out;
    std::vector<NxItem> items = NxDetectAll(content);

    int best = 0;
    for (const auto& d : items) {
        out.labels.push_back(d.type);
        int s = NxTypeSeverity(d.type);
        if (s > best) best = s;
    }
    switch (best) {
        case 3: out.category = "Restricted";   out.score = 0.95; break;
        case 2: out.category = "Confidential"; out.score = 0.85; break;
        case 1: out.category = "Internal";     out.score = 0.50; break;
        default: out.category = "Public";      out.score = 0.00; break;
    }
    // matchedRule carries the highest-severity specific type so the dashboard
    // can show e.g. "CREDIT_CARD" or "AADHAAR" instead of a policy UUID.
    if (!items.empty()) {
        std::string top;
        int topSev = -1;
        for (const auto& d : items) {
            int s = NxTypeSeverity(d.type);
            if (s > topSev) { topSev = s; top = d.type; }
        }
        out.matchedRule = top;
    }
    return out;
}

} // namespace NetworkExfilMonitor
