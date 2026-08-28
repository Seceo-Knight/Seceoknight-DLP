// messaging_text_monitor.cpp — see messaging_text_monitor.h for the design and
// for why every failure path releases the keystroke.

// Feature macros first — they gate QueryFullProcessImageName and the UI
// Automation interface declarations, and only take effect before <windows.h>.
// Kept identical to network_exfil_monitor.cpp so both modules see one ABI.
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
#include <psapi.h>
#include <tlhelp32.h>
#include <UIAutomation.h>

#include "messaging_text_monitor.h"

#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cwchar>

namespace MessagingTextMonitor {
namespace {

Config            g_cfg;
std::atomic<bool> g_running{false};
std::atomic<bool> g_stop{false};

HHOOK       g_hook       = nullptr;
DWORD       g_hookThread = 0;
std::thread g_hookThreadObj;
std::thread g_workerObj;
std::thread g_samplerObj;
std::thread g_watchdogObj;

// ── Hook -> worker handoff ────────────────────────────────────────────────
// The hook must never block, so it publishes the bare facts and wakes the
// worker. One pending item at a time: a second Enter while a decision is in
// flight is passed straight through rather than queued, because queueing
// keystrokes is how you end up delivering them in the wrong order.
std::mutex              g_mx;
std::condition_variable g_cv;
bool                    g_pendingWork  = false;
bool                    g_pendingAudit = false;   // alert mode: nothing was held
HWND                    g_pendingWnd   = nullptr;
DWORD                   g_pendingPid   = 0;
// The name the POLICY matched, which is not always the owner of the window:
// a Chromium renderer owns the window, its parent owns the product. Events
// must name the app the operator listed, not msedgewebview2.exe.
std::string             g_pendingExe;
bool                    g_pendingCtrl  = false;
std::vector<std::string> g_pendingTypes;          // operator-selected detector types

// True from the moment we swallow the Enter keydown until the decision is made.
// Read by the hook to also swallow the matching keyup (an app that sees a keyup
// with no keydown is not harmed, but it is untidy and some Electron composers
// do watch for it).
std::atomic<bool> g_decisionPending{false};

// The held keystroke is resolved exactly once, by whichever of the worker and
// the watchdog claims it first. Two releases would send the message twice; a
// release after a deliberate drop would send the message the policy just
// blocked. `true` is the resting state — nothing is held.
std::atomic<bool>      g_decisionResolved{true};
std::atomic<long long> g_holdStartMs{0};
std::atomic<bool>      g_holdCtrl{false};

// Why an unmanaged app is worth a log line at all: the hook's silent exit for
// "not one of ours" is correct behaviour and was also completely undebuggable.
// When typed-message inspection appears to do nothing, the single most useful
// fact is what the agent actually RESOLVED the foreground app to — a packaged
// app seen through its frame host, a launcher, a webview host, or simply a name
// the policy does not list. Without it the operator is left comparing an empty
// log against a policy that looks correct, which is exactly where this landed.
// Rate-limited hard, and published from the hook for the worker to write, so the
// hook itself still does no I/O.
// Every send key produces one of these, whatever the policy says about the app.
// Rate limiting lives in the worker (per app), not here: a global limiter meant
// pressing Enter in Notepad could hide the WhatsApp keypress tested two seconds
// later, which is precisely the case somebody is trying to diagnose.
std::mutex        g_probeMx;
std::string       g_probeExe;
bool              g_probeManaged = false;
bool              g_probeInspect = false;
bool              g_probeBlock   = false;
bool              g_probeReady   = false;

// Alert-mode composer snapshot (see the header: alert mode never holds input,
// so the box is already empty by the time we get to look at it).
std::mutex             g_snapMx;
std::string            g_snapText;
DWORD                  g_snapPid   = 0;
long long              g_snapAtMs  = 0;

// Alert mode fires on every Enter, including the ones that resend the same
// text; an operator does not need the same message five times.
std::string            g_lastAuditText;
long long              g_lastAuditMs = 0;

// "UI Automation cannot see this app's composer" is a deployment fact worth
// reporting once — it is how you discover a build of WhatsApp this cannot read
// — but not something to raise on every Enter.
std::mutex                       g_uninspectableMx;
std::map<std::string, long long> g_uninspectableAt;

long long NowSteadyMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void LogMsg(const char* level, const std::string& m) {
    if (g_cfg.log) { try { g_cfg.log(level, "MessagingText: " + m); } catch (...) {} }
}
void LogInfo(const std::string& m) { LogMsg("INFO",  m); }
void LogWarn(const std::string& m) { LogMsg("WARNING", m); }
void LogDbg (const std::string& m) { LogMsg("DEBUG", m); }

std::string ToLowerAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
    }
    return true;
}

std::string WideToUtf8(const wchar_t* w) {
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out((size_t)n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &out[0], n, nullptr, nullptr);
    return out;
}

std::string ProcessExeName(DWORD pid) {
    if (!pid) return {};
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH] = {0};
    DWORD sz = MAX_PATH;
    std::string out;
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
        std::string full = WideToUtf8(buf);
        size_t slash = full.find_last_of("\\/");
        out = (slash == std::string::npos) ? full : full.substr(slash + 1);
    }
    CloseHandle(h);
    return ToLowerAscii(out);
}

// ── Which app is the user actually typing into ────────────────────────────
//
// A packaged (MSIX/UWP) app does not own its top-level window: the foreground
// HWND is an ApplicationFrameWindow owned by ApplicationFrameHost.exe, and the
// app itself owns a child CoreWindow. Resolving the process from the foreground
// window alone therefore reports the frame host, which is in no managed-app
// list, and the whole module quietly does nothing for exactly the apps most
// likely to be managed — the Store build of WhatsApp among them.
//
// The rule is simple and does not depend on knowing which apps are packaged:
// if the foreground window belongs to the frame host, the real app is the child
// window that belongs to somebody else.

struct TargetApp {
    HWND        wnd = nullptr;   // the window UI Automation should read from
    DWORD       pid = 0;
    std::string exe;             // lowercased image name
};

struct ChildProbe {
    DWORD framePid = 0;
    DWORD pid      = 0;
    HWND  wnd      = nullptr;
};

BOOL CALLBACK FrameChildProc(HWND h, LPARAM lp) {
    ChildProbe* p = (ChildProbe*)lp;
    DWORD cpid = 0;
    GetWindowThreadProcessId(h, &cpid);
    if (!cpid || cpid == p->framePid) return TRUE;   // frame chrome, keep looking

    wchar_t cls[128] = {0};
    GetClassNameW(h, cls, 128);
    if (wcscmp(cls, L"Windows.UI.Core.CoreWindow") == 0) {
        p->pid = cpid; p->wnd = h;
        return FALSE;                                 // the app itself — done
    }
    if (!p->pid) { p->pid = cpid; p->wnd = h; }       // fallback candidate
    return TRUE;
}

TargetApp ResolveApp(HWND fg) {
    TargetApp t;
    if (!fg) return t;
    DWORD pid = 0;
    GetWindowThreadProcessId(fg, &pid);
    if (!pid || pid == GetCurrentProcessId()) return t;

    t.wnd = fg;
    t.pid = pid;
    t.exe = ProcessExeName(pid);

    if (t.exe == "applicationframehost.exe") {
        ChildProbe p;
        p.framePid = pid;
        EnumChildWindows(fg, FrameChildProc, (LPARAM)&p);
        if (p.pid) {
            t.pid = p.pid;
            t.wnd = p.wnd ? p.wnd : fg;
            t.exe = ProcessExeName(p.pid);
        }
    }
    return t;
}

TargetApp ResolveForegroundApp() { return ResolveApp(GetForegroundWindow()); }

// ── Which app the POLICY should be asked about ────────────────────────────
//
// Stepping through the frame host above solves packaged apps. It does not solve
// the other shape, which is now the common one: a Chromium-family app (WebView2,
// Electron, CEF) renders its UI in a CHILD process, and when that child owns the
// window we resolve, the name we hold is msedgewebview2.exe. That name can never
// be put in a managed-app list — it hosts content for a dozen unrelated
// applications, and listing it would make every one of them a managed messaging
// app. The name that CAN be listed is the process that owns the renderer: its
// parent.
//
// So when the resolved image is not managed, walk up the process tree and ask
// again. Two hops, because a packaged Chromium app is commonly
// launcher -> browser -> renderer. The window and pid are deliberately NOT
// rewritten — the composer lives in the renderer and UI Automation must keep
// reading it there; only the name the policy is asked about moves.

// Walking the process tree means a Toolhelp snapshot, which is far too
// expensive to run inside a low-level keyboard hook on every Enter the user
// presses anywhere on the machine. It is also almost always the same answer:
// the foreground process changes when the user alt-tabs, not when they type. So
// the ancestry is resolved once per (pid, image) and remembered. Keying on the
// image name as well as the pid is what makes a recycled pid safe — a new
// process reusing the number resolves under its own name.
std::mutex g_ancestorMx;
struct AncestorEntry { std::string childExe; std::vector<std::string> exes; };
std::map<DWORD, AncestorEntry> g_ancestorCache;

// A parent pid recorded by the OS outlives the parent process, and Windows
// recycles pids. Without this the walk can name whatever happens to be sitting
// on that number now, and "managed messaging app" is a verdict that withholds a
// keystroke — not somewhere to accept a coincidence. A real ancestor always
// started first.
bool StartedNoLaterThan(DWORD ancestorPid, DWORD childPid) {
    FILETIME a{}, c{}, ignore1{}, ignore2{}, ignore3{};
    bool gotA = false, gotC = false;
    if (HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ancestorPid)) {
        gotA = GetProcessTimes(h, &a, &ignore1, &ignore2, &ignore3) != 0;
        CloseHandle(h);
    }
    if (HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, childPid)) {
        gotC = GetProcessTimes(h, &c, &ignore1, &ignore2, &ignore3) != 0;
        CloseHandle(h);
    }
    if (!gotA || !gotC) return true;   // cannot tell — leave the walk as it was
    return CompareFileTime(&a, &c) <= 0;
}

std::vector<std::string> AncestorExes(DWORD pid, const std::string& childExe) {
    {
        std::lock_guard<std::mutex> lk(g_ancestorMx);
        auto it = g_ancestorCache.find(pid);
        if (it != g_ancestorCache.end() && it->second.childExe == childExe) {
            return it->second.exes;
        }
    }

    std::vector<std::string> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        std::map<DWORD, DWORD> parentOf;
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do { parentOf[pe.th32ProcessID] = pe.th32ParentProcessID; }
            while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);

        DWORD cur = pid;
        for (int hop = 0; hop < 2; ++hop) {
            auto it = parentOf.find(cur);
            if (it == parentOf.end()) break;
            const DWORD par = it->second;
            if (!par || par == cur || par == GetCurrentProcessId()) break;
            if (!StartedNoLaterThan(par, cur)) break;   // recycled pid, not our parent
            const std::string pexe = ProcessExeName(par);
            if (pexe.empty()) break;
            out.push_back(pexe);
            cur = par;
        }
    }

    std::lock_guard<std::mutex> lk(g_ancestorMx);
    if (g_ancestorCache.size() > 64) g_ancestorCache.clear();
    g_ancestorCache[pid] = AncestorEntry{ childExe, out };
    return out;
}

NetworkExfilMonitor::MessagingVerdict AskPolicy(const std::string& exeLower) {
    NetworkExfilMonitor::MessagingVerdict v;
    if (g_cfg.messagingPolicy && !exeLower.empty()) {
        try { v = g_cfg.messagingPolicy(exeLower, g_cfg.username); } catch (...) {}
    }
    return v;
}

// Returns the verdict, and rewrites t.exe to the name that actually matched.
NetworkExfilMonitor::MessagingVerdict VerdictForTarget(TargetApp& t) {
    NetworkExfilMonitor::MessagingVerdict mv = AskPolicy(t.exe);
    if (mv.managed || t.exe.empty() || !t.pid) return mv;

    for (const auto& pexe : AncestorExes(t.pid, t.exe)) {
        if (pexe == t.exe) continue;
        NetworkExfilMonitor::MessagingVerdict pv = AskPolicy(pexe);
        if (pv.managed) {
            LogDbg("foreground window belongs to " + t.exe + ", whose ancestor " + pexe +
                   " IS a managed app — attributing the send to " + pexe);
            t.exe = pexe;
            return pv;
        }
    }
    return mv;
}

// ── Reading the composer ──────────────────────────────────────────────────

// mingw's import libraries carry only PART of the UI Automation IID set:
// IID_IUIAutomationValuePattern resolves (network_exfil_monitor.cpp has linked
// against it for as long as it has existed) but IID_IUIAutomationTextPattern
// does not, and the first CI build of this file died on exactly that undefined
// reference. The header DECLARES the symbol via DEFINE_GUID; nothing DEFINES it.
//
// Defined here instead of reaching for __uuidof: mingw does supply
// __CRT_UUID_DECL for this interface, so __uuidof would work today, but it
// would make linking depend on a header macro surviving in whichever MSYS2
// snapshot CI happens to pull. A literal GUID depends on nothing. The bytes are
// the interface's own identity and cannot drift — taken from mingw-w64's
// uiautomationclient.h, which matches the Windows SDK:
//     DEFINE_GUID(IID_IUIAutomationTextPattern, 0x32eba289, 0x3583, 0x42c9,
//                 0x9c,0x59, 0x3b,0x6d,0x9a,0x1e,0x9b,0x6a);
static const GUID kIID_IUIAutomationTextPattern =
    { 0x32eba289, 0x3583, 0x42c9, { 0x9c, 0x59, 0x3b, 0x6d, 0x9a, 0x1e, 0x9b, 0x6a } };

bool BoolProperty(IUIAutomationElement* el, PROPERTYID prop, bool& value) {
    if (!el) return false;
    VARIANT v; VariantInit(&v);
    bool got = false;
    if (SUCCEEDED(el->GetCurrentPropertyValue(prop, &v)) && v.vt == VT_BOOL) {
        value = (v.boolVal == VARIANT_TRUE);
        got = true;
    }
    VariantClear(&v);
    return got;
}

DWORD ElementProcessId(IUIAutomationElement* el) {
    if (!el) return 0;
    int pid = 0;
    if (SUCCEEDED(el->get_CurrentProcessId(&pid)) && pid > 0) return (DWORD)pid;
    return 0;
}

// "Can the user type here?" — the one question that separates a composer from
// the conversation above it. In a WebView2/Chromium app the chat history is a
// Document node exactly like the composer is, and it is READ-ONLY; that is the
// only reliable difference between them.
// `definite` separates "this node reports it is writable" from "this node did
// not say, so we guessed from focusability". The distinction is what tells a
// composer from a conversation pane: a Chromium history region is commonly
// keyboard-focusable — for scrolling and aria — and so passes the fallback,
// which is how a read-only conversation ends up looking exactly like a message
// box to everything downstream.
struct Editability {
    bool editable = false;
    bool definite = false;   // ValueIsReadOnly answered, and answered "writable"
};

Editability ElementEditability(IUIAutomationElement* el) {
    Editability e;
    bool readOnly = false;
    if (BoolProperty(el, UIA_ValueIsReadOnlyPropertyId, readOnly)) {
        e.editable = !readOnly;
        e.definite = e.editable;
        return e;
    }
    // No Value pattern at all — common for a contenteditable div. Fall back to
    // "the caret can go here", which is weaker and is recorded as such.
    bool focusable = false;
    if (BoolProperty(el, UIA_IsKeyboardFocusablePropertyId, focusable)) e.editable = focusable;
    return e;
}

bool ElementIsEditable(IUIAutomationElement* el) { return ElementEditability(el).editable; }

bool ElementHasFocus(IUIAutomationElement* el) {
    bool focused = false;
    return BoolProperty(el, UIA_HasKeyboardFocusPropertyId, focused) && focused;
}

// Pull text out of one element: ValuePattern for a plain edit, TextPattern for
// the rich/contenteditable composers that Electron and WinUI apps actually use.
std::string TextFromElement(IUIAutomationElement* el) {
    if (!el) return {};
    std::string out;

    IUnknown* pat = nullptr;
    if (SUCCEEDED(el->GetCurrentPattern(UIA_ValuePatternId, &pat)) && pat) {
        IUIAutomationValuePattern* vp = nullptr;
        pat->QueryInterface(IID_IUIAutomationValuePattern, (void**)&vp);
        pat->Release();
        if (vp) {
            BSTR v = nullptr;
            if (SUCCEEDED(vp->get_CurrentValue(&v)) && v) {
                out = WideToUtf8(v);
                SysFreeString(v);
            }
            vp->Release();
        }
    }
    if (!out.empty()) return out;

    pat = nullptr;
    if (SUCCEEDED(el->GetCurrentPattern(UIA_TextPatternId, &pat)) && pat) {
        IUIAutomationTextPattern* tp = nullptr;
        pat->QueryInterface(kIID_IUIAutomationTextPattern, (void**)&tp);
        pat->Release();
        if (tp) {
            IUIAutomationTextRange* range = nullptr;
            if (SUCCEEDED(tp->get_DocumentRange(&range)) && range) {
                BSTR t = nullptr;
                if (SUCCEEDED(range->GetText(-1, &t)) && t) {
                    out = WideToUtf8(t);
                    SysFreeString(t);
                }
                range->Release();
            }
            tp->Release();
        }
    }
    return out;
}

// What UI Automation thinks the focused thing IS. Two property reads, used
// only on a failed read: "no editable node" is a conclusion, not a diagnosis,
// and without this there is no way to tell a composer we failed to recognise
// from a focus that was never on the composer at all.
// Absent from some UIAutomation headers, same reason kIID_IUIAutomationTextPattern
// is spelled out above. 30005 is fixed by the UI Automation specification.
const PROPERTYID kNamePropertyId = 30005;

std::string ElementDescription(IUIAutomationElement* el) {
    if (!el) return "(none)";
    std::string out;
    VARIANT v; VariantInit(&v);
    if (SUCCEEDED(el->GetCurrentPropertyValue(UIA_ControlTypePropertyId, &v)) && v.vt == VT_I4)
        out += "type=" + std::to_string((int)v.lVal);
    VariantClear(&v);

    VariantInit(&v);
    if (SUCCEEDED(el->GetCurrentPropertyValue(kNamePropertyId, &v))
        && v.vt == VT_BSTR && v.bstrVal) {
        std::string n = WideToUtf8(v.bstrVal);
        if (n.size() > 40) n = n.substr(0, 40) + "...";
        if (!out.empty()) out += " ";
        out += "name='" + n + "'";
    }
    VariantClear(&v);
    return out.empty() ? "(opaque)" : out;
}

enum class ReadStatus {
    Ok,          // we read the composer
    EmptyBox,    // we found the composer; there was nothing in it
    NoComposer,  // UI Automation showed us no editable node at all
};

struct ComposerRead {
    ReadStatus  status = ReadStatus::NoComposer;
    std::string text;
    std::string source;   // for the log: which strategy found it
};

struct Candidate {
    std::string text;
    bool        focused  = false;
    bool        definite = false;   // see ElementEditability
};

// Every editable Edit/Document node under `root`. `sizeCap` of 0 means no cap;
// a non-zero cap discards anything larger, which is how the window-wide sweep
// avoids swallowing a conversation.
void CollectEditable(IUIAutomation* uia, IUIAutomationElement* root, size_t sizeCap,
                     std::vector<Candidate>& out, int& editableSeen,
                     long long deadlineMs = 0) {
    if (!uia || !root) return;
    for (int controlType : { UIA_EditControlTypeId, UIA_DocumentControlTypeId }) {
        if (deadlineMs && NowSteadyMs() >= deadlineMs) return;
        IUIAutomationCondition* cond = nullptr;
        VARIANT v; VariantInit(&v);
        v.vt = VT_I4; v.lVal = controlType;
        if (FAILED(uia->CreatePropertyCondition(UIA_ControlTypePropertyId, v, &cond)) || !cond) {
            VariantClear(&v);
            continue;
        }
        VariantClear(&v);
        IUIAutomationElementArray* arr = nullptr;
        root->FindAll(TreeScope_Descendants, cond, &arr);
        if (arr) {
            int n = 0; arr->get_Length(&n);
            for (int i = 0; i < n; ++i) {
                // Every property read below is a cross-process call. On a chat
                // window that is thousands of them, and the caller is holding a
                // keystroke while we make them.
                if (deadlineMs && NowSteadyMs() >= deadlineMs) break;
                IUIAutomationElement* el = nullptr;
                arr->GetElement(i, &el);
                if (!el) continue;
                const Editability ed = ElementEditability(el);
                if (ed.editable) {
                    ++editableSeen;
                    std::string t = TextFromElement(el);
                    if (!t.empty() && (sizeCap == 0 || t.size() <= sizeCap)) {
                        out.push_back({ t, ElementHasFocus(el), ed.definite });
                    }
                }
                el->Release();
            }
            arr->Release();
        }
        cond->Release();
    }
}

// The box the user is typing in is the focused element — true by construction,
// since they just pressed Enter into it. Everything here is anchored on that
// fact. Deliberately NOT "the longest Edit/Document in the window": in a
// WebView2/Chromium app the longest one is the chat history, and picking it
// blocks every send on something said last month while shipping the whole
// conversation off the endpoint as evidence.
ComposerRead ReadComposer(IUIAutomation* uia, HWND wnd, DWORD pid,
                          bool allowWindowSweep = true, long long deadlineMs = 0) {
    ComposerRead r;
    if (!uia) return r;

    int editableSeen = 0;

    // 1. The focused element itself.
    //
    // The focused element routinely belongs to a DIFFERENT process than the
    // window we resolved, and rejecting that outright threw away the only good
    // signal in exactly the apps this module exists for. WhatsApp for Windows is
    // a WebView2 app: the window belongs to WhatsApp.Root.exe and the composer
    // the user is typing in belongs to msedgewebview2.exe. Electron, the new
    // Teams and Outlook clients, and every other Chromium host are the same
    // shape — the renderer is a separate process by design.
    //
    // A cross-process focus is therefore treated as unverified rather than
    // wrong: it is still used, but only under the size cap, so the worst case is
    // that a very large read is declined instead of a conversation being
    // classified and shipped as evidence.
    IUIAutomationElement* focused = nullptr;
    if (SUCCEEDED(uia->GetFocusedElement(&focused)) && focused) {
        const DWORD fpid = ElementProcessId(focused);
        const bool sameProcess = (pid == 0 || fpid == 0 || fpid == pid);
        {
            const bool editable = ElementIsEditable(focused) && sameProcess;
            if (editable) ++editableSeen;
            std::string t = TextFromElement(focused);
            // Focus is the strongest evidence there is that this is the box the
            // user is typing in, so a focused node is trusted even when its
            // editability cannot be established — a web composer that reports
            // neither a Value pattern nor keyboard-focusability would otherwise
            // fail inspection open, which is the bug this module exists to fix.
            // The one shape never accepted on that basis is unverifiable AND the
            // size of a conversation, because that is what a chat history is.
            if (!t.empty() && (editable || t.size() <= g_cfg.maxFallbackTextBytes)) {
                focused->Release();
                r.status = ReadStatus::Ok;
                r.text   = t;
                r.source = editable ? "focused"
                                    : (sameProcess ? "focused-unverified"
                                                   : "focused-crossprocess");
                return r;
            }
            // 2. Focus may sit on a wrapper rather than the editable node.
            //    Search ITS subtree, which is still nowhere near the history.
            std::vector<Candidate> cands;
            CollectEditable(uia, focused, 0, cands, editableSeen, deadlineMs);
            if (!cands.empty()) {
                // Taking cands[0] when nothing reported focus was this module
                // breaking its own rule on the one path where it costs the most.
                // This sweep runs UNCAPPED, so the chat history is an eligible
                // candidate, and in document order it comes FIRST — above the
                // composer. The result is the conversation being classified in
                // place of the message: a card number sitting in the box is
                // reported "clean (Public)" and released, which is precisely the
                // leak this module exists to stop, wearing a passing verdict.
                //
                // Order of evidence, strongest first:
                const Candidate* pick = nullptr;
                const char* how = "";
                for (const auto& c : cands) if (c.focused) { pick = &c; how = "focused"; break; }
                if (!pick) {
                    // Exactly one node that POSITIVELY reports it is writable.
                    // A history pane reaches this list only through the
                    // focusability fallback, so it is never `definite`.
                    const Candidate* only = nullptr; int n = 0;
                    for (const auto& c : cands) if (c.definite) { ++n; only = &c; }
                    if (n == 1) { pick = only; how = "sole-writable"; }
                }
                if (!pick && cands.size() == 1) { pick = &cands[0]; how = "sole-candidate"; }

                if (pick) {
                    focused->Release();
                    r.status = ReadStatus::Ok; r.text = pick->text;
                    r.source = std::string("focused-subtree(") + std::to_string(cands.size()) +
                               "," + how + ")";
                    return r;
                }
                // Genuinely ambiguous. Fall through to the window sweep, which
                // is size-capped and demands an unambiguous answer — and if that
                // declines too, the send is reported as uninspectable rather
                // than silently blessed by whichever node sorted first.
                LogDbg("focused subtree offered " + std::to_string(cands.size()) +
                       " editable candidates, none focused and none uniquely writable"
                       " — not guessing");
            }
        }
        focused->Release();
    }

    // 3. Last resort: the whole window. Editable nodes only, size-capped, and
    //    it must be unambiguous — either exactly one candidate, or one that
    //    reports keyboard focus. Guessing here is how you read a conversation.
    // Step 3 walks EVERY descendant of the window. On WhatsApp for Windows that
    // measured seven seconds — with the user's Enter held the whole time, so the
    // watchdog released the send uninspected at 1.2s and the read eventually
    // came back reporting an empty box: empty because the message it was meant
    // to inspect had already gone. It is a fine thing for the background sampler
    // to do and an indefensible thing to do while holding a keystroke.
    if (wnd && allowWindowSweep) {
        IUIAutomationElement* root = nullptr;
        if (SUCCEEDED(uia->ElementFromHandle(wnd, &root)) && root) {
            std::vector<Candidate> cands;
            CollectEditable(uia, root, g_cfg.maxFallbackTextBytes, cands, editableSeen, deadlineMs);
            root->Release();
            const Candidate* pick = nullptr;
            for (const auto& c : cands) if (c.focused) { pick = &c; break; }
            if (!pick && cands.size() == 1) pick = &cands[0];
            if (pick) {
                r.status = ReadStatus::Ok; r.text = pick->text; r.source = "window-fallback";
                return r;
            }
            if (!cands.empty()) {
                LogDbg("ambiguous composer (" + std::to_string(cands.size()) +
                       " editable candidates, none focused) — not guessing");
            }
        }
    }

    r.status = (editableSeen > 0) ? ReadStatus::EmptyBox : ReadStatus::NoComposer;
    return r;
}

// The ONLY read allowed while a keystroke is held.
//
// Everything expensive lives in one call the hold path must never make:
// FindAll(TreeScope_Descendants). In a Chromium app the focused element's
// subtree is the whole document - the entire chat history - and enumerating it
// cross-process measured seven seconds on WhatsApp for Windows. It is a single
// blocking call, so no deadline can interrupt it: the budget expired before the
// first node was examined, which is why the read reported "no editable node"
// while editable nodes plainly existed.
//
// So this asks UI Automation exactly one question - what has focus, and what is
// in it - and accepts no for an answer. Finding the composer the hard way is
// the sampler's job, done between keystrokes when nothing is held.
ComposerRead ReadFocusedOnly(IUIAutomation* uia, DWORD pid) {
    ComposerRead r;
    if (!uia) return r;

    IUIAutomationElement* focused = nullptr;
    if (FAILED(uia->GetFocusedElement(&focused)) || !focused) return r;

    const DWORD fpid = ElementProcessId(focused);
    const bool sameProcess = (pid == 0 || fpid == 0 || fpid == pid);
    const bool editable = ElementIsEditable(focused) && sameProcess;
    std::string t = TextFromElement(focused);

    if (!t.empty() && (editable || t.size() <= g_cfg.maxFallbackTextBytes)) {
        r.status = ReadStatus::Ok;
        r.text   = t;
        r.source = editable ? "focused"
                            : (sameProcess ? "focused-unverified" : "focused-crossprocess");
    } else {
        r.status = editable ? ReadStatus::EmptyBox : ReadStatus::NoComposer;
        r.source = "focus:" + ElementDescription(focused);
    }
    focused->Release();
    return r;
}

// Locate the composer ELEMENT and keep it. Called by the sampler, never while a
// keystroke is held: this is the expensive path, and finding the box once and
// then reading its text every cycle is the difference between a sample that is
// a quarter of a second old and one that costs seven seconds to take.
IUIAutomationElement* FindComposerElement(IUIAutomation* uia, HWND wnd, DWORD pid,
                                          long long deadlineMs, int& editableSeen) {
    if (!uia) return nullptr;

    IUIAutomationElement* focused = nullptr;
    if (SUCCEEDED(uia->GetFocusedElement(&focused)) && focused) {
        const DWORD fpid = ElementProcessId(focused);
        if ((pid == 0 || fpid == 0 || fpid == pid) && ElementIsEditable(focused)) {
            ++editableSeen;
            return focused;   // caller releases
        }
        focused->Release();
    }

    if (!wnd) return nullptr;
    IUIAutomationElement* root = nullptr;
    if (FAILED(uia->ElementFromHandle(wnd, &root)) || !root) return nullptr;

    IUIAutomationElement* best = nullptr;
    for (int controlType : { UIA_EditControlTypeId, UIA_DocumentControlTypeId }) {
        if (best || (deadlineMs && NowSteadyMs() >= deadlineMs)) break;
        IUIAutomationCondition* cond = nullptr;
        VARIANT v; VariantInit(&v);
        v.vt = VT_I4; v.lVal = controlType;
        if (FAILED(uia->CreatePropertyCondition(UIA_ControlTypePropertyId, v, &cond)) || !cond) {
            VariantClear(&v);
            continue;
        }
        VariantClear(&v);
        IUIAutomationElementArray* arr = nullptr;
        root->FindAll(TreeScope_Descendants, cond, &arr);
        if (arr) {
            int n = 0; arr->get_Length(&n);
            for (int i = 0; i < n; ++i) {
                if (deadlineMs && NowSteadyMs() >= deadlineMs) break;
                IUIAutomationElement* el = nullptr;
                arr->GetElement(i, &el);
                if (!el) continue;
                const Editability ed = ElementEditability(el);
                if (ed.editable) ++editableSeen;
                // Only a node that POSITIVELY reports it is writable. A history
                // pane reaches the editable list through the focusability
                // fallback and is never `definite`, which is what keeps the
                // conversation from being sampled in place of the message.
                if (ed.editable && ed.definite) {
                    if (ElementHasFocus(el)) {          // unambiguous winner
                        if (best) best->Release();
                        best = el;
                        break;
                    }
                    if (!best) { best = el; continue; }
                }
                el->Release();
            }
            arr->Release();
        }
        cond->Release();
    }
    root->Release();
    return best;
}

// Chromium does not build an accessibility tree until something asks it to, and
// the ask that triggers it is the one that then returns nothing — the tree is
// populated a beat later. A single read therefore finds NO editable node on the
// first send into a WebView2/Electron app and finds the composer instantly on
// the second, which is how this module came to report "composer unreadable" for
// exactly the applications it exists to cover.
//
// Retried only for NoComposer. EmptyBox means the tree was there and the box was
// empty, which is the normal alert-mode result after the app has cleared it, and
// re-reading that would just burn the budget the watchdog is counting down.
ComposerRead ReadComposerRetry(IUIAutomation* uia, HWND wnd, DWORD pid, unsigned budgetMs,
                              bool allowWindowSweep = true) {
    const long long deadline = NowSteadyMs() + (long long)budgetMs;
    ComposerRead r;
    int attempts = 0;
    for (;;) {
        ++attempts;
        try { r = ReadComposer(uia, wnd, pid, allowWindowSweep, deadline); } catch (...) {}
        if (r.status != ReadStatus::NoComposer) break;
        if (NowSteadyMs() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
    }
    if (attempts > 1 && r.status != ReadStatus::NoComposer) {
        LogDbg("composer appeared on attempt " + std::to_string(attempts) +
               " (accessibility tree was still being built)");
    }
    return r;
}

// ── Releasing a held keystroke ────────────────────────────────────────────
// Replay as a genuine keypress. Windows stamps it LLKHF_INJECTED, which the
// hook checks first, so this cannot come back round to us.
void ReleaseKeystroke(bool withCtrl) {
    INPUT in[4] = {};
    int n = 0;
    if (withCtrl) {
        in[n].type = INPUT_KEYBOARD; in[n].ki.wVk = VK_CONTROL; ++n;
    }
    in[n].type = INPUT_KEYBOARD; in[n].ki.wVk = VK_RETURN; ++n;
    in[n].type = INPUT_KEYBOARD; in[n].ki.wVk = VK_RETURN;
    in[n].ki.dwFlags = KEYEVENTF_KEYUP; ++n;
    if (withCtrl) {
        in[n].type = INPUT_KEYBOARD; in[n].ki.wVk = VK_CONTROL;
        in[n].ki.dwFlags = KEYEVENTF_KEYUP; ++n;
    }
    SendInput(n, in, sizeof(INPUT));
}

// Exactly one resolver wins. Returns true to the winner.
bool ClaimDecision() { return !g_decisionResolved.exchange(true); }

void ResolveRelease(bool ctrl) {
    if (ClaimDecision()) {
        ReleaseKeystroke(ctrl);
        g_decisionPending.store(false);
    }
}

bool ResolveDrop() {
    if (ClaimDecision()) {
        g_decisionPending.store(false);
        return true;
    }
    return false;
}

// ── Events ────────────────────────────────────────────────────────────────

std::string EscapeJson(const std::string& s) {
    std::string out; out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    sprintf(buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

std::string NowIso8601() {
    SYSTEMTIME st; GetSystemTime(&st);
    char buf[64];
    sprintf(buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

std::string GenerateUuidLike() {
    GUID g;
    if (FAILED(CoCreateGuid(&g))) return "00000000-0000-0000-0000-000000000000";
    char buf[64];
    sprintf(buf, "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            (unsigned long)g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

void EmitEvent(const std::string& exe, DWORD pid, const std::string& action,
               const std::string& severity,
               const NetworkExfilMonitor::ClassifyResult& cls,
               const std::string& reason, const std::string& text) {
    if (!g_cfg.sendEvent) return;
    std::ostringstream j;
    j << "{";
    j << "\"event_id\":\""      << EscapeJson(GenerateUuidLike()) << "\",";
    j << "\"event_type\":\""    << "messaging"                    << "\",";
    j << "\"event_subtype\":\"" << "messaging_message"            << "\",";
    j << "\"agent_id\":\""      << EscapeJson(g_cfg.agentId)      << "\",";
    j << "\"source_type\":\""   << "agent"                        << "\",";
    j << "\"user_email\":\""    << EscapeJson(g_cfg.username + "@" + g_cfg.hostname) << "\",";
    j << "\"severity\":\""      << EscapeJson(severity)           << "\",";
    j << "\"action\":\""        << EscapeJson(action)             << "\",";
    j << "\"channel\":\""       << "MESSAGING"                    << "\",";
    j << "\"process_name\":\""  << EscapeJson(exe)                << "\",";
    j << "\"process_id\":"      << pid                            << ",";
    j << "\"destination\":\""   << EscapeJson(exe)                << "\",";
    j << "\"destination_type\":\"" << "messaging_app"             << "\",";
    j << "\"blocked\":"         << (action == "BLOCK" ? "true" : "false") << ",";
    if (!cls.category.empty()) {
        j << "\"classification_level\":\"" << EscapeJson(cls.category) << "\",";
        j << "\"classification_score\":"   << cls.score                << ",";
    }
    if (!cls.matchedRule.empty()) {
        // Plural, and an array: classification_rules_matched is the field the
        // server declares. The singular string this used to send was not on
        // EventCreate at all, so it was dropped at ingest and the rule that
        // fired never reached the event an analyst opens.
        j << "\"classification_rules_matched\":[\"" << EscapeJson(cls.matchedRule) << "\"],";
    }
    if (!cls.labels.empty()) {
        j << "\"classification_labels\":[";
        for (size_t i = 0; i < cls.labels.size(); ++i) {
            if (i) j << ",";
            j << "\"" << EscapeJson(cls.labels[i]) << "\"";
        }
        j << "],";
    }
    // The message itself is the evidence, exactly as the typed prompt is for the
    // browser extension: "an Aadhaar number went to WhatsApp" is not something an
    // analyst can triage without seeing what was actually about to be sent. It
    // travels the same authenticated channel and inherits the same retention and
    // read-redaction handling as every other captured content field.
    if (!text.empty()) {
        j << "\"content\":\"" << EscapeJson(text) << "\",";
    }
    if (!reason.empty()) {
        j << "\"description\":\"" << EscapeJson(reason) << "\",";
    }
    j << "\"timestamp\":\"" << NowIso8601() << "\"";
    j << "}";
    try { g_cfg.sendEvent(j.str()); } catch (...) {}
}

// A blocked send with no explanation looks like the app is broken, and a user
// who thinks the app is broken files a ticket or works around the agent. Own
// thread: MessageBox is modal and must never stall the worker.
void ShowBlockedNotice(const std::string& appExe, const std::string& what) {
    std::string body =
        "Sending this message was blocked by your organisation's data-loss policy.\n\n"
        "Detected: " + (what.empty() ? std::string("sensitive data") : what) + "\n"
        "Application: " + appExe + "\n\n"
        "The text is still in the message box. Remove the sensitive details to send it.";
    std::thread([body]() {
        MessageBoxA(nullptr, body.c_str(), "SeceoKnight DLP — Message blocked",
                    MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND);
    }).detach();
}

// ── Which detections count here ───────────────────────────────────────────
//
// The classifier reports everything it finds. Which of those findings should
// stop a CHAT MESSAGE is an operator's decision, not the classifier's, and the
// difference is not academic: a phone number is the single most ordinary thing
// anyone sends over WhatsApp, and the shared network-exfil table rates it
// Confidential because in an outbound curl it is a different proposition
// entirely. Blocking on it by default would train users to see the agent as
// broken within an afternoon.
//
// An empty selection means "everything the classifier considers sensitive",
// which is what the attachment path has always done.
NetworkExfilMonitor::ClassifyResult RestrictToTypes(
        const NetworkExfilMonitor::ClassifyResult& in,
        const std::vector<std::string>& selected) {
    if (selected.empty()) return in;

    NetworkExfilMonitor::ClassifyResult out;
    int best = 0, topSev = -1;
    for (const auto& label : in.labels) {
        bool wanted = false;
        for (const auto& s : selected) {
            if (EqualsIgnoreCase(label, s)) { wanted = true; break; }
        }
        if (!wanted) continue;
        out.labels.push_back(label);
        const int sev = NetworkExfilMonitor::TypeSeverity(label);
        if (sev > best)   best = sev;
        if (sev > topSev) { topSev = sev; out.matchedRule = label; }
    }
    switch (best) {
        case 3: out.category = "Restricted";   out.score = 0.95; break;
        case 2: out.category = "Confidential"; out.score = 0.85; break;
        case 1: out.category = "Internal";     out.score = 0.50; break;
        default: out.category = "Public";      out.score = 0.00; break;
    }
    return out;
}

// What was read, WITHOUT putting the message into a plaintext log on the
// endpoint. Length and character mix are enough to separate "we read the
// composer" from "we read the placeholder, or the wrong node entirely" — a
// 14-character all-letters read is "Type a message", not an Aadhaar number —
// and neither is the data this module exists to protect. The message itself
// still travels to the server on the event, where retention and read-redaction
// apply to it.
std::string TextProfile(const std::string& t) {
    size_t digits = 0, letters = 0;
    for (unsigned char c : t) {
        if (std::isdigit(c)) ++digits;
        else if (std::isalpha(c)) ++letters;
    }
    return std::to_string(t.size()) + " chars/" + std::to_string(digits) +
           " digits/" + std::to_string(letters) + " letters";
}

std::string DescribeLabels(const NetworkExfilMonitor::ClassifyResult& cls) {
    std::string what;
    for (const auto& l : cls.labels) {
        if (!what.empty()) what += ", ";
        what += l;
    }
    if (what.empty()) what = cls.matchedRule;
    return what;
}

bool IsSensitive(const NetworkExfilMonitor::ClassifyResult& cls) {
    const std::string cat = ToLowerAscii(cls.category);
    return cat == "confidential" || cat == "restricted";
}

std::string TrimText(std::string text) {
    if (text.size() > g_cfg.maxTextBytes) text.resize(g_cfg.maxTextBytes);
    const auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    auto b = std::find_if(text.begin(), text.end(), notSpace);
    auto e = std::find_if(text.rbegin(), text.rend(), notSpace).base();
    return (b < e) ? std::string(b, e) : std::string();
}

// Report an app whose composer UI Automation cannot see — once per app per
// cooldown. This is the difference between "the policy is working and nobody
// typed anything sensitive" and "this build of the app is invisible to us",
// and from a dashboard those two look identical without it.
void ReportUninspectable(const std::string& exe, DWORD pid) {
    const long long now = NowSteadyMs();
    {
        std::lock_guard<std::mutex> lk(g_uninspectableMx);
        auto it = g_uninspectableAt.find(exe);
        if (it != g_uninspectableAt.end() &&
            now - it->second < (long long)g_cfg.uninspectableCooldownSec * 1000) {
            return;
        }
        g_uninspectableAt[exe] = now;
    }
    NetworkExfilMonitor::ClassifyResult none;
    EmitEvent(exe, pid, "ALLOW", "medium", none,
              "Typed-message inspection could not read the composer in " + exe +
              " — messages in this app are being sent uninspected", "");
    LogWarn("composer unreadable in " + exe + " — typed messages are NOT being inspected");
}

// ── Worker ────────────────────────────────────────────────────────────────

// BLOCK mode. The keystroke is being held right now; every path through here
// must resolve it exactly once.
void DecideAndAct(IUIAutomation* uia, HWND wnd, DWORD pid, bool withCtrl,
                  const std::vector<std::string>& types, const std::string& exeHint) {
    const std::string exe = exeHint.empty() ? ProcessExeName(pid) : exeHint;

    // Two thirds of the hold budget: enough for Chromium to build its tree,
    // with the rest left for classification so the watchdog is not what ends
    // this decision.
    // What the sampler saw while the user was still typing.
    //
    // Asking UI Automation for the composer at the instant Enter is swallowed is
    // the worst possible moment to ask. The hook has just taken the keystroke,
    // the app's input is mid-flight, and the answer has to come back across a
    // process boundary from a Chromium renderer. On WhatsApp for Windows that
    // round trip took SEVEN SECONDS: the watchdog released every send
    // uninspected at 1.2s, and the read returned an empty box long afterwards —
    // empty because the message had already been sent while we waited for the
    // answer about it. No amount of retrying fixes a question asked at the wrong
    // time. The sampler asks it a fraction of a second earlier, while the app is
    // idle and replies immediately.
    std::string snap;
    {
        std::lock_guard<std::mutex> lk(g_snapMx);
        const long long age = g_snapAtMs ? (NowSteadyMs() - g_snapAtMs) : -1;
        // Widened from 5s. A sample only goes stale when the box changes, and
        // the box does not change while the user is looking at what they typed.
        if (g_snapPid == pid && !g_snapText.empty() && age >= 0 && age <= 15000)
            snap = TrimText(g_snapText);
    }

    std::string text, via;

    // If what the sampler already holds is damning, block on it and make no UI
    // Automation call at all. This path cannot time out, which makes it the only
    // one that reliably fires on an app whose accessibility tree answers too
    // slowly to be read while a keystroke is held. Spending the budget is
    // reserved for trying to CLEAR a message, never for condemning one.
    if (!snap.empty()) {
        NetworkExfilMonitor::ClassifyResult sraw;
        try { sraw = g_cfg.classify(snap, "messaging_message"); } catch (...) {}
        if (IsSensitive(RestrictToTypes(sraw, types))) { text = snap; via = "sampled"; }
    }

    if (text.empty()) {
        // Focused element only - no tree walk of any kind. Retried, because
        // Chromium builds its accessibility tree lazily and the request that
        // triggers the build is the one that returns nothing.
        const unsigned budget = (g_cfg.decisionTimeoutMs ? g_cfg.decisionTimeoutMs : 1200) * 2 / 3;
        const long long deadline = NowSteadyMs() + (long long)budget;
        const long long began = NowSteadyMs();
        ComposerRead read;
        int attempts = 0;
        for (;;) {
            ++attempts;
            try { read = ReadFocusedOnly(uia, pid); } catch (...) {}
            if (read.status == ReadStatus::Ok || NowSteadyMs() >= deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
        }
        text = TrimText(read.text);
        via  = read.source;

        if (text.empty()) {
            // How long it took, and what focus actually was. "No composer" is a
            // conclusion; this is the evidence behind it.
            LogInfo("focused read found nothing for " + exe + " after " +
                    std::to_string(NowSteadyMs() - began) + "ms / " +
                    std::to_string(attempts) + " attempt(s) — " + read.source);
        }

        // The live read is preferred because it is current — the sampler can be
        // up to one interval behind the last characters typed. But a stale
        // sample beats no inspection at all.
        if (text.empty() && !snap.empty()) { text = snap; via = "sampled-fallback"; }

        if (text.empty()) {
            // Nothing readable. Could be an empty box, could be an app whose composer
            // UI Automation cannot see. Either way the user's Enter is not ours to
            // keep — release it. See the header on why this fails open.
            LogInfo("no composer text for " + exe + " (" +
                   (read.status == ReadStatus::NoComposer ? "no editable node" : "empty box") +
                   ") — releasing keystroke");
            ResolveRelease(withCtrl);
            if (read.status == ReadStatus::NoComposer) ReportUninspectable(exe, pid);
            return;
        }
    }

    NetworkExfilMonitor::ClassifyResult raw;
    try { raw = g_cfg.classify(text, "messaging_message"); } catch (...) {}
    const NetworkExfilMonitor::ClassifyResult cls = RestrictToTypes(raw, types);

    if (!IsSensitive(cls)) {
        // Why this says more than "clean": RestrictToTypes reports "Public" both
        // when the classifier found nothing AND when it found something the
        // policy did not select, so the one line an operator reads for a block
        // that did not happen could not tell those apart. Alert mode has said
        // this since it shipped; block mode is the mode people actually roll
        // out, and it was the one flying blind.
        std::string dropped;
        if (!raw.labels.empty() && cls.labels.empty()) {
            dropped = " (classifier saw [" + DescribeLabels(raw) +
                      "], none of them selected in this policy)";
        }
        LogInfo("message clean (" + (cls.category.empty() ? std::string("unclassified") : cls.category) +
               ") in " + exe + " via " + via + " [" + TextProfile(text) + "]" +
               dropped + " — releasing");
        ResolveRelease(withCtrl);
        return;
    }

    const std::string what = DescribeLabels(cls);
    const std::string severity = (ToLowerAscii(cls.category) == "restricted") ? "critical" : "high";

    // Dropping the held Enter IS the block — but only if we still own it. If the
    // watchdog gave up on us first the message has already gone, and saying
    // "blocked" then would be a lie in the one record an analyst will trust.
    if (ResolveDrop()) {
        EmitEvent(exe, pid, "BLOCK", severity, cls,
                  "Blocked sensitive message in " + exe + " (" + cls.category + ")", text);
        LogWarn("MESSAGING_TEXT_BLOCKED exe=" + exe + " category=" + cls.category +
                " detected=[" + what + "] via=" + via);
        ShowBlockedNotice(exe, what);
        // The text stays in the box so the user can edit and resend.
    } else {
        EmitEvent(exe, pid, "ALERT", severity, cls,
                  "Sensitive message sent in " + exe + " (" + cls.category +
                  ") — inspection did not finish before the send was released", text);
        LogWarn("MESSAGING_TEXT_LATE exe=" + exe + " category=" + cls.category +
                " detected=[" + what + "] — verdict arrived after the watchdog released the keystroke");
    }
}

// ALERT mode. Nothing was held and nothing may be touched; the send has already
// happened or is happening. Report it.
void AuditAndAct(IUIAutomation* uia, HWND wnd, DWORD pid,
                 const std::vector<std::string>& types, const std::string& exeHint) {
    const std::string exe = exeHint.empty() ? ProcessExeName(pid) : exeHint;

    // We are racing the app's own handling of the Enter. Sometimes we win and
    // the text is still in the box; when we lose, the sampler's last snapshot is
    // what was there a moment ago.
    // Short budget here on purpose: alert mode is racing the app's own clearing
    // of the box, so a long retry reads an empty composer rather than a full
    // one. It is still worth one or two attempts, because they are also what
    // wakes the accessibility tree for the sends that follow.
    ComposerRead read = ReadComposerRetry(uia, wnd, pid, 200);
    std::string text = TrimText(read.text);
    std::string via  = read.source;

    // Why the snapshot age is reported even when it was not needed: alert mode
    // is the mode an operator switches to FIRST, to see whether any of this
    // works before they let it touch anything. If its only visible output is an
    // event, then "no event" means both "nothing sensitive was sent" and "this
    // never read a single message", and there is no way to tell those apart
    // from a dashboard. Every path below therefore says what it did.
    std::string snapshotNote = "no snapshot";
    if (text.empty()) {
        std::lock_guard<std::mutex> lk(g_snapMx);
        const long long age = g_snapAtMs ? (NowSteadyMs() - g_snapAtMs) : -1;
        if (g_snapPid == pid && !g_snapText.empty() && age >= 0 && age <= 5000) {
            text = TrimText(g_snapText);
            via  = "sampled";
            snapshotNote = "snapshot " + std::to_string(age) + "ms old";
        } else if (!g_snapText.empty()) {
            snapshotNote = (g_snapPid != pid)
                ? "snapshot belongs to another process"
                : "snapshot too old (" + std::to_string(age) + "ms)";
        }
    }
    if (text.empty()) {
        LogInfo("alert: nothing to inspect in " + exe + " (" +
               (read.status == ReadStatus::NoComposer ? "no editable node"
                                                      : "empty box") +
               ", " + snapshotNote + ")");
        if (read.status == ReadStatus::NoComposer) ReportUninspectable(exe, pid);
        return;
    }

    // Enter pressed twice, or a send that left the text in place — either way
    // the operator does not need the same message again.
    {
        const long long now = NowSteadyMs();
        std::lock_guard<std::mutex> lk(g_snapMx);
        if (text == g_lastAuditText && now - g_lastAuditMs < 10000) {
            LogDbg("alert: same text already reported for " + exe + " — suppressed");
            return;
        }
        g_lastAuditText = text;
        g_lastAuditMs   = now;
    }

    NetworkExfilMonitor::ClassifyResult raw;
    try { raw = g_cfg.classify(text, "messaging_message"); } catch (...) {}
    const NetworkExfilMonitor::ClassifyResult cls = RestrictToTypes(raw, types);
    if (!IsSensitive(cls)) {
        // The selected-types filter is the difference an operator most often
        // needs to see: the classifier found something, and the policy said it
        // did not count here.
        std::string dropped;
        if (!raw.labels.empty() && cls.labels.empty()) {
            dropped = " (classifier saw [" + DescribeLabels(raw) +
                      "], none of them selected in this policy)";
        }
        LogInfo("alert: message clean in " + exe + " via " + via + " [" + TextProfile(text) + "] — " +
               (cls.category.empty() ? std::string("unclassified") : cls.category) +
               dropped);
        return;
    }

    const std::string what = DescribeLabels(cls);
    const std::string severity = (ToLowerAscii(cls.category) == "restricted") ? "critical" : "high";
    EmitEvent(exe, pid, "ALERT", severity, cls,
              "Sensitive message sent in " + exe + " (" + cls.category +
              ") — policy is in alert mode, the message was not stopped", text);
    LogWarn("MESSAGING_TEXT_ALERT exe=" + exe + " category=" + cls.category +
            " detected=[" + what + "] via=" + via);
}

// UI Automation, acquired lazily and retried for the life of the process.
//
// This used to be one CoCreateInstance at thread start. If it failed — COM not
// ready yet at boot, a transient RPC fault, the service starting before anyone
// has logged into the desktop — the pointer stayed null forever and every
// managed send took the silent release below. Typed-message inspection was
// then simply off until somebody restarted the agent, and the only evidence
// was a single warning thousands of lines earlier in the log. From the outside
// it looked exactly like the feature had never been built: the hook traced the
// keypress, and then nothing at all happened, every time, for days.
//
// A retry costs one failed CoCreateInstance. Not retrying costs the feature.
bool EnsureUia(IUIAutomation*& uia, long long& lastComplaintMs, bool complain = true) {
    if (uia) return true;

    const HRESULT hr = CoCreateInstance(CLSID_CUIAutomation, nullptr,
                                        CLSCTX_INPROC_SERVER, IID_IUIAutomation,
                                        (void**)&uia);
    if (uia) {
        LogInfo("UIAutomation acquired — the message box can be read");
        lastComplaintMs = 0;
        return true;
    }

    if (complain) {
        const long long now = NowSteadyMs();
        if (!lastComplaintMs || now - lastComplaintMs > 60000) {
            lastComplaintMs = now;
            char hex[16];
            snprintf(hex, sizeof(hex), "0x%08lX", (unsigned long)hr);
            LogWarn(std::string("UIAutomation unavailable (hr=") + hex + ") — the message "
                    "box cannot be read, so typed messages are NOT being inspected. "
                    "Retrying on every send.");
        }
    }
    return false;
}

void WorkerThread() {
    // MTA: UI Automation is called from here and nowhere else on this thread.
    HRESULT hrCom = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool comOk = SUCCEEDED(hrCom);

    if (!comOk) {
        LogWarn("COM could not be initialised on the inspection thread — typed "
                "messages cannot be inspected on this agent run");
    }

    IUIAutomation* uia = nullptr;
    long long uiaComplainedAt = 0;
    if (comOk) EnsureUia(uia, uiaComplainedAt);

    std::map<std::string, long long> lastProbeAt;

    while (!g_stop.load()) {
        HWND  wnd   = nullptr;
        DWORD pid   = 0;
        bool  ctrl  = false;
        bool  audit = false;
        std::string exe;
        std::vector<std::string> types;
        {
            std::unique_lock<std::mutex> lk(g_mx);
            g_cv.wait_for(lk, std::chrono::milliseconds(200),
                          [] { return g_pendingWork || g_stop.load(); });
            if (g_stop.load()) break;
        }
        {
            std::string probeExe;
            bool probeManaged = false, probeInspect = false, probeBlock = false;
            {
                std::lock_guard<std::mutex> lk(g_probeMx);
                if (g_probeReady) {
                    probeExe     = g_probeExe;
                    probeManaged = g_probeManaged;
                    probeInspect = g_probeInspect;
                    probeBlock   = g_probeBlock;
                    g_probeReady = false;
                }
            }
            // Per-app, so testing one app never silences the next. Held in the
            // worker because the hook must not own a container it might grow.
            if (!probeExe.empty()) {
                const long long now = NowSteadyMs();
                auto it = lastProbeAt.find(probeExe);
                if (it == lastProbeAt.end() || now - it->second > 30000) {
                    lastProbeAt[probeExe] = now;
                    if (probeExe == "(unknown)") {
                        LogInfo("send key pressed, but the foreground window could not be "
                                "attributed to a process — nothing to inspect");
                    } else if (!probeManaged) {
                        LogInfo("send key pressed in " + probeExe +
                                " — NOT in the policy's managed app list, so it is being ignored. "
                                "If this is the app you meant, add " + probeExe + " to it.");
                    } else if (!probeInspect) {
                        LogInfo("send key pressed in " + probeExe +
                                " — it IS a managed app, but typed-message inspection is off "
                                "for it (tick \"Also inspect typed messages\" on the policy)");
                    } else {
                        LogInfo("send key pressed in " + probeExe + " — managed, inspecting (" +
                                std::string(probeBlock ? "block" : "alert") + " mode)");
                    }
                }
            }
        }
        {
            std::unique_lock<std::mutex> lk(g_mx);
            if (!g_pendingWork) continue;
            wnd   = g_pendingWnd;
            pid   = g_pendingPid;
            exe   = g_pendingExe;
            ctrl  = g_pendingCtrl;
            audit = g_pendingAudit;
            types = g_pendingTypes;
            g_pendingWork = false;
        }

        try {
            const bool haveUia = comOk && EnsureUia(uia, uiaComplainedAt);
            if (audit) {
                if (haveUia) AuditAndAct(uia, wnd, pid, types, exe);
            } else if (haveUia) {
                DecideAndAct(uia, wnd, pid, ctrl, types, exe);
            } else {
                // We swallowed a keystroke we now cannot adjudicate. Give it back —
                // and SAY so. Releasing in silence is what made this failure
                // indistinguishable from the feature not existing: the hook wrote
                // "managed, inspecting", and then no line was ever written again.
                LogWarn("released the Enter in " + exe + " UNINSPECTED — UI Automation "
                        "is not available, so the message was sent unchecked");
                ResolveRelease(ctrl);
            }
        } catch (...) {
            LogWarn("decision threw — releasing keystroke");
            if (!audit) { try { ResolveRelease(ctrl); } catch (...) {} }
        }
    }

    if (uia) uia->Release();
    if (comOk) CoUninitialize();
}

// ── Watchdog ──────────────────────────────────────────────────────────────
// The worker cannot time itself out: when UI Automation wedges, the worker is
// inside that call. Somebody outside it has to give the keystroke back.
void WatchdogThread() {
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (g_decisionResolved.load()) continue;
        const long long started = g_holdStartMs.load();
        if (!started) continue;
        if (NowSteadyMs() - started < (long long)g_cfg.decisionTimeoutMs) continue;

        const bool ctrl = g_holdCtrl.load();
        if (ClaimDecision()) {
            ReleaseKeystroke(ctrl);
            g_decisionPending.store(false);
            LogWarn("inspection exceeded " + std::to_string(g_cfg.decisionTimeoutMs) +
                    "ms — keystroke released UNINSPECTED (the message was sent)");
        }
    }
}

// ── Sampler ───────────────────────────────────────────────────────────────
// Alert mode only. Keeps the last thing seen in the composer of a managed app,
// because alert mode never holds the Enter and so has nothing left to read by
// the time it is asked.
void SamplerThread() {
    HRESULT hrCom = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool comOk = SUCCEEDED(hrCom);

    IUIAutomation* uia = nullptr;
    long long uiaComplainedAt = 0;

    // The composer, found once and then polled. See the loop below.
    IUIAutomationElement* composer = nullptr;
    DWORD     composerPid      = 0;
    long long lastFindMs       = 0;
    long long findComplainedAt = 0;

    const unsigned interval = g_cfg.sampleIntervalMs ? g_cfg.sampleIntervalMs : 250;
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        if (g_stop.load()) break;
        if (!comOk) continue;

        try {
            TargetApp t = ResolveForegroundApp();
            if (t.exe.empty() || !g_cfg.messagingPolicy) continue;

            const NetworkExfilMonitor::MessagingVerdict mv = VerdictForTarget(t);
            if (!mv.managed && composer) {
                composer->Release(); composer = nullptr; composerPid = 0;
            }
            // Block mode used to be excluded here, on the reasoning that it reads
            // at send time and did not want a sampler second-guessing it. That
            // reasoning was backwards: block mode is the one mode that reads
            // while holding the user's keystroke, so it is the mode that can
            // least afford to ask a slow question. It now decides on what this
            // thread saw a moment earlier — see DecideAndAct.
            if (!mv.managed || !mv.inspectMessages) continue;

            // Acquired here rather than at thread start, and quietly: the worker
            // complains at the moment it matters — a real send. A sampler that
            // cannot see the tree has nothing worth saying twice a second.
            if (!EnsureUia(uia, uiaComplainedAt, false)) continue;

            // Focus moved to another app, or another instance of one. The
            // element we were holding belongs to a window nobody types into now.
            if (composer && t.pid != composerPid) {
                composer->Release(); composer = nullptr; composerPid = 0;
            }

            // Locate it the expensive way ONCE. This is the FindAll over a
            // Chromium document that measured seven seconds — affordable here,
            // where nothing is held, and nowhere else. Rate-limited so a window
            // with no composer at all is not re-searched four times a second.
            if (!composer) {
                const long long now = NowSteadyMs();
                if (lastFindMs && now - lastFindMs < 3000) continue;
                lastFindMs = now;
                int seen = 0;
                composer = FindComposerElement(uia, t.wnd, t.pid, now + 8000, seen);
                if (composer) {
                    composerPid = t.pid;
                    LogInfo("sampler locked onto the composer in " + t.exe + " after " +
                            std::to_string(NowSteadyMs() - now) + "ms");
                } else {
                    if (!findComplainedAt || now - findComplainedAt > 60000) {
                        findComplainedAt = now;
                        LogWarn("sampler cannot find a composer in " + t.exe + " (" +
                                std::to_string(seen) + " editable node(s) seen in " +
                                std::to_string(NowSteadyMs() - now) + "ms) — typed "
                                "messages in this app cannot be inspected");
                    }
                    continue;
                }
            }

            // The cheap part, every cycle: one element, one or two property
            // reads. This is what makes the sample a quarter of a second old
            // rather than seven seconds old.
            std::string text;
            try { text = TrimText(TextFromElement(composer)); } catch (...) {}

            std::lock_guard<std::mutex> lk(g_snapMx);
            // Stored even when empty. A sample that is never cleared would block
            // an innocent message on a card number sent five minutes ago.
            g_snapText  = text;
            g_snapPid   = t.pid;
            g_snapAtMs  = NowSteadyMs();
        } catch (...) {}
    }

    if (composer) composer->Release();
    if (uia) uia->Release();
    if (comOk) CoUninitialize();
}

// ── The hook ──────────────────────────────────────────────────────────────

LRESULT CALLBACK KeyProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode != HC_ACTION) return CallNextHookEx(g_hook, nCode, wParam, lParam);

    KBDLLHOOKSTRUCT* k = (KBDLLHOOKSTRUCT*)lParam;
    if (!k || k->vkCode != VK_RETURN) {
        return CallNextHookEx(g_hook, nCode, wParam, lParam);
    }
    // Our own replay. Must be first: everything below would otherwise re-hold it.
    if (k->flags & LLKHF_INJECTED) {
        return CallNextHookEx(g_hook, nCode, wParam, lParam);
    }

    const bool isDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
    const bool isUp   = (wParam == WM_KEYUP   || wParam == WM_SYSKEYUP);

    // Swallow the keyup belonging to a keydown we already took.
    if (isUp && g_decisionPending.load()) return 1;
    if (!isDown) return CallNextHookEx(g_hook, nCode, wParam, lParam);

    // Shift+Enter is "new line" in every one of these apps — never a send.
    if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
        return CallNextHookEx(g_hook, nCode, wParam, lParam);
    }
    // One decision at a time; a second Enter goes straight through.
    if (g_decisionPending.load()) {
        return CallNextHookEx(g_hook, nCode, wParam, lParam);
    }

    // VerdictForTarget can walk the process tree, which is the one thing in this
    // hook that is not a pointer chase. It is bounded and, in practice, already
    // done: the sampler resolves the foreground app every 500ms and fills the
    // same cache, so by the time anyone presses Enter the answer is a map
    // lookup. A cold miss costs one process snapshot — single-digit
    // milliseconds against a LowLevelHooksTimeout of 300.
    TargetApp t = ResolveForegroundApp();
    const NetworkExfilMonitor::MessagingVerdict mv = VerdictForTarget(t);

    // Publish the trace BEFORE any early return, for managed and unmanaged apps
    // alike. The previous version only traced apps the policy did not cover, so
    // "the hook is installed and nothing whatsoever happens when I press Enter"
    // had two indistinguishable causes — the app was not matched, or the hook
    // was never reaching this line at all — and no way to tell them apart.
    // Unresolvable foreground windows report as "(unknown)" rather than
    // returning in silence, because that is a diagnosis too.
    {
        std::lock_guard<std::mutex> lk(g_probeMx);
        g_probeExe     = t.exe.empty() ? std::string("(unknown)") : t.exe;
        g_probeManaged = mv.managed;
        g_probeInspect = mv.inspectMessages;
        g_probeBlock   = mv.block;
        g_probeReady   = true;
    }
    g_cv.notify_one();

    if (t.exe.empty()) return CallNextHookEx(g_hook, nCode, wParam, lParam);
    if (!mv.managed || !mv.inspectMessages) {
        return CallNextHookEx(g_hook, nCode, wParam, lParam);
    }

    const bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;

    // ALERT: never touch input. Ask the worker to record what was sent and let
    // the keystroke through untouched.
    if (!mv.block) {
        {
            std::lock_guard<std::mutex> lk(g_mx);
            if (!g_pendingWork) {          // worker busy? drop this one, never queue
                g_pendingWnd   = t.wnd;
                g_pendingPid   = t.pid;
                g_pendingExe   = t.exe;
                g_pendingCtrl  = false;
                g_pendingAudit = true;
                g_pendingTypes = mv.messageDataTypes;
                g_pendingWork  = true;
            }
        }
        g_cv.notify_one();
        return CallNextHookEx(g_hook, nCode, wParam, lParam);
    }

    // BLOCK: hold it. Order matters — the watchdog acts on g_decisionResolved,
    // so that flag is set last, once everything it will read is in place.
    {
        std::lock_guard<std::mutex> lk(g_mx);
        g_pendingWnd   = t.wnd;
        g_pendingPid   = t.pid;
        g_pendingExe   = t.exe;
        g_pendingCtrl  = ctrl;
        g_pendingAudit = false;
        g_pendingTypes = mv.messageDataTypes;
        g_pendingWork  = true;
    }
    g_holdCtrl.store(ctrl);
    g_holdStartMs.store(NowSteadyMs());
    g_decisionPending.store(true);
    g_decisionResolved.store(false);
    g_cv.notify_one();

    return 1;   // hold it; the worker or the watchdog resolves it
}

void HookThread() {
    g_hookThread = GetCurrentThreadId();
    g_hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyProc, GetModuleHandle(nullptr), 0);
    if (!g_hook) {
        LogWarn("SetWindowsHookEx(WH_KEYBOARD_LL) failed err=" +
                std::to_string((unsigned long)GetLastError()));
        g_running.store(false);
        return;
    }
    LogInfo("typed-message keyboard hook installed");

    // A low-level hook is only serviced while its installing thread pumps
    // messages. No window, no timers — just the pump.
    MSG msg;
    while (!g_stop.load() && GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_hook);
    g_hook = nullptr;
    LogInfo("typed-message keyboard hook removed");
}

} // namespace

bool Start(const Config& cfg) {
    if (g_running.load()) return true;
    if (!cfg.classify || !cfg.sendEvent || !cfg.log || !cfg.messagingPolicy) {
        return false;
    }
    g_cfg = cfg;

    // A one-line proof, on every start, that the classifier this module was
    // handed actually detects something. Without it, "the classifier is not
    // wired up" and "we read the wrong box" produce the identical outcome —
    // every message reported clean — and the only way to tell them apart was to
    // find someone willing to type a card number into a chat app and then read
    // a log. The literal is Visa's published test PAN; it is a checksum-valid
    // number that belongs to nobody.
    try {
        const NetworkExfilMonitor::ClassifyResult probe =
            g_cfg.classify("card 4111 1111 1111 1111 end", "messaging_message");
        if (probe.labels.empty()) {
            LogWarn("classifier self-test FAILED — a known-good test card was not detected. "
                    "Every typed message will be reported clean until this is fixed.");
        } else {
            LogInfo("classifier self-test: detected [" + DescribeLabels(probe) + "] as " +
                    (probe.category.empty() ? std::string("(no category)") : probe.category));
        }
    } catch (...) {
        LogWarn("classifier self-test THREW — typed-message inspection cannot classify anything");
    }

    g_stop.store(false);
    g_decisionPending.store(false);
    g_decisionResolved.store(true);
    g_holdStartMs.store(0);
    g_running.store(true);

    g_workerObj     = std::thread(WorkerThread);
    g_watchdogObj   = std::thread(WatchdogThread);
    g_samplerObj    = std::thread(SamplerThread);
    g_hookThreadObj = std::thread(HookThread);

    // Give the hook a moment to report failure so Start() reflects reality.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    return g_running.load();
}

void Stop() {
    if (!g_running.load()) return;
    g_stop.store(true);
    if (g_hookThread) PostThreadMessage(g_hookThread, WM_QUIT, 0, 0);
    g_cv.notify_all();
    if (g_hookThreadObj.joinable()) g_hookThreadObj.join();
    if (g_workerObj.joinable())     g_workerObj.join();
    if (g_watchdogObj.joinable())   g_watchdogObj.join();
    if (g_samplerObj.joinable())    g_samplerObj.join();

    // Both resolvers have now exited. If a keystroke was still held when the
    // stop came, nobody is left to give it back — and quietly eating the user's
    // Enter on agent shutdown is the same failure this module refuses
    // everywhere else, just at a moment nobody would think to test.
    ResolveRelease(g_holdCtrl.load());

    g_running.store(false);
}

bool IsRunning() { return g_running.load(); }

} // namespace MessagingTextMonitor
