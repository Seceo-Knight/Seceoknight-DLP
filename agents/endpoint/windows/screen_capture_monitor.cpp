#include "screen_capture_monitor.h"
#include <tlhelp32.h>
#include <iostream>
#include <algorithm>
#include <set>
#include <chrono>

// Static members
ScreenCaptureMonitor* ScreenCaptureMonitor::s_instance = nullptr;
HHOOK ScreenCaptureMonitor::s_keyboardHook = NULL;

const std::vector<std::string> ScreenCaptureMonitor::CAPTURE_PROCESSES = {
    "SnippingTool.exe", "ScreenClippingHost.exe", "ScreenSketch.exe",
    "Greenshot.exe", "ShareX.exe", "LightShot.exe", "lightshot.exe",
    "Snagit32.exe", "Snagit.exe", "obs64.exe", "obs32.exe",
    "CamtasiaStudio.exe", "Bandicam.exe", "ScreenToGif.exe",
    "FlameShot.exe", "PicPick.exe", "FastStone.exe"
};

ScreenCaptureMonitor::ScreenCaptureMonitor(CaptureCallback callback, LogCallback logger, ClassifyCallback classifier)
    : m_callback(std::move(callback)), m_logger(std::move(logger)), m_classifier(std::move(classifier)) {
    s_instance = this;
}

ScreenCaptureMonitor::~ScreenCaptureMonitor() {
    Stop();
    s_instance = nullptr;
}

bool ScreenCaptureMonitor::Start() {
    if (m_running) return true;
    m_running = true;
    m_hookThread    = std::thread(&ScreenCaptureMonitor::HookThread, this);
    m_processThread = std::thread(&ScreenCaptureMonitor::ProcessMonitorThread, this);
    m_scanThread    = std::thread(&ScreenCaptureMonitor::ContentScanThread, this);
    if (m_logger) m_logger("INFO",
        "Screen capture monitor started (keyboard hook + content scanner + process monitor)");
    return true;
}

void ScreenCaptureMonitor::Stop() {
    m_running = false;
    // Unhook
    if (s_keyboardHook) {
        UnhookWindowsHookEx(s_keyboardHook);
        s_keyboardHook = NULL;
    }
    // Post quit to hook thread's message loop
    if (m_hookThread.joinable()) {
        PostThreadMessage(GetThreadId((HANDLE)m_hookThread.native_handle()), WM_QUIT, 0, 0);
        m_hookThread.join();
    }
    if (m_processThread.joinable()) m_processThread.join();
    if (m_scanThread.joinable())    m_scanThread.join();
}

bool ScreenCaptureMonitor::IsRunning() const { return m_running; }

std::string ScreenCaptureMonitor::GetActiveWindowTitle() {
    char title[512] = {0};
    HWND hwnd = GetForegroundWindow();
    if (hwnd) GetWindowTextA(hwnd, title, sizeof(title));
    return std::string(title);
}

std::string ScreenCaptureMonitor::GetForegroundProcessName() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return "unknown";
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid) return "unknown";
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return "unknown";
    char name[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameA(hProc, 0, name, &size);
    CloseHandle(hProc);
    std::string path(name);
    auto pos = path.rfind('\\');
    return pos != std::string::npos ? path.substr(pos + 1) : path;
}

std::string ScreenCaptureMonitor::GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    t += 19800;
    struct tm tm_buf;
    gmtime_s(&tm_buf, &t);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d+05:30",
             tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    return buf;
}

void ScreenCaptureMonitor::TerminateProcessByName(const std::string& processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    std::string targetLower = processName;
    std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::tolower);

    if (Process32First(hSnap, &pe)) {
        do {
            std::string procLower = pe.szExeFile;
            std::transform(procLower.begin(), procLower.end(), procLower.begin(), ::tolower);
            if (procLower == targetLower) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 1);
                    CloseHandle(hProc);
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

void ScreenCaptureMonitor::HandleCaptureAttempt(const std::string& method) {
    // EVENT-ONLY: this used to also clear the clipboard and show its own
    // MessageBox. The keyboard hook now handles enforcement (clipboard +
    // popup), so doing it again here would produce TWO popups for every
    // blocked screenshot. We only emit the event for the dashboard.

    std::string windowTitle = GetActiveWindowTitle();
    std::string processName = GetForegroundProcessName();

    bool isSensitive   = m_screenIsSensitive.load();
    std::string classification = isSensitive ? "Restricted" : "Public";
    std::string action         = isSensitive ? "Block"      : "Allow";

    char username[256] = {0};
    DWORD userSize = sizeof(username);
    GetUserNameA(username, &userSize);

    ScreenCaptureEvent event;
    event.method                = method;
    event.processName           = processName;
    event.activeWindow          = windowTitle;
    event.user                  = username;
    event.classification        = classification;
    event.containsSensitiveData = isSensitive;
    event.actionTaken           = action;
    event.timestamp             = GetTimestamp();

    if (m_callback) m_callback(event);
}

/*
 * FLAG-DRIVEN KEYBOARD HOOK
 *
 * A dedicated background thread (ContentScanThread) continuously OCR-
 * classifies the foreground window and maintains m_screenIsSensitive.
 * The keyboard hook is now extremely fast:
 *
 *   * If m_screenIsSensitive is FALSE → return CallNextHookEx and let
 *     Windows take the screenshot normally. The user sees no difference
 *     from an unmanaged machine.
 *
 *   * If m_screenIsSensitive is TRUE  → return 1 to swallow the key,
 *     spawn a background thread that clears the clipboard and shows
 *     the "blocked" popup, and emit an event.
 *
 * This fixes the previous "block-first-OCR-second" design which
 * swallowed EVERY screenshot (including perfectly normal ones) and
 * tried to simulate the allowed path with a programmatic BitBlt —
 * a path that users perceived as a broken/blocked screenshot.
 */
LRESULT CALLBACK ScreenCaptureMonitor::LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode != HC_ACTION || !s_instance) {
        return CallNextHookEx(s_keyboardHook, nCode, wParam, lParam);
    }

    if (wParam != WM_KEYDOWN && wParam != WM_SYSKEYDOWN) {
        return CallNextHookEx(s_keyboardHook, nCode, wParam, lParam);
    }

    KBDLLHOOKSTRUCT* pKey = (KBDLLHOOKSTRUCT*)lParam;

    // Identify the capture key combo, if any.
    bool isPrintScreen = (pKey->vkCode == VK_SNAPSHOT);
    bool isAltPrint    = isPrintScreen && ((pKey->flags & LLKHF_ALTDOWN) != 0);
    bool isWinShiftS   = false;
    if (pKey->vkCode == 'S') {
        bool winDown   = (GetAsyncKeyState(VK_LWIN) & 0x8000) != 0 ||
                         (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0;
        bool shiftDown = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        isWinShiftS = winDown && shiftDown;
    }

    if (!isPrintScreen && !isWinShiftS) {
        return CallNextHookEx(s_keyboardHook, nCode, wParam, lParam);
    }

    std::string method = isAltPrint    ? "alt_printscreen" :
                         isPrintScreen ? "printscreen"     :
                                         "win_shift_s";

    // Decision: block if EITHER the scanner currently says sensitive
    // OR a previous block is still in its "grace" state. The grace flag
    // is cleared by the scanner the moment it re-classifies a real
    // (non-transient) foreground window, so it covers the popup-race
    // window without unfairly blocking screenshots taken AFTER the user
    // has moved focus to a genuinely non-sensitive window.
    bool sensitive   = s_instance->m_screenIsSensitive.load();
    bool grace       = s_instance->m_blockGraceActive.load();
    long long nowCheckMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    if (!sensitive && !grace) {
        // Normal content on screen — let Windows handle the screenshot
        // exactly as it would on an unmanaged machine.
        if (s_instance->m_logger) s_instance->m_logger("INFO",
            "SCREEN_CAPTURE_ALLOWED: " + method + " — no sensitive data on screen");

        // Emit the event asynchronously so we don't slow down the hook.
        std::thread([method]() {
            if (s_instance) s_instance->HandleCaptureAttempt(method);
        }).detach();

        return CallNextHookEx(s_keyboardHook, nCode, wParam, lParam);
    }

    // Sensitive content is on screen — swallow the key and warn the user.
    const char* reason = sensitive ? "sensitive content currently on screen"
                                   : "block grace pending re-classification";
    if (s_instance->m_logger) s_instance->m_logger("WARNING",
        "SCREEN_CAPTURE_BLOCKED: " + method + " — " + reason);

    // Activate the grace flag. Cleared by ContentScanThread on its next
    // real (non-transient) classification cycle.
    s_instance->m_blockGraceActive.store(true);

    // Cooldown — only one popup per 3s. Without this, mashing PrintScreen
    // produces a stack of dialogs and gives the impression that even
    // normal screenshots are being blocked.
    long long nowMs = nowCheckMs;
    long long lastMs = s_instance->m_lastPopupMs.load();
    bool showPopup = (nowMs - lastMs) > 3000;
    if (showPopup) {
        s_instance->m_lastPopupMs.store(nowMs);
    }

    std::thread([method, showPopup]() {
        if (!s_instance) return;

        // Defensive: clear clipboard in case anything slipped through.
        if (OpenClipboard(NULL)) { EmptyClipboard(); CloseClipboard(); }

        if (showPopup) {
            HWND fgWnd = GetForegroundWindow();
            if (fgWnd) {
                DWORD fgThread  = GetWindowThreadProcessId(fgWnd, NULL);
                DWORD curThread = GetCurrentThreadId();
                AttachThreadInput(curThread, fgThread, TRUE);
                MessageBoxA(fgWnd,
                    "Sensitive content detected. Screenshot blocked.\n\n"
                    "CyberSentinel DLP detected restricted/confidential data\n"
                    "on screen. Screenshots are not allowed for this window.",
                    "CyberSentinel DLP - Screenshot Blocked",
                    MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND | MB_SYSTEMMODAL);
                AttachThreadInput(curThread, fgThread, FALSE);
            }
        }

        s_instance->HandleCaptureAttempt(method);
    }).detach();

    return 1; // swallow — no screenshot taken
}

// Returns true if the foreground window is a "transient" window that
// doesn't represent user content — taskbar, desktop, start menu, system
// tray, or our own DLP popup. The scanner MUST ignore these and keep
// the previous sensitivity flag, otherwise:
//   * Clicking the taskbar would unblock screenshots even though the
//     sensitive content is still visible behind it.
//   * The "Screenshot Blocked" popup steals focus when shown — if the
//     scanner classified the popup itself as Public it would clear the
//     flag and the next PrintScreen press would slip through.
static bool IsTransientForegroundWindow(HWND hwnd) {
    if (!hwnd) return true;

    // Skip windows owned by our own process (the DLP popup MessageBox).
    DWORD fgPid = 0;
    GetWindowThreadProcessId(hwnd, &fgPid);
    if (fgPid == GetCurrentProcessId()) return true;

    char cls[256] = {0};
    if (GetClassNameA(hwnd, cls, sizeof(cls)) > 0) {
        // Known shell / system window classes that should never count as
        // user content.
        static const std::set<std::string> transient = {
            "Shell_TrayWnd",                     // primary taskbar
            "Shell_SecondaryTrayWnd",            // secondary monitor taskbar
            "Progman",                           // desktop
            "WorkerW",                           // desktop wallpaper layer
            "Windows.UI.Core.CoreWindow",        // start menu, search, action center
            "Windows.UI.Input.InputSite.WindowClass",
            "ApplicationFrameWindow",            // empty UWP frame (rare)
            "Button",                            // start button
            "DV2ControlHost",                    // start menu legacy
            "Xaml_WindowedPopupClass",           // floating UI popups
        };
        if (transient.count(cls)) return true;
    }
    return false;
}

/*
 * Content scanner — runs continuously while the monitor is active.
 * Polls the foreground window roughly every second, classifies it via
 * the agent's screenClassifier (which does the full multi-stage OCR),
 * and updates the m_screenIsSensitive atomic.
 *
 * IMPORTANT: when the foreground is a transient/system window (taskbar,
 * desktop, our own popup, etc.) we LEAVE m_screenIsSensitive unchanged.
 * Whatever the user's last real application window was decided still
 * applies, because that content is still visible on screen.
 */
void ScreenCaptureMonitor::ContentScanThread() {
    HWND        lastHwnd  = nullptr;
    std::string lastTitle;
    std::string lastClass = "Public";

    while (m_running) {
        HWND fg = GetForegroundWindow();

        // Transient foreground (taskbar, popup, desktop, start menu) →
        // do not touch the flag. This is the entire fix for both the
        // "popup steals focus and unblocks itself" bug and the
        // "click taskbar to bypass" bug.
        if (IsTransientForegroundWindow(fg)) {
            for (int i = 0; i < 10 && m_running; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }

        std::string title = GetActiveWindowTitle();

        std::string classification;
        if (fg == lastHwnd && title == lastTitle) {
            // Foreground unchanged — reuse the last classification to
            // avoid hammering Tesseract on an idle desktop.
            classification = lastClass;
        } else {
            classification = "Public";
            if (m_classifier) {
                try { classification = m_classifier(title, ""); }
                catch (...) { classification = "Public"; }
            }
            lastHwnd  = fg;
            lastTitle = title;
            lastClass = classification;
        }

        bool nowSensitive = (classification == "Restricted" ||
                             classification == "Confidential");
        bool wasSensitive = m_screenIsSensitive.exchange(nowSensitive);

        // We just produced a fresh classification on a real foreground
        // window — the post-block grace can be released now. From this
        // point forward the actual flag value (nowSensitive) decides.
        if (m_blockGraceActive.exchange(false) && m_logger) {
            m_logger("INFO", "SCREEN_BLOCK_GRACE_CLEARED: re-classified foreground as " +
                             classification + " | Window: " + title);
        }

        if (nowSensitive != wasSensitive && m_logger) {
            if (nowSensitive) {
                m_logger("WARNING", "SCREEN_CONTEXT_SENSITIVE: " + classification +
                                    " content on screen — screenshots will be blocked"
                                    " | Window: " + title);
            } else {
                m_logger("INFO", "SCREEN_CONTEXT_CLEAR: foreground no longer sensitive"
                                 " — screenshots allowed | Window: " + title);
            }
        }

        // ~1s cadence. Short enough that newly-opened sensitive windows
        // are caught before most users can alt-tab + PrintScreen, long
        // enough that Tesseract isn't thrashing CPU on idle screens.
        for (int i = 0; i < 10 && m_running; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

/*
 * Hook thread — installs the keyboard hook and runs the message loop.
 * The hook only works while a message loop is running in the same thread.
 */
void ScreenCaptureMonitor::HookThread() {
    // Install low-level keyboard hook
    s_keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);

    if (!s_keyboardHook) {
        if (m_logger) m_logger("ERROR", "Failed to install keyboard hook: " + std::to_string(GetLastError()));
        return;
    }

    if (m_logger) m_logger("INFO", "Low-level keyboard hook installed — PrintScreen interception active");

    // Message loop — REQUIRED for the hook to work
    MSG msg;
    while (m_running) {
        // Use PeekMessage with a timeout so we can check m_running
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) break;
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        } else {
            Sleep(50); // Don't spin CPU
        }
    }

    if (s_keyboardHook) {
        UnhookWindowsHookEx(s_keyboardHook);
        s_keyboardHook = NULL;
    }
}

/*
 * Process monitor thread — detects screenshot tool processes.
 * Separate from the hook thread to avoid blocking the message loop.
 */
void ScreenCaptureMonitor::ProcessMonitorThread() {
    std::set<std::string> knownCapProcesses;

    while (m_running) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(pe);
            std::set<std::string> currentCapProcesses;

            if (Process32First(hSnap, &pe)) {
                do {
                    std::string procName = pe.szExeFile;
                    std::string procLower = procName;
                    std::transform(procLower.begin(), procLower.end(), procLower.begin(), ::tolower);

                    for (const auto& capProc : CAPTURE_PROCESSES) {
                        std::string capLower = capProc;
                        std::transform(capLower.begin(), capLower.end(), capLower.begin(), ::tolower);

                        if (procLower == capLower) {
                            currentCapProcesses.insert(procName);

                            if (knownCapProcesses.find(procName) == knownCapProcesses.end()) {
                                if (m_logger) m_logger("INFO", "SCREEN_CAPTURE_PROCESS_DETECTED: " + procName);

                                std::string windowTitle = GetActiveWindowTitle();
                                std::string classification = "Public";
                                if (m_classifier) classification = m_classifier(windowTitle, procName);

                                bool isSensitive = (classification == "Restricted" || classification == "Confidential");

                                if (isSensitive) {
                                    TerminateProcessByName(procName);
                                    // Also clear clipboard
                                    if (OpenClipboard(NULL)) { EmptyClipboard(); CloseClipboard(); }
                                    if (m_logger) m_logger("WARNING", "SCREEN_ACTION_ENFORCED: Terminated " +
                                                           procName + " — " + classification + " data visible");
                                }

                                HandleCaptureAttempt("capture_tool");
                            }
                        }
                    }
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
            knownCapProcesses = currentCapProcesses;
        }

        // Check every 2 seconds
        for (int i = 0; i < 20 && m_running; i++) Sleep(100);
    }
}
