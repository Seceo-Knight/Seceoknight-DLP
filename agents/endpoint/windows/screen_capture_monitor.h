#pragma once
#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>

struct ScreenCaptureEvent {
    std::string eventType = "screen_capture";
    std::string method;             // printscreen, alt_printscreen, win_shift_s, capture_tool
    std::string processName;
    std::string activeWindow;
    std::string user;
    std::string classification;     // Public, Internal, Confidential, Restricted
    bool containsSensitiveData = false;
    std::string actionTaken;        // Allow, Block, Alert
    std::string timestamp;
};

class ScreenCaptureMonitor {
public:
    using CaptureCallback = std::function<void(ScreenCaptureEvent& event)>;
    using LogCallback = std::function<void(const std::string& level, const std::string& message)>;
    using ClassifyCallback = std::function<std::string(const std::string& windowTitle, const std::string& processName)>;

    ScreenCaptureMonitor(CaptureCallback callback, LogCallback logger = nullptr,
                         ClassifyCallback classifier = nullptr);
    ~ScreenCaptureMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const;

    void SetClassifier(ClassifyCallback classifier) { m_classifier = classifier; }

    // Static hook callback — must be static for Windows API
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

private:
    void HookThread();             // Thread that runs the keyboard hook message loop
    void ProcessMonitorThread();   // Thread that monitors capture tool processes
    void ContentScanThread();      // Background OCR — maintains m_screenIsSensitive
    std::string GetActiveWindowTitle();
    std::string GetForegroundProcessName();
    std::string GetTimestamp();
    void TerminateProcessByName(const std::string& processName);
    void HandleCaptureAttempt(const std::string& method);

    CaptureCallback m_callback;
    LogCallback m_logger;
    ClassifyCallback m_classifier;
    std::thread m_hookThread;
    std::thread m_processThread;
    std::thread m_scanThread;
    std::atomic<bool> m_running{false};

    // Continuously updated by ContentScanThread. The keyboard hook ONLY
    // swallows PrintScreen / Win+Shift+S when this flag is true; otherwise
    // the key is passed to Windows unchanged and the screenshot happens
    // normally.
    std::atomic<bool> m_screenIsSensitive{false};

    // Cooldown — only show ONE blocked-screenshot popup per N milliseconds.
    // Stops the dialog from being spammed when the user mashes PrintScreen.
    std::atomic<long long> m_lastPopupMs{0};

    // Block grace — set true whenever the hook blocks a screenshot.
    // Cleared by ContentScanThread the moment it produces a fresh
    // classification on a real (non-transient) foreground window.
    // While true, every screenshot attempt is force-blocked regardless
    // of the m_screenIsSensitive flag. This eliminates the race where
    // the DLP popup steals focus and the scanner clears the flag
    // before it has had a chance to re-classify the user's actual
    // current window. As soon as the scanner sees a real window after
    // the block, the grace clears and the actual flag value takes over
    // — so switching to a normal window after a block correctly
    // allows screenshots of that normal window.
    std::atomic<bool> m_blockGraceActive{false};

    // Static instance pointer for the hook callback
    static ScreenCaptureMonitor* s_instance;
    static HHOOK s_keyboardHook;

    static const std::vector<std::string> CAPTURE_PROCESSES;
};
