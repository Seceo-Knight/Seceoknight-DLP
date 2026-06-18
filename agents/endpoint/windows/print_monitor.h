#pragma once
#include <windows.h>
#include <winspool.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>

struct PrintEvent {
    std::string eventType = "print_attempt";
    std::string documentName;
    std::string processName;
    std::string printerName;
    std::string user;
    std::string classificationRule;
    std::string category;           // Public, Internal, Confidential, Restricted
    std::string actionTaken;        // Allow, Block, Alert
    int pages = 0;
    int jobId = 0;
    std::string timestamp;
};

class PrintMonitor {
public:
    using PrintCallback = std::function<void(PrintEvent& event)>;
    using LogCallback = std::function<void(const std::string& level, const std::string& message)>;
    using ClassifyCallback = std::function<std::string(const std::string& documentName, const std::string& processName)>;

    PrintMonitor(PrintCallback callback, LogCallback logger = nullptr,
                 ClassifyCallback classifier = nullptr);
    ~PrintMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const;

    void SetClassifier(ClassifyCallback classifier) { m_classifier = classifier; }

private:
    void MonitorLoop();
    std::string GetTimestamp();
    bool CancelPrintJob(const std::string& printerName, int jobId);

    PrintCallback m_callback;
    LogCallback m_logger;
    ClassifyCallback m_classifier;
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    HANDLE m_changeNotification{INVALID_HANDLE_VALUE};
};
