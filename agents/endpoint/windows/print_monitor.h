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
    std::string fileHash;           // SHA-256 of the spooled document data file, if hashed
    std::string timestamp;
};

class PrintMonitor {
public:
    using PrintCallback = std::function<void(PrintEvent& event)>;
    using LogCallback = std::function<void(const std::string& level, const std::string& message)>;
    using ClassifyCallback = std::function<std::string(const std::string& documentName, const std::string& processName)>;
    // Hashes the spooled data file for a given print job ID. Injected
    // (rather than hardcoded here) because the SHA-256 implementation
    // (CalculateFileHash) already lives in agent.cpp and is reused as-is
    // rather than duplicated. Must be called BEFORE any job cancellation,
    // since CUPS/Windows both purge a cancelled job's spool file promptly --
    // see MonitorLoop for where this is invoked relative to CancelPrintJob.
    using HashCallback = std::function<std::string(int jobId)>;

    PrintMonitor(PrintCallback callback, LogCallback logger = nullptr,
                 ClassifyCallback classifier = nullptr, HashCallback hasher = nullptr);
    ~PrintMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const;

    void SetClassifier(ClassifyCallback classifier) { m_classifier = classifier; }
    void SetHasher(HashCallback hasher) { m_hasher = hasher; }

private:
    void MonitorLoop();
    std::string GetTimestamp();
    bool CancelPrintJob(const std::string& printerName, int jobId);

    PrintCallback m_callback;
    LogCallback m_logger;
    ClassifyCallback m_classifier;
    HashCallback m_hasher;
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    HANDLE m_changeNotification{INVALID_HANDLE_VALUE};
};
