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
    // "" | "content" | "printer_control" -- which control actually fired, so
    // the dashboard can tell a device-control block apart from a content
    // block on the same job. Ported from CyberSentinel-DLP, additive.
    std::string blockReason;
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
    // Printer DEVICE control: return true if this printer must be blocked by a
    // printer_control policy (independent of document content). Additive --
    // leaves the content-classification path below untouched. Ported from
    // CyberSentinel-DLP.
    using PrinterControlCallback = std::function<bool(const std::string& printerName)>;
    // Print CONTENT control: inspect the spooled document and return true to
    // block. When set, the job is PAUSED before this runs (so it can't print
    // during the server round-trip) and resumed if allowed. Returns false to
    // allow. Ported from CyberSentinel-DLP -- when unset, MonitorLoop falls
    // back to the legacy filename/keyword classifier result exactly as
    // before, so this is purely additive.
    using PrintContentCallback = std::function<bool(const std::string& printerName, int jobId,
                                                    const std::string& documentName)>;

    PrintMonitor(PrintCallback callback, LogCallback logger = nullptr,
                 ClassifyCallback classifier = nullptr, HashCallback hasher = nullptr);
    ~PrintMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const;

    void SetClassifier(ClassifyCallback classifier) { m_classifier = classifier; }
    void SetHasher(HashCallback hasher) { m_hasher = hasher; }
    void SetPrinterControl(PrinterControlCallback cb) { m_printerControl = cb; }
    void SetPrintContent(PrintContentCallback cb) { m_printContent = cb; }

private:
    void MonitorLoop();
    std::string GetTimestamp();
    bool CancelPrintJob(const std::string& printerName, int jobId);
    bool ControlJob(const std::string& printerName, int jobId, unsigned long command);

    PrintCallback m_callback;
    LogCallback m_logger;
    ClassifyCallback m_classifier;
    HashCallback m_hasher;
    PrinterControlCallback m_printerControl;
    PrintContentCallback m_printContent;
    std::thread m_thread;
    std::atomic<bool> m_running{false};
    HANDLE m_changeNotification{INVALID_HANDLE_VALUE};
};
