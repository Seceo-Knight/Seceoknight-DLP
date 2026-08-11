#include "print_monitor.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <tlhelp32.h>

#pragma comment(lib, "winspool.lib")

PrintMonitor::PrintMonitor(PrintCallback callback, LogCallback logger, ClassifyCallback classifier, HashCallback hasher)
    : m_callback(std::move(callback)), m_logger(std::move(logger)), m_classifier(std::move(classifier)), m_hasher(std::move(hasher)) {}

PrintMonitor::~PrintMonitor() { Stop(); }

bool PrintMonitor::Start() {
    if (m_running) return true;

    HANDLE hPrinter = NULL;
    PRINTER_DEFAULTS defaults = {NULL, NULL, PRINTER_ALL_ACCESS};

    if (!OpenPrinter(NULL, &hPrinter, &defaults)) {
        if (!OpenPrinter(NULL, &hPrinter, NULL)) {
            if (m_logger) m_logger("ERROR", "PRINT_JOB_DETECTED: Failed to open print server");
            return false;
        }
    }

    DWORD filter = PRINTER_CHANGE_ADD_JOB | PRINTER_CHANGE_SET_JOB | PRINTER_CHANGE_DELETE_JOB;
    m_changeNotification = FindFirstPrinterChangeNotification(hPrinter, filter, 0, NULL);

    if (m_changeNotification == INVALID_HANDLE_VALUE) {
        ClosePrinter(hPrinter);
        if (m_logger) m_logger("ERROR", "PRINT_JOB_DETECTED: Failed to create change notification");
        return false;
    }

    // Deliberately NOT closed here (was: ClosePrinter(hPrinter) right after
    // this point) -- see m_hPrinter's declaration in print_monitor.h for
    // why the handle must outlive the notification's use, not just its
    // creation. Kept open until Stop().
    m_hPrinter = hPrinter;
    m_running = true;
    m_thread = std::thread(&PrintMonitor::MonitorLoop, this);

    if (m_logger) m_logger("INFO", "Print monitor started — monitoring print jobs");
    return true;
}

void PrintMonitor::Stop() {
    m_running = false;
    if (m_changeNotification != INVALID_HANDLE_VALUE) {
        FindClosePrinterChangeNotification(m_changeNotification);
        m_changeNotification = INVALID_HANDLE_VALUE;
    }
    if (m_hPrinter != NULL) {
        ClosePrinter(m_hPrinter);
        m_hPrinter = NULL;
    }
    if (m_thread.joinable()) m_thread.join();
}

bool PrintMonitor::IsRunning() const { return m_running; }

std::string PrintMonitor::GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    t += 19800; // IST
    struct tm tm_buf;
    gmtime_s(&tm_buf, &t);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d+05:30",
             tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    return buf;
}

bool PrintMonitor::CancelPrintJob(const std::string& printerName, int jobId) {
    HANDLE hPrinter = NULL;
    if (!OpenPrinterA(const_cast<LPSTR>(printerName.c_str()), &hPrinter, NULL)) {
        if (m_logger) m_logger("ERROR", "Failed to open printer for job cancellation: " + printerName);
        return false;
    }

    BOOL result = SetJob(hPrinter, jobId, 0, NULL, JOB_CONTROL_DELETE);
    ClosePrinter(hPrinter);

    if (result) {
        if (m_logger) m_logger("WARNING", "PRINT_JOB_BLOCKED: Cancelled job " +
                               std::to_string(jobId) + " on " + printerName);
        return true;
    } else {
        if (m_logger) m_logger("ERROR", "Failed to cancel print job " + std::to_string(jobId));
        return false;
    }
}

// Ported from CyberSentinel-DLP. Used by MonitorLoop to pause a job before
// content inspection (so it can't finish printing during the server round
// trip) and resume it if the verdict allows.
bool PrintMonitor::ControlJob(const std::string& printerName, int jobId, unsigned long command) {
    HANDLE hPrinter = NULL;
    if (!OpenPrinterA(const_cast<LPSTR>(printerName.c_str()), &hPrinter, NULL)) return false;
    BOOL ok = SetJob(hPrinter, jobId, 0, NULL, command);
    ClosePrinter(hPrinter);
    return ok ? true : false;
}

// Enumerates every printer's job queue and processes any job not already
// handled this "generation" (see m_processedJobIds). Shared by two call
// sites in MonitorLoop: the PRINTER_CHANGE_ADD_JOB notification path, and a
// fallback poll that runs unconditionally on every wait timeout.
//
// The fallback poll exists because FindFirstPrinterChangeNotification has
// proven unreliable in practice: CONFIRMED LIVE, a real physical print job
// went completely undetected (zero PRINT_JOB_DETECTED lines) for an agent
// that had otherwise been running fine for hours, traced to Start()
// closing the printer handle too early (see m_hPrinter's comment -- now
// fixed). Since Windows print-spooler notification delivery has more than
// one way to silently fail depending on driver/permission/session
// specifics, this poll is defense in depth: even if the notification never
// fires again for some other reason, a real job sitting in a queue will
// still be caught within ~2 seconds.
//
// m_processedJobIds prevents a single slow physical print job (which can
// legitimately sit in the queue across many consecutive 2-second poll
// cycles) from being re-classified/re-evaluated/re-blocked on every pass.
// It's cleared whenever a full pass finds zero jobs queued anywhere, which
// is a safe, natural point to forget old IDs -- nothing still in flight
// could collide with a recycled job ID after that.
void PrintMonitor::ProcessPendingJobs() {
    char username[256] = {0};
    DWORD userSize = sizeof(username);
    GetUserNameA(username, &userSize);

    DWORD needed = 0, count = 0;
    EnumPrintersA(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2, NULL, 0, &needed, &count);
    if (needed == 0) {
        m_processedJobIds.clear();
        return;
    }

    std::vector<BYTE> buffer(needed);
    PRINTER_INFO_2A* printers = reinterpret_cast<PRINTER_INFO_2A*>(buffer.data());
    if (!EnumPrintersA(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2,
                        buffer.data(), needed, &needed, &count)) {
        return;
    }

    bool anyQueued = false;
    for (DWORD i = 0; i < count; i++) {
        if (printers[i].cJobs == 0) continue;
        anyQueued = true;

        HANDLE hPrinter = NULL;
        if (!OpenPrinterA(printers[i].pPrinterName, &hPrinter, NULL)) continue;

        DWORD jobNeeded = 0, jobCount = 0;
        EnumJobsA(hPrinter, 0, printers[i].cJobs, 1, NULL, 0, &jobNeeded, &jobCount);

        if (jobNeeded > 0) {
            std::vector<BYTE> jobBuffer(jobNeeded);
            JOB_INFO_1A* jobs = reinterpret_cast<JOB_INFO_1A*>(jobBuffer.data());

            if (EnumJobsA(hPrinter, 0, printers[i].cJobs, 1,
                          jobBuffer.data(), jobNeeded, &jobNeeded, &jobCount)) {
                for (DWORD j = 0; j < jobCount; j++) {
                    int jobId = jobs[j].JobId;
                    if (m_processedJobIds.count(jobId)) continue;
                    m_processedJobIds.insert(jobId);

                    std::string printerName = printers[i].pPrinterName ? printers[i].pPrinterName : "Unknown";
                    std::string docName = jobs[j].pDocument ? jobs[j].pDocument : "Unknown";
                    std::string jobUser = jobs[j].pUserName ? jobs[j].pUserName : username;
                    int pages = jobs[j].TotalPages;

                    // Hash the spooled data file BEFORE any
                    // enforcement decision below -- CancelPrintJob
                    // (JOB_CONTROL_DELETE) removes the spool file,
                    // so hashing after that point would silently
                    // miss a hash on exactly the jobs we most want
                    // one for (blocked/Restricted documents).
                    std::string fileHash;
                    if (m_hasher) {
                        fileHash = m_hasher(jobId);
                    }

                    if (m_logger) m_logger("INFO", "PRINT_CONTENT_ANALYZED: " +
                                           docName + " on " + printerName);

                    // Classify document
                    std::string classification = "Public";
                    if (m_classifier) {
                        classification = m_classifier(docName, "");
                    }

                    if (m_logger) m_logger("INFO", "PRINT_CLASSIFICATION_RESULT: " +
                                           docName + " → " + classification);

                    bool isSensitive = (classification == "Restricted" ||
                                        classification == "Confidential");

                    // Printer DEVICE control (additive): block this job if the
                    // printer itself is disallowed by a printer_control policy,
                    // regardless of content. Leaves the content path below
                    // intact. Ported from CyberSentinel-DLP.
                    bool deviceBlocked = m_printerControl && m_printerControl(printerName);

                    // Print CONTENT control: when configured, pause the job,
                    // inspect the spooled document's REAL content via the
                    // server, and use that decision instead of the filename
                    // heuristic above. When unset, falls back to the legacy
                    // filename/keyword classifier result exactly as before this
                    // change -- purely additive. Ported from CyberSentinel-DLP.
                    bool contentBlocked;
                    std::string contentStatus = "not_configured";
                    if (m_printContent) {
                        ControlJob(printerName, jobId, JOB_CONTROL_PAUSE);
                        PrintContentResult pcr = m_printContent(printerName, jobId, docName);
                        contentBlocked = pcr.block;
                        contentStatus = pcr.status;
                        if (!contentBlocked && !deviceBlocked)
                            ControlJob(printerName, jobId, JOB_CONTROL_RESUME);
                    } else {
                        contentBlocked = isSensitive;   // legacy filename fallback
                    }
                    // CONFIRMED LIVE: without this, a job whose content
                    // genuinely couldn't be read (see PrintContentResult's
                    // comment) looked EXACTLY like a verified-clean allow in
                    // both the log and the dashboard -- a real, silent false
                    // sense of security. Make it loud instead.
                    if (contentStatus == "unavailable" && m_logger) {
                        m_logger("WARNING", "PRINT_CONTENT_UNAVAILABLE: " + docName +
                            " on " + printerName + " -- could not read this job's real "
                            "spooled content; the decision above is based on the "
                            "filename only and has NOT verified what was actually printed.");
                    }
                    std::string action = (contentBlocked || deviceBlocked) ? "Block" : "Allow";

                    if (m_logger) m_logger("INFO", "PRINT_POLICY_DECISION: " +
                                           action + " for " + docName);

                    // Enforce
                    if (deviceBlocked) {
                        CancelPrintJob(printerName, jobId);
                        if (m_logger) m_logger("WARNING",
                            "PRINT_DEVICE_BLOCKED: " + printerName +
                            " — blocked by printer control policy");
                    } else if (contentBlocked) {
                        CancelPrintJob(printerName, jobId);
                        if (m_logger) m_logger("WARNING",
                            "PRINT_JOB_BLOCKED: " + docName +
                            " — sensitive content detected");
                    }

                    // Build event
                    PrintEvent event;
                    event.documentName = docName;
                    event.printerName = printerName;
                    event.user = jobUser;
                    event.category = classification;
                    event.actionTaken = action;
                    event.blockReason = deviceBlocked ? "printer_control"
                                        : (contentBlocked ? "content" : "");
                    event.contentInspectionStatus = contentStatus;
                    event.pages = pages;
                    event.jobId = jobId;
                    event.fileHash = fileHash;
                    event.timestamp = GetTimestamp();

                    if (m_callback) m_callback(event);
                }
            }
        }
        ClosePrinter(hPrinter);
    }

    if (!anyQueued) m_processedJobIds.clear();
}

void PrintMonitor::MonitorLoop() {
    while (m_running) {
        DWORD waitResult = WaitForSingleObject(m_changeNotification, 2000);
        if (!m_running) break;

        if (waitResult == WAIT_OBJECT_0) {
            DWORD change = 0;
            FindNextPrinterChangeNotification(m_changeNotification, &change, NULL, NULL);

            if (change & PRINTER_CHANGE_ADD_JOB) {
                if (m_logger) m_logger("INFO", "PRINT_JOB_DETECTED: New print job submitted");
            }
            ProcessPendingJobs();
        } else {
            // Fallback poll (see ProcessPendingJobs' comment) -- runs every
            // ~2s regardless of whether the notification ever fires, so job
            // detection doesn't depend entirely on that one API working.
            ProcessPendingJobs();
        }
    }
}
