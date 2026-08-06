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

    ClosePrinter(hPrinter);
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

void PrintMonitor::MonitorLoop() {
    char username[256] = {0};
    DWORD userSize = sizeof(username);
    GetUserNameA(username, &userSize);

    while (m_running) {
        DWORD waitResult = WaitForSingleObject(m_changeNotification, 2000);
        if (!m_running) break;

        if (waitResult == WAIT_OBJECT_0) {
            DWORD change = 0;
            FindNextPrinterChangeNotification(m_changeNotification, &change, NULL, NULL);

            if (change & PRINTER_CHANGE_ADD_JOB) {
                if (m_logger) m_logger("INFO", "PRINT_JOB_DETECTED: New print job submitted");

                DWORD needed = 0, count = 0;
                EnumPrintersA(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2, NULL, 0, &needed, &count);

                if (needed > 0) {
                    std::vector<BYTE> buffer(needed);
                    PRINTER_INFO_2A* printers = reinterpret_cast<PRINTER_INFO_2A*>(buffer.data());

                    if (EnumPrintersA(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2,
                                      buffer.data(), needed, &needed, &count)) {
                        for (DWORD i = 0; i < count; i++) {
                            if (printers[i].cJobs > 0) {
                                HANDLE hPrinter = NULL;
                                if (OpenPrinterA(printers[i].pPrinterName, &hPrinter, NULL)) {
                                    DWORD jobNeeded = 0, jobCount = 0;
                                    EnumJobsA(hPrinter, 0, printers[i].cJobs, 1, NULL, 0, &jobNeeded, &jobCount);

                                    if (jobNeeded > 0) {
                                        std::vector<BYTE> jobBuffer(jobNeeded);
                                        JOB_INFO_1A* jobs = reinterpret_cast<JOB_INFO_1A*>(jobBuffer.data());

                                        if (EnumJobsA(hPrinter, 0, printers[i].cJobs, 1,
                                                      jobBuffer.data(), jobNeeded, &jobNeeded, &jobCount)) {
                                            for (DWORD j = 0; j < jobCount; j++) {
                                                std::string printerName = printers[i].pPrinterName ? printers[i].pPrinterName : "Unknown";
                                                std::string docName = jobs[j].pDocument ? jobs[j].pDocument : "Unknown";
                                                std::string jobUser = jobs[j].pUserName ? jobs[j].pUserName : username;
                                                int pages = jobs[j].TotalPages;
                                                int jobId = jobs[j].JobId;

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
                                                if (m_printContent) {
                                                    ControlJob(printerName, jobId, JOB_CONTROL_PAUSE);
                                                    contentBlocked = m_printContent(printerName, jobId, docName);
                                                    if (!contentBlocked && !deviceBlocked)
                                                        ControlJob(printerName, jobId, JOB_CONTROL_RESUME);
                                                } else {
                                                    contentBlocked = isSensitive;   // legacy filename fallback
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
                            }
                        }
                    }
                }
            }
        }
    }
}
