/**
 * CyberSentinel DLP — User-Mode Filter Communication Client
 *
 * Connects to the kernel minifilter via FilterConnectCommunicationPort,
 * receives file operation events, evaluates policies, and sends
 * allow/block decisions back to the driver.
 *
 * Integration point: sits between kernel driver and PolicyEngine.
 *
 * Thread model:
 *   - Listener thread: blocks on FilterGetMessage(), receives events
 *   - Inline evaluation: PolicyEngine::Evaluate() called synchronously (<10ms)
 *   - Reply sent via FilterReplyMessage() immediately
 *   - Async event logging queued to separate thread
 */

#pragma once

#include <windows.h>
#include <fltUser.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <queue>
#include <mutex>
#include <condition_variable>

/* Include shared structures */
#include "csfilter.h"
#include "../policy_engine.h"

#pragma comment(lib, "fltlib.lib")

namespace cs {

/* ────────────────────────────────────────────────────────────────────────────
 * Filter message wrapper (FILTER_MESSAGE_HEADER + our payload)
 * ──────────────────────────────────────────────────────────────────────────── */

#pragma pack(push, 1)
struct FilterMessage {
    FILTER_MESSAGE_HEADER Header;
    CS_EVENT_MESSAGE      Body;
};

struct FilterReply {
    FILTER_REPLY_HEADER   Header;
    CS_DECISION_REPLY     Body;
};
#pragma pack(pop)

/* ────────────────────────────────────────────────────────────────────────────
 * Logged event (queued for async processing)
 * ──────────────────────────────────────────────────────────────────────────── */

struct LoggedEvent {
    CS_EVENT_MESSAGE    eventData;
    Decision            decision;
    std::chrono::steady_clock::time_point timestamp;
};

/* ────────────────────────────────────────────────────────────────────────────
 * FilterCommClient — the integration layer
 * ──────────────────────────────────────────────────────────────────────────── */

class FilterCommClient {
public:
    using EventLogCallback = std::function<void(const LoggedEvent&)>;

    FilterCommClient(PolicyEngine* engine, ClassificationEngine* classifier)
        : engine_(engine), classifier_(classifier), port_(INVALID_HANDLE_VALUE) {
        engine_->SetClassifier(classifier_);
    }

    ~FilterCommClient() { Stop(); }

    /**
     * Connect to the minifilter communication port and start listening.
     * Returns false if the driver is not loaded or port unavailable.
     */
    bool Start() {
        if (running_) return true;

        HRESULT hr = FilterConnectCommunicationPort(
            CS_FILTER_PORT_NAME,
            0,          /* Options */
            NULL,       /* Context */
            0,          /* ContextSize */
            NULL,       /* SecurityAttributes */
            &port_
        );

        if (FAILED(hr)) {
            /* Driver not loaded or port not available.
               This is normal during startup — agent runs in user-mode-only mode. */
            return false;
        }

        running_ = true;

        /* Start listener thread */
        listenerThread_ = std::thread(&FilterCommClient::ListenerLoop, this);

        /* Start async log processing thread */
        logThread_ = std::thread(&FilterCommClient::LogProcessingLoop, this);

        return true;
    }

    void Stop() {
        running_ = false;

        if (port_ != INVALID_HANDLE_VALUE) {
            CloseHandle(port_);
            port_ = INVALID_HANDLE_VALUE;
        }

        /* Wake up log thread */
        logCondVar_.notify_all();

        if (listenerThread_.joinable()) listenerThread_.join();
        if (logThread_.joinable()) logThread_.join();
    }

    bool IsConnected() const { return running_ && port_ != INVALID_HANDLE_VALUE; }

    /** Set callback for processed events (for backend upload) */
    void SetEventLogCallback(EventLogCallback cb) { logCallback_ = std::move(cb); }

    /** Stats */
    uint64_t EventsProcessed() const { return eventsProcessed_; }
    uint64_t EventsBlocked() const { return eventsBlocked_; }
    uint64_t EventsAllowed() const { return eventsAllowed_; }

private:
    /**
     * Main listener loop — blocks on FilterGetMessage.
     * Each message is processed inline (classify + evaluate + reply).
     * Target: entire cycle < 10ms.
     */
    void ListenerLoop() {
        FilterMessage msg;
        DWORD bytesReturned;

        while (running_) {
            HRESULT hr = FilterGetMessage(
                port_,
                &msg.Header,
                sizeof(msg),
                NULL /* Overlapped — NULL = synchronous */
            );

            if (FAILED(hr)) {
                if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                    /* Port closed — driver unloaded or service stopping */
                    break;
                }
                /* Transient error — retry */
                Sleep(100);
                continue;
            }

            /* Process the event and send reply */
            ProcessEvent(msg);
        }
    }

    /**
     * Process a single kernel event:
     * 1. Convert kernel message to Event struct
     * 2. If content needed, read first N KB of file
     * 3. Classify (regex patterns)
     * 4. Evaluate against policies
     * 5. Send decision back to driver
     * 6. Queue event for async logging
     */
    void ProcessEvent(FilterMessage& msg) {
        auto startTime = std::chrono::steady_clock::now();

        /* Step 1: Convert to PolicyEngine Event */
        Event event;
        event.filePath = WcharToString(msg.Body.FilePath);
        event.fileName = ExtractFileName(event.filePath);
        event.fileExtension = ExtractExtension(event.fileName);
        event.fileSize = msg.Body.FileSize;
        event.userId = WcharToString(msg.Body.UserSid);
        event.endpointId = "local";

        /* Set channel flags from device type */
        if (msg.Body.DeviceFlags & CsDeviceRemovable) {
            event.channelFlags = CH_USB | CH_REMOVABLE;
        } else if (msg.Body.DeviceFlags & CsDeviceNetwork) {
            event.channelFlags = CH_NETWORK;
        } else {
            event.channelFlags = CH_NONE;
        }

        /* Set action type from event type */
        switch (msg.Body.EventType) {
        case CsEventFileCreate: event.actionType = "CREATE"; break;
        case CsEventFileWrite:  event.actionType = "WRITE"; break;
        case CsEventFileRename: event.actionType = "RENAME"; break;
        case CsEventFileDelete: event.actionType = "DELETE"; break;
        default:                event.actionType = "UNKNOWN"; break;
        }

        /* Step 2: Read partial content for classification (if file exists and is small enough) */
        if (msg.Body.NeedsDecision && msg.Body.EventType != CsEventFileDelete) {
            ReadPartialContent(event, 64 * 1024); /* First 64KB */
        }

        /* Step 3 + 4: Classify and evaluate (inline, <10ms target) */
        Decision decision = engine_->Evaluate(event);

        /* Step 5: Send reply to kernel */
        if (msg.Body.NeedsDecision) {
            SendDecisionReply(msg.Header.ReplyLength > 0 ? msg.Header.MessageId : msg.Body.MessageId,
                              decision);
        }

        eventsProcessed_++;
        if (decision.action == Action::Block) eventsBlocked_++;
        else eventsAllowed_++;

        /* Step 6: Queue for async logging (don't block the IRP) */
        QueueEventLog(msg.Body, decision);

        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - startTime);

        if (elapsed.count() > 10000) { /* > 10ms warning */
            /* Log slow evaluation for performance monitoring */
        }
    }

    void SendDecisionReply(ULONG messageId, const Decision& decision) {
        FilterReply reply = {};
        reply.Header.Status = 0;
        reply.Header.MessageId = messageId;
        reply.Body.MessageId = messageId;
        reply.Body.ReasonCode = 0;

        switch (decision.action) {
        case Action::Block:
        case Action::Encrypt:  /* Encrypt = block the raw write, encrypt separately */
            reply.Body.Decision = CsDecisionBlock;
            break;
        case Action::Warn:
            reply.Body.Decision = CsDecisionWarn;
            break;
        default:
            reply.Body.Decision = CsDecisionAllow;
            break;
        }

        FilterReplyMessage(port_, &reply.Header, sizeof(reply));
    }

    void QueueEventLog(const CS_EVENT_MESSAGE& eventData, const Decision& decision) {
        LoggedEvent entry;
        entry.eventData = eventData;
        entry.decision = decision;
        entry.timestamp = std::chrono::steady_clock::now();

        {
            std::lock_guard<std::mutex> lock(logMutex_);
            if (logQueue_.size() < 100000) { /* Cap queue size */
                logQueue_.push(std::move(entry));
            }
        }
        logCondVar_.notify_one();
    }

    void LogProcessingLoop() {
        while (running_) {
            LoggedEvent entry;
            {
                std::unique_lock<std::mutex> lock(logMutex_);
                logCondVar_.wait_for(lock, std::chrono::seconds(1),
                    [this] { return !logQueue_.empty() || !running_; });

                if (logQueue_.empty()) continue;
                entry = std::move(logQueue_.front());
                logQueue_.pop();
            }

            if (logCallback_) {
                logCallback_(entry);
            }
        }

        /* Drain remaining events on shutdown */
        std::lock_guard<std::mutex> lock(logMutex_);
        while (!logQueue_.empty()) {
            if (logCallback_) {
                logCallback_(logQueue_.front());
            }
            logQueue_.pop();
        }
    }

    /* ── Helpers ────────────────────────────────────────────────────────── */

    static std::string WcharToString(const wchar_t* wstr) {
        if (!wstr || !wstr[0]) return "";
        int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return "";
        std::string result(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, NULL, NULL);
        return result;
    }

    static std::string ExtractFileName(const std::string& path) {
        auto pos = path.find_last_of("\\/");
        return (pos != std::string::npos) ? path.substr(pos + 1) : path;
    }

    static std::string ExtractExtension(const std::string& fileName) {
        auto pos = fileName.find_last_of('.');
        if (pos != std::string::npos) {
            std::string ext = fileName.substr(pos);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            return ext;
        }
        return "";
    }

    void ReadPartialContent(Event& event, size_t maxBytes) {
        /* Convert UTF-8 path back to wide for Win32 API */
        int wlen = MultiByteToWideChar(CP_UTF8, 0, event.filePath.c_str(), -1, NULL, 0);
        if (wlen <= 0) return;
        std::wstring wpath(wlen - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, event.filePath.c_str(), -1, &wpath[0], wlen);

        HANDLE hFile = CreateFileW(wpath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) return;

        std::vector<char> buffer(maxBytes);
        DWORD bytesRead = 0;
        if (ReadFile(hFile, buffer.data(), (DWORD)maxBytes, &bytesRead, NULL) && bytesRead > 0) {
            event.content.assign(buffer.data(), bytesRead);
        }
        CloseHandle(hFile);
    }

    PolicyEngine*           engine_;
    ClassificationEngine*   classifier_;
    HANDLE                  port_ = INVALID_HANDLE_VALUE;
    std::atomic<bool>       running_{false};
    std::thread             listenerThread_;
    std::thread             logThread_;

    std::queue<LoggedEvent> logQueue_;
    std::mutex              logMutex_;
    std::condition_variable logCondVar_;
    EventLogCallback        logCallback_;

    std::atomic<uint64_t>   eventsProcessed_{0};
    std::atomic<uint64_t>   eventsBlocked_{0};
    std::atomic<uint64_t>   eventsAllowed_{0};
};

} /* namespace cs */
