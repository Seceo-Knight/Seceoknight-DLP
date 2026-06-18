/*
 * CyberSentinel DLP - Windows Endpoint Agent (C++)
 * 
 * Monitors file operations, clipboard, and USB devices for data loss prevention
 * 
 * Build Instructions (MinGW):
 * g++ -std=c++17 -O2 agent.cpp -o cybersentinel_agent.exe -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 -lws2_32 -static
 * 
 * Build Instructions (MSVC):
 * cl.exe /EHsc /std:c++17 /O2 agent.cpp /link winhttp.lib wbemuuid.lib ole32.lib oleaut32.lib user32.lib ws2_32.lib
 */

 #define _WIN32_WINNT 0x0601
 #define WIN32_LEAN_AND_MEAN
 #define NOMINMAX
 
 // Include Winsock2 BEFORE windows.h to avoid conflicts
 #include <winsock2.h>
 #include <ws2tcpip.h>
 #include <windows.h>
 #include <winhttp.h>
 #include <wbemidl.h>
 #include <shlobj.h>
 #include <comdef.h>
 
 #include <iostream>
 #include <fstream>
 #include <sstream>
 #include <string>
 #include <vector>
 #include <map>
 #include <set>
 #include <memory>
 #include <algorithm>
 #include <thread>
 #include <mutex>
 #include <atomic>
 #include <chrono>
 #include "screen_capture_monitor.h"
 #include "print_monitor.h"
 #include "network_exfil_monitor.h"
 #include <regex>
 #include <iomanip>
 #include <filesystem>
 #include <ctime>
 #include <cctype>
 #include <dbt.h>
#include <setupapi.h>
#include <initguid.h>
#include <cfgmgr32.h>
#include <winioctl.h>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

#pragma comment(lib, "cfgmgr32.lib")


// USB Device Interface GUID
DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE, 0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);
#define USB_STOR_REG_PATH "SYSTEM\\CurrentControlSet\\Services\\USBSTOR"

 
 #pragma comment(lib, "winhttp.lib")
 #pragma comment(lib, "wbemuuid.lib")
 #pragma comment(lib, "ole32.lib")
 #pragma comment(lib, "oleaut32.lib")
 #pragma comment(lib, "user32.lib")
 #pragma comment(lib, "ws2_32.lib")
 #pragma comment(lib, "setupapi.lib")
 
 namespace fs = std::filesystem;
 
 // ==================== Forward Declarations ====================
 class DLPAgent;
 
 // ==================== Utilities ====================
 
 std::string GenerateUUID() {
     GUID guid;
     CoCreateGuid(&guid);
     char buf[64];
     sprintf_s(buf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
         guid.Data1, guid.Data2, guid.Data3,
         guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
         guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
     return std::string(buf);
 }
 
 std::string GetCurrentTimestampISO() {
     auto now = std::chrono::system_clock::now();
     auto now_c = std::chrono::system_clock::to_time_t(now);
     auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

     std::tm tm_utc;
     gmtime_s(&tm_utc, &now_c);

     std::ostringstream oss;
     oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%S");
     oss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
     return oss.str();
 }

 // Timestamp for LOG FILE lines, formatted in Asia/Kolkata (IST, UTC+5:30)
 // regardless of system timezone. Event payloads sent to the server continue
 // to use GetCurrentTimestampISO() which stays in UTC (backend contract).
 std::string GetCurrentTimestampLocalIST() {
     auto now = std::chrono::system_clock::now();
     auto now_c = std::chrono::system_clock::to_time_t(now);
     auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

     // IST = UTC + 5h30m, hardcoded so we are timezone-independent.
     now_c += (5 * 3600 + 30 * 60);

     std::tm tm_ist;
     gmtime_s(&tm_ist, &now_c);   // interpret shifted time_t as UTC fields

     std::ostringstream oss;
     oss << std::put_time(&tm_ist, "%Y-%m-%dT%H:%M:%S");
     oss << "." << std::setfill('0') << std::setw(3) << ms.count() << "+05:30";
     return oss.str();
 }
 
 std::string ToLower(const std::string& str) {
     std::string result = str;
     std::transform(result.begin(), result.end(), result.begin(), ::tolower);
     return result;
 }
 
 std::string ExpandEnvironmentPath(const std::string& path) {
     char expanded[MAX_PATH];
     ExpandEnvironmentStringsA(path.c_str(), expanded, MAX_PATH);
     return std::string(expanded);
 }
 
 std::string NormalizeFilesystemPath(const std::string& path) {
     std::string expanded = ExpandEnvironmentPath(path);
     std::replace(expanded.begin(), expanded.end(), '/', '\\');
     return expanded;
 }
 
 std::string GetHostname() {
     char buffer[256];
     DWORD size = sizeof(buffer);
     if (GetComputerNameA(buffer, &size)) {
         return std::string(buffer);
     }
     return "unknown";
 }
 
 std::string GetUsername() {
     char buffer[256];
     DWORD size = sizeof(buffer);
     if (GetUserNameA(buffer, &size)) {
         return std::string(buffer);
     }
     return "unknown";
 }
 
 std::string GetRealIPAddress() {
     WSADATA wsaData;
     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
         return "127.0.0.1";
     }
     
     SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
     if (sock == INVALID_SOCKET) {
         WSACleanup();
         return "127.0.0.1";
     }
     
     sockaddr_in addr;
     addr.sin_family = AF_INET;
     addr.sin_port = htons(80);
     inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
     
     if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
         sockaddr_in localAddr;
         int addrLen = sizeof(localAddr);
         getsockname(sock, (sockaddr*)&localAddr, &addrLen);
         
         char ip[INET_ADDRSTRLEN];
         inet_ntop(AF_INET, &localAddr.sin_addr, ip, INET_ADDRSTRLEN);
         
         closesocket(sock);
         WSACleanup();
         return std::string(ip);
     }
     
     closesocket(sock);
     WSACleanup();
     return "127.0.0.1";
 }
 
 std::string CalculateFileHash(const std::string& filePath) {
     std::ifstream file(filePath, std::ios::binary);
     if (!file.is_open()) {
         throw std::runtime_error("Cannot open file");
     }
     
     // Simple hash implementation (for production use proper SHA-256)
     std::ostringstream hash;
     hash << std::hex << std::setfill('0');
     
     char buffer[4096];
     unsigned long long hashValue = 0;
     while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
         for (std::streamsize i = 0; i < file.gcount(); ++i) {
             hashValue = hashValue * 31 + static_cast<unsigned char>(buffer[i]);
         }
     }
     
     hash << std::setw(64) << hashValue;
     return hash.str();
 }
 
 std::string ReadFileContent(const std::string& filePath, size_t maxBytes = 100000) {
     std::ifstream file(filePath, std::ios::binary);
     if (!file.is_open()) return "";
     
     std::string content;
     content.resize(maxBytes);
     file.read(&content[0], maxBytes);
     content.resize(file.gcount());
     return content;
 }
 
 // ==================== JSON Helper ====================
 
 class JsonBuilder {
 private:
     std::ostringstream oss;
     bool firstItem = true;
     
 public:
     JsonBuilder() { oss << "{"; }
     
     void AddString(const std::string& key, const std::string& value) {
         if (!firstItem) oss << ",";
         oss << "\"" << key << "\":\"" << EscapeJson(value) << "\"";
         firstItem = false;
     }
     
     void AddInt(const std::string& key, int value) {
         if (!firstItem) oss << ",";
         oss << "\"" << key << "\":" << value;
         firstItem = false;
     }
     
     void AddBool(const std::string& key, bool value) {
         if (!firstItem) oss << ",";
         oss << "\"" << key << "\":" << (value ? "true" : "false");
         firstItem = false;
     }

     void AddDouble(const std::string& key, double value) {
         if (!firstItem) oss << ",";
         oss << "\"" << key << "\":" << value;
         firstItem = false;
     }

     void AddArray(const std::string& key, const std::vector<std::string>& values) {
         if (!firstItem) oss << ",";
         oss << "\"" << key << "\":[";
         for (size_t i = 0; i < values.size(); i++) {
             if (i > 0) oss << ",";
             oss << "\"" << EscapeJson(values[i]) << "\"";
         }
         oss << "]";
         firstItem = false;
     }
     
     std::string Build() {
         oss << "}";
         return oss.str();
     }
     
 private:
     std::string EscapeJson(const std::string& str) {
         std::string escaped;
         for (char c : str) {
             switch (c) {
                 case '\"': escaped += "\\\""; break;
                 case '\\': escaped += "\\\\"; break;
                 case '\b': escaped += "\\b"; break;
                 case '\f': escaped += "\\f"; break;
                 case '\n': escaped += "\\n"; break;
                 case '\r': escaped += "\\r"; break;
                 case '\t': escaped += "\\t"; break;
                 default:
                     if (c < 32) {
                         char buf[8];
                         sprintf_s(buf, "\\u%04x", c);
                         escaped += buf;
                     } else {
                         escaped += c;
                     }
             }
         }
         return escaped;
     }
 };
 
 // ==================== HTTP Client ====================
 
 class HttpClient {
 private:
     HINTERNET hSession = nullptr;
     HINTERNET hConnect = nullptr;
     std::string serverUrl;
     std::string host;
     std::string basePath;
     int port;
     
 public:
     HttpClient(const std::string& url) : serverUrl(url) {
         ParseUrl(url);
         hSession = WinHttpOpen(L"CyberSentinel/1.0",
             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
             WINHTTP_NO_PROXY_NAME,
             WINHTTP_NO_PROXY_BYPASS, 0);
         
         if (hSession) {
             std::wstring whost(host.begin(), host.end());
             hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
         }
     }
     
     ~HttpClient() {
         if (hConnect) WinHttpCloseHandle(hConnect);
         if (hSession) WinHttpCloseHandle(hSession);
     }
     
     std::pair<int, std::string> Post(const std::string& path, const std::string& jsonData) {
         return SendRequest(L"POST", path, jsonData);
     }
     
     std::pair<int, std::string> Put(const std::string& path, const std::string& jsonData) {
         return SendRequest(L"PUT", path, jsonData);
     }
     
     std::pair<int, std::string> Delete(const std::string& path) {
         return SendRequest(L"DELETE", path, "");
     }
     
 private:
     void ParseUrl(const std::string& url) {
         // Parse: http(s)://host[:port][/path]
         //
         // SECURITY: a previous version of this function silently fell
         // back to a hardcoded LAN address (192.168.1.63) on parse
         // failure, which (a) shipped an internal IP in every binary
         // and (b) made misconfigured agents quietly attach to whatever
         // happened to live at that address. We now require a valid URL
         // and clear the host instead — SendRequest then refuses to send.
         std::regex urlRegex(R"(https?://([^:/]+):?(\d+)?(/.*)?$)");
         std::smatch match;
         if (std::regex_search(url, match, urlRegex)) {
             host = match[1].str();
             port = match[2].length() > 0 ? std::stoi(match[2].str()) : 55000;
             basePath = match[3].length() > 0 ? match[3].str() : "";
         } else {
             host = "";
             port = 0;
             basePath = "";
         }
     }
     
     std::pair<int, std::string> SendRequest(const wchar_t* method, const std::string& path, const std::string& data) {
         if (!hConnect) return {0, ""};
         
         // Combine base path with request path
         std::string fullPath = basePath + path;
         
         std::wstring wpath(fullPath.begin(), fullPath.end());
         HINTERNET hRequest = WinHttpOpenRequest(hConnect, method, wpath.c_str(),
             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
         
         if (!hRequest) return {0, ""};
         
         std::wstring headers = L"Content-Type: application/json\r\n";
         
         BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), -1,
             (LPVOID)data.c_str(), data.length(), data.length(), 0);
         
         if (!result) {
             WinHttpCloseHandle(hRequest);
             return {0, ""};
         }
         
         WinHttpReceiveResponse(hRequest, nullptr);
         
         DWORD statusCode = 0;
         DWORD statusCodeSize = sizeof(statusCode);
         WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
             nullptr, &statusCode, &statusCodeSize, nullptr);
         
         std::string response;
         DWORD bytesAvailable = 0;
         while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
             std::vector<char> buffer(bytesAvailable + 1);
             DWORD bytesRead = 0;
             if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                 response.append(buffer.data(), bytesRead);
             }
         }
         
         WinHttpCloseHandle(hRequest);
         return {statusCode, response};
     }
 };
 
 // ==================== Logger ====================
 
 class Logger {
    private:
        std::ofstream logFile;
        std::mutex logMutex;
        std::string logFilePath;
        std::chrono::system_clock::time_point lastRotationCheck;
        const size_t MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
        
    public:
        Logger(const std::string& filename = "cybersentinel_agent.log") {
            // Check if custom log directory is specified in environment
            const char* envLogDir = std::getenv("CYBERSENTINEL_LOG_DIR");
            std::string logDir = envLogDir ? envLogDir : "";
            
            if (!logDir.empty()) {
                // Use custom log directory
                logFilePath = logDir + "\\" + filename;
            } else {
                // Default to current directory
                logFilePath = filename;
            }
            
            OpenLogFile();
            lastRotationCheck = std::chrono::system_clock::now();
            
            Info("=================================================");
            Info("CyberSentinel DLP Agent Logger Initialized");
            Info("Log file: " + logFilePath);
            Info("=================================================");
        }
        
        ~Logger() {
            if (logFile.is_open()) {
                Info("Logger shutting down");
                logFile.close();
            }
        }
        
        void Info(const std::string& message) {
            Log("INFO", message);
        }
        
        void Warning(const std::string& message) {
            Log("WARNING", message);
        }
        
        void Error(const std::string& message) {
            Log("ERROR", message);
        }
        
        void Debug(const std::string& message) {
            Log("DEBUG", message);
        }
        
    private:
        void OpenLogFile() {
            logFile.open(logFilePath, std::ios::app);
            if (!logFile.is_open()) {
                std::cerr << "WARNING: Could not open log file: " << logFilePath << std::endl;
            }
        }
        
        void CheckAndRotateLog() {
            auto now = std::chrono::system_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - lastRotationCheck);
            
            // Check every 30 minutes
            if (elapsed.count() < 30) {
                return;
            }
            
            lastRotationCheck = now;
            
            try {
                // Check file size
                if (fs::exists(logFilePath)) {
                    size_t fileSize = fs::file_size(logFilePath);
                    
                    if (fileSize > MAX_LOG_SIZE) {
                        // Rotate log
                        if (logFile.is_open()) {
                            logFile.close();
                        }
                        
                        // Create rotated filename with timestamp
                        auto time_t_now = std::chrono::system_clock::to_time_t(now);
                        std::tm tm_now;
                        localtime_s(&tm_now, &time_t_now);
                        
                        char timestamp[32];
                        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", &tm_now);
                        
                        std::string rotatedPath = logFilePath + "." + timestamp;
                        
                        // Rename current log
                        fs::rename(logFilePath, rotatedPath);
                        
                        // Open new log file
                        OpenLogFile();
                        
                        Info("Log rotated: Previous log saved to " + rotatedPath);
                        Info("Log file size was: " + std::to_string(fileSize) + " bytes");
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Log rotation error: " << e.what() << std::endl;
            }
        }
        
void Log(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);

    // Log timestamps use Asia/Kolkata (IST). Event payloads sent to the
    // server continue to use UTC via GetCurrentTimestampISO().
    std::string timestamp = GetCurrentTimestampLocalIST();
    std::string logMsg = timestamp + " - CyberSentinelAgent - " + level + " - " + message;
    
    // Only output to console if window is visible (not in background mode)
    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow != NULL && IsWindowVisible(consoleWindow)) {
        std::cout << logMsg << std::endl;
    }
    
    if (logFile.is_open()) {
        logFile << logMsg << std::endl;
        logFile.flush();
    }
    
    // Check if log rotation is needed
    CheckAndRotateLog();
}
    };
 
 // ==================== Configuration ====================
 
 struct MonitoringConfig {
     bool fileSystem = true;
     bool clipboard = true;
     bool usbDevices = true;
     std::vector<std::string> monitoredPaths;
     std::vector<std::string> fileExtensions;
     bool transferBlockingEnabled = false;
     int pollIntervalSeconds = 5;
 };
 
 struct QuarantineConfig {
     bool enabled = true;
     std::string folder = "C:\\Quarantine";
 };
 
 struct ClassificationConfig {
     bool enabled = true;
     int maxFileSizeMB = 10;
 };
 
 class AgentConfig {
    private:
        MonitoringConfig monitoring;
        QuarantineConfig quarantine;
        ClassificationConfig classification;
        
    public:
        std::string agentId;
        std::string agentName;
        std::string serverUrl;
        int heartbeatInterval = 3;
        int policySyncInterval = 60;
        
        AgentConfig(const std::string& configPath = "agent_config.json") {
            // Try to load from file first
            if (!LoadFromFile(configPath)) {
                // If file doesn't exist or is invalid, load defaults
                LoadDefaults();
                SaveToFile(configPath);
            }
        }
        
        const MonitoringConfig& GetMonitoring() const { return monitoring; }
        const QuarantineConfig& GetQuarantine() const { return quarantine; }
        const ClassificationConfig& GetClassification() const { return classification; }
        
    private:
        void LoadDefaults() {
            // Default server URL: check environment variable, then use localhost
            const char* envUrl = std::getenv("CYBERSENTINEL_SERVER_URL");
            serverUrl = envUrl ? envUrl : "http://localhost:55000/api/v1";
            
            // Generate unique agent ID
            agentId = GenerateUUID();
            
            // Default agent name: hostname
            agentName = GetHostname();
            
            // Default intervals
            heartbeatInterval = 30;
            policySyncInterval = 60;
            
            // Monitoring config
            monitoring.fileSystem = true;
            monitoring.clipboard = true;
            monitoring.usbDevices = true;
            monitoring.transferBlockingEnabled = false;
            monitoring.pollIntervalSeconds = 5;
            
            // Get user profile for default paths
            char userProfile[MAX_PATH];
            if (SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile) == S_OK) {
                std::string profile(userProfile);
                monitoring.monitoredPaths = {
                    "C:\\Users\\Public\\Documents",
                    profile + "\\Documents",
                    profile + "\\Desktop",
                    profile + "\\Downloads"
                };
            }
            
            monitoring.fileExtensions = {
                ".pdf", ".docx", ".doc", ".xlsx", ".xls",
                ".csv", ".txt", ".json", ".xml", ".sql"
            };
            
            // Quarantine config
            quarantine.enabled = true;
            quarantine.folder = "C:\\Quarantine";
            
            // Classification config
            classification.enabled = true;
            classification.maxFileSizeMB = 10;
        }
        
        bool LoadFromFile(const std::string& path) {
            std::ifstream file(path);
            if (!file.is_open()) {
                return false;
            }
            
            std::string content((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
            file.close();
            
            if (content.empty()) {
                return false;
            }
            
            // Parse JSON manually (simple key-value extraction)
            try {
                // Extract server_url
                std::string extractedUrl = ExtractJsonValue(content, "server_url");
                if (!extractedUrl.empty()) {
                    serverUrl = extractedUrl;
                } else {
                    // Fallback to environment or default
                    const char* envUrl = std::getenv("CYBERSENTINEL_SERVER_URL");
                    serverUrl = envUrl ? envUrl : "http://localhost:55000/api/v1";
                }
                
                // Extract agent_name
                std::string extractedName = ExtractJsonValue(content, "agent_name");
                if (!extractedName.empty()) {
                    agentName = extractedName;
                } else {
                    agentName = GetHostname();
                }
                
                // Extract agent_id (or generate new one)
                std::string extractedId = ExtractJsonValue(content, "agent_id");
                if (!extractedId.empty()) {
                    agentId = extractedId;
                } else {
                    agentId = GenerateUUID();
                }
                
                // Extract heartbeat_interval
                std::string hbInterval = ExtractJsonValue(content, "heartbeat_interval");
                if (!hbInterval.empty()) {
                    heartbeatInterval = std::stoi(hbInterval);
                } else {
                    heartbeatInterval = 3;
                }
                
                // Extract policy_sync_interval
                std::string psInterval = ExtractJsonValue(content, "policy_sync_interval");
                if (!psInterval.empty()) {
                    policySyncInterval = std::stoi(psInterval);
                } else {
                    policySyncInterval = 60;
                }
                
                // Load other configs with defaults
                monitoring.fileSystem = true;
                monitoring.clipboard = true;
                monitoring.usbDevices = true;
                monitoring.transferBlockingEnabled = false;
                monitoring.pollIntervalSeconds = 5;
                
                char userProfile[MAX_PATH];
                if (SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile) == S_OK) {
                    std::string profile(userProfile);
                    monitoring.monitoredPaths = {
                        "C:\\Users\\Public\\Documents",
                        profile + "\\Documents",
                        profile + "\\Desktop",
                        profile + "\\Downloads"
                    };
                }
                
                monitoring.fileExtensions = {
                    ".pdf", ".docx", ".doc", ".xlsx", ".xls",
                    ".csv", ".txt", ".json", ".xml", ".sql"
                };
                
                quarantine.enabled = true;
                quarantine.folder = "C:\\Quarantine";
                
                classification.enabled = true;
                classification.maxFileSizeMB = 10;
                
                return true;
                
            } catch (...) {
                return false;
            }
        }

    public:
        std::string ExtractJsonValue(const std::string& json, const std::string& key) {
            size_t keyPos = json.find("\"" + key + "\"");
            if (keyPos == std::string::npos) return "";
            
            size_t colonPos = json.find(":", keyPos);
            if (colonPos == std::string::npos) return "";
            
            // Skip whitespace after colon
            size_t valueStart = colonPos + 1;
            while (valueStart < json.length() && std::isspace(json[valueStart])) {
                valueStart++;
            }
            
            if (valueStart >= json.length()) return "";
            
            // Check if value is a string (starts with ")
            if (json[valueStart] == '"') {
                size_t quoteEnd = json.find("\"", valueStart + 1);
                if (quoteEnd == std::string::npos) return "";
                return json.substr(valueStart + 1, quoteEnd - valueStart - 1);
            } else {
                // Number value
                size_t valueEnd = valueStart;
                while (valueEnd < json.length() && 
                       (std::isdigit(json[valueEnd]) || json[valueEnd] == '.' || json[valueEnd] == '-')) {
                    valueEnd++;
                }
                return json.substr(valueStart, valueEnd - valueStart);
            }
        }
        
        void SaveToFile(const std::string& path) {
            std::ofstream file(path);
            if (!file.is_open()) {
                std::cerr << "WARNING: Could not create config file: " << path << std::endl;
                return;
            }
            
            file << "{\n";
            file << "  \"server_url\": \"" << serverUrl << "\",\n";
            file << "  \"agent_id\": \"" << agentId << "\",\n";
            file << "  \"agent_name\": \"" << agentName << "\",\n";
            file << "  \"heartbeat_interval\": " << heartbeatInterval << ",\n";
            file << "  \"policy_sync_interval\": " << policySyncInterval << "\n";
            file << "}\n";
            
            file.close();
            
            std::cout << "Configuration saved to: " << path << std::endl;
        }
    };
 
 // ==================== Policy Rule Structure ====================
 
 struct PolicyRule {
    std::string policyId;
    std::string name;
    std::string policyType;
    std::string action;
    std::string severity;  // From server policy. Empty when the operator
                           // didn't pin a severity, in which case callers
                           // fall back to an action-derived guess.
    std::vector<std::string> dataTypes;
    std::vector<std::string> fileExtensions;
    std::vector<std::string> monitoredPaths;
    std::vector<std::string> monitoredEvents;  // NEW: e.g., ["file_created", "file_modified", "file_deleted"]
    int minMatchCount = 1;
    bool enabled = true;
    std::string quarantinePath;
};

// ==================== USB File Transfer Monitoring Structures ====================

struct FileMetadata {
    std::string name;
    std::string relativePath;
    time_t timestamp;
    bool inMonitored;
    std::string fullPath;
    ULONGLONG fileSize;
    FILETIME lastModified;
};

struct ShadowEntry {
    std::string lastKnownPath;
    time_t lastSeen;
    ULONGLONG fileSize;
    FILETIME lastModified;
};

struct USBFileTransferPolicy {
    std::string policyId;
    std::string name;
    std::string action;  // "block", "quarantine", "alert"
    std::string severity;  // From server policy
    std::vector<std::string> monitoredPaths;
    std::string quarantinePath;
    bool enabled;
};
 
 // ==================== Content Classifier ====================
 
 struct ClassificationResult {
     std::vector<std::string> labels;
     std::string severity;
     double score;
     std::string method;
     std::vector<std::string> matchedPolicies;
     std::string suggestedAction;
    std::string quarantinePath;  // Store quarantine path from matched policy
     std::map<std::string, std::vector<std::string>> detectedContent;  // dataType -> detected values
 };
 
 class ContentClassifier {
    public:
static ClassificationResult Classify(const std::string& content, 
                                const std::vector<PolicyRule>& policies,
                                const std::string& eventType = "") {
    ClassificationResult result;
    result.severity = "low";
    result.score = 0.0;
    result.method = "regex";
    result.suggestedAction = "logged";
    
    // If no policies provided, return empty result
    if (policies.empty()) {
        return result;
    }
    
    // Check content against each policy's data types
    for (const auto& policy : policies) {
        if (!policy.enabled) continue;
        
        // Check if policy monitors this event type (if eventType is specified)
        if (!eventType.empty() && !policy.monitoredEvents.empty()) {
            bool monitorsThisEvent = false;
            
            for (const auto& monitoredEvent : policy.monitoredEvents) {
                if (eventType == monitoredEvent || 
                    monitoredEvent == "all" || 
                    monitoredEvent == "*" ||
                    monitoredEvent == "clipboard") {
                    monitorsThisEvent = true;
                    break;
                }
            }
            
            if (!monitorsThisEvent) {
                continue;  // Skip this policy
            }
        }
        
        int matchCount = 0;
        std::vector<std::string> matchedTypes;
        
        // Check each data type specified in the policy
        for (const auto& dataType : policy.dataTypes) {
            std::vector<std::string> detectedValues = ExtractDataType(content, dataType);
            
            if (!detectedValues.empty()) {
                matchCount++;
                matchedTypes.push_back(dataType);
                result.detectedContent[dataType] = detectedValues;
                
                // Debug logging
                std::cout << "[DEBUG] Detected " << dataType << ": " << detectedValues.size() << " matches" << std::endl;
            }
        }
        
        // Check if policy threshold is met
        if (matchCount >= policy.minMatchCount && matchCount > 0) {
            result.matchedPolicies.push_back(policy.policyId);
            result.labels.insert(result.labels.end(), matchedTypes.begin(), matchedTypes.end());
            
            // Update severity based on policy action
            if (policy.action == "block" || policy.action == "quarantine") {
                result.severity = "critical";
                result.suggestedAction = policy.action;
            } else if (policy.action == "alert" && result.severity != "critical") {
                result.severity = "high";
                result.suggestedAction = "alerted";
            }
            
            result.score = 0.9;
        }
    }
    
    return result;
}
    
 private:
 static std::vector<std::string> ExtractDataType(const std::string& content, const std::string& dataType) {
    std::vector<std::string> results;
    std::string lowerType = ToLower(dataType);

    // DEBUG: Log what we're searching for
    std::cout << "[DEBUG] ExtractDataType: Searching for '" << dataType << "' (lowercase: '" << lowerType << "')" << std::endl;
    std::cout << "[DEBUG] Content length: " << content.length() << " chars" << std::endl;
    std::cout << "[DEBUG] Content preview: " << content.substr(0, std::min<size_t>(100, content.length())) << std::endl;
    
    // MAP SERVER PATTERN NAMES TO DETECTION LOGIC
    // Normalize pattern names from server to match our detection logic
    std::string mappedType = lowerType;
    
    if (lowerType == "aadhaar" || lowerType == "aadhaar_number") {
        mappedType = "aadhaar";
    } else if (lowerType == "pan" || lowerType == "pan_card") {
        mappedType = "pan";
    } else if (lowerType == "ifsc" || lowerType == "ifsc_code") {
        mappedType = "ifsc";
    } else if (lowerType == "email" || lowerType == "email_address") {
        mappedType = "email";
    } else if (lowerType == "phone" || lowerType == "indian_phone" || lowerType == "phone_number") {
        mappedType = "phone";
    } else if (lowerType == "credit_card" || lowerType == "card_number") {
        mappedType = "credit_card";
    } else if (lowerType == "ssn" || lowerType == "social_security") {
        mappedType = "ssn";
    } else if (lowerType == "api_key" || lowerType == "secret_key" || lowerType == "access_token" || lowerType == "api_key_in_code") {
        mappedType = "api_key";
    } else if (lowerType == "aws_key") {
        mappedType = "aws_key";
    } else if (lowerType == "password") {
        mappedType = "password";
    } else if (lowerType == "upi" || lowerType == "upi_id") {
        mappedType = "upi";
    } else if (lowerType == "source_code" || lowerType == "source_code_content" || lowerType == "code") {
        mappedType = "source_code";
    } else if (lowerType == "database_connection" || lowerType == "database_connection_string" || lowerType == "connection_string") {
        mappedType = "database_connection";
    } else if (lowerType == "ip_address") {
        mappedType = "ip_address";
    } else if (lowerType == "indian_bank_account" || lowerType == "bank_account") {
        mappedType = "indian_bank_account";
    } else if (lowerType == "micr" || lowerType == "micr_code") {
        mappedType = "micr";
    } else if (lowerType == "indian_dob" || lowerType == "dob" || lowerType == "date_of_birth") {
        mappedType = "indian_dob";
    } else if (lowerType == "private_key") {
        mappedType = "private_key";
    }
    
    std::cout << "[DEBUG] Mapped to detection type: '" << mappedType << "'" << std::endl;
    
    // Map data types to regex patterns and extract matches
    // C++ std::regex uses ECMAScript — no lookbehind support
    // Use \b word boundaries and post-match digit-count validation instead
    if (mappedType == "aadhaar") {
        // 12 digits in 4-4-4 format with space or dash separator (mandatory separator)
        std::regex pattern(R"(\b\d{4}[\s-]\d{4}[\s-]\d{4}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            std::string m = iter->str();
            std::string d; for (char c : m) if (std::isdigit(c)) d += c;
            if (d.length() == 12) results.push_back(m);
        }
    }
    else if (mappedType == "pan") {
        std::regex pattern(R"(\b[A-Z]{5}\d{4}[A-Z]\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "ifsc") {
        std::regex pattern(R"(\b[A-Z]{4}0[A-Z0-9]{6}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "email") {
        std::regex pattern(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "phone") {
        // Indian mobile: +91 prefix or starts with 6-9, exactly 10 digits
        std::regex inPattern(R"((?:\+91[\s.-]?|0)[6-9]\d{4}[\s.-]?\d{5})");
        std::sregex_iterator inIter(content.begin(), content.end(), inPattern);
        std::sregex_iterator end;
        for (; inIter != end && results.size() < 10; ++inIter) {
            std::string m = inIter->str();
            std::string d; for (char c : m) if (std::isdigit(c)) d += c;
            if (d.length() >= 10 && d.length() <= 12) results.push_back(m);
        }
        // US phone: must have separator — (XXX) XXX-XXXX or XXX-XXX-XXXX
        std::regex usPattern(R"((?:\+?1[\s.-])?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4})");
        std::sregex_iterator usIter(content.begin(), content.end(), usPattern);
        for (; usIter != end && results.size() < 10; ++usIter) {
            std::string m = usIter->str();
            std::string d; for (char c : m) if (std::isdigit(c)) d += c;
            if (d.length() >= 10 && d.length() <= 11) results.push_back(m);
        }
    }
    else if (mappedType == "credit_card") {
        // 16 digits with optional separators, Luhn validated
        std::regex pattern(R"(\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            std::string digits;
            for (char c : iter->str()) { if (std::isdigit(c)) digits += c; }
            if (digits.length() == 16) {
                int sum = 0;
                for (int i = digits.length() - 1; i >= 0; i--) {
                    int d = digits[i] - '0';
                    if ((digits.length() - 1 - i) % 2 == 1) { d *= 2; if (d > 9) d -= 9; }
                    sum += d;
                }
                if (sum % 10 == 0) results.push_back(iter->str());
            }
        }
    }
    else if (mappedType == "ssn") {
        std::regex pattern(R"(\b\d{3}-\d{2}-\d{4}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "api_key") {
        std::vector<std::regex> apiPatterns = {
            // Pattern 1: key=value or key: value or key = value format
            // Matches: api_key = "sk_live_abc123xyz"
            //          api_key: sk_live_abc123xyz
            //          secret_key="abc123"
            std::regex(R"((api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?)", std::regex::icase),
            
            // Pattern 2: Common API key formats (standalone)
            // Matches: sk_live_abc123xyz, pk_test_123456, api_key_abc123
            std::regex(R"(\b(sk|pk|api|key|secret|token)_(?:live|test|prod|dev|staging)?_?[A-Za-z0-9_\-]{8,}\b)", std::regex::icase),
            
            // Pattern 3: Stripe/similar format without underscore prefix
            // Matches: sk_live_51H8xY2abcDEF123456
            std::regex(R"(\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b)"),
            std::regex(R"(\bpk_(?:live|test)_[A-Za-z0-9]{10,}\b)"),
            
            // Pattern 4: Generic key in backticks or quotes
            // Matches: `sk_live_51H8xY2abcDEF123456`
            std::regex(R"([`'"]([A-Za-z0-9_\-]{15,})[`'"])"),
            
            // Pattern 5: JWT tokens (longer)
            std::regex(R"(\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)"),
            
            // Pattern 6: AWS style keys
            std::regex(R"(\b(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16,}\b)"),
            
            // Pattern 7: GitHub tokens
            std::regex(R"(\bgh[pousr]_[A-Za-z0-9]{36,}\b)"),
            
            // Pattern 8: Generic long alphanumeric that looks like a key (32+ chars)
            std::regex(R"(\b[A-Za-z0-9]{32,}\b)"),
            
            // Pattern 9: Hex keys (crypto/blockchain)
            std::regex(R"(\b0x[a-fA-F0-9]{40,}\b)"),
            
            // Pattern 10: Base64-like keys (40+ chars)
            std::regex(R"(\b[A-Za-z0-9+/]{40,}={0,2}\b)")
        };
        
        std::set<std::string> uniqueResults;  // Use set to avoid duplicates
        
        for (const auto& pattern : apiPatterns) {
            std::sregex_iterator iter(content.begin(), content.end(), pattern);
            std::sregex_iterator end;
            
            for (; iter != end && uniqueResults.size() < 10; ++iter) {
                std::string match = iter->str();
                
                // For patterns with capture groups, try to get the captured value
                if (iter->size() > 1 && !(*iter)[1].str().empty()) {
                    match = (*iter)[1].str();
                }
                if (iter->size() > 2 && !(*iter)[2].str().empty()) {
                    match = (*iter)[2].str();
                }
                
                // Clean up surrounding quotes/backticks if present
                if (!match.empty()) {
                    if (match.front() == '"' || match.front() == '\'' || match.front() == '`') {
                        match = match.substr(1);
                    }
                    if (!match.empty() && (match.back() == '"' || match.back() == '\'' || match.back() == '`')) {
                        match = match.substr(0, match.length() - 1);
                    }
                }
                
                // Only add if it looks like a real key (has letters and numbers, min 8 chars)
                if (match.length() >= 8) {
                    bool hasLetter = false, hasDigit = false;
                    for (char c : match) {
                        if (std::isalpha(c)) hasLetter = true;
                        if (std::isdigit(c)) hasDigit = true;
                    }
                    
                    // Must have both letters and digits to be a valid key
                    if (hasLetter && hasDigit) {
                        uniqueResults.insert(match);
                    }
                }
            }
        }
        
        // Convert set to vector
        for (const auto& match : uniqueResults) {
            results.push_back(match);
        }
    }
    else if (mappedType == "aws_key") {
        std::regex pattern(R"(\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "password") {
        std::regex pattern(R"(password\s*[:=]\s*[^\s\n]+)", std::regex::icase);
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 5; ++iter) {
            results.push_back("[REDACTED]");  // Don't show actual passwords
        }
    }
    else if (mappedType == "upi") {
        std::regex pattern(R"(\b[\w.-]+@(paytm|phonepe|ybl|okaxis|okhdfcbank|oksbi|okicici)\b)", std::regex::icase);
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "source_code") {
        std::regex pattern(R"(\b(function|def|class|public|private|protected|static|import|from|require|include|using|package)\s+\w+)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 5; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "database_connection") {
        std::vector<std::regex> dbPatterns = {
            // Pattern 1: JDBC connections
            std::regex(R"(jdbc:(mysql|postgresql|oracle|sqlserver|h2|derby)://[^\s\n;]+)", std::regex::icase),
            
            // Pattern 2: MongoDB connections
            std::regex(R"(mongodb(\+srv)?://[^\s\n]+)", std::regex::icase),
            
            // Pattern 3: Redis connections
            std::regex(R"(redis://[^\s\n]+)", std::regex::icase),
            
            // Pattern 4: PostgreSQL standard format
            std::regex(R"(postgresql://[^\s\n]+)", std::regex::icase),
            
            // Pattern 5: MySQL standard format
            std::regex(R"(mysql://[^\s\n]+)", std::regex::icase),
            
            // Pattern 6: Generic connection string with credentials
            std::regex(R"((Server|Data Source|Host)\s*=\s*[^;]+;\s*(Database|Initial Catalog)\s*=\s*[^;]+;\s*(User\s*Id|UID|Username)\s*=\s*[^;]+;\s*(Password|PWD)\s*=\s*[^;]+)", std::regex::icase),
            
            // Pattern 7: Generic URI with credentials
            std::regex(R"((https?|ftp)://[^\s:]+:[^\s@]+@[^\s/]+)", std::regex::icase),
            
            // Pattern 8: Database connection with user:pass@host format
            std::regex(R"(\b\w+://[^\s:]+:[^\s@]+@[^\s/:\n]+(?::\d+)?(?:/[^\s\n]*)?\b)", std::regex::icase)
        };
        
        for (const auto& pattern : dbPatterns) {
            std::sregex_iterator iter(content.begin(), content.end(), pattern);
            std::sregex_iterator end;
            for (; iter != end && results.size() < 10; ++iter) {
                std::string match = iter->str();
                // Avoid duplicates
                if (std::find(results.begin(), results.end(), match) == results.end()) {
                    results.push_back(match);
                }
            }
        }
    }
    else if (mappedType == "ip_address") {
        std::vector<std::regex> ipPatterns = {
            // IPv4
            std::regex(R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)"),
            
            // IPv6
            std::regex(R"(\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b)"),
            std::regex(R"(\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b)"),
            std::regex(R"(\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b)")
        };
        
        for (const auto& pattern : ipPatterns) {
            std::sregex_iterator iter(content.begin(), content.end(), pattern);
            std::sregex_iterator end;
            for (; iter != end && results.size() < 10; ++iter) {
                std::string match = iter->str();
                // Avoid duplicates
                if (std::find(results.begin(), results.end(), match) == results.end()) {
                    results.push_back(match);
                }
            }
        }
    }
    else if (mappedType == "indian_bank_account") {
        // Indian bank account: 9-18 digits
        std::regex pattern(R"(\b\d{9,18}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "micr") {
        // MICR code: 9 digits
        std::regex pattern(R"(\b\d{9}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "indian_dob") {
        // Date formats: DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY
        std::regex pattern(R"(\b\d{2}[/.-]\d{2}[/.-]\d{4}\b)");
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        for (; iter != end && results.size() < 10; ++iter) {
            results.push_back(iter->str());
        }
    }
    else if (mappedType == "private_key") {
        std::vector<std::regex> keyPatterns = {
            // Pattern 1: PEM format headers
            std::regex(R"(-----BEGIN[A-Z\s]+PRIVATE KEY-----)", std::regex::icase),
            
            // Pattern 2: SSH private key
            std::regex(R"(-----BEGIN OPENSSH PRIVATE KEY-----)", std::regex::icase),
            
            // Pattern 3: PuTTY private key
            std::regex(R"(PuTTY-User-Key-File-[0-9]:)", std::regex::icase),
            
            // Pattern 4: Generic private key indicator
            std::regex(R"(\bprivate[_-]?key\s*[:=]\s*[^\s\n]{20,})", std::regex::icase)
        };
        
        for (const auto& pattern : keyPatterns) {
            std::sregex_iterator iter(content.begin(), content.end(), pattern);
            std::sregex_iterator end;
            for (; iter != end && results.size() < 5; ++iter) {
                results.push_back("[PRIVATE_KEY_DETECTED]");
            }
        }
    }
    
    std::cout << "[DEBUG] ExtractDataType: Found " << results.size() << " matches for '" << mappedType << "'" << std::endl;
    
    return results;
}
     
     static bool MatchDataType(const std::string& content, const std::string& dataType) {
         return !ExtractDataType(content, dataType).empty();
     }
     
     static ClassificationResult ClassifyBasic(const std::string& content) {
         ClassificationResult result;
         result.severity = "low";
         result.score = 0.1;
         result.method = "regex";
         result.suggestedAction = "logged";
         
         // Basic detection without policies
         auto aadhaar = ExtractDataType(content, "aadhaar");
         if (!aadhaar.empty()) {
             result.labels.push_back("AADHAAR");
             result.detectedContent["AADHAAR"] = aadhaar;
             result.severity = "critical";
         }
         
         auto pan = ExtractDataType(content, "pan");
         if (!pan.empty()) {
             result.labels.push_back("PAN");
             result.detectedContent["PAN"] = pan;
             result.severity = "critical";
         }
         
         auto email = ExtractDataType(content, "email");
         if (!email.empty()) {
             result.labels.push_back("EMAIL");
             result.detectedContent["EMAIL"] = email;
             if (result.severity == "low") result.severity = "medium";
         }
         
         auto apiKey = ExtractDataType(content, "api_key");
         if (!apiKey.empty()) {
             result.labels.push_back("API_KEY");
             result.detectedContent["API_KEY"] = apiKey;
             result.severity = "high";
         }
         
         if (!result.labels.empty()) {
             result.score = 0.9;
         }
         
         return result;
     }
 };
 
 // ==================== DLP Agent ====================
 
 class DLPAgent {
 private:
     AgentConfig config;
     Logger logger;
     std::unique_ptr<HttpClient> httpClient;
     
     std::atomic<bool> running{false};
     std::atomic<bool> hasFilePolices{false};
     std::atomic<bool> hasClipboardPolicies{false};
     std::atomic<bool> hasUsbDevicePolicies{false};
     std::atomic<bool> hasUsbTransferPolicies{false};
     std::atomic<bool> allowEvents{false};
     
     std::string activePolicyVersion;
     std::string lastClipboard;
     std::string lastActiveWindow;
     std::string lastActiveFile;
     std::set<std::string> removableDrives;
     std::vector<std::string> monitoredDirectories;
     std::map<std::pair<std::string, std::string>, std::chrono::steady_clock::time_point> recentEvents;
     
     // Policy storage
     std::vector<PolicyRule> filePolicies;
     std::vector<PolicyRule> clipboardPolicies;
     std::vector<PolicyRule> usbPolicies;
     
     std::mutex policiesMutex;
     std::mutex eventsMutex;
     std::set<std::string> filesBeingQuarantined;
     std::mutex quarantineMutex;
     
     // Track recently restored files to prevent re-quarantining
     std::set<std::string> recentlyRestored;
     std::mutex restoredMutex;
     
     // Store original file contents for restoration
     std::map<std::string, std::string> originalFileContents;
     std::mutex originalContentsMutex;
     
     std::vector<std::thread> workerThreads;
     HWND usbMonitorWindow = nullptr;
     HDEVNOTIFY usbDevNotify = nullptr;
     // USB file transfer monitoring
     std::map<std::string, std::set<std::string>> usbDriveFiles;  // drive -> set of files
     std::mutex usbFilesMutex;
     std::map<std::string, std::string> usbDriveToDeviceId;  // drive letter -> device ID

     // USB File Transfer Monitoring
    std::map<std::string, FileMetadata> monitoredFiles;  // Key: relative path
    std::map<std::string, ShadowEntry> shadowCopies;     // For BLOCK mode
    std::map<std::string, bool> currentUSBFileState;     // Track if file is currently on USB (true = on USB, false = removed)
    std::set<std::string> quarantinedUSBFiles;
    std::vector<USBFileTransferPolicy> usbTransferPolicies;
    std::mutex usbTransferMutex;
    std::atomic<bool> usbBlockingActive{false};  // Track if USB blocking is currently active

     static DLPAgent* s_instance;
    
     static LRESULT CALLBACK UsbWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
         if (uMsg == WM_DEVICECHANGE && s_instance) {
             return s_instance->HandleDeviceChange(wParam, lParam);
         }
         return DefWindowProc(hwnd, uMsg, wParam, lParam);
     }
     
     LRESULT HandleDeviceChange(WPARAM wParam, LPARAM lParam) {
         switch (wParam) {
             case DBT_DEVICEARRIVAL: {
                 PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;
                 
                 if (pHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
                     DEV_BROADCAST_DEVICEINTERFACE_A* pDevInf = (DEV_BROADCAST_DEVICEINTERFACE_A*)pHdr;
                     std::string deviceName = GetDeviceDescription(pDevInf);
                     std::string deviceId = pDevInf->dbcc_name;
                     
                     logger.Info("USB device connected: " + deviceName);
                     
                     // Handle based on policy
                     HandleUsbDeviceArrival(deviceName, deviceId);
                 }
                 break;
             }
             
             case DBT_DEVICEREMOVECOMPLETE: {
                 PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;
                 
                 if (pHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
                     DEV_BROADCAST_DEVICEINTERFACE_A* pDevInf = (DEV_BROADCAST_DEVICEINTERFACE_A*)pHdr;
                     std::string deviceName = GetDeviceDescription(pDevInf);
                     std::string deviceId = pDevInf->dbcc_name;
                     
                     logger.Info("USB device disconnected: " + deviceName);
                     
                     // Handle disconnect event
                     HandleUsbEvent(deviceName, deviceId, "disconnect");
                     {
                        std::lock_guard<std::mutex> lock(usbFilesMutex);
                        
                        // Find and remove drive letter mapping
                        std::string driveToRemove;
                        for (const auto& [drive, devId] : usbDriveToDeviceId) {
                            if (devId == deviceId) {
                                driveToRemove = drive;
                                break;
                            }
                        }
                        
                        if (!driveToRemove.empty()) {
                            usbDriveFiles.erase(driveToRemove);
                            usbDriveToDeviceId.erase(driveToRemove);
                            logger.Info("Removed file tracking for drive: " + driveToRemove);
                        }
                    }
                 }
                 break;
             }
         }
         return 0;
     }
     
     void HandleUsbDeviceArrival(const std::string& deviceName, const std::string& deviceId) {
        if (!allowEvents || !hasUsbDevicePolicies) return;
    
        std::string betterDeviceName = GetBetterDeviceName(deviceId);
        
        std::cout << "[DEBUG] ===========================================" << std::endl;
        std::cout << "[DEBUG] HandleUsbDeviceArrival" << std::endl;
        std::cout << "[DEBUG] Device name: " << betterDeviceName << std::endl;
        std::cout << "[DEBUG] Device ID: " << deviceId << std::endl;
        
        // NEW: Find the drive letter for this USB device
        std::string driveLetter = GetDriveLetterForDevice(deviceId);
        if (!driveLetter.empty()) {
            std::cout << "[DEBUG] Drive letter: " << driveLetter << std::endl;
            
            // Store mapping
            {
                std::lock_guard<std::mutex> lock(usbFilesMutex);
                usbDriveToDeviceId[driveLetter] = deviceId;
            }
            
            logger.Info("USB drive mounted at: " + driveLetter);
        }
        
        std::cout << "[DEBUG] ===========================================" << std::endl;
         // Get USB policies
         std::vector<PolicyRule> policies;
         {
             std::lock_guard<std::mutex> lock(policiesMutex);
             policies = usbPolicies;
         }
         
         if (policies.empty()) return;
         
         // Check if any policy monitors connect events
         std::string policyAction = "log";
         std::string matchedPolicyId;
         std::string matchedPolicyName;
         bool shouldBlock = false;
         
         for (const auto& policy : policies) {
             if (!policy.enabled) continue;
             
             // Check if this policy monitors usb_connect
             for (const auto& event : policy.monitoredEvents) {
                 if (event == "usb_connect" || event == "all" || event == "*") {
                     policyAction = policy.action;
                     matchedPolicyId = policy.policyId;
                     matchedPolicyName = policy.name;
                     
                     if (policyAction == "block") {
                         shouldBlock = true;
                     }
                     break;
                 }
             }
             
             if (shouldBlock) break;
         }
         
// BLOCK ACTION
// BLOCK ACTION - only if blocking is currently active
if (shouldBlock && usbBlockingActive.load()) {
    logger.Warning("============================================================");
    logger.Warning(" USB DEVICE BLOCKED BY POLICY!");
    logger.Warning("============================================================");
    logger.Warning("  Device: " + betterDeviceName);
    logger.Warning("  Policy: " + matchedPolicyName);
    logger.Warning("  Action: BLOCKING device...");
    logger.Warning("============================================================");
    
    // CRITICAL FIX: Block IMMEDIATELY before device fully initializes
    bool blockSuccess = false;
    
    // Method 1: Registry block (prevents driver from loading)
    bool registryBlocked = BlockUSBStorageViaRegistry(true);
    if (registryBlocked) {
        logger.Info("✓ Step 1: Registry block applied");
        blockSuccess = true;
    }
    
    // Method 2: Disable existing devices (in case driver already loaded)
    Sleep(200); // Small delay for device enumeration
    bool devicesDisabled = DisableAllUSBStorageDevices();
    if (devicesDisabled) {
        logger.Info("✓ Step 2: Device(s) disabled");
        blockSuccess = true;
    }
    
    // Method 3: Aggressive blocking - Eject all removable drives
    DWORD driveMask = GetLogicalDrives();
    int ejectedCount = 0;
    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        if (driveMask & 1) {
            std::string drivePath = std::string(1, letter) + ":\\";
            UINT driveType = GetDriveTypeA(drivePath.c_str());
            
            if (driveType == DRIVE_REMOVABLE) {
                // Try to eject the drive
                std::string devicePath = "\\\\.\\" + std::string(1, letter) + ":";
                HANDLE hDevice = CreateFileA(
                    devicePath.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    0,
                    NULL
                );
                
                if (hDevice != INVALID_HANDLE_VALUE) {
                    DWORD bytesReturned;
                    if (DeviceIoControl(
                        hDevice,
                        IOCTL_STORAGE_EJECT_MEDIA,
                        NULL, 0,
                        NULL, 0,
                        &bytesReturned,
                        NULL
                    )) {
                        logger.Info("✓ Step 3: Ejected drive " + std::string(1, letter) + ":");
                        ejectedCount++;
                        blockSuccess = true;
                    }
                    CloseHandle(hDevice);
                }
            }
        }
        driveMask >>= 1;
    }
    
    if (ejectedCount > 0) {
        logger.Info("✓ Ejected " + std::to_string(ejectedCount) + " removable drive(s)");
    }
    
    // Final status
    if (blockSuccess) {
        logger.Warning("✅ USB DEVICE SUCCESSFULLY BLOCKED!");
        logger.Warning("   - Registry: " + std::string(registryBlocked ? "BLOCKED" : "FAILED"));
        logger.Warning("   - Devices: " + std::string(devicesDisabled ? "DISABLED" : "NONE FOUND"));
        logger.Warning("   - Drives: " + std::to_string(ejectedCount) + " EJECTED");
    } else {
        logger.Error("❌ FAILED TO BLOCK USB DEVICE");
        logger.Error("   Administrator rights may be required");
        logger.Error("   Please run the agent as Administrator");
    }
    logger.Warning("============================================================");
    
    // Send blocked event
    JsonBuilder json;
    json.AddString("event_id", GenerateUUID());
    json.AddString("event_type", "usb");
    json.AddString("event_subtype", "usb_blocked");
    json.AddString("agent_id", config.agentId);
    json.AddString("source_type", "agent");
    json.AddString("user_email", GetUsername() + "@" + GetHostname());
    json.AddString("description", "USB device blocked by policy: " + betterDeviceName);
    json.AddString("severity", "critical");
    json.AddString("action", "blocked");
    json.AddString("device_name", betterDeviceName);
    json.AddString("device_id", deviceId);
    json.AddString("policy_id", matchedPolicyId);
    json.AddString("policy_name", matchedPolicyName);
    json.AddBool("block_success", blockSuccess);
    json.AddBool("registry_blocked", registryBlocked);
    json.AddBool("devices_disabled", devicesDisabled);
    json.AddInt("drives_ejected", ejectedCount);
    json.AddString("timestamp", GetCurrentTimestampISO());
    
    SendEvent(json.Build());
    return;
} else if (shouldBlock && !usbBlockingActive.load()) {
    logger.Warning("============================================================");
    logger.Warning(" USB BLOCKING POLICY EXISTS BUT IS NOT ACTIVE");
    logger.Warning("============================================================");
    logger.Warning("  Device: " + betterDeviceName);
    logger.Warning("  Policy found but action changed to: " + policyAction);
    logger.Warning("  Device will be allowed (alert/log mode)");
    logger.Warning("============================================================");
    
    // Treat as alert instead
    HandleUsbEvent(betterDeviceName, deviceId, "connect");
    return;
}

// NORMAL CASE: Not blocking (alert/log policy)
// Always send connect event for monitoring
if (!shouldBlock) {
    logger.Info("USB device connected (non-blocking policy): " + betterDeviceName);
    HandleUsbEvent(betterDeviceName, deviceId, "connect");
}
     }

     bool BlockUSBStorageViaRegistry(bool block) {
        HKEY hKey;
        LONG result;
        
        result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, USB_STOR_REG_PATH, 0, KEY_SET_VALUE, &hKey);
        
        if (result != ERROR_SUCCESS) {
            logger.Error("Failed to open registry key for USB blocking - Administrator rights required");
            logger.Error("Error code: " + std::to_string(result));
            return false;
        }
        
        DWORD startValue = block ? 4 : 3; // 4 = Disabled, 3 = Manual
        result = RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE*)&startValue, sizeof(DWORD));
        RegCloseKey(hKey);
        
        if (result != ERROR_SUCCESS) {
            logger.Error("Failed to set registry value for USB blocking");
            logger.Error("Error code: " + std::to_string(result));
            return false;
        }
        
        logger.Info(block ? "✓ USB Storage driver DISABLED in registry" : "✓ USB Storage driver ENABLED in registry");
        
        // CRITICAL: Force Windows to reload the driver settings
        if (block) {
            // Stop the USBSTOR service immediately
            SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (schSCManager) {
                SC_HANDLE schService = OpenServiceA(schSCManager, "USBSTOR", SERVICE_STOP | SERVICE_QUERY_STATUS);
                if (schService) {
                    SERVICE_STATUS status;
                    ControlService(schService, SERVICE_CONTROL_STOP, &status);
                    CloseServiceHandle(schService);
                    logger.Info("✓ USBSTOR service stopped");
                }
                CloseServiceHandle(schSCManager);
            }
        }
        
        return true;
    }
     
     bool DisableDevice(HDEVINFO hDevInfo, PSP_DEVINFO_DATA pDevInfoData) {
         SP_PROPCHANGE_PARAMS propChangeParams;
         ZeroMemory(&propChangeParams, sizeof(SP_PROPCHANGE_PARAMS));
         
         propChangeParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
         propChangeParams.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
         propChangeParams.Scope = DICS_FLAG_CONFIGSPECIFIC;
         propChangeParams.HwProfile = 0;
         propChangeParams.StateChange = DICS_DISABLE;
         
         if (!SetupDiSetClassInstallParamsA(hDevInfo, pDevInfoData, 
             (SP_CLASSINSTALL_HEADER*)&propChangeParams, sizeof(propChangeParams))) {
             return false;
         }
         
         if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, pDevInfoData)) {
             return false;
         }
         
         return true;
     }
     
     bool DisableAllUSBStorageDevices() {
        HDEVINFO hDevInfo;
        SP_DEVINFO_DATA devInfoData;
        DWORD i;
        bool anyDisabled = false;
        int deviceCount = 0;
    
        // Get ALL USB storage devices (not just present ones)
        hDevInfo = SetupDiGetClassDevsA(NULL, "USBSTOR", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    
        if (hDevInfo == INVALID_HANDLE_VALUE) {
            logger.Error("Failed to get USB storage devices - Error: " + std::to_string(GetLastError()));
            return false;
        }
    
        devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
        for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
            char deviceID[256];
            if (SetupDiGetDeviceInstanceIdA(hDevInfo, &devInfoData, deviceID, sizeof(deviceID), NULL)) {
                if (strstr(deviceID, "USBSTOR") != NULL) {
                    deviceCount++;
                    
                    // Use ConfigManager API for more reliable disabling
                    DEVINST devInst = devInfoData.DevInst;
                    CONFIGRET cr = CM_Disable_DevNode(devInst, 0);
                    
                    if (cr == CR_SUCCESS) {
                        logger.Warning("✓ Disabled USB device: " + std::string(deviceID));
                        anyDisabled = true;
                    } else {
                        // Fallback to SetupDi method
                        if (DisableDevice(hDevInfo, &devInfoData)) {
                            logger.Warning("✓ Disabled USB device (fallback): " + std::string(deviceID));
                            anyDisabled = true;
                        } else {
                            logger.Error("✗ Failed to disable: " + std::string(deviceID));
                        }
                    }
                }
            }
        }
    
        SetupDiDestroyDeviceInfoList(hDevInfo);
        
        if (deviceCount == 0) {
            logger.Info("No USB storage devices found to disable");
        } else {
            logger.Info("Processed " + std::to_string(deviceCount) + " USB storage device(s)");
        }
        
        return anyDisabled;
    }
     
     bool EnableAllUSBStorageDevices() {
         HDEVINFO hDevInfo;
         SP_DEVINFO_DATA devInfoData;
         DWORD i;
         bool anyEnabled = false;
 
         hDevInfo = SetupDiGetClassDevsA(NULL, "USBSTOR", NULL, DIGCF_ALLCLASSES);
 
         if (hDevInfo == INVALID_HANDLE_VALUE) {
             return false;
         }
 
         devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
 
         for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
             char deviceID[256];
             if (SetupDiGetDeviceInstanceIdA(hDevInfo, &devInfoData, deviceID, sizeof(deviceID), NULL)) {
                 if (strstr(deviceID, "USBSTOR") != NULL) {
                     SP_PROPCHANGE_PARAMS propChangeParams;
                     ZeroMemory(&propChangeParams, sizeof(SP_PROPCHANGE_PARAMS));
                     
                     propChangeParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
                     propChangeParams.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
                     propChangeParams.Scope = DICS_FLAG_CONFIGSPECIFIC;
                     propChangeParams.HwProfile = 0;
                     propChangeParams.StateChange = DICS_ENABLE;
                     
                     if (SetupDiSetClassInstallParamsA(hDevInfo, &devInfoData, 
                         (SP_CLASSINSTALL_HEADER*)&propChangeParams, sizeof(propChangeParams))) {
                         if (SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData)) {
                             logger.Info("Enabled USB device: " + std::string(deviceID));
                             anyEnabled = true;
                         }
                     }
                 }
             }
         }
 
         SetupDiDestroyDeviceInfoList(hDevInfo);
         return anyEnabled;
     }
     
     std::string GetDeviceDescription(DEV_BROADCAST_DEVICEINTERFACE_A* pDevInf) {
         if (pDevInf && pDevInf->dbcc_name[0]) {
             std::string devName = pDevInf->dbcc_name;
             size_t pos = devName.find("#{");
             if (pos != std::string::npos) {
                 devName = devName.substr(0, pos);
             }
             // Extract vendor/product info
             size_t vidPos = devName.find("VID_");
             size_t pidPos = devName.find("PID_");
             if (vidPos != std::string::npos && pidPos != std::string::npos) {
                 return "USB Device (" + devName.substr(vidPos, 8) + " " + devName.substr(pidPos, 8) + ")";
             }
             return devName;
         }
         return "USB Device";
     }

     // USB File Transfer Helper Methods
    std::string GetRelativePathUSB(const std::string& fullPath, const std::string& basePath) {
        std::string normalizedFull = NormalizeFilesystemPath(fullPath);
        std::string normalizedBase = NormalizeFilesystemPath(basePath);
        
        if (normalizedFull.find(normalizedBase) == 0) {
            std::string relative = normalizedFull.substr(normalizedBase.length());
            if (!relative.empty() && (relative[0] == '\\' || relative[0] == '/')) {
                relative = relative.substr(1);
            }
            return relative;
        }
        return fullPath;
    }
    
    void ScanDirectoryRecursiveUSB(const std::string& dir, const std::string& basePath, 
                                   std::vector<std::pair<std::string, std::string>>& files) {
        try {
            for (const auto& entry : fs::recursive_directory_iterator(
                dir, fs::directory_options::skip_permission_denied)) {
                
                if (entry.is_regular_file()) {
                    std::string fullPath = entry.path().string();
                    std::string relativePath = GetRelativePathUSB(fullPath, basePath);
                    std::string fileName = entry.path().filename().string();
                    files.push_back(std::make_pair(fileName, relativePath));
                }
            }
        } catch (const std::exception& e) {
            logger.Debug("Error scanning directory: " + std::string(e.what()));
        }
    }
    
    void InitializeUSBFileTracking() {
        std::lock_guard<std::mutex> lock(usbTransferMutex);
        monitoredFiles.clear();
        shadowCopies.clear();
        
        // Initialize tracking for all monitored paths from policies
        for (const auto& policy : usbTransferPolicies) {
            if (!policy.enabled) continue;
            
            for (const auto& monitoredPath : policy.monitoredPaths) {
                std::string normalizedPath = NormalizeFilesystemPath(monitoredPath);
                
                if (!fs::exists(normalizedPath)) {
                    logger.Warning("USB transfer monitored path does not exist: " + monitoredPath);
                    continue;
                }
                
                std::vector<std::pair<std::string, std::string>> files;
                ScanDirectoryRecursiveUSB(normalizedPath, normalizedPath, files);
                
                logger.Info("USB File Transfer: Tracking " + std::to_string(files.size()) + 
                           " files in " + monitoredPath);
                
                for (const auto& filePair : files) {
                    FileMetadata meta;
                    meta.name = filePair.first;
                    meta.relativePath = filePair.second;
                    meta.timestamp = time(NULL);
                    meta.inMonitored = true;
                    meta.fullPath = normalizedPath + "\\" + filePair.second;
                    
                    try {
                        meta.fileSize = fs::file_size(meta.fullPath);
                        auto ftime = fs::last_write_time(meta.fullPath);
                        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                        auto cftime = std::chrono::system_clock::to_time_t(sctp);
                        
                        FILETIME ft;
                        ULARGE_INTEGER ull;
                        ull.QuadPart = (cftime * 10000000ULL) + 116444736000000000ULL;
                        ft.dwLowDateTime = ull.LowPart;
                        ft.dwHighDateTime = ull.HighPart;
                        meta.lastModified = ft;
                    } catch (...) {
                        meta.fileSize = 0;
                        GetSystemTimeAsFileTime(&meta.lastModified);
                    }
                    
                    std::string key = normalizedPath + ":" + filePair.second;
                    monitoredFiles[key] = meta;
                    
                    // For BLOCK mode: create shadow entry
                    if (policy.action == "block") {
                        ShadowEntry shadow;
                        shadow.lastKnownPath = meta.fullPath;
                        shadow.lastSeen = time(NULL);
                        shadow.fileSize = meta.fileSize;
                        shadow.lastModified = meta.lastModified;
                        shadowCopies[key] = shadow;
                    }
                }
            }
        }
        
        logger.Info("USB File Transfer: Initialized tracking for " + 
                   std::to_string(monitoredFiles.size()) + " files");
    }
    
void HandleUSBFileTransferBlock(const std::string& fileName, const std::string& relativePath,
                                const std::string& usbPath, const std::string& monitoredPath,
                                const USBFileTransferPolicy& policy) {
    std::string usbFile = usbPath + "\\" + fileName;
    std::string monitoredFile = monitoredPath + "\\" + relativePath;
    std::string fileKey = usbPath + ":" + fileName;
    
    bool existsInMonitored = fs::exists(monitoredFile);
    bool fileOnUSB = fs::exists(usbFile);
    
    if (!fileOnUSB) return;
    
    logger.Warning("============================================================");
    logger.Warning("  🚫 USB FILE TRANSFER BLOCKED!");
    logger.Warning("============================================================");
    logger.Warning("  File: " + relativePath);
    logger.Warning("  Policy: " + policy.name);
    logger.Warning("  Severity: " + policy.severity);
    
    
    try {
        std::string transferType;
        if (existsInMonitored) {
            // File was COPIED
            transferType = "copy";
            logger.Warning("  Transfer Type: COPY");
            fs::remove(usbFile);
            logger.Warning("  ✅ Deleted from USB");
        } else {
            // File was MOVED - restore from USB to monitored directory
            transferType = "move";
            logger.Warning("  Transfer Type: MOVE");
            
            // Create parent directories if needed
            size_t pos = relativePath.find_last_of("\\/");
            if (pos != std::string::npos) {
                std::string dirPath = monitoredPath + "\\" + relativePath.substr(0, pos);
                fs::create_directories(dirPath);
            }
            
            // Copy from USB back to monitored, then delete from USB
            fs::copy_file(usbFile, monitoredFile, fs::copy_options::overwrite_existing);
            logger.Warning("  ✅ Restored to monitored directory");
            
            fs::remove(usbFile);
            logger.Warning("  ✅ Deleted from USB");
            
            // Update shadow entry
            std::string key = monitoredPath + ":" + relativePath;
            ShadowEntry shadow;
            shadow.lastKnownPath = monitoredFile;
            shadow.lastSeen = time(NULL);
            shadow.fileSize = fs::file_size(monitoredFile);
            auto ftime = fs::last_write_time(monitoredFile);
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
            auto cftime = std::chrono::system_clock::to_time_t(sctp);
            FILETIME ft;
            ULARGE_INTEGER ull;
            ull.QuadPart = (cftime * 10000000ULL) + 116444736000000000ULL;
            ft.dwLowDateTime = ull.LowPart;
            ft.dwHighDateTime = ull.HighPart;
            shadow.lastModified = ft;
            shadowCopies[key] = shadow;
        }
        
        SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "blocked_" + transferType, 
                            policy.severity, policy.policyId, policy.name, true);
        
        logger.Warning("============================================================\n");
    } catch (const std::exception& e) {
        logger.Error("Failed to block USB transfer: " + std::string(e.what()));
        SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "block_failed", 
                            policy.severity, policy.policyId, policy.name, false);
        logger.Warning("============================================================\n");
    }
}
    
void HandleUSBFileTransferQuarantine(const std::string& fileName, const std::string& relativePath,
                                     const std::string& usbPath, const std::string& monitoredPath,
                                     const USBFileTransferPolicy& policy) {
    std::string usbFile = usbPath + "\\" + fileName;
    std::string monitoredFile = monitoredPath + "\\" + relativePath;
    std::string timestamp = std::to_string(time(NULL));
    std::string quarantinePath = policy.quarantinePath.empty() ? "C:\\Quarantine" : policy.quarantinePath;
    std::string quarantineFile = quarantinePath + "\\" + fileName + "_" + timestamp;
    std::string fileKey = usbPath + ":" + fileName;
    
    if (!fs::exists(usbFile)) return;
    
    bool existsInMonitored = fs::exists(monitoredFile);
    
    logger.Warning("============================================================");
    logger.Warning("  ⚠️ USB FILE TRANSFER QUARANTINED!");
    logger.Warning("============================================================");
    logger.Warning("  File: " + relativePath);
    logger.Warning("  Policy: " + policy.name);
    logger.Warning("  Severity: " + policy.severity);
    
    
    try {
        // Ensure quarantine directory exists
        fs::create_directories(quarantinePath);
        
        std::string transferType;
        if (existsInMonitored) {
            // File was COPIED
            transferType = "copy";
            logger.Warning("  Transfer Type: COPY");
            
            // Move from monitored to quarantine
            fs::rename(monitoredFile, quarantineFile);
            logger.Warning("  ✅ Moved to quarantine from monitored dir");
            
            // Delete from USB
            fs::remove(usbFile);
            logger.Warning("  ✅ Deleted from USB");
        } else {
            // File was MOVED
            transferType = "move";
            logger.Warning("  Transfer Type: MOVE");
            
            // Move from USB to quarantine
            fs::rename(usbFile, quarantineFile);
            logger.Warning("  ✅ Moved to quarantine from USB");
        }
        
        SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "quarantined_" + transferType, 
                            policy.severity, policy.policyId, policy.name, true);
        
        quarantinedUSBFiles.insert(fileName);
        
        // Schedule restoration in 2 minutes
        std::thread restoreThread([this, quarantineFile, monitoredFile, relativePath, 
                                  monitoredPath, fileName, policyName = policy.name]() {
            logger.Info("USB Quarantine [" + policyName + "]: Will restore in 2 minutes: " + relativePath);
            std::this_thread::sleep_for(std::chrono::minutes(2));
            
            try {
                // Create parent directories if needed
                size_t pos = relativePath.find_last_of("\\/");
                if (pos != std::string::npos) {
                    std::string dirPath = monitoredPath + "\\" + relativePath.substr(0, pos);
                    fs::create_directories(dirPath);
                }
                
                if (fs::exists(quarantineFile)) {
                    fs::rename(quarantineFile, monitoredFile);
                    logger.Info("✅ USB Quarantine [" + policyName + "]: Restored to monitored directory: " + relativePath);
                    
                    std::lock_guard<std::mutex> lock(usbTransferMutex);
                    quarantinedUSBFiles.erase(fileName);
                }
            } catch (const std::exception& e) {
                logger.Error("Failed to restore from USB quarantine: " + std::string(e.what()));
            }
        });
        restoreThread.detach();
        
        logger.Warning("  🕐 Scheduled restoration in 2 minutes");
        logger.Warning("============================================================\n");
        
    } catch (const std::exception& e) {
        logger.Error("Failed to quarantine USB transfer: " + std::string(e.what()));
        SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "quarantine_failed", 
                            policy.severity, policy.policyId, policy.name, false);
        logger.Warning("============================================================\n");
    }
}
    
void HandleUSBFileTransferAlert(const std::string& fileName, const std::string& relativePath,
                                const std::string& usbPath, const std::string& monitoredPath,
                                const USBFileTransferPolicy& policy) {
    std::string usbFile = usbPath + "\\" + fileName;
    std::string fileKey = usbPath + ":" + fileName;
    
    if (!fs::exists(usbFile)) return;
    
    logger.Warning("============================================================");
    logger.Warning("  ⚠️ USB FILE TRANSFER ALERT!");
    logger.Warning("============================================================");
    logger.Warning("  File: " + relativePath);
    logger.Warning("  Source: " + monitoredPath);
    logger.Warning("  Destination: " + usbFile);
    logger.Warning("  Policy: " + policy.name);
    logger.Warning("  Severity: " + policy.severity);
    logger.Warning("  Timestamp: " + GetCurrentTimestampISO());
    logger.Warning("============================================================\n");
    
    
    SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "alerted", 
                        policy.severity, policy.policyId, policy.name, true);
}
    
void SendUSBTransferEvent(const std::string& relativePath, const std::string& usbFile,
                         const std::string& monitoredPath, const std::string& action,
                         const std::string& severity, const std::string& policyId,
                         const std::string& policyName, bool success,
                         const std::string& classificationLevel = "",
                         double confidenceScore = 0.0,
                         const std::vector<std::string>& classificationLabels = {}) {
    try {
        std::string fileName = fs::path(relativePath).filename().string();
        size_t fileSize = 0;
        std::string fileHash = "";

        // Try to get file info from monitored directory first
        std::string sourceFile = monitoredPath + "\\" + relativePath;
        if (fs::exists(sourceFile)) {
            fileSize = fs::file_size(sourceFile);
            try {
                fileHash = CalculateFileHash(sourceFile);
            } catch (...) {}
        } else if (fs::exists(usbFile)) {
            // Fallback to USB file
            try {
                fileSize = fs::file_size(usbFile);
                fileHash = CalculateFileHash(usbFile);
            } catch (...) {}
        }

        std::string description = "USB File Transfer " + action;
        description += "\nFile: " + fileName;
        description += "\nSource: " + monitoredPath;
        description += "\nDestination: " + usbFile;
        description += "\nPolicy: " + policyName;
        description += "\nSize: " + std::to_string(fileSize) + " bytes";

        JsonBuilder json;
        json.AddString("event_id", GenerateUUID());
        json.AddString("event_type", "usb");
        json.AddString("event_subtype", "usb_file_transfer");
        json.AddString("agent_id", config.agentId);
        json.AddString("source_type", "agent");
        json.AddString("user_email", GetUsername() + "@" + GetHostname());
        json.AddString("description", description);
        json.AddString("severity", severity);
        json.AddString("action", action);
        json.AddString("file_name", fileName);
        json.AddString("file_path", relativePath);
        json.AddInt("file_size", static_cast<int>(fileSize));
        json.AddString("source_path", monitoredPath);
        json.AddString("destination_path", usbFile);
        json.AddString("policy_id", policyId);
        json.AddString("policy_name", policyName);
        json.AddBool("success", success);

        if (!fileHash.empty()) {
            json.AddString("file_hash", fileHash);
        }

        // Add classification data if provided
        if (!classificationLevel.empty()) {
            json.AddString("classification_level", classificationLevel);
            json.AddDouble("classification_score", confidenceScore);

            // Add classification labels array
            if (!classificationLabels.empty()) {
                json.AddArray("classification_labels", classificationLabels);
            }
        }

        json.AddString("timestamp", GetCurrentTimestampISO());

        SendEvent(json.Build());

        logger.Info("✅ Event sent to server: " + action + " - " + fileName);
    } catch (const std::exception& e) {
        logger.Error("Failed to send USB transfer event: " + std::string(e.what()));
    }
}
    std::string ExtractSeverityFromPolicyJson(const std::string& bundleJson, const std::string& policyId) {
    // Find the policy by ID in the JSON
    size_t idPos = bundleJson.find("\"id\":\"" + policyId + "\"");
    if (idPos == std::string::npos) return "medium";  // Default
    
    // Search backwards to find the start of this policy object
    size_t policyStart = bundleJson.rfind("{", idPos);
    if (policyStart == std::string::npos) return "medium";
    
    // Search forwards to find the end of this policy object
    size_t policyEnd = FindMatchingBracket(bundleJson, policyStart, '{', '}');
    if (policyEnd == std::string::npos) return "medium";
    
    std::string policyObj = bundleJson.substr(policyStart, policyEnd - policyStart + 1);
    
    // Extract severity
    std::string severity = ExtractJsonString(policyObj, "severity");
    return severity.empty() ? "medium" : severity;
}
     
 public:
     DLPAgent(const std::string& configPath = "agent_config.json") 
         : config(configPath) {
         
         httpClient = std::make_unique<HttpClient>(config.serverUrl);
         
         if (config.GetQuarantine().enabled) {
             try {
                 fs::create_directories(config.GetQuarantine().folder);
                 logger.Info("Quarantine folder configured: " + config.GetQuarantine().folder);
             } catch (...) {
                 logger.Error("Failed to create quarantine folder");
             }
         }
         
         logger.Info("Agent initialized: " + config.agentId);
         logger.Info("Agent name: " + config.agentName);
         logger.Info("Server URL: " + config.serverUrl);
     }
     
     ~DLPAgent() {
        try {
            logger.Info("Cleaning up agent...");
            
            // Re-enable USB devices if they were blocked
            if (hasUsbDevicePolicies) {
                logger.Info("Re-enabling USB storage...");
                EnableAllUSBStorageDevices();
                BlockUSBStorageViaRegistry(false);
                logger.Info("USB storage access restored");
            }
            
            Stop();
        } catch (const std::exception& e) {
            std::cerr << "Error during cleanup: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Unknown error during cleanup" << std::endl;
        }
    }

    const AgentConfig& GetConfig() const {
        return config;
    }
     
     void Start() {
         logger.Info("Starting CyberSentinel DLP Agent...");
         logger.Info("Server URL: " + config.serverUrl);
         logger.Info("Agent ID: " + config.agentId);
         
         running = true;
         
         // Test server connectivity
         logger.Info("Testing server connectivity...");
         RegisterAgent();
         
         logger.Info("Fetching initial policies...");
         SyncPolicies(true);
         if (allowEvents && hasFilePolices) {
            logger.Info("Scanning existing files to establish baselines...");
            ScanAndStoreExistingFiles();
        }
         
         if (!allowEvents) {
             logger.Warning("==============================================");
             logger.Warning("WARNING: No active policies found!");
             logger.Warning("The agent will continue running but won't");
             logger.Warning("generate events until policies are configured");
             logger.Warning("on the server.");
             logger.Warning("==============================================");
         }
         
         workerThreads.emplace_back(&DLPAgent::HeartbeatLoop, this);
         workerThreads.emplace_back(&DLPAgent::PolicySyncLoop, this);
         workerThreads.emplace_back(&DLPAgent::ClipboardMonitor, this);
         workerThreads.emplace_back(&DLPAgent::UsbMonitor, this);
         workerThreads.emplace_back(&DLPAgent::FileSystemMonitor, this);
        // workerThreads.emplace_back(&DLPAgent::RemovableDriveMonitor, this);
         workerThreads.emplace_back(&DLPAgent::UsbFileTransferMonitor, this);
         workerThreads.emplace_back(&DLPAgent::MonitorUSBTransferDirectories, this);

         // ── Screen Capture Monitor ──
         // Multi-method text extraction + classification:
         //   1) Window title keywords (instant)
         //   2) Window text via WM_GETTEXT + EnumChildWindows (reads ALL visible text)
         //   3) File content from disk (if editor with filename in title)
         auto screenClassifier = [this](const std::string& windowTitle, const std::string& processName) -> std::string {

             // Luhn checksum — eliminates random 16-digit sequences (IMEIs,
             // serial numbers, GSTIN suffixes) from being mis-classified as
             // credit cards. Real PANs always pass Luhn.
             auto luhnValid = [](const std::string& s) -> bool {
                 std::string digits;
                 for (char c : s) if (c >= '0' && c <= '9') digits += c;
                 if (digits.size() < 13 || digits.size() > 19) return false;
                 int sum = 0;
                 bool alt = false;
                 for (int i = (int)digits.size() - 1; i >= 0; --i) {
                     int d = digits[i] - '0';
                     if (alt) { d *= 2; if (d > 9) d -= 9; }
                     sum += d;
                     alt = !alt;
                 }
                 return (sum % 10) == 0;
             };

             // Shared: classify any text using regex patterns.
             // Logs every matched pattern name + the actual matched text so
             // we can tell at a glance why a file was flagged.
             auto classifyText = [this, luhnValid](const std::string& content, const std::string& source) -> std::string {
                 if (content.empty()) return "Public";
                 static const std::vector<std::pair<std::string, std::regex>> patterns = {
                     {"AADHAAR",     std::regex(R"(\b\d{4}[\s-]\d{4}[\s-]\d{4}\b)")},
                     {"PAN",         std::regex(R"(\b[A-Z]{5}\d{4}[A-Z]\b)")},
                     {"CREDIT_CARD", std::regex(R"(\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)")},
                     {"SSN",         std::regex(R"(\b\d{3}-\d{2}-\d{4}\b)")},
                     {"PRIVATE_KEY", std::regex(R"(-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----)")},
                     {"AWS_KEY",     std::regex(R"(AKIA[0-9A-Z]{16})")},
                     {"IFSC",        std::regex(R"(\b[A-Z]{4}0[A-Z0-9]{6}\b)")},
                 };
                 float score = 0.0f;
                 std::vector<std::string> matchedNames;
                 for (const auto& [name, pattern] : patterns) {
                     try {
                         auto it  = std::sregex_iterator(content.begin(), content.end(), pattern);
                         auto end = std::sregex_iterator();
                         bool fired = false;
                         std::string sample;
                         for (; it != end; ++it) {
                             std::string m = it->str();
                             // CREDIT_CARD: drop matches that don't pass Luhn.
                             // This kills the most common false positive
                             // (any 16 digits in a row).
                             if (name == "CREDIT_CARD" && !luhnValid(m)) {
                                 continue;
                             }
                             fired = true;
                             sample = m;
                             if (sample.size() > 60) sample.resize(60);
                             break;
                         }
                         if (fired) {
                             logger.Warning("CLASSIFIER_MATCH [" + source + "] pattern=" + name +
                                            " matched=\"" + sample + "\"");
                             matchedNames.push_back(name);
                             if (name == "CREDIT_CARD" || name == "SSN" || name == "AADHAAR" ||
                                 name == "PRIVATE_KEY" || name == "AWS_KEY") score += 0.9f;
                             else if (name == "PAN" || name == "IFSC") score += 0.7f;
                         }
                     } catch (...) {}
                 }
                 std::string result;
                 if (score >= 0.8f)      result = "Restricted";
                 else if (score >= 0.6f) result = "Confidential";
                 else if (score >= 0.3f) result = "Internal";
                 else                    result = "Public";
                 if (!matchedNames.empty()) {
                     std::string joined;
                     for (size_t i = 0; i < matchedNames.size(); ++i) {
                         if (i) joined += ",";
                         joined += matchedNames[i];
                     }
                     logger.Info("CLASSIFIER_VERDICT [" + source + "] score=" +
                                 std::to_string(score) + " patterns=[" + joined +
                                 "] => " + result);
                 }
                 return result;
             };

             // ── Stage 1: Window title keywords (microseconds) ──
             std::string lower = windowTitle;
             std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
             static const std::vector<std::string> restrictedKw = {
                 "restricted", "confidential", "secret", "classified",
                 "employee", "salary", "payroll", "ssn", "aadhaar",
                 "credit card", "bank account", "password", "private key"
             };
             for (const auto& kw : restrictedKw) {
                 if (lower.find(kw) != std::string::npos) return "Restricted";
             }

             // ── Stage 2: Read ALL visible text from foreground window ──
             // Uses EnumChildWindows to find ALL text controls and reads their content.
             // Works for Notepad, WordPad, browsers, terminals, most applications.
             HWND fgWnd = GetForegroundWindow();
             if (fgWnd) {
                 std::string allText;

                 // Callback to collect text from all child windows
                 struct EnumData { std::string* text; };
                 EnumData data{&allText};

                 EnumChildWindows(fgWnd, [](HWND hwnd, LPARAM lParam) -> BOOL {
                     // CRITICAL: skip hidden child windows. Win11 Notepad
                     // (and any tabbed editor) keeps every tab's edit
                     // control as a child of the same top-level window;
                     // only the active tab is visible. Without this guard
                     // we'd read sensitive data from BACKGROUND tabs the
                     // user can't even see and incorrectly classify the
                     // foreground tab as sensitive.
                     if (!IsWindowVisible(hwnd)) return TRUE;

                     EnumData* d = (EnumData*)lParam;
                     int len = (int)SendMessageA(hwnd, WM_GETTEXTLENGTH, 0, 0);
                     if (len > 0 && len < 500000) {
                         int readLen = std::min(len, 65536);
                         std::vector<char> buf(readLen + 1, 0);
                         SendMessageA(hwnd, WM_GETTEXT, readLen + 1, (LPARAM)buf.data());
                         if (buf[0] != 0) {
                             *(d->text) += std::string(buf.data()) + "\n";
                         }
                     }
                     return TRUE; // Continue enumeration
                 }, (LPARAM)&data);

                 // Also try the main window itself
                 {
                     int len = (int)SendMessageA(fgWnd, WM_GETTEXTLENGTH, 0, 0);
                     if (len > 0 && len < 500000) {
                         int readLen = std::min(len, 65536);
                         std::vector<char> buf(readLen + 1, 0);
                         SendMessageA(fgWnd, WM_GETTEXT, readLen + 1, (LPARAM)buf.data());
                         allText += std::string(buf.data()) + "\n";
                     }
                 }

                 if (allText.length() > 10) {
                     logger.Debug("Screen text extracted: " + std::to_string(allText.length()) + " chars from window");
                     std::string result = classifyText(allText, "stage2-wm_gettext:" + windowTitle);
                     if (result != "Public") return result;
                 }
             }

             // ── Stage 3: File content from disk ──
             auto dashPos = windowTitle.find(" - ");
             if (dashPos != std::string::npos) {
                 std::string candidate = windowTitle.substr(0, dashPos);
                 while (!candidate.empty() && (candidate[0] == ' ' || candidate[0] == '*')) candidate.erase(0, 1);
                 while (!candidate.empty() && candidate.back() == ' ') candidate.pop_back();

                 if (!candidate.empty()) {
                     char userProfile[MAX_PATH] = {0};
                     GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH);
                     std::string up(userProfile);
                     std::vector<std::string> paths = {
                         up + "\\Desktop\\" + candidate, up + "\\Documents\\" + candidate,
                         up + "\\Downloads\\" + candidate, up + "\\OneDrive\\Desktop\\" + candidate,
                     };
                     for (const auto& path : paths) {
                         if (fs::exists(path) && fs::is_regular_file(path)) {
                             try {
                                 std::ifstream f(path, std::ios::binary);
                                 if (f.is_open()) {
                                     std::vector<char> buf(65536);
                                     f.read(buf.data(), buf.size());
                                     std::string content(buf.data(), f.gcount());
                                     f.close();
                                     std::string result = classifyText(content, "stage3-file:" + path);
                                     if (result != "Public") return result;
                                 }
                             } catch (...) {}
                             break;
                         }
                     }
                 }
             }

             // ── Stage 4: Tesseract OCR on the FOREGROUND WINDOW RECT ──
             // Scoped to the currently-active window only — NOT the full
             // desktop. This prevents a hidden/background window with
             // stale sensitive content (or Tesseract noise on wallpaper /
             // icons) from poisoning the classification of the window the
             // user is actually looking at.
             //
             // Requires: choco install tesseract -y (on Windows endpoint)
             if (fgWnd) {
                 try {
                     RECT wr{};
                     if (GetWindowRect(fgWnd, &wr)) {
                         int x = wr.left, y = wr.top;
                         int w = wr.right  - wr.left;
                         int h = wr.bottom - wr.top;

                         // Clamp to virtual screen to avoid weirdness.
                         int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
                         int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
                         int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
                         int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
                         if (x < vx) { w -= (vx - x); x = vx; }
                         if (y < vy) { h -= (vy - y); y = vy; }
                         if (x + w > vx + vw) w = (vx + vw) - x;
                         if (y + h > vy + vh) h = (vy + vh) - y;

                         if (w > 16 && h > 16) {
                             std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp");
                             std::string tempBmp = tempDir + "\\cs_ocr_fg.bmp";
                             std::string tempTxt = tempDir + "\\cs_ocr_fg_result";

                             HDC hScreenDC = GetDC(NULL);
                             HDC hMemDC    = CreateCompatibleDC(hScreenDC);
                             HBITMAP hBmp  = CreateCompatibleBitmap(hScreenDC, w, h);
                             HGDIOBJ old   = SelectObject(hMemDC, hBmp);
                             BitBlt(hMemDC, 0, 0, w, h, hScreenDC, x, y, SRCCOPY);

                             BITMAPINFOHEADER bi = {};
                             bi.biSize = sizeof(bi); bi.biWidth = w; bi.biHeight = -h;
                             bi.biPlanes = 1; bi.biBitCount = 24; bi.biCompression = BI_RGB;
                             int rowSz = ((w * 3 + 3) & ~3);
                             bi.biSizeImage = rowSz * h;
                             std::vector<BYTE> px(bi.biSizeImage);
                             GetDIBits(hMemDC, hBmp, 0, h, px.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

                             BITMAPFILEHEADER bf = {};
                             bf.bfType = 0x4D42;
                             bf.bfOffBits = sizeof(bf) + sizeof(bi);
                             bf.bfSize = bf.bfOffBits + bi.biSizeImage;

                             HANDLE hF = CreateFileA(tempBmp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                             if (hF != INVALID_HANDLE_VALUE) {
                                 DWORD wrBytes;
                                 WriteFile(hF, &bf, sizeof(bf), &wrBytes, NULL);
                                 WriteFile(hF, &bi, sizeof(bi), &wrBytes, NULL);
                                 WriteFile(hF, px.data(), bi.biSizeImage, &wrBytes, NULL);
                                 CloseHandle(hF);
                             }
                             SelectObject(hMemDC, old);
                             DeleteObject(hBmp); DeleteDC(hMemDC); ReleaseDC(NULL, hScreenDC);

                             std::string tessCmd = "tesseract \"" + tempBmp + "\" \"" + tempTxt + "\" --psm 6 -l eng 2>nul";
                             int tessResult = system(tessCmd.c_str());

                             std::string ocrText;
                             std::string ocrFile = tempTxt + ".txt";
                             if (tessResult == 0) {
                                 std::ifstream ifs(ocrFile);
                                 if (ifs.is_open()) {
                                     std::stringstream ss; ss << ifs.rdbuf();
                                     ocrText = ss.str();
                                     ifs.close();
                                 }
                             }

                             DeleteFileA(tempBmp.c_str());
                             DeleteFileA(ocrFile.c_str());

                             if (ocrText.length() > 10) {
                                 logger.Debug("Tesseract OCR (foreground window) extracted " +
                                              std::to_string(ocrText.length()) + " chars");
                                 std::string result = classifyText(ocrText, "stage4-ocr:" + windowTitle);
                                 if (result != "Public") {
                                     logger.Info("OCR detected sensitive content in foreground window: " + result);
                                     return result;
                                 }
                             }
                         }
                     }
                 } catch (...) {
                     logger.Debug("Tesseract OCR unavailable — install with: choco install tesseract -y");
                 }
             }

             return "Public";
         };

         auto screenMonitor = std::make_shared<ScreenCaptureMonitor>(
             [this](ScreenCaptureEvent& event) {
                 // Send event to server
                 JsonBuilder json;
                 json.AddString("event_id", GenerateUUID());
                 json.AddString("event_type", "screen_capture");
                 json.AddString("event_subtype", event.method);
                 json.AddString("agent_id", config.agentId);
                 json.AddString("source_type", "agent");
                 json.AddString("user_email", event.user + "@" + config.agentName);
                 json.AddString("description", event.containsSensitiveData
                     ? "SCREEN CAPTURE BLOCKED: " + event.classification + " data visible in " + event.activeWindow
                     : "Screen capture detected — no sensitive data");
                 json.AddString("severity", event.containsSensitiveData ? "high" : "low");
                 json.AddString("action", event.actionTaken == "Block" ? "blocked" : "allowed");
                 json.AddString("classification_level", event.classification);
                 json.AddBool("blocked", event.actionTaken == "Block");
                 json.AddString("timestamp", GetCurrentTimestampISO());
                 SendEvent(json.Build());
             },
             [this](const std::string& level, const std::string& msg) {
                 if (level == "WARNING") logger.Warning(msg);
                 else if (level == "ERROR") logger.Error(msg);
                 else logger.Info(msg);
             },
             screenClassifier
         );
         screenMonitor->Start();
         logger.Info("Screen capture monitoring started");

         // ── Print Monitor ──
         auto printClassifier = [this](const std::string& docName, const std::string& processName) -> std::string {
             std::string lower = docName;
             std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
             static const std::vector<std::string> restrictedKeywords = {
                 "restricted", "confidential", "secret", "classified", "sensitive",
                 "employee", "salary", "payroll", "ssn", "aadhaar", "pan",
                 "credit card", "bank", "account", "password", "private"
             };
             static const std::vector<std::string> internalKeywords = {
                 "internal", "draft", "budget", "financial", "revenue"
             };
             for (const auto& kw : restrictedKeywords) {
                 if (lower.find(kw) != std::string::npos) return "Restricted";
             }
             for (const auto& kw : internalKeywords) {
                 if (lower.find(kw) != std::string::npos) return "Internal";
             }
             return "Public";
         };

         auto printMonitor = std::make_shared<PrintMonitor>(
             [this](PrintEvent& event) {
                 JsonBuilder json;
                 json.AddString("event_id", GenerateUUID());
                 json.AddString("event_type", "print");
                 json.AddString("event_subtype", "print_job");
                 json.AddString("agent_id", config.agentId);
                 json.AddString("source_type", "agent");
                 json.AddString("user_email", event.user + "@" + config.agentName);
                 json.AddString("description", event.actionTaken == "Block"
                     ? "PRINT JOB BLOCKED: " + event.documentName + " — " + event.category + " data"
                     : "Print job: " + event.documentName);
                 json.AddString("severity", event.actionTaken == "Block" ? "high" : "low");
                 json.AddString("action", event.actionTaken == "Block" ? "blocked" : "allowed");
                 json.AddString("classification_level", event.category);
                 json.AddBool("blocked", event.actionTaken == "Block");
                 json.AddString("file_path", event.documentName);
                 json.AddString("timestamp", GetCurrentTimestampISO());
                 SendEvent(json.Build());
             },
             [this](const std::string& level, const std::string& msg) {
                 if (level == "WARNING") logger.Warning(msg);
                 else if (level == "ERROR") logger.Error(msg);
                 else logger.Info(msg);
             },
             printClassifier
         );
         printMonitor->Start();
         logger.Info("Print monitoring started");

         // ── Network Exfiltration Monitor ──
         // ISOLATED module. Callbacks bridge it to the existing classifier,
         // event sender, and logger. Handles curl / wget / PowerShell /
         // bitsadmin / certutil / python with pre-send blocking, and browser
         // file-dialog selection with alert-only detection. No hooks installed
         // in other processes; all monitoring happens via WMI and UIAutomation
         // from within this agent process. See network_exfil_monitor.{h,cpp}.
         {
             NetworkExfilMonitor::Config nemCfg;
             nemCfg.agentId   = config.agentId;
             nemCfg.agentName = config.agentName;
             nemCfg.username  = GetUsername();
             nemCfg.hostname  = GetHostname();

             nemCfg.classify = [this](const std::string& content,
                                      const std::string& /*eventType*/) {
                 // Use the DEDICATED network-exfil classifier. It has its own
                 // regex patterns, Luhn validation, and canonical labels, and
                 // does NOT touch ContentClassifier / ExtractDataType - so
                 // clipboard / USB / file / screen-capture classification
                 // logic remains completely unchanged.
                 NetworkExfilMonitor::ClassifyResult out =
                     NetworkExfilMonitor::ClassifyNetworkContent(content);

                 std::string labelStr;
                 for (const auto& l : out.labels) {
                     if (!labelStr.empty()) labelStr += ",";
                     labelStr += l;
                 }
                 logger.Debug("network_exfil classify: content_bytes=" +
                              std::to_string(content.size()) +
                              " detected=[" + labelStr + "]" +
                              " top=" + (out.matchedRule.empty() ? "none" : out.matchedRule) +
                              " -> category=" + out.category);
                 return out;
             };

             nemCfg.sendEvent = [this](const std::string& json) {
                 SendEvent(json);
             };

             nemCfg.log = [this](const std::string& level, const std::string& msg) {
                 if      (level == "DEBUG")   logger.Debug(msg);
                 else if (level == "WARNING") logger.Warning(msg);
                 else if (level == "ERROR")   logger.Error(msg);
                 else                         logger.Info(msg);
             };

             if (NetworkExfilMonitor::Start(nemCfg)) {
                 logger.Info("Network Exfiltration Monitor started");
             } else {
                 logger.Warning("Network Exfiltration Monitor did not start");
             }
         }

         logger.Info("Agent started successfully");
         logger.Info("Press Ctrl+C to stop the agent");
         
         while (running) {
             std::this_thread::sleep_for(std::chrono::seconds(1));
         }
     }
     
     void Stop() {
         if (!running) return;
         
         logger.Info("Stopping agent...");
         running = false;

         // Shut down the isolated network exfil monitor before joining the
         // DLPAgent worker threads so its background threads exit cleanly.
         try { NetworkExfilMonitor::Stop(); } catch (...) {}

         try {
             UnregisterAgent();
         } catch (...) {
             logger.Debug("Failed to unregister during shutdown");
         }
         
         // Wait for threads to finish with timeout
         for (auto& thread : workerThreads) {
             if (thread.joinable()) {
                 try {
                     thread.join();
                 } catch (...) {
                     // Ignore join errors
                 }
             }
         }
         workerThreads.clear();
         
         logger.Info("Agent stopped");
     }
     
 private:
     void RegisterAgent() {
         try {
             JsonBuilder json;
             json.AddString("agent_id", config.agentId);
             json.AddString("name", config.agentName);
             json.AddString("hostname", GetHostname());
             json.AddString("os", "windows");
             json.AddString("os_version", "Windows 10");
             json.AddString("ip_address", GetRealIPAddress());
             json.AddString("version", "1.0.0");
             
             auto [status, response] = httpClient->Post("/agents", json.Build());
             
             if (status == 200 || status == 201) {
                 logger.Info("Agent registered with server");
             } else if (status == 0) {
                 logger.Error("Cannot connect to server at " + config.serverUrl);
                 logger.Error("Please ensure the server is running and accessible");
             } else {
                 logger.Warning("Failed to register agent: HTTP " + std::to_string(status));
                 if (!response.empty()) {
                     logger.Warning("Response: " + response.substr(0, 200));
                 }
             }
         } catch (const std::exception& e) {
             logger.Error(std::string("Error registering agent: ") + e.what());
         } catch (...) {
             logger.Error("Unknown error registering agent");
         }
     }
     
     void UnregisterAgent() {
         try {
             auto [status, response] = httpClient->Delete("/agents/" + config.agentId + "/unregister");
             if (status == 200 || status == 204) {
                 logger.Info("Agent unregistered from server");
             }
         } catch (...) {
             logger.Debug("Failed to unregister agent");
         }
     }
     
     void SyncPolicies(bool initial = false) {
         try {
             logger.Info("Syncing policy bundle from server...");
             
             JsonBuilder json;
             json.AddString("platform", "windows");
             if (!activePolicyVersion.empty()) {
                 json.AddString("installed_version", activePolicyVersion);
             }
             
             std::string requestBody = json.Build();
             logger.Debug("Policy sync request: " + requestBody);
             
             auto [status, response] = httpClient->Post(
                 "/agents/" + config.agentId + "/policies/sync",
                 requestBody
             );
             
             if (status == 200) {
                 logger.Debug("Policy sync response (first 1000 chars): " + response.substr(0, 1000));
                 
                 if (response.find("\"status\":\"up_to_date\"") != std::string::npos) {
                     logger.Info("Agent policy bundle up to date");
                 } else {
                     logger.Info("Policy bundle received from server");
                     ApplyPolicyBundle(response);
                 }
             } else if (status == 0) {
                 logger.Error("Cannot connect to server for policy sync");
                 logger.Error("Make sure server is running at: " + config.serverUrl);
             } else {
                 logger.Warning("Policy sync failed: HTTP " + std::to_string(status));
                 if (!response.empty()) {
                     logger.Warning("Response: " + response.substr(0, 500));
                 }
             }
         } catch (const std::exception& e) {
             logger.Error(std::string("Failed to sync policies: ") + e.what());
         } catch (...) {
             logger.Error("Unknown error syncing policies");
         }
     }
     
     void ApplyPolicyBundle(const std::string& bundleJson) {
         std::lock_guard<std::mutex> lock(policiesMutex);
         
         logger.Debug("Parsing policy bundle from server...");
         
         // Reset policy flags and storage
         hasFilePolices = false;
         hasClipboardPolicies = false;
         hasUsbDevicePolicies = false;
         hasUsbTransferPolicies = false;
         filePolicies.clear();
         clipboardPolicies.clear();
         usbPolicies.clear();
         monitoredDirectories.clear();
         
         // Parse the nested policies structure
         size_t policiesPos = bundleJson.find("\"policies\"");
         if (policiesPos != std::string::npos) {
             size_t objectStart = bundleJson.find("{", policiesPos);
             if (objectStart != std::string::npos) {
                 // Parse file_system_monitoring policies
                 // Parse file_system_monitoring policies
                 bool tempHasFilePolicies = hasFilePolices.load();
                 ParsePolicyArray(bundleJson, "file_system_monitoring", filePolicies, tempHasFilePolicies);
                 hasFilePolices.store(tempHasFilePolicies);
                 
                 // Parse clipboard_monitoring policies
                 bool tempHasClipboardPolicies = hasClipboardPolicies.load();
                 ParsePolicyArray(bundleJson, "clipboard_monitoring", clipboardPolicies, tempHasClipboardPolicies);
                 hasClipboardPolicies.store(tempHasClipboardPolicies);
                 
// Parse usb_device_monitoring policies
bool tempHasUsbDevicePolicies = hasUsbDevicePolicies.load();
bool previousUsbBlocking = usbBlockingActive.load();  // Store previous state
bool newUsbBlocking = false;  // Track if any policy requires blocking

ParsePolicyArray(bundleJson, "usb_device_monitoring", usbPolicies, tempHasUsbDevicePolicies);
hasUsbDevicePolicies.store(tempHasUsbDevicePolicies);

// Check if any USB policy has blocking enabled
if (tempHasUsbDevicePolicies) {
    for (const auto& policy : usbPolicies) {
        if (!policy.enabled) continue;
        
        // Check if policy has blocking action for connect events
        for (const auto& evt : policy.monitoredEvents) {
            if ((evt == "usb_connect" || evt == "all" || evt == "*") && 
                policy.action == "block") {
                newUsbBlocking = true;
                break;
            }
        }
        if (newUsbBlocking) break;
    }
}

// Detect state change: blocking was active but now should be disabled
if (previousUsbBlocking && !newUsbBlocking) {
    logger.Warning("============================================================");
    logger.Warning("  USB BLOCKING POLICY REMOVED OR CHANGED TO NON-BLOCKING");
    logger.Warning("============================================================");
    logger.Warning("  Restoring USB device access...");
    
    // Re-enable USB devices
    EnableAllUSBStorageDevices();
    BlockUSBStorageViaRegistry(false);
    
    logger.Warning("  âœ… USB storage access restored");
    logger.Warning("============================================================");
}

// Update blocking state
usbBlockingActive.store(newUsbBlocking);

if (newUsbBlocking) {
    logger.Info("  âš ï¸  USB blocking policy is ACTIVE");
} else if (tempHasUsbDevicePolicies) {
    logger.Info("  âœ… USB monitoring active (alert/log mode only)");
}
                 
                // Parse usb_file_transfer_monitoring policies
                std::vector<PolicyRule> transferPolicyRules;
                bool tempHasUsbTransferPolicies = hasUsbTransferPolicies.load();
                ParsePolicyArray(bundleJson, "usb_file_transfer_monitoring", transferPolicyRules, tempHasUsbTransferPolicies);
                hasUsbTransferPolicies.store(tempHasUsbTransferPolicies);

                // Convert to USB transfer policies
// Convert to USB transfer policies
                {
                    std::lock_guard<std::mutex> lock(usbTransferMutex);
                    usbTransferPolicies.clear();
                    
                    for (const auto& rule : transferPolicyRules) {
                        USBFileTransferPolicy policy;
                        policy.policyId = rule.policyId;
                        policy.name = rule.name;
                        policy.action = rule.action;
                        policy.severity = ExtractSeverityFromPolicyJson(bundleJson, rule.policyId);  // Extract from policy JSON
                        policy.monitoredPaths = rule.monitoredPaths;
                        policy.quarantinePath = rule.quarantinePath;
                        policy.enabled = rule.enabled;
                        usbTransferPolicies.push_back(policy);
                        
                        logger.Info("  - USB Transfer Policy: " + policy.name + " (Action: " + policy.action + ")");
                        for (const auto& path : policy.monitoredPaths) {
                            logger.Info("    * Monitoring: " + path);
                        }
                        if (!policy.quarantinePath.empty()) {
                            logger.Info("    * Quarantine: " + policy.quarantinePath);
                        }
                    }
                }

                // If NO USB policies exist anymore, restore USB access
if (!tempHasUsbDevicePolicies && previousUsbBlocking) {
    logger.Warning("============================================================");
    logger.Warning("  ALL USB POLICIES DISABLED/REMOVED");
    logger.Warning("============================================================");
    logger.Warning("  Restoring full USB device access...");
    
    EnableAllUSBStorageDevices();
    BlockUSBStorageViaRegistry(false);
    
    logger.Warning(" USB storage fully restored");
    logger.Warning("============================================================");
    
    usbBlockingActive.store(false);
}
                // Initialize USB file tracking if policies exist
                if (tempHasUsbTransferPolicies) {
                    InitializeUSBFileTracking();
                }
                 
                 // Parse file_transfer_monitoring policies (also enables file monitoring)
                 std::vector<PolicyRule> transferPolicies;
                 bool hasTransferPolicies = false;
                 ParsePolicyArray(bundleJson, "file_transfer_monitoring", transferPolicies, hasTransferPolicies);
                 if (hasTransferPolicies) {
                     hasFilePolices = true;
                     filePolicies.insert(filePolicies.end(), transferPolicies.begin(), transferPolicies.end());
                 }
             }
         }
         
         // Extract monitored paths from all file policies
         std::set<std::string> uniquePaths;
         for (const auto& policy : filePolicies) {
             for (const auto& path : policy.monitoredPaths) {
                 std::string normalized = NormalizeFilesystemPath(path);
                 if (!normalized.empty() && fs::exists(normalized)) {
                     uniquePaths.insert(normalized);
                 }
             }
         }
         monitoredDirectories.assign(uniquePaths.begin(), uniquePaths.end());
         
         // Extract version
         size_t versionPos = bundleJson.find("\"version\"");
         if (versionPos != std::string::npos) {
             size_t colonPos = bundleJson.find(":", versionPos);
             size_t quoteStart = bundleJson.find("\"", colonPos);
             size_t quoteEnd = bundleJson.find("\"", quoteStart + 1);
             if (quoteStart != std::string::npos && quoteEnd != std::string::npos) {
                 activePolicyVersion = bundleJson.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
             }
         }
         
         // Extract policy_count (include USB transfer policies)
         std::string policyCount = std::to_string(filePolicies.size() + clipboardPolicies.size() + usbPolicies.size() + usbTransferPolicies.size());

         allowEvents = hasFilePolices || hasClipboardPolicies ||
                       hasUsbDevicePolicies || hasUsbTransferPolicies;

         logger.Info("========================================");
         logger.Info("Policy Bundle Applied from Server:");
         logger.Info("  Version: " + (activePolicyVersion.empty() ? "unknown" : activePolicyVersion));
         logger.Info("  Total Policies: " + policyCount);
         logger.Info("  File System Policies: " + std::to_string(filePolicies.size()) + (hasFilePolices ? " (ACTIVE)" : " (INACTIVE)"));
         logger.Info("  Clipboard Policies: " + std::to_string(clipboardPolicies.size()) + (hasClipboardPolicies ? " (ACTIVE)" : " (INACTIVE)"));
         logger.Info("  USB Device Policies: " + std::to_string(usbPolicies.size()) + (hasUsbDevicePolicies ? " (ACTIVE)" : " (INACTIVE)"));
         logger.Info("  USB Transfer Policies: " + std::to_string(usbTransferPolicies.size()) + (hasUsbTransferPolicies ? " (ACTIVE)" : " (INACTIVE)"));
         logger.Info("  Monitored Paths: " + std::to_string(monitoredDirectories.size()));
         logger.Info("  Events Allowed: " + std::string(allowEvents ? "YES" : "NO"));
         logger.Info("========================================");
         
         // Log policy details and monitored paths
         for (const auto& policy : filePolicies) {
             logger.Info("  - File Policy: " + policy.name + " (Action: " + policy.action + ")");
             for (const auto& path : policy.monitoredPaths) {
                 logger.Info("    * Monitoring: " + path);
             }
             if (!policy.monitoredEvents.empty()) {
                 std::string eventsStr = "";
                 for (const auto& event : policy.monitoredEvents) {
                     if (!eventsStr.empty()) eventsStr += ", ";
                     eventsStr += event;
                 }
                 logger.Info("    * Monitored Events: [" + eventsStr + "]");
             } else {
                 logger.Info("    * Monitored Events: [all] (backward compatibility)");
             }
            if (!policy.quarantinePath.empty()) {
                logger.Info("    * Quarantine Path: " + policy.quarantinePath);
            }
         }
         for (const auto& policy : clipboardPolicies) {
             logger.Info("  - Clipboard Policy: " + policy.name + " (Action: " + policy.action + ")");
         }
         
         if (!allowEvents) {
             logger.Warning("============================================================");
             logger.Warning("  NO ACTIVE POLICIES FOUND!");
             logger.Warning("  Agent will not generate events.");
             logger.Warning("  Please configure policies on server.");
             logger.Warning("============================================================");
         } else {
             logger.Info(">> Agent is actively monitoring based on " + policyCount + " server policies");
         }
     }
     
     void ParsePolicyArray(const std::string& bundleJson, const std::string& policyType, 
                          std::vector<PolicyRule>& policyStorage, bool& hasPolicy) {
         size_t typePos = bundleJson.find("\"" + policyType + "\"");
         if (typePos == std::string::npos) return;
         
         size_t arrayStart = bundleJson.find("[", typePos);
         size_t arrayEnd = FindMatchingBracket(bundleJson, arrayStart, '[', ']');
         
         if (arrayStart == std::string::npos || arrayEnd == std::string::npos) return;
         
         std::string arrayContent = bundleJson.substr(arrayStart + 1, arrayEnd - arrayStart - 1);
         
         // Check if array is empty
         bool isEmpty = true;
         for (char c : arrayContent) {
             if (!std::isspace(c)) {
                 isEmpty = false;
                 break;
             }
         }
         
         if (isEmpty) return;
         
         // Parse individual policy objects
         size_t pos = 0;
         while (pos < arrayContent.length()) {
             size_t objStart = arrayContent.find("{", pos);
             if (objStart == std::string::npos) break;
             
             size_t objEnd = FindMatchingBracket(arrayContent, objStart, '{', '}');
             if (objEnd == std::string::npos) break;
             
             std::string policyObj = arrayContent.substr(objStart, objEnd - objStart + 1);
             PolicyRule rule = ParsePolicyObject(policyObj, policyType);
             
             if (rule.enabled) {
                 policyStorage.push_back(rule);
                 hasPolicy = true;
             }
             
             pos = objEnd + 1;
         }
     }
     
     size_t FindMatchingBracket(const std::string& str, size_t start, char open, char close) {
         if (start >= str.length() || str[start] != open) return std::string::npos;
         
         int depth = 1;
         for (size_t i = start + 1; i < str.length(); i++) {
             if (str[i] == open) depth++;
             else if (str[i] == close) {
                 depth--;
                 if (depth == 0) return i;
             }
         }
         return std::string::npos;
     }
     
     PolicyRule ParsePolicyObject(const std::string& policyObj, const std::string& policyType) {
        PolicyRule rule;
        rule.policyType = policyType;
        rule.enabled = true;
        
        std::cout << "[DEBUG] ===========================================" << std::endl;
        std::cout << "[DEBUG] ParsePolicyObject called" << std::endl;
        std::cout << "[DEBUG] Policy type: " << policyType << std::endl;
        
        // Extract policy_id
        rule.policyId = ExtractJsonString(policyObj, "id");
        if (rule.policyId.empty()) {
            rule.policyId = ExtractJsonString(policyObj, "policy_id");
        }
        
        // Extract name
        rule.name = ExtractJsonString(policyObj, "name");

        // Extract severity (top-level on each policy in the bundle, see
        // server/app/policies/agent_policy_transformer.py:_serialize_policy).
        // When empty, the agent's USB/clipboard handlers fall back to
        // action-derived severity. This was the missing link that made
        // log-only USB connect events surface as "medium" instead of
        // honoring the operator-configured severity.
        rule.severity = ExtractJsonString(policyObj, "severity");

        // Extract enabled status
        size_t enabledPos = policyObj.find("\"enabled\"");
        if (enabledPos != std::string::npos) {
            if (policyObj.find("false", enabledPos) != std::string::npos) {
                rule.enabled = false;
            }
        }
        
        // Extract config section
        size_t configPos = policyObj.find("\"config\"");
        if (configPos != std::string::npos) {
            size_t configStart = policyObj.find("{", configPos);
            size_t configEnd = FindMatchingBracket(policyObj, configStart, '{', '}');
            
            if (configStart != std::string::npos && configEnd != std::string::npos) {
                std::string configObj = policyObj.substr(configStart, configEnd - configStart + 1);
                
                std::cout << "[DEBUG] Config section: " << configObj.substr(0, 200) << std::endl;
                
                // Extract action from config.action first
                rule.action = ExtractJsonString(configObj, "action");

                // If no action in config, check the top-level "actions" object
                // for "block", "quarantine", or "alert" keys
                if (rule.action.empty()) {
                    size_t actionsCheckPos = policyObj.find("\"actions\"");
                    if (actionsCheckPos != std::string::npos) {
                        size_t actionsCheckStart = policyObj.find("{", actionsCheckPos);
                        size_t actionsCheckEnd = FindMatchingBracket(policyObj, actionsCheckStart, '{', '}');
                        if (actionsCheckStart != std::string::npos && actionsCheckEnd != std::string::npos) {
                            std::string actionsStr = policyObj.substr(actionsCheckStart, actionsCheckEnd - actionsCheckStart + 1);
                            // Priority: block > quarantine > alert > log
                            if (actionsStr.find("\"block\"") != std::string::npos) {
                                rule.action = "block";
                            } else if (actionsStr.find("\"quarantine\"") != std::string::npos) {
                                rule.action = "quarantine";
                            } else if (actionsStr.find("\"alert\"") != std::string::npos) {
                                rule.action = "alert";
                            } else {
                                rule.action = "alert";
                            }
                        } else {
                            rule.action = "alert";
                        }
                    } else {
                        rule.action = "alert";
                    }
                }
                // Extract quarantinePath for usb_file_transfer_monitoring
                if (policyType == "usb_file_transfer_monitoring") {
                    rule.quarantinePath = ExtractJsonString(configObj, "quarantinePath");
                    
                    // Also check in actions.quarantine.path
                    size_t actionsPos = policyObj.find("\"actions\"");
                    if (actionsPos != std::string::npos) {
                        size_t actionsStart = policyObj.find("{", actionsPos);
                        size_t actionsEnd = FindMatchingBracket(policyObj, actionsStart, '{', '}');
                        
                        if (actionsStart != std::string::npos && actionsEnd != std::string::npos) {
                            std::string actionsObj = policyObj.substr(actionsStart, actionsEnd - actionsStart + 1);
                            
                            size_t quarPos = actionsObj.find("\"quarantine\"");
                            if (quarPos != std::string::npos) {
                                size_t quarStart = actionsObj.find("{", quarPos);
                                size_t quarEnd = FindMatchingBracket(actionsObj, quarStart, '{', '}');
                                
                                if (quarStart != std::string::npos && quarEnd != std::string::npos) {
                                    std::string quarObj = actionsObj.substr(quarStart, quarEnd - quarStart + 1);
                                    std::string quarPath = ExtractJsonString(quarObj, "path");
                                    if (!quarPath.empty()) {
                                        rule.quarantinePath = quarPath;
                                    }
                                }
                            }
                        }
                    }
                    
                    // Extract monitoredPaths
                    rule.monitoredPaths = ExtractJsonArray(configObj, "monitoredPaths");
                }
                
                // ============================================================
                // CRITICAL: USB POLICY MUST BE PARSED FIRST
                // ============================================================
                if (policyType == "usb_device_monitoring" || policyType == "usb_file_transfer_monitoring") {
                    std::cout << "[DEBUG] *** PARSING USB POLICY ***" << std::endl;
                    
                    size_t eventsPos = configObj.find("\"events\"");
                    if (eventsPos != std::string::npos) {
                        size_t eventsStart = configObj.find("{", eventsPos);
                        size_t eventsEnd = FindMatchingBracket(configObj, eventsStart, '{', '}');
                        
                        if (eventsStart != std::string::npos && eventsEnd != std::string::npos) {
                            std::string eventsObj = configObj.substr(eventsStart, eventsEnd - eventsStart + 1);
                            
                            std::cout << "[DEBUG] Events object: " << eventsObj << std::endl;
                            
                            // Extract boolean flags
                            bool connectEnabled = ExtractJsonBool(eventsObj, "connect");
                            bool disconnectEnabled = ExtractJsonBool(eventsObj, "disconnect");
                            bool fileTransferEnabled = ExtractJsonBool(eventsObj, "fileTransfer");
                            
                            std::cout << "[DEBUG] connect: " << (connectEnabled ? "TRUE" : "FALSE") << std::endl;
                            std::cout << "[DEBUG] disconnect: " << (disconnectEnabled ? "TRUE" : "FALSE") << std::endl;
                            std::cout << "[DEBUG] fileTransfer: " << (fileTransferEnabled ? "TRUE" : "FALSE") << std::endl;
                            
                            // Add to monitoredEvents
                            if (connectEnabled) {
                                rule.monitoredEvents.push_back("usb_connect");
                                std::cout << "[DEBUG] ✓ Added: usb_connect" << std::endl;
                            }
                            if (disconnectEnabled) {
                                rule.monitoredEvents.push_back("usb_disconnect");
                                std::cout << "[DEBUG] ✓ Added: usb_disconnect" << std::endl;
                            }
                            if (fileTransferEnabled) {
                                rule.monitoredEvents.push_back("usb_file_transfer");
                                std::cout << "[DEBUG] ✓ Added: usb_file_transfer" << std::endl;
                            }
                            
                            std::cout << "[DEBUG] *** USB EVENTS ADDED TO RULE ***" << std::endl;
                            std::cout << "[DEBUG] rule.monitoredEvents.size() = " << rule.monitoredEvents.size() << std::endl;
                        }
                    }
                }
                // ============================================================
                // END USB PARSING
                // ============================================================
                
                // Continue with other config parsing (patterns, etc.)
                // ... rest of your config parsing code ...
                
                // Extract patterns for clipboard/file policies
                if (policyType == "clipboard_monitoring" || policyType == "file_system_monitoring") {
                    size_t patternsPos = configObj.find("\"patterns\"");
                    if (patternsPos != std::string::npos) {
                        size_t patternsStart = configObj.find("{", patternsPos);
                        size_t patternsEnd = FindMatchingBracket(configObj, patternsStart, '{', '}');
                        
                        if (patternsStart != std::string::npos && patternsEnd != std::string::npos) {
                            std::string patternsObj = configObj.substr(patternsStart, patternsEnd - patternsStart + 1);
                            
                            std::vector<std::string> predefined = ExtractJsonArray(patternsObj, "predefined");
                            rule.dataTypes.insert(rule.dataTypes.end(), predefined.begin(), predefined.end());
                            
                            std::vector<std::string> custom = ExtractJsonArray(patternsObj, "custom");
                            rule.dataTypes.insert(rule.dataTypes.end(), custom.begin(), custom.end());
                        }
                    }
                    
                    // Fallback for old format
                    if (rule.dataTypes.empty()) {
                        rule.dataTypes = ExtractJsonArray(configObj, "dataTypes");
                    }
                }
            }
        }
        
        std::cout << "[DEBUG] ===========================================" << std::endl;
        std::cout << "[DEBUG] FINAL PARSED POLICY:" << std::endl;
        std::cout << "[DEBUG]   ID: " << rule.policyId << std::endl;
        std::cout << "[DEBUG]   Name: " << rule.name << std::endl;
        std::cout << "[DEBUG]   Type: " << rule.policyType << std::endl;
        std::cout << "[DEBUG]   Enabled: " << (rule.enabled ? "YES" : "NO") << std::endl;
        std::cout << "[DEBUG]   Action: " << rule.action << std::endl;
        std::cout << "[DEBUG]   monitoredEvents.size(): " << rule.monitoredEvents.size() << std::endl;
        for (size_t i = 0; i < rule.monitoredEvents.size(); i++) {
            std::cout << "[DEBUG]     [" << i << "] " << rule.monitoredEvents[i] << std::endl;
        }
        std::cout << "[DEBUG]   dataTypes.size(): " << rule.dataTypes.size() << std::endl;
        std::cout << "[DEBUG] ===========================================" << std::endl;
        
        return rule;
    }
     
     std::string ExtractJsonString(const std::string& json, const std::string& key) {
         size_t keyPos = json.find("\"" + key + "\"");
         if (keyPos == std::string::npos) return "";
         
         size_t colonPos = json.find(":", keyPos);
         if (colonPos == std::string::npos) return "";
         
         size_t quoteStart = json.find("\"", colonPos);
         if (quoteStart == std::string::npos) return "";
         
         size_t quoteEnd = json.find("\"", quoteStart + 1);
         if (quoteEnd == std::string::npos) return "";
         
         return json.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
     }
     
     std::vector<std::string> ExtractJsonArray(const std::string& json, const std::string& key) {
        std::vector<std::string> result;
        
        std::cout << "[DEBUG] ExtractJsonArray: Looking for key '" << key << "'" << std::endl;
        std::cout << "[DEBUG] JSON content (first 200 chars): " << json.substr(0, 200) << std::endl;
        
        // Find the key
        std::string keyPattern = "\"" + key + "\"";
        size_t keyPos = json.find(keyPattern);
        
        if (keyPos == std::string::npos) {
            std::cout << "[DEBUG] ExtractJsonArray: Key '" << key << "' not found" << std::endl;
            return result;
        }
        
        std::cout << "[DEBUG] ExtractJsonArray: Key found at position " << keyPos << std::endl;
        
        // Find the colon after the key
        size_t colonPos = json.find(":", keyPos);
        if (colonPos == std::string::npos) {
            std::cout << "[DEBUG] ExtractJsonArray: Colon not found after key" << std::endl;
            return result;
        }
        
        // Skip whitespace after colon
        size_t searchStart = colonPos + 1;
        while (searchStart < json.length() && std::isspace(json[searchStart])) {
            searchStart++;
        }
        
        // Check if it's an array
        if (searchStart >= json.length() || json[searchStart] != '[') {
            std::cout << "[DEBUG] ExtractJsonArray: Not an array (char at position: '" << json[searchStart] << "')" << std::endl;
            return result;
        }
        
        size_t arrayStart = searchStart;
        size_t arrayEnd = json.find("]", arrayStart);
        
        if (arrayEnd == std::string::npos) {
            std::cout << "[DEBUG] ExtractJsonArray: Closing bracket ] not found" << std::endl;
            return result;
        }
        
        std::string arrayContent = json.substr(arrayStart + 1, arrayEnd - arrayStart - 1);
        std::cout << "[DEBUG] ExtractJsonArray: Array content: '" << arrayContent << "'" << std::endl;
        
        // Check if array is empty
        bool isEmpty = true;
        for (char c : arrayContent) {
            if (!std::isspace(c)) {
                isEmpty = false;
                break;
            }
        }
        
        if (isEmpty) {
            std::cout << "[DEBUG] ExtractJsonArray: Array is empty" << std::endl;
            return result;
        }
        
        // Parse array elements
        size_t pos = 0;
        while (pos < arrayContent.length()) {
            // Skip whitespace
            while (pos < arrayContent.length() && std::isspace(arrayContent[pos])) {
                pos++;
            }
            
            if (pos >= arrayContent.length()) break;
            
            // Check for quoted string
            if (arrayContent[pos] == '"') {
                size_t quoteStart = pos;
                // Find closing quote, skipping escaped characters (\" and \\)
                size_t quoteEnd = quoteStart + 1;
                while (quoteEnd < arrayContent.length()) {
                    if (arrayContent[quoteEnd] == '\\') {
                        quoteEnd += 2; // Skip escaped character
                        continue;
                    }
                    if (arrayContent[quoteEnd] == '"') {
                        break;
                    }
                    quoteEnd++;
                }

                if (quoteEnd >= arrayContent.length()) {
                    std::cout << "[DEBUG] ExtractJsonArray: Unterminated string at position " << pos << std::endl;
                    break;
                }

                std::string rawval = arrayContent.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                std::string cleanval = "";
                for (size_t vi = 0; vi < rawval.length(); vi++) {
                    if (rawval[vi] == '\\' && vi + 1 < rawval.length()) {
                        cleanval += rawval[vi + 1];
                        vi++;
                    } else {
                        cleanval += rawval[vi];
                    }
                }
                result.push_back(cleanval);
                std::cout << "[DEBUG] ExtractJsonArray: Extracted value: '" << cleanval << "'" << std::endl;

                pos = quoteEnd + 1;
            } else {
                // Skip to next comma or end
                size_t commaPos = arrayContent.find(",", pos);
                if (commaPos == std::string::npos) {
                    break;
                }
                pos = commaPos + 1;
            }
            
            // Skip comma and whitespace
            while (pos < arrayContent.length() && (arrayContent[pos] == ',' || std::isspace(arrayContent[pos]))) {
                pos++;
            }
        }
        
        std::cout << "[DEBUG] ExtractJsonArray: Total extracted: " << result.size() << " values" << std::endl;
        return result;
    }
    
    bool ExtractJsonBool(const std::string& json, const std::string& key) {
        size_t keyPos = json.find("\"" + key + "\"");
        if (keyPos == std::string::npos) return false;
        
        size_t colonPos = json.find(":", keyPos);
        if (colonPos == std::string::npos) return false;
        
        // Skip whitespace after colon
        size_t valueStart = colonPos + 1;
        while (valueStart < json.length() && std::isspace(json[valueStart])) {
            valueStart++;
        }
        
        // Check for "true" or "false"
        if (valueStart + 4 <= json.length() && json.substr(valueStart, 4) == "true") {
            return true;
        }
        
        return false;
    }
    
    void HeartbeatLoop() {
         while (running) {
             try {
                 SendHeartbeat();
             } catch (...) {
                 logger.Error("Heartbeat error");
             }
             std::this_thread::sleep_for(std::chrono::seconds(config.heartbeatInterval));
         }
     }
     
     void SendHeartbeat() {
         try {
             JsonBuilder json;
             json.AddString("timestamp", GetCurrentTimestampISO());
             json.AddString("ip_address", GetRealIPAddress());
             if (!activePolicyVersion.empty()) {
                 json.AddString("policy_version", activePolicyVersion);
             }
             
             auto [status, response] = httpClient->Put(
                 "/agents/" + config.agentId + "/heartbeat",
                 json.Build()
             );
             
             if (status == 200) {
                 logger.Debug("Heartbeat sent successfully");
             } else if (status == 0) {
                 logger.Debug("Cannot reach server for heartbeat");
             } else {
                 logger.Debug("Heartbeat response: HTTP " + std::to_string(status));
             }
         } catch (const std::exception& e) {
             logger.Debug(std::string("Heartbeat failed: ") + e.what());
         } catch (...) {
             logger.Debug("Heartbeat error");
         }
     }
     
     void PolicySyncLoop() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(config.policySyncInterval));
            try {
                bool hadPoliciesBefore = hasFilePolices;
                SyncPolicies();
                
                // If file policies were just enabled, scan existing files
                if (!hadPoliciesBefore && hasFilePolices) {
                    logger.Info("File policies now active - scanning existing files...");
                    ScanAndStoreExistingFiles();
                }
            } catch (...) {
                logger.Debug("Policy sync loop error");
            }
        }
    }
     
     void ClipboardMonitor() {
         logger.Info("Clipboard monitoring started");
         
         while (running) {
             if (!hasClipboardPolicies || !allowEvents) {
                 std::this_thread::sleep_for(std::chrono::seconds(2));
                 continue;
             }
             
             try {
                 // Get active window title to detect source file
                 HWND hwnd = GetForegroundWindow();
                 char windowTitle[256] = {0};
                 if (hwnd) {
                     GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
                     lastActiveWindow = std::string(windowTitle);
                 }
                 
                 if (OpenClipboard(nullptr)) {
                     HANDLE hData = GetClipboardData(CF_UNICODETEXT);
                     if (hData != nullptr) {
                         wchar_t* pData = static_cast<wchar_t*>(GlobalLock(hData));
                         if (pData != nullptr) {
                             std::wstring wtext(pData);
                             std::string text(wtext.begin(), wtext.end());
                             GlobalUnlock(hData);
                             
                             if (!text.empty() && text != lastClipboard) {
                                 lastClipboard = text;
                                 HandleClipboardEvent(text, lastActiveWindow);
                             }
                         }
                     }
                     CloseClipboard();
                 }
             } catch (...) {
                 logger.Debug("Clipboard access error");
             }
             
             std::this_thread::sleep_for(std::chrono::seconds(2));
         }
     }
     
     void HandleClipboardEvent(const std::string& content, const std::string& windowTitle) {
        try {
            std::cout << "\n[DEBUG] ========================================" << std::endl;
            std::cout << "[DEBUG] HandleClipboardEvent called" << std::endl;
            std::cout << "[DEBUG] Content length: " << content.length() << std::endl;
            std::cout << "[DEBUG] Content: " << content.substr(0, std::min<size_t>(200, content.length())) << std::endl;
            std::cout << "[DEBUG] ========================================\n" << std::endl;
            
            // Get clipboard policies
            std::vector<PolicyRule> policies;
            {
                std::lock_guard<std::mutex> lock(policiesMutex);
                policies = clipboardPolicies;
            }
            
            std::cout << "[DEBUG] Number of clipboard policies: " << policies.size() << std::endl;
            
            // Exit early if no clipboard policies configured
            if (policies.empty()) {
                logger.Info("No clipboard policies configured - skipping");
                return;
            }
            
            // Log policy details
            for (const auto& policy : policies) {
                std::cout << "[DEBUG] Policy: " << policy.name << std::endl;
                std::cout << "[DEBUG]   Enabled: " << (policy.enabled ? "YES" : "NO") << std::endl;
                std::cout << "[DEBUG]   Data types: ";
                for (const auto& dt : policy.dataTypes) {
                    std::cout << dt << " ";
                }
                std::cout << std::endl;
            }
            
            // Classify content against clipboard policies
            std::cout << "[DEBUG] Calling ContentClassifier::Classify..." << std::endl;
            auto classification = ContentClassifier::Classify(content, policies, "clipboard");
            
            std::cout << "[DEBUG] Classification results:" << std::endl;
            std::cout << "[DEBUG]   Matched policies: " << classification.matchedPolicies.size() << std::endl;
            std::cout << "[DEBUG]   Labels: " << classification.labels.size() << std::endl;
            std::cout << "[DEBUG]   Detected content types: " << classification.detectedContent.size() << std::endl;
            
            // Check results
            if (classification.matchedPolicies.empty()) {
                // FALLBACK: If policy has no dataTypes specified, do basic detection
                bool hasEmptyDataTypes = false;
                for (const auto& policy : policies) {
                    if (policy.enabled && policy.dataTypes.empty()) {
                        hasEmptyDataTypes = true;
                        break;
                    }
                }
                
                if (hasEmptyDataTypes) {
                    logger.Warning("Policy has no patterns configured - cannot detect anything");
                    logger.Warning("Please configure patterns in the policy on the server");
                    return;
                }
            }
            
            // Count total matches
            int totalMatches = 0;
            for (const auto& [dataType, values] : classification.detectedContent) {
                totalMatches += values.size();
            }

            // If no sensitive content detected, send a Public/Allowed event
            if (classification.detectedContent.empty() || totalMatches == 0) {
                logger.Info("Clipboard content classified as Public - allowed");
                JsonBuilder pubJson;
                pubJson.AddString("event_id", GenerateUUID());
                pubJson.AddString("event_type", "clipboard");
                pubJson.AddString("event_subtype", "clipboard_copy");
                pubJson.AddString("agent_id", config.agentId);
                pubJson.AddString("source_type", "agent");
                pubJson.AddString("user_email", GetUsername() + "@" + GetHostname());
                pubJson.AddString("description", "Clipboard content - no sensitive data detected");
                pubJson.AddString("severity", "low");
                pubJson.AddString("action", "allowed");
                pubJson.AddString("content", content);
                pubJson.AddString("classification_level", "Public");
                pubJson.AddDouble("classification_score", 0.0);
                pubJson.AddString("timestamp", GetCurrentTimestampISO());
                if (!windowTitle.empty()) {
                    pubJson.AddString("source_window", windowTitle);
                }
                SendEvent(pubJson.Build());
                return;
            }
            
            std::cout << "[DEBUG] Total matches found: " << totalMatches << std::endl;
            
            // Extract file name from window title if possible
            std::string sourceFile = ExtractFileFromWindowTitle(windowTitle);
            
            // Build detailed detected content summary
            std::string detectedSummary = "";
            std::vector<std::string> detectedTypes;
            
            for (const auto& [dataType, values] : classification.detectedContent) {
                if (values.empty()) continue;
                
                detectedTypes.push_back(dataType);
                detectedSummary += "\n  • " + dataType + ": " + std::to_string(values.size()) + " found\n";
                
                // Determine if this type should be redacted
                std::string lowerType = ToLower(dataType);
                bool shouldRedact = (lowerType.find("password") != std::string::npos ||
                                    lowerType.find("api_key") != std::string::npos ||
                                    lowerType.find("secret") != std::string::npos ||
                                    lowerType.find("token") != std::string::npos ||
                                    lowerType.find("private_key") != std::string::npos);
                
                // Show examples (up to 3)
                detectedSummary += "    Values: ";
                for (size_t i = 0; i < values.size() && i < 3; i++) {
                    if (i > 0) detectedSummary += ", ";
                    
                    if (shouldRedact) {
                        detectedSummary += "[REDACTED]";
                    } else {
                        std::string value = values[i];
                        if (value.length() > 40) {
                            value = value.substr(0, 37) + "...";
                        }
                        detectedSummary += value;
                    }
                }
                
                if (values.size() > 3) {
                    detectedSummary += " ... (+" + std::to_string(values.size() - 3) + " more)";
                }
                detectedSummary += "\n";
            }
            
            // Build comprehensive description
            std::string description = "🚨 CLIPBOARD ALERT: Sensitive data detected\n";
            description += "Total matches: " + std::to_string(totalMatches) + "\n";
            if (!sourceFile.empty()) {
                description += "Source file: " + sourceFile + "\n";
            } else if (!windowTitle.empty()) {
                description += "Application: " + windowTitle + "\n";
            }
            description += "\nDetected sensitive data:" + detectedSummary;
            description += "\nMatched policies: " + std::to_string(classification.matchedPolicies.size());
            
            // Determine classification level from confidence score
            float classScore = std::min(1.0f, (float)totalMatches * 0.3f);
            // Boost score based on severity of detected types
            for (const auto& dt : detectedTypes) {
                std::string lower = ToLower(dt);
                if (lower == "credit_card" || lower == "ssn" || lower == "aadhaar" ||
                    lower == "private_key" || lower == "aws_key") {
                    classScore = std::max(classScore, 0.9f);
                } else if (lower == "pan" || lower == "ifsc" || lower == "bank_account") {
                    classScore = std::max(classScore, 0.7f);
                } else if (lower == "email" || lower == "phone") {
                    classScore = std::max(classScore, 0.4f);
                }
            }
            // Map score to classification level
            std::string classLevel;
            if (classScore >= 0.8f) classLevel = "Restricted";
            else if (classScore >= 0.6f) classLevel = "Confidential";
            else if (classScore >= 0.3f) classLevel = "Internal";
            else classLevel = "Public";

            // Build matched rules list for the event
            std::string matchedRulesJson = "[";
            bool firstRule = true;
            for (const auto& [dataType, values] : classification.detectedContent) {
                if (values.empty()) continue;
                if (!firstRule) matchedRulesJson += ",";
                firstRule = false;
                matchedRulesJson += "{\"rule_name\":\"" + dataType + "\",\"match_count\":" + std::to_string(values.size()) + "}";
            }
            matchedRulesJson += "]";

            // Build clean description based on classification level
            std::string preciseDesc;
            if (classLevel == "Restricted" || classLevel == "Confidential") {
                preciseDesc = "CLIPBOARD ALERT: Sensitive data detected";
            } else if (classLevel == "Internal") {
                preciseDesc = "CLIPBOARD: Internal data detected";
            } else {
                preciseDesc = "CLIPBOARD: Public data detected";
            }

            // Build JSON event
            JsonBuilder json;
            json.AddString("event_id", GenerateUUID());
            json.AddString("event_type", "clipboard");
            json.AddString("event_subtype", "clipboard_copy");
            json.AddString("agent_id", config.agentId);
            json.AddString("source_type", "agent");
            json.AddString("user_email", GetUsername() + "@" + GetHostname());
            json.AddString("description", preciseDesc);
            json.AddString("severity", classification.severity);
            json.AddString("action", classification.suggestedAction);
            json.AddString("content", content);
            json.AddString("classification_level", classLevel);
            json.AddDouble("classification_score", classScore);
            json.AddString("classification_category", classLevel);
            json.AddArray("classification_labels", detectedTypes);
            json.AddArray("classification_rules_matched", detectedTypes);
            json.AddString("detected_content", detectedSummary);
            json.AddArray("data_types", detectedTypes);
            json.AddArray("matched_policies", classification.matchedPolicies);
            json.AddInt("total_matches", totalMatches);
            json.AddBool("blocked", classification.suggestedAction == "block");

            if (!sourceFile.empty()) {
                json.AddString("source_file", sourceFile);
            }
            if (!windowTitle.empty()) {
                json.AddString("source_window", windowTitle);
            }

            json.AddString("timestamp", GetCurrentTimestampISO());

            SendEvent(json.Build());

            // ENFORCEMENT: If policy says block, clear the clipboard completely
            if (classification.suggestedAction == "block") {
                logger.Warning("  CLEARING CLIPBOARD — sensitive data detected!");

                // Step 1: Clear traditional clipboard
                if (OpenClipboard(NULL)) {
                    EmptyClipboard();
                    // Set empty text so clipboard history gets an empty entry
                    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, sizeof(wchar_t));
                    if (hMem) {
                        wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
                        if (pMem) {
                            pMem[0] = L'\0';
                            GlobalUnlock(hMem);
                            SetClipboardData(CF_UNICODETEXT, hMem);
                        }
                    }
                    CloseClipboard();
                    logger.Warning("  Clipboard cleared successfully");
                } else {
                    logger.Error("  Failed to clear clipboard");
                }


                // Update lastClipboard to prevent re-triggering on the empty clipboard
                lastClipboard = "";
            }

            // Enhanced console logging
            logger.Warning("\n============================================================");
            logger.Warning("  🚨 CLIPBOARD ALERT: SENSITIVE DATA DETECTED!");
            logger.Warning("============================================================");
            
            if (!sourceFile.empty()) {
                logger.Warning("  📄 Source File: " + sourceFile);
            } else if (!windowTitle.empty()) {
                logger.Warning("  💻 Application: " + windowTitle);
            } else {
                logger.Warning("  📋 Source: Clipboard");
            }
            
            logger.Warning("  ⚠️  Severity: " + classification.severity);
            logger.Warning("  🎯 Action: " + classification.suggestedAction);
            logger.Warning("  📊 Total Matches: " + std::to_string(totalMatches));
            logger.Warning("  🔍 Policies Matched: " + std::to_string(classification.matchedPolicies.size()));
            logger.Warning("");
            logger.Warning("  📋 DETECTED SENSITIVE DATA:");
            
            // Log detailed breakdown
            for (const auto& [dataType, values] : classification.detectedContent) {
                if (values.empty()) continue;
                
                logger.Warning("    ▶ " + dataType + ": " + std::to_string(values.size()) + " instance(s)");
                
                std::string lowerType = ToLower(dataType);
                bool shouldRedact = (lowerType.find("password") != std::string::npos ||
                                    lowerType.find("api_key") != std::string::npos ||
                                    lowerType.find("secret") != std::string::npos ||
                                    lowerType.find("token") != std::string::npos ||
                                    lowerType.find("private_key") != std::string::npos);
                
                if (shouldRedact) {
                    logger.Warning("      └─ [REDACTED FOR SECURITY]");
                } else if (!values.empty()) {
                    std::string example = values[0];
                    if (example.length() > 35) {
                        example = example.substr(0, 32) + "...";
                    }
                    logger.Warning("      └─ Example: " + example);
                }
            }
            
            logger.Warning("============================================================\n");
            
        } catch (const std::exception& e) {
            logger.Error(std::string("Error handling clipboard event: ") + e.what());
        } catch (...) {
            logger.Error("Unknown error handling clipboard event");
        }
    }
     
     std::string ExtractFileFromWindowTitle(const std::string& windowTitle) {
         // Common patterns: "filename.txt - Notepad", "filename.docx - Word", etc.
         size_t dashPos = windowTitle.find(" - ");
         if (dashPos != std::string::npos) {
             std::string filename = windowTitle.substr(0, dashPos);
             // Check if it looks like a filename (has extension)
             if (filename.find('.') != std::string::npos) {
                 return filename;
             }
         }
         
         // Try to find filename patterns
         std::regex filePattern(R"(([^\\/:\*\?"<>\|]+\.(txt|doc|docx|pdf|csv|xls|xlsx|json|xml|sql|cpp|h|py|java|js)))");
         std::smatch match;
         if (std::regex_search(windowTitle, match, filePattern)) {
             return match[0];
         }
         
         return "";
     }
     
     void UsbMonitor() {
        logger.Info("USB monitoring started using Windows Device Notifications");
        
        if (!hasUsbDevicePolicies || !allowEvents) {
            logger.Info("No USB policies configured - USB monitoring inactive");
            while (running && (!hasUsbDevicePolicies || !allowEvents)) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
        
        // Set static instance
        s_instance = this;
        
        // Register window class
        const char CLASS_NAME[] = "DLPAgentUSBMonitor";
        
        WNDCLASSA wc = {};
        wc.lpfnWndProc = UsbWindowProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = CLASS_NAME;
        
        if (!RegisterClassA(&wc)) {
            logger.Error("Failed to register USB monitor window class");
            return;
        }
        
        // Create message-only window
        usbMonitorWindow = CreateWindowExA(
            0,
            CLASS_NAME,
            "USB Monitor",
            0,
            0, 0, 0, 0,
            HWND_MESSAGE,
            NULL,
            GetModuleHandle(NULL),
            NULL
        );
        
        if (usbMonitorWindow == NULL) {
            logger.Error("Failed to create USB monitor window");
            return;
        }
        
        // Register for device notifications
        DEV_BROADCAST_DEVICEINTERFACE_A notificationFilter;
        ZeroMemory(&notificationFilter, sizeof(notificationFilter));
        notificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE_A);
        notificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        notificationFilter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;
        
        usbDevNotify = RegisterDeviceNotificationA(
            usbMonitorWindow,
            &notificationFilter,
            DEVICE_NOTIFY_WINDOW_HANDLE
        );
        
        if (usbDevNotify == NULL) {
            logger.Error("Failed to register for USB device notifications");
            DestroyWindow(usbMonitorWindow);
            return;
        }
        
        logger.Info("USB device notification registered successfully");
        logger.Info("Monitoring USB connect/disconnect events...");
        
        // Message loop
        MSG msg;
        while (running) {
            while (PeekMessage(&msg, usbMonitorWindow, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) {
                    goto cleanup;
                }
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
    cleanup:
        // Cleanup
        if (usbDevNotify) {
            UnregisterDeviceNotification(usbDevNotify);
        }
        if (usbMonitorWindow) {
            DestroyWindow(usbMonitorWindow);
        }
        
        s_instance = nullptr;
        logger.Info("USB monitoring stopped");
    }

     bool BlockUsbDevice(const std::string& deviceId) {
        try {
            std::cout << "[DEBUG] Attempting to block USB device: " << deviceId << std::endl;
            
            // Initialize COM
            HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
            if (FAILED(hres) && hres != RPC_E_CHANGED_MODE) {
                std::cout << "[DEBUG] COM initialization failed" << std::endl;
                return false;
            }
            
            // Create WMI locator
            IWbemLocator* pLoc = nullptr;
            hres = CoCreateInstance(
                CLSID_WbemLocator,
                0,
                CLSCTX_INPROC_SERVER,
                IID_IWbemLocator,
                (LPVOID*)&pLoc
            );
            
            if (FAILED(hres)) {
                std::cout << "[DEBUG] Failed to create WMI locator" << std::endl;
                return false;
            }
            
            // Connect to WMI
            IWbemServices* pSvc = nullptr;
            hres = pLoc->ConnectServer(
                _bstr_t(L"ROOT\\CIMV2"),
                nullptr,
                nullptr,
                0,
                0,
                0,
                0,
                &pSvc
            );
            
            if (FAILED(hres)) {
                std::cout << "[DEBUG] Failed to connect to WMI" << std::endl;
                pLoc->Release();
                return false;
            }
            
            // Set security levels
            hres = CoSetProxyBlanket(
                pSvc,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                nullptr,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr,
                EOAC_NONE
            );
            
            if (FAILED(hres)) {
                std::cout << "[DEBUG] Failed to set proxy blanket" << std::endl;
                pSvc->Release();
                pLoc->Release();
                return false;
            }
            
            // Query for the specific USB device
            std::wstring deviceIdW(deviceId.begin(), deviceId.end());
            std::wstring query = L"SELECT * FROM Win32_PnPEntity WHERE DeviceID = '" + deviceIdW + L"'";
            
            IEnumWbemClassObject* pEnumerator = nullptr;
            hres = pSvc->ExecQuery(
                _bstr_t("WQL"),
                _bstr_t(query.c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &pEnumerator
            );
            
            if (FAILED(hres)) {
                std::cout << "[DEBUG] WMI query failed" << std::endl;
                pSvc->Release();
                pLoc->Release();
                return false;
            }
            
            // Get the device object
            IWbemClassObject* pclsObj = nullptr;
            ULONG uReturn = 0;
            
            bool deviceDisabled = false;
            
            while (pEnumerator) {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                
                if (uReturn == 0) break;
                
                // Get the Disable method
                IWbemClassObject* pClass = nullptr;
                BSTR MethodName = SysAllocString(L"Disable");
                BSTR ClassName = SysAllocString(L"Win32_PnPEntity");
                
                hres = pSvc->GetObject(ClassName, 0, nullptr, &pClass, nullptr);
                
                if (SUCCEEDED(hres)) {
                    IWbemClassObject* pInParamsDefinition = nullptr;
                    IWbemClassObject* pOutParams = nullptr;
                    
                    // Execute Disable method
                    BSTR objPath = nullptr;
                    VARIANT vtProp;
                    pclsObj->Get(L"__PATH", 0, &vtProp, 0, 0);
                    objPath = vtProp.bstrVal;
                    
                    hres = pSvc->ExecMethod(
                        objPath,
                        MethodName,
                        0,
                        nullptr,
                        nullptr,
                        &pOutParams,
                        nullptr
                    );
                    
                    if (SUCCEEDED(hres)) {
                        VARIANT varReturnValue;
                        hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, nullptr, 0);
                        
                        if (SUCCEEDED(hres) && varReturnValue.uintVal == 0) {
                            deviceDisabled = true;
                            std::cout << "[DEBUG] Device successfully disabled" << std::endl;
                        } else {
                            std::cout << "[DEBUG] Disable method returned error code: " << varReturnValue.uintVal << std::endl;
                        }
                        
                        VariantClear(&varReturnValue);
                        if (pOutParams) pOutParams->Release();
                    }
                    
                    VariantClear(&vtProp);
                    if (pClass) pClass->Release();
                }
                
                SysFreeString(MethodName);
                SysFreeString(ClassName);
                pclsObj->Release();
            }
            
            pEnumerator->Release();
            pSvc->Release();
            pLoc->Release();
            
            return deviceDisabled;
            
        } catch (const std::exception& e) {
            std::cout << "[DEBUG] Exception in BlockUsbDevice: " << e.what() << std::endl;
            return false;
        } catch (...) {
            std::cout << "[DEBUG] Unknown exception in BlockUsbDevice" << std::endl;
            return false;
        }
    }
     
    void HandleUsbEvent(const std::string& deviceName, const std::string& deviceId, const std::string& eventType = "connect") {
        try {
            std::cout << "\n[DEBUG] ===========================================" << std::endl;
            std::cout << "[DEBUG] HandleUsbEvent called" << std::endl;
            std::cout << "[DEBUG] Device: " << deviceName << std::endl;
            std::cout << "[DEBUG] Device ID: " << deviceId << std::endl;
            std::cout << "[DEBUG] Event type: " << eventType << std::endl;
            std::cout << "[DEBUG] allowEvents: " << (allowEvents ? "true" : "false") << std::endl;
            std::cout << "[DEBUG] hasUsbDevicePolicies: " << (hasUsbDevicePolicies ? "true" : "false") << std::endl;
            
            if (!allowEvents) {
                std::cout << "[DEBUG] Events not allowed - skipping" << std::endl;
                return;
            }
            
            // Get USB policies
            std::vector<PolicyRule> policies;
            {
                std::lock_guard<std::mutex> lock(policiesMutex);
                policies = usbPolicies;
            }
            
            std::cout << "[DEBUG] USB policies count: " << policies.size() << std::endl;
            
            if (policies.empty()) {
                std::cout << "[DEBUG] No USB policies configured" << std::endl;
                return;
            }
            
            // Check if any policy monitors this event type
            bool eventMonitored = false;
            std::string policyAction = "log";
            std::string matchedPolicyId;
            std::string matchedPolicyName;
            std::string matchedPolicySeverity;  // Empty until a policy matches
            std::string severity;

            std::string eventToCheck = "usb_" + eventType;
            std::cout << "[DEBUG] Looking for event: " << eventToCheck << std::endl;

            for (const auto& policy : policies) {
                if (!policy.enabled) {
                    std::cout << "[DEBUG] Policy '" << policy.name << "' is disabled - skipping" << std::endl;
                    continue;
                }

                std::cout << "[DEBUG] ========================================" << std::endl;
                std::cout << "[DEBUG] Checking policy: " << policy.name << std::endl;
                std::cout << "[DEBUG] Policy ID: " << policy.policyId << std::endl;
                std::cout << "[DEBUG] Policy action: " << policy.action << std::endl;
                std::cout << "[DEBUG] Monitored events count: " << policy.monitoredEvents.size() << std::endl;

                for (const auto& evt : policy.monitoredEvents) {
                    std::cout << "[DEBUG]   - " << evt << std::endl;
                }

                // Check if this policy monitors this specific USB event
                for (const auto& monitoredEvent : policy.monitoredEvents) {
                    std::cout << "[DEBUG] Comparing: '" << monitoredEvent << "' vs '" << eventToCheck << "'" << std::endl;

                    if (monitoredEvent == eventToCheck ||
                        monitoredEvent == "all" ||
                        monitoredEvent == "*" ||
                        monitoredEvent == "usb_" + eventType) {

                        eventMonitored = true;
                        policyAction = policy.action;
                        matchedPolicyId = policy.policyId;
                        matchedPolicyName = policy.name;
                        matchedPolicySeverity = policy.severity;

                        std::cout << "[DEBUG] *** EVENT MATCHED! ***" << std::endl;
                        std::cout << "[DEBUG] Action: " << policyAction << std::endl;
                        std::cout << "[DEBUG] Policy severity: '" << matchedPolicySeverity << "'" << std::endl;
                        break;
                    }
                }

                if (eventMonitored) {
                    std::cout << "[DEBUG] Policy matched - stopping search" << std::endl;
                    break;
                }
            }

            std::cout << "[DEBUG] ========================================" << std::endl;
            std::cout << "[DEBUG] Event monitored: " << (eventMonitored ? "YES" : "NO") << std::endl;
            std::cout << "[DEBUG] ===========================================" << std::endl;

            if (!eventMonitored) {
                logger.Info("USB event '" + eventType + "' not monitored by any active policy");
                return;
            }

            // Severity comes strictly from the matched policy. The legacy
            // action-based guess (block→critical, alert→high, else medium)
            // remains only as a fallback for policies that didn't pin a
            // severity in their config — never as an override.
            if (!matchedPolicySeverity.empty()) {
                severity = matchedPolicySeverity;
            } else if (policyAction == "block") {
                severity = "critical";
            } else if (policyAction == "alert") {
                severity = "high";
            } else {
                severity = "medium";
            }
            
            // Extract vendor/product IDs from device ID
            std::string vendorId = "unknown";
            std::string productId = "unknown";
            size_t vidPos = deviceId.find("VID_");
            size_t pidPos = deviceId.find("PID_");
            
            if (vidPos != std::string::npos) {
                vendorId = deviceId.substr(vidPos + 4, 4);
            }
            if (pidPos != std::string::npos) {
                productId = deviceId.substr(pidPos + 4, 4);
            }
            
            // Build comprehensive description
            std::string description = "USB Device " + eventType;
            description += "\nDevice: " + deviceName;
            description += "\nVendor ID: " + vendorId;
            description += "\nProduct ID: " + productId;
            description += "\nPolicy: " + matchedPolicyName;
            description += "\nAction: " + policyAction;
            
            std::string eventSubtype = "usb_" + eventType;
            
            // Build JSON event
            JsonBuilder json;
            json.AddString("event_id", GenerateUUID());
            json.AddString("event_type", "usb");
            json.AddString("event_subtype", eventSubtype);
            json.AddString("agent_id", config.agentId);
            json.AddString("source_type", "agent");
            json.AddString("user_email", GetUsername() + "@" + GetHostname());
            json.AddString("description", description);
            json.AddString("severity", severity);
            json.AddString("action", policyAction);
            json.AddString("device_name", deviceName);
            json.AddString("device_id", deviceId);
            json.AddString("vendor_id", vendorId);
            json.AddString("product_id", productId);
            json.AddString("policy_id", matchedPolicyId);
            json.AddString("policy_name", matchedPolicyName);
            json.AddString("event_action", eventType);
            json.AddString("timestamp", GetCurrentTimestampISO());
            
            std::cout << "[DEBUG] Sending event to server..." << std::endl;
            SendEvent(json.Build());
            std::cout << "[DEBUG] Event sent successfully" << std::endl;
            
            // Display alert based on action
            if (policyAction == "alert" || policyAction == "block") {
                logger.Warning("\n============================================================");
                logger.Warning("  " + std::string(policyAction == "block" ? "🚫" : "⚠️") + " USB DEVICE " + 
                              (policyAction == "block" ? "BLOCKED!" : "ALERT!"));
                logger.Warning("============================================================");
                logger.Warning("  Event: " + eventType);
                logger.Warning("  Device: " + deviceName);
                logger.Warning("  Vendor ID: " + vendorId);
                logger.Warning("  Product ID: " + productId);
                logger.Warning("  Policy: " + matchedPolicyName);
                logger.Warning("  Action: " + policyAction);
                logger.Warning("  Severity: " + severity);
                logger.Warning("============================================================\n");
            } else {
                logger.Info("USB " + eventType + ": " + deviceName + " (logged)");
            }
            
        } catch (const std::exception& e) {
            logger.Error(std::string("Error handling USB event: ") + e.what());
        } catch (...) {
            logger.Error("Unknown error handling USB event");
        }
    }
     
     void FileSystemMonitor() {
         logger.Info("File system monitoring started");
         
         std::set<std::string> watchedPaths;  // Track which paths we're already watching
         
         while (running) {
             if (!hasFilePolices || !allowEvents) {
                 std::this_thread::sleep_for(std::chrono::seconds(5));
                 continue;
             }
             
             // Get monitored directories from policies
             std::vector<std::string> currentMonitoredDirs;
             {
                 std::lock_guard<std::mutex> lock(policiesMutex);
                 currentMonitoredDirs = monitoredDirectories;
             }
             
             // Start watching new directories
             for (const auto& path : currentMonitoredDirs) {
                 if (watchedPaths.find(path) == watchedPaths.end()) {
                     try {
                         if (fs::exists(path)) {
                             watchedPaths.insert(path);
                             logger.Info("Started monitoring directory from policy: " + path);
                             
                             // Start watching this directory in a separate thread
                             workerThreads.emplace_back(&DLPAgent::WatchDirectory, this, path);
                         } else {
                             logger.Warning("Policy-defined path does not exist: " + path);
                         }
                     } catch (const std::exception& e) {
                         logger.Error("Error starting monitor for path: " + path + " - " + e.what());
                     }
                 }
             }
             
             std::this_thread::sleep_for(std::chrono::seconds(30));
         }
     }
     
     void WatchDirectory(const std::string& directoryPath) {
         std::wstring wPath(directoryPath.begin(), directoryPath.end());
         
         HANDLE hDir = CreateFileW(
             wPath.c_str(),
             FILE_LIST_DIRECTORY,
             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
             nullptr,
             OPEN_EXISTING,
             FILE_FLAG_BACKUP_SEMANTICS,
             nullptr
         );
         
         if (hDir == INVALID_HANDLE_VALUE) {
             logger.Error("Failed to open directory for monitoring: " + directoryPath);
             return;
         }
         
         char buffer[4096];
         DWORD bytesReturned;
         
         logger.Info("Started watching directory: " + directoryPath);
         
         while (running && hasFilePolices) {
             BOOL result = ReadDirectoryChangesW(
                 hDir,
                 buffer,
                 sizeof(buffer),
                 TRUE,  // Watch subdirectories
                 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION,
                 &bytesReturned,
                 nullptr,
                 nullptr
             );
             
             if (!result || bytesReturned == 0) {
                 std::this_thread::sleep_for(std::chrono::milliseconds(500));
                 continue;
             }
             
             FILE_NOTIFY_INFORMATION* pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
             
             do {
                 std::wstring wFileName(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
                 std::string fileName(wFileName.begin(), wFileName.end());
                 std::string fullPath = directoryPath + "\\" + fileName;
                 
                 std::string action;
                 std::string eventSubtype;
                 
                 switch (pNotify->Action) {
                    case FILE_ACTION_ADDED:
                        action = "created";
                        eventSubtype = "file_created";
                        break;
                    case FILE_ACTION_MODIFIED:
                        action = "modified";
                        eventSubtype = "file_modified";
                        break;
                    case FILE_ACTION_REMOVED:
                        action = "deleted";
                        eventSubtype = "file_deleted";
                        // Note: File might already be deleted by the time we get this event
                        // We need to rely on stored original content for quarantine
                        break;
                     case FILE_ACTION_RENAMED_OLD_NAME:
                         action = "renamed_from";
                         eventSubtype = "file_renamed";
                         break;
                     case FILE_ACTION_RENAMED_NEW_NAME:
                         action = "renamed_to";
                         eventSubtype = "file_renamed";
                         break;
                     default:
                         action = "unknown";
                         eventSubtype = "file_access";
                 }
                 
// Check if file should be monitored based on policies
bool shouldMonitor = ShouldMonitorFile(fullPath);

if (shouldMonitor) {
    if (pNotify->Action == FILE_ACTION_REMOVED) {
        // Handle deletion immediately - no delay needed
        HandleFileEvent(fullPath, eventSubtype, action);
    } else {
        // Delay to ensure file is written completely for other events
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        HandleFileEvent(fullPath, eventSubtype, action);
    }
}
                 
                 if (pNotify->NextEntryOffset == 0) break;
                 pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                     reinterpret_cast<char*>(pNotify) + pNotify->NextEntryOffset
                 );
             } while (true);
         }
         
         CloseHandle(hDir);
         logger.Info("Stopped watching directory: " + directoryPath);
     }
     
     bool ShouldMonitorFile(const std::string& filePath) {
         std::string extension = fs::path(filePath).extension().string();
         std::string lowerExt = ToLower(extension);
         
         // Get file policies
         std::vector<PolicyRule> policies;
         {
             std::lock_guard<std::mutex> lock(policiesMutex);
             policies = filePolicies;
         }
         
         // If no policies, don't monitor
         if (policies.empty()) return false;
         
         // Check if file matches any policy's criteria
         for (const auto& policy : policies) {
             // Check if file is in a monitored path for this policy
             bool inMonitoredPath = false;
             for (const auto& policyPath : policy.monitoredPaths) {
                 std::string normalizedPolicyPath = NormalizeFilesystemPath(policyPath);
                 if (filePath.find(normalizedPolicyPath) == 0) {
                     inMonitoredPath = true;
                     break;
                 }
             }
             
             if (!inMonitoredPath) continue;
             
             // If policy has no file extension restrictions, monitor all files
             if (policy.fileExtensions.empty()) {
                 return true;
             }
             
             // Check if extension matches
             for (const auto& policyExt : policy.fileExtensions) {
                 if (lowerExt == ToLower(policyExt)) {
                     return true;
                 }
             }
         }
         
         return false;
     }
     
     void HandleFileEvent(const std::string& filePath, const std::string& eventSubtype, const std::string& action) {
        try {
            if (!allowEvents || !hasFilePolices) return;
            
            // Check if this file is currently being quarantined by us
            {
                std::lock_guard<std::mutex> lock(quarantineMutex);
                if (filesBeingQuarantined.find(filePath) != filesBeingQuarantined.end()) {
                    logger.Debug("Ignoring event for file being quarantined: " + filePath);
                    return;
                }
            }
            
            // Special handling for deletion events
            bool isDeleteEvent = (eventSubtype == "file_deleted");
            
            // For non-delete events, check if file exists
            if (!isDeleteEvent) {
                if (!fs::exists(filePath) || !fs::is_regular_file(filePath)) {
                    return;
                }
            }
            
            // Deduplicate events
            auto eventKey = std::make_pair(filePath, eventSubtype);
            auto now = std::chrono::steady_clock::now();
            
            {
                std::lock_guard<std::mutex> lock(eventsMutex);
                auto it = recentEvents.find(eventKey);
                if (it != recentEvents.end()) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
                    if (elapsed < 2) {
                        return;
                    }
                }
                recentEvents[eventKey] = now;
            }
            
            std::string fileName = fs::path(filePath).filename().string();
            logger.Info("File " + action + ": " + fileName);

            // ── USB Transfer Tracking: register new/modified files ──
            // When a file is created or modified in a monitored path,
            // add it to monitoredFiles so USB transfer detection can find it.
            if (eventSubtype == "file_created" || eventSubtype == "file_modified") {
                std::lock_guard<std::mutex> lock(usbTransferMutex);
                for (const auto& policy : usbTransferPolicies) {
                    if (!policy.enabled) continue;
                    for (const auto& monPath : policy.monitoredPaths) {
                        std::string normalizedMonPath = NormalizeFilesystemPath(monPath);
                        if (filePath.find(normalizedMonPath) == 0) {
                            // File is under a USB-monitored path — add to tracking
                            std::string relativePath = filePath.substr(normalizedMonPath.length());
                            if (!relativePath.empty() && (relativePath[0] == '\\' || relativePath[0] == '/')) {
                                relativePath = relativePath.substr(1);
                            }
                            std::string key = normalizedMonPath + ":" + relativePath;

                            FileMetadata meta;
                            meta.name = fileName;
                            meta.relativePath = relativePath;
                            meta.fullPath = filePath;
                            meta.timestamp = time(NULL);
                            meta.inMonitored = true;
                            try {
                                meta.fileSize = fs::file_size(filePath);
                            } catch (...) {
                                meta.fileSize = 0;
                            }
                            GetSystemTimeAsFileTime(&meta.lastModified);
                            monitoredFiles[key] = meta;

                            logger.Debug("USB tracking: added " + fileName + " (key=" + key + ")");
                            break;
                        }
                    }
                }
            }

            size_t fileSize = 0;
            std::string fileHash = "";
            std::string content = "";
            ClassificationResult classification;
            
            // Get copy of policies
            std::vector<PolicyRule> policies;
            {
                std::lock_guard<std::mutex> lock(policiesMutex);
                policies = filePolicies;
            }
            
            // Filter policies to only those that monitor the file's path AND the event type
            std::vector<PolicyRule> relevantPolicies;
            for (const auto& policy : policies) {
                // Check if policy monitors this path
                bool pathMatches = false;
                for (const auto& policyPath : policy.monitoredPaths) {
                    std::string normalizedPolicyPath = NormalizeFilesystemPath(policyPath);
                    if (filePath.find(normalizedPolicyPath) == 0) {
                        pathMatches = true;
                        break;
                    }
                }
                if (!pathMatches) {
                    logger.Debug("Policy '" + policy.name + "' doesn't match path for file: " + fileName);
                    continue;
                }
                
                // Check if policy monitors this event type
                bool eventMatches = false;
                if (policy.monitoredEvents.empty()) {
                    // Empty monitoredEvents: for backward compatibility, if policy has other config,
                    // treat as "monitor all events". Otherwise, don't monitor.
                    bool hasOtherConfig = !policy.dataTypes.empty() || !policy.monitoredPaths.empty() || !policy.fileExtensions.empty();
                    eventMatches = hasOtherConfig;
                    if (eventMatches) {
                        logger.Debug("Policy '" + policy.name + "' has empty monitoredEvents but other config - treating as monitor all (backward compatibility)");
                    }
                } else {
                    // Check if this specific event type is in the monitoredEvents list
                    std::string monitoredEventsStr = "";
                    for (const auto& monitoredEvent : policy.monitoredEvents) {
                        if (!monitoredEventsStr.empty()) monitoredEventsStr += ", ";
                        monitoredEventsStr += monitoredEvent;
                        if (eventSubtype == monitoredEvent || 
                            monitoredEvent == "all" || 
                            monitoredEvent == "*") {
                            eventMatches = true;
                        }
                    }
                    logger.Debug("Policy '" + policy.name + "' monitoredEvents: [" + monitoredEventsStr + "], event '" + eventSubtype + "' matches: " + (eventMatches ? "YES" : "NO"));
                }
                
                if (eventMatches) {
                    relevantPolicies.push_back(policy);
                    logger.Debug("Policy '" + policy.name + "' added to relevant policies for event '" + eventSubtype + "'");
                }
            }
            
            // If no policies monitor this event type, skip processing entirely
            if (relevantPolicies.empty()) {
                logger.Info("No policies monitor event type '" + eventSubtype + "' for file: " + fileName);
                logger.Debug("Checked " + std::to_string(policies.size()) + " policies, none match event type '" + eventSubtype + "'");
                return;
            } else {
                logger.Debug("Found " + std::to_string(relevantPolicies.size()) + " policies monitoring event type '" + eventSubtype + "'");
            }
            
            // For deletion events, try to get content from stored originals
            if (isDeleteEvent) {
                logger.Info("*** DELETION EVENT: Attempting to retrieve stored content");
                
                // Check if we have original content stored
                {
                    std::lock_guard<std::mutex> lock(originalContentsMutex);
                    auto it = originalFileContents.find(filePath);
                    if (it != originalFileContents.end()) {
                        content = it->second;
                        fileSize = content.size();
                        logger.Info("*** Retrieved original content: " + std::to_string(content.size()) + " bytes");
                        
                        // Calculate hash from stored content
                        std::hash<std::string> hasher;
                        fileHash = std::to_string(hasher(content));
                        
                        // Classify the stored content
                        classification = ContentClassifier::Classify(content, relevantPolicies, eventSubtype);
                    } else {
                        logger.Warning("*** NO ORIGINAL CONTENT STORED for deleted file!");
                        content = "";
                        fileSize = 0;
                    }
                }
                
                // For deletion events with relevant policies, force quarantine action
                if (!relevantPolicies.empty()) {
                    logger.Info("*** DELETION EVENT with " + std::to_string(relevantPolicies.size()) + " relevant policies");
                    
                    // If classification didn't find anything, create a basic result
                    if (classification.labels.empty() && classification.matchedPolicies.empty()) {
                        logger.Info("*** No content classification, but deletion is monitored by policies");
                        classification.severity = "high";
                        classification.suggestedAction = "quarantine";
                        classification.labels.push_back("MONITORED_DELETION");
                        
                        // Add all relevant policies as matched
                        for (const auto& policy : relevantPolicies) {
                            classification.matchedPolicies.push_back(policy.policyId);
                            
                            // Use the policy's action
                            if (policy.action == "quarantine" || policy.action == "block") {
                                classification.suggestedAction = "quarantine";
                                classification.severity = "critical";
                            }
                        }
                    }
                    
                    logger.Info("*** Deletion classification: " + classification.suggestedAction + 
                                ", severity: " + classification.severity + 
                                ", matched policies: " + std::to_string(classification.matchedPolicies.size()));
                }
            } else {
                // For non-deletion events, read file normally
                try {
                    fileSize = fs::file_size(filePath);
                    
                    // Only read and classify files under max size
                    if (fileSize < config.GetClassification().maxFileSizeMB * 1024 * 1024) {
                        fileHash = CalculateFileHash(filePath);
                        content = ReadFileContent(filePath);
                        
                        logger.Debug("Read file content: " + filePath + " (" + std::to_string(content.size()) + " bytes) [Event: " + eventSubtype + "]");
                        
                        // CRITICAL FIX: Store content ONLY on file_created event
                        // This ensures we capture the ORIGINAL content, not modified content
                        if (eventSubtype == "file_created") {
                            std::lock_guard<std::mutex> lock(originalContentsMutex);
                            originalFileContents[filePath] = content;
                            logger.Info("============================================================");
                            logger.Info("*** STORED ORIGINAL CONTENT ***");
                            logger.Info("  File: " + filePath);
                            logger.Info("  Size: " + std::to_string(content.size()) + " bytes");
                            logger.Info("  Content preview: " + content.substr(0, std::min<size_t>(50, content.size())));
                            logger.Info("============================================================");
                        } else {
                            // For other events (modified, etc.), check if we have original stored
                            std::lock_guard<std::mutex> lock(originalContentsMutex);
                            auto it = originalFileContents.find(filePath);
                            if (it != originalFileContents.end()) {
                                logger.Debug("Original content exists: " + std::to_string(it->second.size()) + " bytes (not overwriting)");
                            } else {
                                logger.Warning("*** NO ORIGINAL CONTENT STORED for: " + filePath);
                                logger.Warning("*** This file was created before monitoring started or file_created event was missed");
                            }
                        }
                        
                        // Pass eventSubtype to classification so it can filter policies by event type
                        classification = ContentClassifier::Classify(content, relevantPolicies, eventSubtype);
                    } else {
                        classification.severity = "low";
                        classification.labels.push_back("LARGE_FILE");
                        classification.suggestedAction = "logged";
                    }
                } catch (...) {
                    logger.Debug("Failed to read file details: " + filePath);
                    classification.severity = "low";
                    classification.suggestedAction = "logged";
                }
            }
            
            // Modified skip check - allow deletion events to proceed if policies match
            if (classification.labels.empty() && classification.matchedPolicies.empty()) {
                if (isDeleteEvent && !relevantPolicies.empty()) {
                    logger.Warning("*** DELETION EVENT: Proceeding despite no classification match");
                    classification.severity = "high";
                    classification.suggestedAction = "quarantine";
                    classification.labels.push_back("MONITORED_DELETION");
                    for (const auto& policy : relevantPolicies) {
                        classification.matchedPolicies.push_back(policy.policyId);
                        if (policy.action == "quarantine" || policy.action == "block") {
                            classification.suggestedAction = "quarantine";
                            classification.severity = "critical";
                        }
                    }
                } else {
                    logger.Debug("No sensitive data detected, skipping event");
                    return;
                }
            }
            
        // Build detailed detected content summary
        std::string detectedSummary = "";
        std::vector<std::string> detectedTypes;
        int totalMatches = 0;
        
        for (const auto& [dataType, values] : classification.detectedContent) {
            if (values.empty()) continue;  // Skip empty detections
            
            totalMatches += values.size();
            detectedTypes.push_back(dataType);
            
            detectedSummary += "\n  • " + dataType + ": " + std::to_string(values.size()) + " found\n";
            
            // Determine if this type should be redacted
            std::string lowerType = ToLower(dataType);
            bool shouldRedact = (lowerType.find("password") != std::string::npos ||
                                lowerType.find("api_key") != std::string::npos ||
                                lowerType.find("secret") != std::string::npos ||
                                lowerType.find("token") != std::string::npos ||
                                lowerType.find("private_key") != std::string::npos);
            
            // Show examples (up to 3)
            detectedSummary += "    Values: ";
            for (size_t i = 0; i < values.size() && i < 3; i++) {
                if (i > 0) detectedSummary += ", ";
                
                if (shouldRedact) {
                    detectedSummary += "[REDACTED]";
                } else {
                    std::string value = values[i];
                    // Truncate long values
                    if (value.length() > 40) {
                        value = value.substr(0, 37) + "...";
                    }
                    detectedSummary += value;
                }
            }
            
            if (values.size() > 3) {
                detectedSummary += " ... (+" + std::to_string(values.size() - 3) + " more)";
            }
            detectedSummary += "\n";
        }
        
        // Final check: if summary is empty after building, don't send alert
        if (detectedSummary.empty() || totalMatches == 0) {
            logger.Debug("No sensitive content to report - skipping alert");
            return;
        }
            
            std::string severity = classification.severity;
            std::string detectedAction = classification.suggestedAction;
            
            // CRITICAL: Only enforce actions (quarantine/block) if policies explicitly matched
            // If no policies matched, only log the event - don't enforce actions
            bool shouldEnforceAction = !classification.matchedPolicies.empty();
            
            logger.Debug("Event: " + eventSubtype + ", Action: " + detectedAction + ", Policies Matched: " + 
                         std::to_string(classification.matchedPolicies.size()) + ", Should Enforce: " + 
                         (shouldEnforceAction ? "YES" : "NO"));
            
            // Enforce policy actions only if policies matched
            if (detectedAction == "quarantine" && shouldEnforceAction) {
                logger.Info("Quarantine requested for event '" + eventSubtype + "' - " + 
                           std::to_string(classification.matchedPolicies.size()) + " policies matched");
                
                // Check if this file was recently restored
                bool isRecentlyRestored = false;
                {
                    std::lock_guard<std::mutex> lock(restoredMutex);
                    isRecentlyRestored = (recentlyRestored.find(filePath) != recentlyRestored.end());
                }
                
                // SPECIAL HANDLING FOR DELETION EVENTS
                if (isDeleteEvent && !isRecentlyRestored) {
                    logger.Warning("============================================================");
                    logger.Warning("*** DELETION INTERCEPTED ***");
                    logger.Warning("  File: " + filePath);
                    logger.Warning("  User attempted to delete this file");
                    logger.Warning("  Policy requires quarantine on deletion - preventing deletion");
                    logger.Warning("============================================================");
                    
                    // Check if we have original content stored
                    std::string originalContent;
                    bool hasOriginal = false;
                    {
                        std::lock_guard<std::mutex> lock(originalContentsMutex);
                        auto it = originalFileContents.find(filePath);
                        if (it != originalFileContents.end()) {
                            originalContent = it->second;
                            hasOriginal = true;
                            logger.Info("*** Found original content: " + std::to_string(originalContent.size()) + " bytes");
                        } else {
                            logger.Warning("*** No original content stored for deleted file!");
                        }
                    }
                    
                    if (hasOriginal && !originalContent.empty()) {
                        // Mark file as being quarantined BEFORE the operation
                        {
                            std::lock_guard<std::mutex> lock(quarantineMutex);
                            filesBeingQuarantined.insert(filePath);
                        }
                        
                        try {
                            // Ensure quarantine folder exists
                            if (!fs::exists(config.GetQuarantine().folder)) {
                                fs::create_directories(config.GetQuarantine().folder);
                            }
                            
                            // Generate unique quarantine path
                            std::string timestamp = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
                            std::string fileName = fs::path(filePath).filename().string();
                            std::string quarantinePath = config.GetQuarantine().folder + "\\" + timestamp + "_" + fileName;
                            
                            // Write original content to quarantine location
                            std::ofstream quarantineFile(quarantinePath, std::ios::binary | std::ios::trunc);
                            if (quarantineFile.is_open()) {
                                quarantineFile.write(originalContent.c_str(), originalContent.size());
                                quarantineFile.flush();
                                quarantineFile.close();
                                
                                logger.Warning("*** Saved deleted file to quarantine: " + quarantinePath);
                                detectedAction = "quarantined_on_delete";
                                
                                // Schedule restoration - capture filePath by value
                                std::string filePathCopy = filePath;
                                std::thread restoreThread([this, quarantinePath, filePathCopy, originalContent]() {
                                    logger.Info("*** QUARANTINE (Delete): File saved to: " + quarantinePath);
                                    logger.Info("*** RESTORATION: Will restore in 10 minutes...");
                                    
                                    std::this_thread::sleep_for(std::chrono::minutes(10));
                                    
                                    logger.Info("*** RESTORATION STARTED for deleted file: " + filePathCopy);
                                    
                                    try {
                                        // Mark as being quarantined during restoration too
                                        {
                                            std::lock_guard<std::mutex> lock(quarantineMutex);
                                            filesBeingQuarantined.insert(filePathCopy);
                                        }
                                        
                                        // Restore the file from original content
                                        std::ofstream out(filePathCopy, std::ios::binary | std::ios::trunc);
                                        if (out.is_open()) {
                                            out.write(originalContent.c_str(), originalContent.size());
                                            out.flush();
                                            out.close();
                                            
                                            size_t restoredSize = fs::file_size(filePathCopy);
                                            logger.Info("*** RESTORED deleted file: " + filePathCopy);
                                            logger.Info("*** Restored size: " + std::to_string(restoredSize) + " bytes");
                                            
                                            // Delete quarantine file
                                            if (fs::exists(quarantinePath)) {
                                                fs::remove(quarantinePath);
                                                logger.Info("*** Deleted quarantine file: " + quarantinePath);
                                            }
                                            
                                            // Clear stored content
                                            {
                                                std::lock_guard<std::mutex> lock(originalContentsMutex);
                                                originalFileContents.erase(filePathCopy);
                                            }
                                            
                                            // Mark as recently restored
                                            {
                                                std::lock_guard<std::mutex> lock(restoredMutex);
                                                recentlyRestored.insert(filePathCopy);
                                            }
                                            
                                            // Remove from quarantine tracking and restored set after delay
                                            std::thread cleanupThread([this, filePathCopy]() {
                                                std::this_thread::sleep_for(std::chrono::seconds(30));
                                                {
                                                    std::lock_guard<std::mutex> lock(quarantineMutex);
                                                    filesBeingQuarantined.erase(filePathCopy);
                                                }
                                                {
                                                    std::lock_guard<std::mutex> lock(restoredMutex);
                                                    recentlyRestored.erase(filePathCopy);
                                                }
                                                logger.Info("*** Grace period ended for: " + filePathCopy);
                                            });
                                            cleanupThread.detach();
                                            
                                        } else {
                                            logger.Error("*** FAILED to restore deleted file: " + filePathCopy);
                                            // Remove from quarantine tracking on failure
                                            std::lock_guard<std::mutex> lock(quarantineMutex);
                                            filesBeingQuarantined.erase(filePathCopy);
                                        }
                                    } catch (const std::exception& e) {
                                        logger.Error("*** RESTORATION FAILED: " + std::string(e.what()));
                                        // Remove from quarantine tracking on error
                                        std::lock_guard<std::mutex> lock(quarantineMutex);
                                        filesBeingQuarantined.erase(filePathCopy);
                                    }
                                });
                                restoreThread.detach();
                                
                            } else {
                                logger.Error("*** Failed to create quarantine file: " + quarantinePath);
                                // Remove from tracking on failure
                                std::lock_guard<std::mutex> lock(quarantineMutex);
                                filesBeingQuarantined.erase(filePath);
                            }
                            
                        } catch (const std::exception& e) {
                            logger.Error("*** Failed to quarantine deleted file: " + std::string(e.what()));
                            // Remove from tracking on error
                            std::lock_guard<std::mutex> lock(quarantineMutex);
                            filesBeingQuarantined.erase(filePath);
                        }
                    } else {
                        logger.Warning("*** Cannot quarantine deletion - no original content stored!");
                        logger.Warning("*** File will remain deleted");
                    }
                    
                    // Skip the normal quarantine logic below since we handled deletion specially
                    goto skip_normal_quarantine;
                }
                
                // NORMAL QUARANTINE (for modify/create events)
                if (!isRecentlyRestored) {
                    // Check if we have original content stored
                    bool hasOriginalContent = false;
                    size_t storedSize = 0;
                    std::string storedContentPreview;
                    {
                        std::lock_guard<std::mutex> lock(originalContentsMutex);
                        auto it = originalFileContents.find(filePath);
                        if (it != originalFileContents.end()) {
                            hasOriginalContent = true;
                            storedSize = it->second.size();
                            storedContentPreview = it->second.substr(0, std::min<size_t>(50, it->second.size()));
                        }
                    }
                    
                    logger.Info("============================================================");
                    logger.Info("*** QUARANTINE CHECK ***");
                    logger.Info("  File: " + filePath);
                    logger.Info("  Event: " + eventSubtype);
                    logger.Info("  Current content size: " + std::to_string(content.size()) + " bytes");
                    logger.Info("  Current content preview: " + content.substr(0, std::min<size_t>(50, content.size())));
                    
                    if (hasOriginalContent) {
                        logger.Info("  ✓ Original content stored: " + std::to_string(storedSize) + " bytes");
                        logger.Info("  ✓ Original content preview: " + storedContentPreview);
                        logger.Info("  ✓ Will restore to original content after quarantine");
                    } else {
                        logger.Warning("  ✗ NO ORIGINAL CONTENT STORED!");
                        logger.Warning("  ✗ File will NOT be restored properly");
                    }
                    logger.Info("============================================================");
                    
                    try {
                        // Mark file as being quarantined BEFORE moving it
                        {
                            std::lock_guard<std::mutex> lock(quarantineMutex);
                            filesBeingQuarantined.insert(filePath);
                        }
                        
                        // Ensure quarantine folder exists
                        if (!fs::exists(config.GetQuarantine().folder)) {
                            fs::create_directories(config.GetQuarantine().folder);
                        }
                        
                        // Generate a unique quarantine path
                        std::string timestamp = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
                        std::string quarantinePath = config.GetQuarantine().folder + "\\" + timestamp + "_" + fileName;
                        
                        fs::rename(filePath, quarantinePath);
                        logger.Warning("Quarantined file: " + filePath + " to " + quarantinePath);
                        detectedAction = "quarantined";
                        
                        // Schedule restoration - capture filePath by value
                        std::string filePathCopy = filePath;
                        std::thread restoreThread([this, quarantinePath, filePathCopy]() {
                            logger.Info("*** QUARANTINE: File moved to: " + quarantinePath);
                            logger.Info("*** RESTORATION: Will restore in 10 minutes...");
                            
                            std::this_thread::sleep_for(std::chrono::minutes(10));
                            
                            logger.Info("*** RESTORATION STARTED for: " + filePathCopy);
                            
                            try {
                                // Check if we have original content
                                std::string originalContent;
                                bool hasOriginal = false;
                                size_t originalSize = 0;
                                
                                {
                                    std::lock_guard<std::mutex> lock(originalContentsMutex);
                                    auto it = originalFileContents.find(filePathCopy);
                                    if (it != originalFileContents.end()) {
                                        originalContent = it->second;
                                        originalSize = originalContent.size();
                                        hasOriginal = true;
                                        logger.Info("*** FOUND ORIGINAL CONTENT: " + std::to_string(originalSize) + " bytes");
                                    } else {
                                        logger.Warning("*** NO ORIGINAL CONTENT FOUND in storage!");
                                    }
                                }
                                
                                if (hasOriginal && !originalContent.empty()) {
                                    logger.Info("*** WRITING ORIGINAL CONTENT back to: " + filePathCopy);
                                    
                                    std::ofstream out(filePathCopy, std::ios::binary | std::ios::trunc);
                                    if (out.is_open()) {
                                        out.write(originalContent.c_str(), originalContent.size());
                                        out.flush();
                                        out.close();
                                        
                                        if (fs::exists(filePathCopy)) {
                                            size_t restoredSize = fs::file_size(filePathCopy);
                                            logger.Info("*** RESTORED with ORIGINAL content: " + filePathCopy);
                                            logger.Info("*** Original size: " + std::to_string(originalSize) + " bytes");
                                            logger.Info("*** Restored size: " + std::to_string(restoredSize) + " bytes");
                                            
                                            if (restoredSize == originalSize) {
                                                logger.Info("*** VERIFICATION: Size matches - restoration successful!");
                                            } else {
                                                logger.Error("*** VERIFICATION FAILED: Size mismatch!");
                                            }
                                        }
                                        
                                        // Delete the quarantined file
                                        try {
                                            if (fs::exists(quarantinePath)) {
                                                fs::remove(quarantinePath);
                                                logger.Info("*** Deleted quarantine file: " + quarantinePath);
                                            }
                                        } catch (const std::exception& e) {
                                            logger.Warning("Could not delete quarantine file: " + std::string(e.what()));
                                        }
                                        
                                        // Clear stored content after successful restoration
                                        {
                                            std::lock_guard<std::mutex> lock(originalContentsMutex);
                                            originalFileContents.erase(filePathCopy);
                                            logger.Info("*** Cleared stored original content");
                                        }
                                    } else {
                                        logger.Error("*** FAILED to open file for restoration: " + filePathCopy);
                                        // Fallback: restore quarantined file
                                        if (fs::exists(quarantinePath) && !fs::exists(filePathCopy)) {
                                            fs::rename(quarantinePath, filePathCopy);
                                            logger.Warning("*** Restored quarantined file as fallback: " + filePathCopy);
                                        }
                                    }
                                } else {
                                    // No original content, restore the quarantined file as-is
                                    logger.Warning("*** NO ORIGINAL CONTENT - restoring quarantined version");
                                    if (fs::exists(quarantinePath) && !fs::exists(filePathCopy)) {
                                        fs::rename(quarantinePath, filePathCopy);
                                        logger.Info("*** Restored quarantined file: " + filePathCopy);
                                    }
                                }
                                
                                // Mark as recently restored to prevent immediate re-quarantining
                                {
                                    std::lock_guard<std::mutex> lock(restoredMutex);
                                    recentlyRestored.insert(filePathCopy);
                                    logger.Info("*** Marked as recently restored (30 second grace period)");
                                }
                                
                                // Remove from both tracking sets after delay
                                std::thread cleanupThread([this, filePathCopy]() {
                                    std::this_thread::sleep_for(std::chrono::seconds(30));
                                    {
                                        std::lock_guard<std::mutex> lock(quarantineMutex);
                                        filesBeingQuarantined.erase(filePathCopy);
                                    }
                                    {
                                        std::lock_guard<std::mutex> lock(restoredMutex);
                                        recentlyRestored.erase(filePathCopy);
                                    }
                                    logger.Info("*** Grace period ended for: " + filePathCopy);
                                });
                                cleanupThread.detach();
                                
                            } catch (const std::exception& e) {
                                logger.Error("*** RESTORATION FAILED: " + std::string(e.what()));
                                // Remove from quarantine tracking on error
                                std::lock_guard<std::mutex> lock(quarantineMutex);
                                filesBeingQuarantined.erase(filePathCopy);
                            }
                        });
                        restoreThread.detach();
                    } catch (const std::exception& e) {
                        logger.Error("Failed to quarantine file: " + filePath + " - " + e.what());
                        // Remove from tracking on failure
                        std::lock_guard<std::mutex> lock(quarantineMutex);
                        filesBeingQuarantined.erase(filePath);
                    }
                } else {
                    logger.Info("Skipping quarantine for recently restored file: " + filePath);
                    detectedAction = "logged";
                }
                
            skip_normal_quarantine:
                ; // Empty statement for goto label
                
            } else if (detectedAction == "quarantine" && !shouldEnforceAction) {
                // Sensitive data detected but no policies matched - only log
                logger.Info("Sensitive data detected but no policies matched for event type '" + eventSubtype + "' - logging only");
                detectedAction = "logged";
            } else if (detectedAction == "block" && shouldEnforceAction) {
                try {
                    fs::remove(filePath);
                    logger.Warning("Enforced policy by deleting file: " + filePath);
                    detectedAction = "deleted";
                } catch (const std::exception& e) {
                    logger.Error("Failed to enforce policy on file: " + filePath + " - " + e.what());
                }
            } else if (detectedAction == "block" && !shouldEnforceAction) {
                // Sensitive data detected but no policies matched - only log
                logger.Info("Sensitive data detected but no policies matched for event type '" + eventSubtype + "' - logging only");
                detectedAction = "logged";
            } else {
                // No policies matched - just log if sensitive data detected
                if (!classification.labels.empty()) {
                    logger.Info("Sensitive data detected but no policies matched for event type '" + eventSubtype + "' - logging only");
                    detectedAction = "logged";
                } else {
                    // No sensitive data, skip event
                    return;
                }
            }
            
            JsonBuilder json;
            json.AddString("event_id", GenerateUUID());
            json.AddString("event_type", "file");
            json.AddString("event_subtype", eventSubtype);
            json.AddString("agent_id", config.agentId);
            json.AddString("source_type", "agent");
            json.AddString("user_email", GetUsername() + "@" + GetHostname());
            json.AddString("description", "File " + action + ": " + fileName + " - " + detectedSummary);
            json.AddString("severity", severity);
            json.AddString("action", detectedAction);
            json.AddString("file_path", filePath);
            json.AddString("file_name", fileName);
            json.AddInt("file_size", static_cast<int>(fileSize));
            json.AddString("detected_content", detectedSummary);
            json.AddArray("data_types", detectedTypes);
            json.AddArray("matched_policies", classification.matchedPolicies);
            json.AddInt("total_matches", totalMatches);
            
            if (!fileHash.empty()) {
                json.AddString("file_hash", fileHash);
            }
            
            json.AddString("timestamp", GetCurrentTimestampISO());
            
            SendEvent(json.Build());
            
            logger.Warning("============================================================");
            logger.Warning("  FILE ALERT: Sensitive Data Detected!");
            logger.Warning("============================================================");
            logger.Warning("  File: " + fileName);
            logger.Warning("  Action: " + action);
            logger.Warning("  Severity: " + severity);
            logger.Warning("  Detected: " + detectedSummary);
            logger.Warning("  Matched Policies: " + std::to_string(classification.matchedPolicies.size()));
            logger.Warning("  Policy Action: " + detectedAction);
            logger.Warning("============================================================");
            
        } catch (const std::exception& e) {
            logger.Error(std::string("Error handling file event: ") + e.what());
        } catch (...) {
            logger.Error("Unknown error handling file event");
        }
    }
     
     void RemovableDriveMonitor() {
         logger.Info("Removable drive monitoring started");
         
         while (running) {
             if (!hasUsbTransferPolicies || !allowEvents) {
                 std::this_thread::sleep_for(std::chrono::seconds(5));
                 continue;
             }
             
             try {
                 std::set<std::string> currentDrives = GetRemovableDrives();
                 
                 for (const auto& drive : currentDrives) {
                     if (removableDrives.find(drive) == removableDrives.end()) {
                         MonitorRemovableDrive(drive);
                     }
                 }
                 
                 removableDrives = currentDrives;
             } catch (...) {
                 logger.Error("Error monitoring removable drives");
             }
             
             std::this_thread::sleep_for(std::chrono::seconds(5));
         }
     }
     
     std::set<std::string> GetRemovableDrives() {
         std::set<std::string> drives;
         
         DWORD driveMask = GetLogicalDrives();
         for (char letter = 'A'; letter <= 'Z'; ++letter) {
             if (driveMask & 1) {
                 std::string drive = std::string(1, letter) + ":";
                 if (GetDriveTypeA(drive.c_str()) == DRIVE_REMOVABLE) {
                     drives.insert(drive);
                 }
             }
             driveMask >>= 1;
         }
         
         return drives;
     }
     
     void MonitorRemovableDrive(const std::string& driveLetter) {
                 logger.Info("Monitoring removable drive: " + driveLetter);
         
         try {
             for (const auto& entry : fs::recursive_directory_iterator(driveLetter)) {
                 if (entry.is_regular_file()) {
                     HandleRemovableDriveFile(entry.path().string());
                 }
             }
         } catch (...) {
             logger.Debug("Error accessing removable drive: " + driveLetter);
         }
     }
     
     void HandleRemovableDriveFile(const std::string& filePath) {
         try {
             if (!allowEvents || !hasUsbTransferPolicies) return;
             
             logger.Info("File detected on removable drive: " + filePath);
             
             if (!fs::exists(filePath)) return;
             
             size_t fileSize = fs::file_size(filePath);
             std::string fileName = fs::path(filePath).filename().string();
             
             std::this_thread::sleep_for(std::chrono::milliseconds(300));
             
             
             std::string fileHash = "";
             try {
                 fileHash = CalculateFileHash(filePath);
             } catch (...) {
                 logger.Error("Failed to calculate hash for: " + filePath);
                 return;
             }
             
             std::string sourceFile = FindSourceFileInMonitoredDirs(fileHash, fileSize, fileName);
             
             if (!sourceFile.empty()) {
                 logger.Warning("Copy detected: " + sourceFile + " -> " + filePath);
                 
                 bool blocked = BlockFileTransfer(filePath);
                 SendBlockedTransferEvent(sourceFile, filePath, fileHash, fileSize, blocked);
             }
         } catch (...) {
             logger.Error("Error handling removable drive file");
         }
     }
     
     std::string FindSourceFileInMonitoredDirs(const std::string& fileHash,
                                              size_t fileSize,
                                              const std::string& fileName) {
         if (fileHash.empty()) return "";
         
         // Get monitored directories from policies
         std::vector<std::string> dirsToSearch;
         {
             std::lock_guard<std::mutex> lock(policiesMutex);
             dirsToSearch = monitoredDirectories;
         }
         
         for (const auto& monitoredDir : dirsToSearch) {
             try {
                 for (const auto& entry : fs::recursive_directory_iterator(monitoredDir)) {
                     if (entry.is_regular_file() &&
                         entry.path().filename().string() == fileName) {
                         
                         if (fs::file_size(entry.path()) == fileSize) {
                             std::string candidateHash = CalculateFileHash(entry.path().string());
                             if (candidateHash == fileHash) {
                                 return entry.path().string();
                             }
                         }
                     }
                 }
             } catch (...) {
                 continue;
             }
         }
         
         return "";
     }
     
     bool BlockFileTransfer(const std::string& filePath) {
         try {
             if (fs::exists(filePath)) {
                 fs::remove(filePath);
                 logger.Warning("Blocked file transfer by deleting: " + filePath);
                 return true;
             }
             return false;
         } catch (...) {
             logger.Error("Failed to block transfer: " + filePath);
             return false;
         }
     }
     
     void SendBlockedTransferEvent(const std::string& sourceFile,
                                   const std::string& destFile,
                                   const std::string& fileHash,
                                   size_t fileSize,
                                   bool blocked) {
         try {
             std::string content = ReadFileContent(sourceFile);
             std::vector<PolicyRule> policies;
             {
                 std::lock_guard<std::mutex> lock(policiesMutex);
                 policies = clipboardPolicies;
             }
             auto classification = ContentClassifier::Classify(content, policies);
             
             std::string severity = blocked ? "critical" : "high";
             std::string description = blocked ?
                 "File transfer blocked: " + fs::path(sourceFile).filename().string() :
                 "File transfer detected: " + fs::path(sourceFile).filename().string();
             
             JsonBuilder json;
             json.AddString("event_id", GenerateUUID());
             json.AddString("event_type", "file");
             json.AddString("event_subtype", blocked ? "transfer_blocked" : "transfer_attempt");
             json.AddString("agent_id", config.agentId);
             json.AddString("source_type", "agent");
             json.AddString("user_email", GetUsername() + "@" + GetHostname());
             json.AddString("description", description);
             json.AddString("severity", severity);
             json.AddString("action", blocked ? "blocked" : "logged");
             json.AddString("file_path", sourceFile);
             json.AddString("file_name", fs::path(sourceFile).filename().string());
             json.AddInt("file_size", static_cast<int>(fileSize));
             json.AddString("file_hash", fileHash);
             json.AddString("destination", destFile);
             json.AddBool("blocked", blocked);
             json.AddString("destination_type", "removable_drive");
             json.AddString("transfer_type", "usb_copy");
             json.AddString("timestamp", GetCurrentTimestampISO());
             
             SendEvent(json.Build());
             logger.Info("Transfer event sent - Blocked: " + std::to_string(blocked));
         } catch (...) {
             logger.Error("Error sending blocked transfer event");
         }
     }
     
     void SendEvent(const std::string& eventData) {
         try {
             if (!allowEvents) {
                 logger.Debug("Dropping event because no active policies");
                 return;
             }
             
             auto [status, response] = httpClient->Post("/events", eventData);
             
             if (status == 200 || status == 201) {
                 logger.Debug("Event sent successfully");
             } else {
                 logger.Warning("Failed to send event: " + std::to_string(status));
             }
         } catch (...) {
             logger.Error("Error sending event");
         }
     }
     void CleanupOldOriginalContents() {
        const size_t MAX_STORED_FILES = 1000;
        std::lock_guard<std::mutex> lock(originalContentsMutex);
        
        if (originalFileContents.size() > MAX_STORED_FILES) {
            // Remove oldest half of entries (simple approach)
            size_t toRemove = originalFileContents.size() - (MAX_STORED_FILES / 2);
            auto it = originalFileContents.begin();
            for (size_t i = 0; i < toRemove && it != originalFileContents.end(); ++i) {
                it = originalFileContents.erase(it);
            }
            logger.Debug("Cleaned up old original content entries");
        }
    }
    void DumpOriginalContentStorage() {
        std::lock_guard<std::mutex> lock(originalContentsMutex);
        logger.Info("========================================");
        logger.Info("ORIGINAL CONTENT STORAGE DUMP:");
        logger.Info("Total files stored: " + std::to_string(originalFileContents.size()));
        for (const auto& [path, content] : originalFileContents) {
            logger.Info("  - " + path + " (" + std::to_string(content.size()) + " bytes)");
        }
        logger.Info("========================================");
    }
    void ScanAndStoreExistingFiles() {
        logger.Info("========================================");
        logger.Info("Scanning existing files in monitored directories...");
        logger.Info("========================================");
        
        std::vector<std::string> dirsToScan;
        {
            std::lock_guard<std::mutex> lock(policiesMutex);
            dirsToScan = monitoredDirectories;
        }
        
        int filesScanned = 0;
        int filesStored = 0;
        
        for (const auto& dir : dirsToScan) {
            try {
                if (!fs::exists(dir)) {
                    logger.Warning("Directory does not exist: " + dir);
                    continue;
                }
                
                logger.Info("Scanning directory: " + dir);
                
                for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                    try {
                        if (!entry.is_regular_file()) continue;
                        
                        std::string filePath = entry.path().string();
                        filesScanned++;
                        
                        // Check if file should be monitored
                        if (!ShouldMonitorFile(filePath)) {
                            continue;
                        }
                        
                        // Check if already stored
                        bool alreadyStored = false;
                        {
                            std::lock_guard<std::mutex> lock(originalContentsMutex);
                            alreadyStored = (originalFileContents.find(filePath) != originalFileContents.end());
                        }
                        
                        if (alreadyStored) {
                            continue;
                        }
                        
                        // Read and store content
                        size_t fileSize = fs::file_size(filePath);
                        if (fileSize < config.GetClassification().maxFileSizeMB * 1024 * 1024) {
                            std::string content = ReadFileContent(filePath);
                            if (!content.empty()) {
                                std::lock_guard<std::mutex> lock(originalContentsMutex);
                                originalFileContents[filePath] = content;
                                filesStored++;
                                
                                logger.Info("  ✓ Stored baseline for existing file: " + entry.path().filename().string() + 
                                          " (" + std::to_string(content.size()) + " bytes)");
                            }
                        }
                        
                    } catch (const std::exception& e) {
                        logger.Debug("Error scanning file: " + std::string(e.what()));
                    }
                }
                
            } catch (const std::exception& e) {
                logger.Warning("Error scanning directory " + dir + ": " + std::string(e.what()));
            }
        }
        
        logger.Info("========================================");
        logger.Info("Scan complete:");
        logger.Info("  Files scanned: " + std::to_string(filesScanned));
        logger.Info("  Baselines stored: " + std::to_string(filesStored));
        logger.Info("========================================");
    }

    std::string GetBetterDeviceName(const std::string& deviceId) {
        std::string deviceName = "USB Device";
        
        // Extract Vendor and Product IDs
        std::string vendorId = "????";
        std::string productId = "????";
        
        size_t vidPos = deviceId.find("VID_");
        if (vidPos != std::string::npos && vidPos + 8 <= deviceId.length()) {
            vendorId = deviceId.substr(vidPos + 4, 4);
        }
        
        size_t pidPos = deviceId.find("PID_");
        if (pidPos != std::string::npos && pidPos + 8 <= deviceId.length()) {
            productId = deviceId.substr(pidPos + 4, 4);
        }
        
        // Try to get friendly name using SetupAPI
        HDEVINFO hDevInfo = SetupDiGetClassDevsA(
            NULL,
            "USB",
            NULL,
            DIGCF_PRESENT | DIGCF_ALLCLASSES
        );
        
        if (hDevInfo != INVALID_HANDLE_VALUE) {
            SP_DEVINFO_DATA devInfoData;
            devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
            
            for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
                char currentDeviceId[256];
                if (SetupDiGetDeviceInstanceIdA(hDevInfo, &devInfoData, currentDeviceId, sizeof(currentDeviceId), NULL)) {
                    // Check if this matches our device
                    if (deviceId.find(vendorId) != std::string::npos && 
                        std::string(currentDeviceId).find(vendorId) != std::string::npos &&
                        std::string(currentDeviceId).find(productId) != std::string::npos) {
                        
                        // Get friendly name
                        char friendlyName[256];
                        DWORD propertyType;
                        if (SetupDiGetDeviceRegistryPropertyA(
                            hDevInfo,
                            &devInfoData,
                            SPDRP_FRIENDLYNAME,
                            &propertyType,
                            (BYTE*)friendlyName,
                            sizeof(friendlyName),
                            NULL)) {
                            deviceName = std::string(friendlyName);
                            break;
                        }
                        
                        // Try device description
                        if (SetupDiGetDeviceRegistryPropertyA(
                            hDevInfo,
                            &devInfoData,
                            SPDRP_DEVICEDESC,
                            &propertyType,
                            (BYTE*)friendlyName,
                            sizeof(friendlyName),
                            NULL)) {
                            deviceName = std::string(friendlyName);
                            break;
                        }
                    }
                }
            }
            
            SetupDiDestroyDeviceInfoList(hDevInfo);
        }
        
        // If we couldn't get a friendly name, use VID/PID
        if (deviceName == "USB Device") {
            deviceName = "USB Device (VID:" + vendorId + " PID:" + productId + ")";
        }
        
        return deviceName;
    }

    std::string GetDriveLetterForDevice(const std::string& deviceId) {
        // Scan all removable drives
        DWORD driveMask = GetLogicalDrives();
        
        for (char letter = 'A'; letter <= 'Z'; ++letter) {
            if (driveMask & 1) {
                std::string drivePath = std::string(1, letter) + ":";
                UINT driveType = GetDriveTypeA(drivePath.c_str());
                
                // Check if removable
                if (driveType == DRIVE_REMOVABLE) {
                    // This is a USB drive - we'll assume the most recently detected one
                    // matches our device (good enough for most cases)
                    return drivePath;
                }
            }
            driveMask >>= 1;
        }
        
        return "";
    }
    void UsbFileTransferMonitor() {
        logger.Info("USB file transfer monitoring started (monitor.cpp logic)");
        
        std::set<std::string> knownUSBDrives;  // Track which USB drives we've already seen
        
        while (running) {
            if (!hasUsbTransferPolicies || !allowEvents) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
            
            try {
                // Get all removable drives
                DWORD driveMask = GetLogicalDrives();
                std::set<std::string> currentDrives;
                
                for (char letter = 'A'; letter <= 'Z'; ++letter) {
                    if (driveMask & 1) {
                        std::string drivePath = std::string(1, letter) + ":";
                        UINT driveType = GetDriveTypeA(drivePath.c_str());
                        
                        if (driveType == DRIVE_REMOVABLE) {
                            // CRITICAL: Verify drive is actually accessible before adding
                            DWORD sectorsPerCluster, bytesPerSector, numberOfFreeClusters, totalNumberOfClusters;
                            if (GetDiskFreeSpaceA(drivePath.c_str(), &sectorsPerCluster, &bytesPerSector, 
                                                 &numberOfFreeClusters, &totalNumberOfClusters)) {
                                // Drive is accessible
                                currentDrives.insert(drivePath);
                                
                                // Check if this is a NEW USB drive
                                if (knownUSBDrives.find(drivePath) == knownUSBDrives.end()) {
                                    logger.Info("\n[USB DETECTED] New USB drive connected: " + drivePath);
                                    
                                    // CRITICAL: Mark all existing files on new USB as already processed
                                    // This prevents alerts for files that were already on the USB
                                    MarkExistingUSBFilesAsProcessed(drivePath);
                                    
                                    knownUSBDrives.insert(drivePath);
                                }
                            } else {
                                // Drive exists but is not accessible (blocked/ejected)
                                logger.Debug("Drive " + drivePath + " exists but is not accessible (likely blocked)");
                            }
                        }
                    }
                    driveMask >>= 1;
                }
                
                // Remove disconnected drives from known list
                for (auto it = knownUSBDrives.begin(); it != knownUSBDrives.end();) {
                    if (currentDrives.find(*it) == currentDrives.end()) {
                        logger.Info("[USB REMOVED] USB drive disconnected: " + *it);
                        
                        // Clean up state tracking for this drive
                        std::lock_guard<std::mutex> lock(usbTransferMutex);
                        std::string drive = *it;
                        
                        // Remove all state entries for this drive
                        for (auto stateIt = currentUSBFileState.begin(); stateIt != currentUSBFileState.end();) {
                            if (stateIt->first.find(drive + ":") == 0) {
                                stateIt = currentUSBFileState.erase(stateIt);
                            } else {
                                ++stateIt;
                            }
                        }
                        
                        it = knownUSBDrives.erase(it);
                    } else {
                        ++it;
                    }
                }
                
                // Check each USB drive for NEW tracked files (only accessible drives)
                for (const auto& drive : currentDrives) {
                    CheckUSBDriveForMonitoredFiles(drive);
                }
                
            } catch (const std::exception& e) {
                logger.Error(std::string("USB file transfer monitor error: ") + e.what());
            } catch (...) {
                logger.Error("Unknown USB file transfer monitor error");
            }
            
            // Check every 1 second
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        logger.Info("USB file transfer monitoring stopped");
    }

    void MarkExistingUSBFilesAsProcessed(const std::string& drivePath) {
        try {
            // CRITICAL: Verify drive is accessible before scanning
            DWORD sectorsPerCluster, bytesPerSector, numberOfFreeClusters, totalNumberOfClusters;
            if (!GetDiskFreeSpaceA(drivePath.c_str(), &sectorsPerCluster, &bytesPerSector, 
                                   &numberOfFreeClusters, &totalNumberOfClusters)) {
                logger.Debug("Drive " + drivePath + " is not accessible - skipping pre-existing file marking");
                return;
            }
            
            std::vector<std::pair<std::string, std::string>> existingFiles;
            ScanDirectoryRecursiveUSB(drivePath, drivePath, existingFiles);
            
            std::lock_guard<std::mutex> lock(usbTransferMutex);
            
            int markedCount = 0;
            for (const auto& filePair : existingFiles) {
                const std::string& fileName = filePair.first;
                
                // Check if this matches any monitored file
                for (const auto& monitoredPair : monitoredFiles) {
                    if (monitoredPair.second.name == fileName) {
                        std::string fileKey = drivePath + ":" + fileName;
                        currentUSBFileState[fileKey] = true;  // Mark as currently on USB
                        markedCount++;
                        break;
                    }
                }
            }
            
            if (markedCount > 0) {
                logger.Info("[INFO] Ignoring " + std::to_string(markedCount) +
                           " pre-existing monitored files on USB: " + drivePath);
            }

            // Also mark all USB files with classif: prefix for classification-based policies
            // (policies with empty monitoredPaths). This prevents false alerts for files
            // already on the USB when the drive is first connected.
            bool hasClassificationPolicies = false;
            for (const auto& policy : usbTransferPolicies) {
                if (policy.enabled && policy.monitoredPaths.empty()) {
                    hasClassificationPolicies = true;
                    break;
                }
            }
            if (hasClassificationPolicies) {
                for (const auto& filePair : existingFiles) {
                    std::string classifKey = std::string("classif:") + drivePath + ":" + filePair.first;
                    currentUSBFileState[classifKey] = true;
                }
                logger.Info("[INFO] Marked " + std::to_string(existingFiles.size()) +
                           " pre-existing USB files (classification-based monitoring): " + drivePath);
            }

        } catch (const fs::filesystem_error& e) {
            logger.Debug("Drive not accessible for pre-existing file scan: " + drivePath);
        } catch (const std::exception& e) {
            logger.Debug("Error marking existing USB files: " + std::string(e.what()));
        }
    }

    // Real-time classification evaluation result
    struct PolicyEvaluationResult {
        bool shouldBlock;
        std::string action;  // "allow" or "block"
        std::string reason;
        std::string classificationLevel;  // "Public", "Internal", "Confidential", "Restricted"
        double confidenceScore;
        std::vector<std::string> matchedRules;
        int totalMatches;
        bool evaluationSucceeded;
    };

    // Call server-side real-time policy evaluation
    PolicyEvaluationResult EvaluatePolicyRealtime(
        const std::string& fileName,
        const std::string& filePath,
        const std::string& destinationPath,
        const std::string& eventType = "usb_file_transfer"
    ) {
        PolicyEvaluationResult result;
        result.shouldBlock = false;
        result.action = "allow";
        result.evaluationSucceeded = false;
        result.confidenceScore = 0.0;
        result.totalMatches = 0;
        result.classificationLevel = "Public";

        try {
            // Read file content (limit to 10MB to avoid memory issues)
            const size_t MAX_FILE_SIZE = 10 * 1024 * 1024;

            if (!fs::exists(filePath)) {
                logger.Warning("File not found for classification: " + filePath);
                result.reason = "File not found";
                return result;
            }

            size_t fileSize = fs::file_size(filePath);
            if (fileSize > MAX_FILE_SIZE) {
                logger.Warning("File too large for classification: " + std::to_string(fileSize) + " bytes");
                result.reason = "File too large (>10MB)";
                // For large files, fail-open (allow) but log
                result.evaluationSucceeded = true;
                return result;
            }

            // Read file content
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                logger.Warning("Cannot open file for classification: " + filePath);
                result.reason = "Cannot read file";
                return result;
            }

            std::string fileContent((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
            file.close();

            // Escape the file content for JSON (basic escaping)
            std::string escapedContent;
            escapedContent.reserve(fileContent.size());
            for (char c : fileContent) {
                switch (c) {
                    case '"': escapedContent += "\\\""; break;
                    case '\\': escapedContent += "\\\\"; break;
                    case '\n': escapedContent += "\\n"; break;
                    case '\r': escapedContent += "\\r"; break;
                    case '\t': escapedContent += "\\t"; break;
                    default:
                        if (c >= 32 && c < 127) {
                            escapedContent += c;
                        } else {
                            // Skip non-printable characters
                            escapedContent += ' ';
                        }
                }
            }

            // Build JSON request using JsonBuilder
            JsonBuilder json;
            json.AddString("file_name", fileName);
            json.AddString("file_content", escapedContent);
            json.AddInt("file_size", static_cast<int>(fileSize));
            json.AddString("event_type", eventType);
            json.AddString("destination_type", "removable_drive");
            json.AddString("source_path", filePath);
            json.AddString("destination_path", destinationPath);

            std::string requestBody = json.Build();

            // Call API endpoint
            std::string apiPath = "/agents/" + config.agentId + "/policy/evaluate";

            logger.Info("🔍 Calling real-time classification API for: " + fileName);

            auto [statusCode, responseBody] = httpClient->Post(apiPath, requestBody);

            if (statusCode != 200) {
                logger.Warning("Classification API returned status " + std::to_string(statusCode));
                logger.Debug("Response: " + responseBody);
                result.reason = "API error: " + std::to_string(statusCode);
                // Fail-open: allow on API error
                result.evaluationSucceeded = true;
                return result;
            }

            // Parse response
            result.action = config.ExtractJsonValue(responseBody, "action");
            result.reason = config.ExtractJsonValue(responseBody, "reason");

            // Extract classification details (nested in "classification" object)
            // Find the "classification" object in the response
            size_t classPos = responseBody.find("\"classification\"");
            if (classPos != std::string::npos) {
                size_t classObjStart = responseBody.find("{", classPos);
                if (classObjStart != std::string::npos) {
                    size_t classObjEnd = FindMatchingBracket(responseBody, classObjStart, '{', '}');
                    if (classObjEnd != std::string::npos) {
                        std::string classificationObj = responseBody.substr(classObjStart, classObjEnd - classObjStart + 1);

                        result.classificationLevel = config.ExtractJsonValue(classificationObj, "level");
                        std::string confStr = config.ExtractJsonValue(classificationObj, "confidence");
                        if (!confStr.empty()) {
                            result.confidenceScore = std::stod(confStr);
                        }

                        std::string totalMatchesStr = config.ExtractJsonValue(classificationObj, "total_matches");
                        if (!totalMatchesStr.empty()) {
                            result.totalMatches = std::stoi(totalMatchesStr);
                        }

                        // Extract matched_rules array (simplified - just get rule names)
                        size_t rulesPos = classificationObj.find("\"matched_rules\"");
                        if (rulesPos != std::string::npos) {
                            size_t arrayStart = classificationObj.find("[", rulesPos);
                            size_t arrayEnd = classificationObj.find("]", arrayStart);
                            if (arrayStart != std::string::npos && arrayEnd != std::string::npos) {
                                std::string rulesArray = classificationObj.substr(arrayStart + 1, arrayEnd - arrayStart - 1);

                                // Simple extraction of "rule_name" values
                                size_t pos = 0;
                                while ((pos = rulesArray.find("\"rule_name\"", pos)) != std::string::npos) {
                                    size_t colonPos = rulesArray.find(":", pos);
                                    size_t valueStart = rulesArray.find("\"", colonPos + 1);
                                    size_t valueEnd = rulesArray.find("\"", valueStart + 1);
                                    if (valueStart != std::string::npos && valueEnd != std::string::npos) {
                                        std::string ruleName = rulesArray.substr(valueStart + 1, valueEnd - valueStart - 1);
                                        result.matchedRules.push_back(ruleName);
                                    }
                                    pos = valueEnd;
                                }
                            }
                        }
                    }
                }
            }

            result.shouldBlock = (result.action == "block");
            result.evaluationSucceeded = true;

            // Log classification result
            logger.Info("📊 Classification Result:");
            logger.Info("   File: " + fileName);
            logger.Info("   Level: " + result.classificationLevel);
            logger.Info("   Confidence: " + std::to_string(static_cast<int>(result.confidenceScore * 100)) + "%");
            logger.Info("   Decision: " + result.action);
            if (!result.matchedRules.empty()) {
                logger.Info("   Detected sensitive data types:");
                for (size_t i = 0; i < result.matchedRules.size() && i < 5; i++) {
                    logger.Info("      - " + result.matchedRules[i]);
                }
                if (result.matchedRules.size() > 5) {
                    logger.Info("      ... and " + std::to_string(result.matchedRules.size() - 5) + " more");
                }
            }

            return result;

        } catch (const std::exception& e) {
            logger.Error("Error in real-time evaluation: " + std::string(e.what()));
            result.reason = "Evaluation error: " + std::string(e.what());
            result.evaluationSucceeded = true;  // Fail-open
            return result;
        }
    }

void CheckUSBDriveForMonitoredFiles(const std::string& drivePath) {
    try {
        // CRITICAL FIX: Check if drive is actually accessible before scanning
        std::string driveRoot = drivePath + "\\";
        
        // Verify drive exists and is ready
        UINT driveType = GetDriveTypeA(drivePath.c_str());
        if (driveType != DRIVE_REMOVABLE) {
            return; // Not a removable drive anymore
        }
        
        // Check if drive is accessible
        DWORD sectorsPerCluster, bytesPerSector, numberOfFreeClusters, totalNumberOfClusters;
        if (!GetDiskFreeSpaceA(drivePath.c_str(), &sectorsPerCluster, &bytesPerSector, 
                               &numberOfFreeClusters, &totalNumberOfClusters)) {
            // Drive is not accessible (likely ejected or blocked)
            logger.Debug("Drive " + drivePath + " is not accessible - skipping scan");
            return;
        }
        
        // Verify we can actually list the directory
        if (!fs::exists(driveRoot) || !fs::is_directory(driveRoot)) {
            logger.Debug("Drive " + drivePath + " is not a valid directory - skipping scan");
            return;
        }
        
        std::vector<std::pair<std::string, std::string>> usbFiles;
        ScanDirectoryRecursiveUSB(drivePath, drivePath, usbFiles);
        
        std::lock_guard<std::mutex> lock(usbTransferMutex);
        
        // Build set of files currently on USB
        std::set<std::string> currentFilesOnUSB;
        for (const auto& filePair : usbFiles) {
            currentFilesOnUSB.insert(filePair.first);
        }
        
        // Check each monitored file to see if it's on USB
        for (const auto& monitoredPair : monitoredFiles) {
            const FileMetadata& meta = monitoredPair.second;
            const std::string& fileName = meta.name;
            
            std::string fileKey = drivePath + ":" + fileName;
            
            // Check if file is currently on USB
            bool isOnUSBNow = (currentFilesOnUSB.find(fileName) != currentFilesOnUSB.end());
            
            // Get previous state (was it on USB before?)
            bool wasOnUSBBefore = false;
            auto stateIt = currentUSBFileState.find(fileKey);
            if (stateIt != currentUSBFileState.end()) {
                wasOnUSBBefore = stateIt->second;
            }
            
            // Detect NEW transfer: file is on USB now but wasn't before
            if (isOnUSBNow && !wasOnUSBBefore) {
                // NEW TRANSFER DETECTED!
                logger.Debug("[DETECTED] New transfer of: " + fileName + " to " + drivePath);
                
                // Mark as currently on USB
                currentUSBFileState[fileKey] = true;
                
                // Find which policy applies
                for (const auto& policy : usbTransferPolicies) {
                    if (!policy.enabled) continue;
                    
                    // Check if file is from a monitored path
                    bool isFromMonitoredPath = false;
                    std::string matchedMonitoredPath;
                    
                    for (const auto& monPath : policy.monitoredPaths) {
                        std::string normalizedMonPath = NormalizeFilesystemPath(monPath);
                        if (meta.fullPath.find(normalizedMonPath) == 0) {
                            isFromMonitoredPath = true;
                            matchedMonitoredPath = normalizedMonPath;
                            break;
                        }
                    }
                    
                    if (!isFromMonitoredPath) continue;

                    // REAL-TIME CLASSIFICATION-AWARE BLOCKING
                    // Call server to classify content and evaluate classification-aware policies
                    std::string usbFile = drivePath + "\\" + fileName;
                    std::string sourceFile = matchedMonitoredPath + "\\" + meta.relativePath;

                    logger.Info("🔍 Evaluating file transfer with real-time classification:");
                    logger.Info("   File: " + fileName);
                    logger.Info("   Source: " + sourceFile);
                    logger.Info("   Destination: " + usbFile);
                    logger.Info("   Traditional Policy: " + policy.name + " (action: " + policy.action + ")");

                    // Try source file first, fallback to USB file
                    std::string fileToClassify = fs::exists(sourceFile) ? sourceFile : usbFile;

                    if (!fs::exists(fileToClassify)) {
                        logger.Warning("File not found for classification, skipping: " + fileToClassify);
                        break;
                    }

                    PolicyEvaluationResult evalResult = EvaluatePolicyRealtime(
                        fileName,
                        fileToClassify,
                        usbFile,
                        "usb_file_transfer"
                    );

                    if (!evalResult.evaluationSucceeded) {
                        logger.Warning("⚠️ Classification evaluation failed: " + evalResult.reason);
                        logger.Warning("⚠️ Falling back to traditional path-based policy action");

                        // Fallback to traditional policy action on evaluation failure
                        if (policy.action == "block") {
                            HandleUSBFileTransferBlockNoTimestamp(fileName, meta.relativePath, drivePath,
                                                      matchedMonitoredPath, policy);
                        } else if (policy.action == "quarantine") {
                            HandleUSBFileTransferQuarantineNoTimestamp(fileName, meta.relativePath, drivePath,
                                                           matchedMonitoredPath, policy);
                        } else if (policy.action == "alert") {
                            HandleUSBFileTransferAlertNoTimestamp(fileName, meta.relativePath, drivePath,
                                                      matchedMonitoredPath, policy);
                        }
                    } else {
                        // Use classification-aware decision
                        if (evalResult.shouldBlock) {
                            logger.Warning("============================================================");
                            logger.Warning("  🚫 CONTENT-AWARE BLOCKING TRIGGERED!");
                            logger.Warning("============================================================");
                            logger.Warning("  File: " + fileName);
                            logger.Warning("  Classification: " + evalResult.classificationLevel);
                            logger.Warning("  Confidence: " + std::to_string(static_cast<int>(evalResult.confidenceScore * 100)) + "%");
                            logger.Warning("  Reason: " + evalResult.reason);

                            if (!evalResult.matchedRules.empty()) {
                                logger.Warning("  Sensitive data detected:");
                                for (size_t i = 0; i < evalResult.matchedRules.size() && i < 10; i++) {
                                    logger.Warning("    • " + evalResult.matchedRules[i]);
                                }
                            }
                            logger.Warning("============================================================");

                            // Execute block action with classification data
                            HandleUSBFileTransferBlockNoTimestamp(fileName, meta.relativePath, drivePath,
                                                      matchedMonitoredPath, policy,
                                                      evalResult.classificationLevel,
                                                      evalResult.confidenceScore,
                                                      evalResult.matchedRules);
                        } else {
                            logger.Info("✅ File ALLOWED - Classification: " + evalResult.classificationLevel +
                                       " (" + std::to_string(static_cast<int>(evalResult.confidenceScore * 100)) + "% confidence)");
                            logger.Info("   No sensitive data detected, allowing transfer");

                            // Create an informational event for allowed transfers with classification data
                            SendUSBTransferEvent(meta.relativePath, usbFile, matchedMonitoredPath, "allowed",
                                                "info", policy.policyId, policy.name, true,
                                                evalResult.classificationLevel,
                                                evalResult.confidenceScore,
                                                evalResult.matchedRules);
                        }
                    }

                    break; // Process only once per file
                }
            }
            // Detect REMOVAL: file was on USB before but isn't now
            else if (!isOnUSBNow && wasOnUSBBefore) {
                logger.Debug("[REMOVED] File removed from USB: " + fileName);
                currentUSBFileState[fileKey] = false;  // Mark as not on USB
            }
            // File state unchanged - do nothing
        }

        // CLASSIFICATION-BASED MONITORING: For policies with no monitoredPaths,
        // scan ALL USB files directly and evaluate each NEW file via classification API.
        // This handles seeded policies that rely on content classification rather than
        // source-path matching.
        bool hasClassificationOnlyPolicies = false;
        for (const auto& policy : usbTransferPolicies) {
            if (policy.enabled && policy.monitoredPaths.empty()) {
                hasClassificationOnlyPolicies = true;
                break;
            }
        }

        // PASS 2: Classify ALL new files on USB — catches files not in monitoredFiles
        {
            int newFileCount = 0;
            int skippedCount = 0;

            for (const auto& filePair : usbFiles) {
                const std::string& fileName = filePair.first;
                std::string classifKey = std::string("classif:") + drivePath + ":" + fileName;

                // Skip files already evaluated
                if (currentUSBFileState.find(classifKey) != currentUSBFileState.end()) {
                    skippedCount++;
                    continue;
                }
                std::string monFileKey = drivePath + ":" + fileName;
                if (currentUSBFileState.find(monFileKey) != currentUSBFileState.end()) {
                    skippedCount++;
                    continue;
                }

                // NEW FILE DETECTED ON USB!
                currentUSBFileState[classifKey] = true;
                newFileCount++;

                std::string usbFilePath = drivePath + "\\" + filePair.second;
                if (usbFilePath.find("\\\\") != std::string::npos) {
                    // filePair.second is relative path, build full path
                    usbFilePath = drivePath + "\\" + filePair.second;
                }
                if (!fs::exists(usbFilePath)) {
                    usbFilePath = drivePath + "\\" + fileName;
                    if (!fs::exists(usbFilePath)) continue;
                }

                logger.Warning("USB_FILE_TRANSFER_DETECTED: New file on USB — " + fileName);
                logger.Info("  Path: " + usbFilePath);
                logger.Info("  Size: " + std::to_string(fs::file_size(usbFilePath)) + " bytes");

                // Apply the first enabled USB transfer policy
                for (const auto& policy : usbTransferPolicies) {
                    if (!policy.enabled) continue;

                    logger.Info("🔍 Classification-based evaluation for new USB file:");
                    logger.Info("   File: " + fileName);
                    logger.Info("   Path: " + usbFilePath);
                    logger.Info("   Policy: " + policy.name + " (Action: " + policy.action + ")");

                    PolicyEvaluationResult evalResult = EvaluatePolicyRealtime(
                        fileName, usbFilePath, usbFilePath, "usb_file_transfer");

                    if (!evalResult.evaluationSucceeded) {
                        logger.Warning("⚠️ Classification failed for: " + fileName +
                                      " — falling back to policy action: " + policy.action);
                        if (policy.action == "block") {
                            HandleUSBFileTransferBlockNoTimestamp(
                                fileName, fileName, drivePath, drivePath, policy);
                            currentUSBFileState.erase(classifKey);
                        } else if (policy.action == "quarantine") {
                            HandleUSBFileTransferQuarantineNoTimestamp(
                                fileName, fileName, drivePath, drivePath, policy);
                            currentUSBFileState.erase(classifKey);
                        } else {
                            HandleUSBFileTransferAlertNoTimestamp(
                                fileName, fileName, drivePath, drivePath, policy);
                        }
                    } else if (evalResult.shouldBlock) {
                        logger.Warning("🚫 CONTENT-AWARE BLOCK: " + fileName +
                                      " (" + evalResult.classificationLevel + " " +
                                      std::to_string(static_cast<int>(evalResult.confidenceScore * 100)) + "%)");
                        HandleUSBFileTransferBlockNoTimestamp(
                            fileName, fileName, drivePath, drivePath, policy,
                            evalResult.classificationLevel,
                            evalResult.confidenceScore,
                            evalResult.matchedRules);
                        // Reset classifKey so the same file can be detected if re-copied
                        currentUSBFileState.erase(classifKey);
                    } else {
                        logger.Info("✅ ALLOWED: " + fileName +
                                   " (" + evalResult.classificationLevel + " " +
                                   std::to_string(static_cast<int>(evalResult.confidenceScore * 100)) + "%)");
                        SendUSBTransferEvent(fileName, usbFilePath, drivePath, "allowed", "info",
                                           policy.policyId, policy.name, true,
                                           evalResult.classificationLevel,
                                           evalResult.confidenceScore,
                                           evalResult.matchedRules);
                    }
                    break;  // Apply first matching policy only
                }
            }

            if (newFileCount > 0) {
                logger.Info("USB scan: " + std::to_string(newFileCount) + " new file(s) detected, " +
                           std::to_string(skippedCount) + " pre-existing skipped on " + drivePath);
            }
        }

    } catch (const fs::filesystem_error& e) {
        logger.Debug("Drive " + drivePath + " is not accessible - likely blocked or ejected");
    } catch (const std::exception& e) {
        logger.Debug("Error checking USB drive " + drivePath + ": " + std::string(e.what()));
    }
}
void MonitorUSBTransferDirectories() {
    logger.Info("Starting directory monitoring for USB file transfer policies");
    
    while (running) {
        if (!hasUsbTransferPolicies || !allowEvents) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        
        try {
            std::lock_guard<std::mutex> lock(usbTransferMutex);
            
            // Update file tracking for monitored paths
            for (auto& pair : monitoredFiles) {
                FileMetadata& meta = pair.second;
                
                if (fs::exists(meta.fullPath)) {
                    // File still exists - update metadata
                    meta.inMonitored = true;
                    try {
                        auto currentSize = fs::file_size(meta.fullPath);
                        auto ftime = fs::last_write_time(meta.fullPath);
                        
                        if (currentSize != meta.fileSize) {
                            meta.fileSize = currentSize;
                            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                                ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                            auto cftime = std::chrono::system_clock::to_time_t(sctp);
                            FILETIME ft;
                            ULARGE_INTEGER ull;
                            ull.QuadPart = (cftime * 10000000ULL) + 116444736000000000ULL;
                            ft.dwLowDateTime = ull.LowPart;
                            ft.dwHighDateTime = ull.HighPart;
                            meta.lastModified = ft;
                        }
                    } catch (...) {}
                } else {
                    // File no longer exists in monitored directory
                    meta.inMonitored = false;
                }
            }
            
        } catch (const std::exception& e) {
            logger.Debug("Error in USB transfer directory monitoring: " + std::string(e.what()));
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}
    void ScanUsbDriveForChanges(const std::string& drivePath) {
        try {
            std::string driveRoot = drivePath + "\\";
            
            if (!fs::exists(driveRoot)) {
                return;
            }
            
            std::set<std::string> currentFiles;
            
            // Recursively scan all files on the drive
            for (const auto& entry : fs::recursive_directory_iterator(
                driveRoot, 
                fs::directory_options::skip_permission_denied)) {
                
                try {
                    if (entry.is_regular_file()) {
                        std::string filePath = entry.path().string();
                        currentFiles.insert(filePath);
                    }
                } catch (...) {
                    // Skip files we can't access
                    continue;
                }
            }
            
            // Compare with previously known files
            std::lock_guard<std::mutex> lock(usbFilesMutex);
            
            if (usbDriveFiles.find(drivePath) == usbDriveFiles.end()) {
                // First scan of this drive - store all files
                usbDriveFiles[drivePath] = currentFiles;
                std::cout << "[DEBUG] Initial scan of " << drivePath << " - " 
                          << currentFiles.size() << " files found" << std::endl;
                return;
            }
            
            // Find NEW files (files that weren't there before)
            std::set<std::string> previousFiles = usbDriveFiles[drivePath];
            std::vector<std::string> newFiles;
            
            for (const auto& file : currentFiles) {
                if (previousFiles.find(file) == previousFiles.end()) {
                    newFiles.push_back(file);
                }
            }
            
            // Update known files
            usbDriveFiles[drivePath] = currentFiles;
            
            // Process new files
            if (!newFiles.empty()) {
                std::cout << "[DEBUG] Detected " << newFiles.size() 
                          << " new files on " << drivePath << std::endl;
                
                for (const auto& filePath : newFiles) {
                    std::cout << "[DEBUG] New file: " << filePath << std::endl;
                    
                    // Get device ID for this drive
                    std::string deviceId = "";
                    auto it = usbDriveToDeviceId.find(drivePath);
                    if (it != usbDriveToDeviceId.end()) {
                        deviceId = it->second;
                    }
                    
                    // Handle the file transfer
                    HandleUsbFileTransfer(drivePath, filePath, deviceId);
                }
            }
            
        } catch (const std::exception& e) {
            std::cout << "[DEBUG] Error scanning drive " << drivePath << ": " << e.what() << std::endl;
        } catch (...) {
            std::cout << "[DEBUG] Unknown error scanning drive " << drivePath << std::endl;
        }
    }
    void HandleUsbFileTransfer(const std::string& drivePath, const std::string& filePath, const std::string& deviceId) {
        try {
            std::cout << "\n[DEBUG] ===========================================" << std::endl;
            std::cout << "[DEBUG] HandleUsbFileTransfer" << std::endl;
            std::cout << "[DEBUG] Drive: " << drivePath << std::endl;
            std::cout << "[DEBUG] File: " << filePath << std::endl;
            std::cout << "[DEBUG] Device ID: " << deviceId << std::endl;
            
            if (!allowEvents || !hasUsbTransferPolicies) {
                std::cout << "[DEBUG] USB file transfer monitoring not active" << std::endl;
                return;
            }
            
            // Get USB policies
            std::vector<PolicyRule> policies;
            {
                std::lock_guard<std::mutex> lock(policiesMutex);
                policies = usbPolicies;
            }
            
            if (policies.empty()) {
                std::cout << "[DEBUG] No USB policies" << std::endl;
                return;
            }
            
            // Check if any policy monitors file transfer
            bool eventMonitored = false;
            std::string policyAction = "log";
            std::string matchedPolicyId;
            std::string matchedPolicyName;
            
            for (const auto& policy : policies) {
                if (!policy.enabled) continue;
                
                for (const auto& event : policy.monitoredEvents) {
                    if (event == "usb_file_transfer" || event == "all" || event == "*") {
                        eventMonitored = true;
                        policyAction = policy.action;
                        matchedPolicyId = policy.policyId;
                        matchedPolicyName = policy.name;
                        std::cout << "[DEBUG] Policy matched: " << policy.name << std::endl;
                        break;
                    }
                }
                
                if (eventMonitored) break;
            }
            
            if (!eventMonitored) {
                std::cout << "[DEBUG] USB file transfer not monitored by policies" << std::endl;
                return;
            }
            
            // Get file info
            std::string fileName = fs::path(filePath).filename().string();
            size_t fileSize = 0;
            std::string fileHash = "";
            
            try {
                if (fs::exists(filePath)) {
                    fileSize = fs::file_size(filePath);
                    
                    // Calculate hash for small files
                    if (fileSize < 10 * 1024 * 1024) {  // < 10MB
                        fileHash = CalculateFileHash(filePath);
                    }
                }
            } catch (...) {
                std::cout << "[DEBUG] Could not read file details" << std::endl;
            }
            
            // Read file content for classification (if not too large)
            std::string content = "";
            ClassificationResult classification;
            
            if (fileSize < config.GetClassification().maxFileSizeMB * 1024 * 1024) {
                try {
                    content = ReadFileContent(filePath);
                    
                    if (!content.empty()) {
                        // Classify content against policies
                        classification = ContentClassifier::Classify(content, policies, "usb_file_transfer");
                    }
                } catch (...) {
                    std::cout << "[DEBUG] Could not read file content" << std::endl;
                }
            }
            
            // Build detected content summary
            std::string detectedSummary = "";
            if (!classification.detectedContent.empty()) {
                for (const auto& [dataType, values] : classification.detectedContent) {
                    if (values.empty()) continue;
                    
                    detectedSummary += "\n  • " + dataType + ": " + std::to_string(values.size()) + " found";
                    
                    // Show first value
                    if (!values.empty()) {
                        std::string value = values[0];
                        if (value.length() > 30) {
                            value = value.substr(0, 27) + "...";
                        }
                        detectedSummary += "\n    Example: " + value;
                    }
                }
            }
            
            // Determine severity
            std::string severity = "medium";
            if (policyAction == "block") {
                severity = "critical";
            } else if (policyAction == "alert" || !classification.labels.empty()) {
                severity = "high";
            }
            
            // Build description
            std::string description = "USB File Transfer Detected";
            description += "\nFile: " + fileName;
            description += "\nDestination: " + drivePath;
            description += "\nSize: " + std::to_string(fileSize) + " bytes";
            if (!detectedSummary.empty()) {
                description += "\nSensitive Data:" + detectedSummary;
            }
            description += "\nPolicy: " + matchedPolicyName;
            description += "\nAction: " + policyAction;
            
            // Build JSON event
            JsonBuilder json;
            json.AddString("event_id", GenerateUUID());
            json.AddString("event_type", "usb");
            json.AddString("event_subtype", "usb_file_transfer");
            json.AddString("agent_id", config.agentId);
            json.AddString("source_type", "agent");
            json.AddString("user_email", GetUsername() + "@" + GetHostname());
            json.AddString("description", description);
            json.AddString("severity", severity);
            json.AddString("action", policyAction);
            json.AddString("file_name", fileName);
            json.AddString("file_path", filePath);
            json.AddInt("file_size", static_cast<int>(fileSize));
            json.AddString("destination_drive", drivePath);
            json.AddString("device_id", deviceId);
            json.AddString("policy_id", matchedPolicyId);
            json.AddString("policy_name", matchedPolicyName);
            
            if (!fileHash.empty()) {
                json.AddString("file_hash", fileHash);
            }
            
            if (!classification.labels.empty()) {
                json.AddArray("detected_data_types", classification.labels);
                json.AddString("detected_content", detectedSummary);
            }
            
            json.AddString("timestamp", GetCurrentTimestampISO());
            
            std::cout << "[DEBUG] Sending USB file transfer event to server..." << std::endl;
            SendEvent(json.Build());
            
            // Display alert
            logger.Warning("\n============================================================");
            logger.Warning("  ⚠️ USB FILE TRANSFER ALERT!");
            logger.Warning("============================================================");
            logger.Warning("  File: " + fileName);
            logger.Warning("  Size: " + std::to_string(fileSize) + " bytes");
            logger.Warning("  Destination: " + drivePath);
            logger.Warning("  Policy: " + matchedPolicyName);
            logger.Warning("  Action: " + policyAction);
            logger.Warning("  Severity: " + severity);
            
            if (!classification.labels.empty()) {
                logger.Warning("  Sensitive Data Detected:");
                for (const auto& label : classification.labels) {
                    logger.Warning("    • " + label);
                }
            }
            
            logger.Warning("============================================================\n");
            
            std::cout << "[DEBUG] ===========================================" << std::endl;
            
        } catch (const std::exception& e) {
            logger.Error(std::string("Error handling USB file transfer: ") + e.what());
        } catch (...) {
            logger.Error("Unknown error handling USB file transfer");
        }
    }
    void HandleUSBFileTransferAlertNoTimestamp(const std::string& fileName, const std::string& relativePath,
                                const std::string& usbPath, const std::string& monitoredPath,
                                const USBFileTransferPolicy& policy) {
    std::string usbFile = usbPath + "\\" + fileName;
    
    if (!fs::exists(usbFile)) return;
    
    logger.Warning("============================================================");
    logger.Warning("  ⚠️ USB FILE TRANSFER ALERT!");
    logger.Warning("============================================================");
    logger.Warning("  File: " + relativePath);
    logger.Warning("  Source: " + monitoredPath);
    logger.Warning("  Destination: " + usbFile);
    logger.Warning("  Policy: " + policy.name);
    logger.Warning("  Severity: " + policy.severity);
    logger.Warning("  Timestamp: " + GetCurrentTimestampISO());
    logger.Warning("============================================================\n");
    
    // DO NOT SET TIMESTAMP HERE - already set in CheckUSBDriveForMonitoredFiles
    
    SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "alerted", 
                        policy.severity, policy.policyId, policy.name, true);
}
void HandleUSBFileTransferBlockNoTimestamp(const std::string& fileName, const std::string& relativePath,
                                const std::string& usbPath, const std::string& monitoredPath,
                                const USBFileTransferPolicy& policy,
                                const std::string& classificationLevel = "",
                                double confidenceScore = 0.0,
                                const std::vector<std::string>& classificationLabels = {}) {
    std::string usbFile = usbPath + "\\" + fileName;
    std::string monitoredFile = monitoredPath + "\\" + relativePath;

    bool existsInMonitored = fs::exists(monitoredFile);
    bool fileOnUSB = fs::exists(usbFile);

    if (!fileOnUSB) return;

    logger.Warning("============================================================");
    logger.Warning("  🚫 USB FILE TRANSFER BLOCKED!");
    logger.Warning("============================================================");
    logger.Warning("  File: " + relativePath);
    logger.Warning("  Policy: " + policy.name);
    logger.Warning("  Severity: " + policy.severity);

    // DO NOT SET TIMESTAMP HERE - already set in CheckUSBDriveForMonitoredFiles

    try {
        std::string transferType;
        if (existsInMonitored) {
            // File was COPIED
            transferType = "copy";
            logger.Warning("  Transfer Type: COPY");
            fs::remove(usbFile);
            logger.Warning("  ✅ Deleted from USB");
        } else {
            // File was MOVED - restore from USB to monitored directory
            transferType = "move";
            logger.Warning("  Transfer Type: MOVE");

            // Create parent directories if needed
            size_t pos = relativePath.find_last_of("\\/");
            if (pos != std::string::npos) {
                std::string dirPath = monitoredPath + "\\" + relativePath.substr(0, pos);
                fs::create_directories(dirPath);
            }

            // Copy from USB back to monitored, then delete from USB
            fs::copy_file(usbFile, monitoredFile, fs::copy_options::overwrite_existing);
            logger.Warning("  ✅ Restored to monitored directory");

            fs::remove(usbFile);
            logger.Warning("  ✅ Deleted from USB");

            // Update shadow entry
            std::string key = monitoredPath + ":" + relativePath;
            ShadowEntry shadow;
            shadow.lastKnownPath = monitoredFile;
            shadow.lastSeen = time(NULL);
            shadow.fileSize = fs::file_size(monitoredFile);
            auto ftime = fs::last_write_time(monitoredFile);
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
            auto cftime = std::chrono::system_clock::to_time_t(sctp);
            FILETIME ft;
            ULARGE_INTEGER ull;
            ull.QuadPart = (cftime * 10000000ULL) + 116444736000000000ULL;
            ft.dwLowDateTime = ull.LowPart;
            ft.dwHighDateTime = ull.HighPart;
            shadow.lastModified = ft;
            shadowCopies[key] = shadow;
        }

        SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "blocked_" + transferType,
                            policy.severity, policy.policyId, policy.name, true,
                            classificationLevel, confidenceScore, classificationLabels);

        logger.Warning("============================================================\n");
    } catch (const std::exception& e) {
        logger.Error("Failed to block USB transfer: " + std::string(e.what()));
        SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "block_failed",
                            policy.severity, policy.policyId, policy.name, false,
                            classificationLevel, confidenceScore, classificationLabels);
        logger.Warning("============================================================\n");
    }
}
void HandleUSBFileTransferQuarantineNoTimestamp(const std::string& fileName, const std::string& relativePath,
                                     const std::string& usbPath, const std::string& monitoredPath,
                                     const USBFileTransferPolicy& policy) {
    std::string usbFile = usbPath + "\\" + fileName;
    std::string monitoredFile = monitoredPath + "\\" + relativePath;
    std::string timestamp = std::to_string(time(NULL));
    std::string quarantinePath = policy.quarantinePath.empty() ? "C:\\Quarantine" : policy.quarantinePath;
    std::string quarantineFile = quarantinePath + "\\" + fileName + "_" + timestamp;
    
    if (!fs::exists(usbFile)) return;
    
    bool existsInMonitored = fs::exists(monitoredFile);
    
    logger.Warning("============================================================");
    logger.Warning("  ⚠️ USB FILE TRANSFER QUARANTINED!");
    logger.Warning("============================================================");
    logger.Warning("  File: " + relativePath);
    logger.Warning("  Policy: " + policy.name);
    logger.Warning("  Severity: " + policy.severity);
    
    // DO NOT SET TIMESTAMP HERE - already set in CheckUSBDriveForMonitoredFiles
    
    try {
        // Ensure quarantine directory exists
        fs::create_directories(quarantinePath);
        
        std::string transferType;
        if (existsInMonitored) {
            // File was COPIED
            transferType = "copy";
            logger.Warning("  Transfer Type: COPY");
            
            // Move from monitored to quarantine
            fs::rename(monitoredFile, quarantineFile);
            logger.Warning("  ✅ Moved to quarantine from monitored dir");
            
            // Delete from USB
            fs::remove(usbFile);
            logger.Warning("  ✅ Deleted from USB");
        } else {
            // File was MOVED
            transferType = "move";
            logger.Warning("  Transfer Type: MOVE");
            
            // Move from USB to quarantine
            fs::rename(usbFile, quarantineFile);
            logger.Warning("  ✅ Moved to quarantine from USB");
        }
        
        SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "quarantined_" + transferType, 
                            policy.severity, policy.policyId, policy.name, true);
        
        quarantinedUSBFiles.insert(fileName);
        
        // Schedule restoration in 2 minutes
        std::thread restoreThread([this, quarantineFile, monitoredFile, relativePath, 
                                  monitoredPath, fileName, policyName = policy.name]() {
            logger.Info("USB Quarantine [" + policyName + "]: Will restore in 2 minutes: " + relativePath);
            std::this_thread::sleep_for(std::chrono::minutes(2));
            
            try {
                // Create parent directories if needed
                size_t pos = relativePath.find_last_of("\\/");
                if (pos != std::string::npos) {
                    std::string dirPath = monitoredPath + "\\" + relativePath.substr(0, pos);
                    fs::create_directories(dirPath);
                }
                
                if (fs::exists(quarantineFile)) {
                    fs::rename(quarantineFile, monitoredFile);
                    logger.Info("✅ USB Quarantine [" + policyName + "]: Restored to monitored directory: " + relativePath);
                    
                    std::lock_guard<std::mutex> lock(usbTransferMutex);
                    quarantinedUSBFiles.erase(fileName);
                }
            } catch (const std::exception& e) {
                logger.Error("Failed to restore from USB quarantine: " + std::string(e.what()));
            }
        });
        restoreThread.detach();
        
        logger.Warning("  🕐 Scheduled restoration in 2 minutes");
        logger.Warning("============================================================\n");
        
    } catch (const std::exception& e) {
        logger.Error("Failed to quarantine USB transfer: " + std::string(e.what()));
        SendUSBTransferEvent(relativePath, usbFile, monitoredPath, "quarantine_failed", 
                            policy.severity, policy.policyId, policy.name, false);
        logger.Warning("============================================================\n");
    }
}
 };
 
 // ==================== Main Entry Point ====================
 
 DLPAgent* g_agent = nullptr;
 DLPAgent* DLPAgent::s_instance = nullptr;

 
 BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
     if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
         std::cout << "\nShutting down agent...\n";
         if (g_agent) {
             g_agent->Stop();
         }
         return TRUE;
     }
     return FALSE;
 }

 // ==================== Background Mode Helper ====================

bool ShouldRunInBackground(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        std::transform(arg.begin(), arg.end(), arg.begin(), ::tolower);
        
        if (arg == "-background" || arg == "--background" || arg == "-bg" || arg == "--bg" || arg == "bg") {
            return true;
        }
    }
    return false;
}

void HideConsoleWindow() {
    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow != NULL) {
        ShowWindow(consoleWindow, SW_HIDE);
    }
}

void ShowUsage() {
    std::cout << "Usage: cybersentinel_agent.exe [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -background, --background, -bg, --bg, bg\n";
    std::cout << "                        Run agent in background mode (no console output)\n";
    std::cout << "  -h, --help            Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  cybersentinel_agent.exe\n";
    std::cout << "  cybersentinel_agent.exe -background\n";
    std::cout << "  cybersentinel_agent.exe --bg\n\n";
}
 
int main(int argc, char* argv[]) {
    // Check for help flag
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help" || arg == "-?" || arg == "/?") {
            ShowUsage();
            return 0;
        }
    }
    
    // Check if should run in background
    bool backgroundMode = ShouldRunInBackground(argc, argv);
    
    if (backgroundMode) {
        // Hide console window immediately
        HideConsoleWindow();
    } else {
        // Show startup banner only in foreground mode
        std::cout << "============================================================\n";
        std::cout << "CyberSentinel DLP - Windows Agent (C++)\n";
        std::cout << "============================================================\n\n";
        
        // Check for server URL environment variable
        const char* envUrl = std::getenv("CYBERSENTINEL_SERVER_URL");
        if (envUrl) {
            std::cout << "Using server URL from environment: " << envUrl << "\n";
        } else {
            std::cout << "Using default server URL: http://localhost:55000/api/v1\n";
            std::cout << "To change server URL, set environment variable:\n";
            std::cout << "  set CYBERSENTINEL_SERVER_URL=http://your-server:port/api/v1\n\n";
        }
    }
    
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    
    try {
        DLPAgent agent("agent_config.json");
        g_agent = &agent;
        
        SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
        
        if (backgroundMode) {
            // In background mode, log startup info to file only
            Logger bgLogger;
            bgLogger.Info("============================================================");
            bgLogger.Info("CyberSentinel DLP Agent started in BACKGROUND MODE");
            bgLogger.Info("============================================================");
            bgLogger.Info("Process ID: " + std::to_string(GetCurrentProcessId()));
            bgLogger.Info("Console window hidden - all output redirected to log file");
            bgLogger.Info("============================================================");
        }
        
        agent.Start();
    } catch (const std::exception& e) {
        if (backgroundMode) {
            // Log error to file in background mode
            Logger bgLogger;
            bgLogger.Error("Fatal error: " + std::string(e.what()));
            bgLogger.Error("Troubleshooting:");
            bgLogger.Error("1. Ensure the CyberSentinel server is running");
            bgLogger.Error("2. Check network connectivity to the server");
            bgLogger.Error("3. Verify firewall settings allow connections");
            bgLogger.Error("4. Check server URL in agent_config.json or environment variable");
        } else {
            // Show error in console in foreground mode
            std::cerr << "\nFatal error: " << e.what() << std::endl;
            std::cerr << "\nTroubleshooting:\n";
            std::cerr << "1. Ensure the CyberSentinel server is running\n";
            std::cerr << "2. Check network connectivity to the server\n";
            std::cerr << "3. Verify firewall settings allow connections\n";
            std::cerr << "4. Check server URL in agent_config.json or environment variable\n";
        }
        CoUninitialize();
        return 1;
    }
    
    CoUninitialize();
    return 0;
}
