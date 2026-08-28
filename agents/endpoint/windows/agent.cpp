/*
 * SeceoKnight DLP - Windows Endpoint Agent (C++)
 * 
 * Monitors file operations, clipboard, and USB devices for data loss prevention
 * 
 * Build Instructions (MinGW):
 * g++ -std=c++17 -O2 agent.cpp -o seceoknight_agent.exe -lwinhttp -lwbemuuid -lole32 -loleaut32 -luser32 -lws2_32 -lmpr -static
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
 // WNetGetConnectionA (resolve a mapped drive letter -> its \\server\share UNC
 // path, used by ResolveDriveUnc() for network-share exfiltration monitoring)
 // lives in Mpr.dll / mpr.lib. NOTE: this build uses MinGW g++, where
 // #pragma comment(lib,...) is a silent no-op -- the real link dependency is
 // the explicit -lmpr flag in .github/workflows/build-windows-agent.yml.
 #include <winnetwk.h>
 
 #include <cstdio>
 #include <iostream>
 #include <fstream>
 #include <sstream>
 #include <string>
 #include <vector>
 #include <map>
 #include <set>
 #include <deque>
 #include <memory>
 #include <algorithm>
 #include <thread>
 #include <mutex>
 #include <atomic>
 #include <chrono>
 #include "screen_capture_monitor.h"
 #include "print_monitor.h"
 #include "network_exfil_monitor.h"
 #include "messaging_text_monitor.h"
 #include "policy_engine.h"
 #include "kernel/filter_comm.h"
 #include <regex>
 #include <iomanip>
 #include <filesystem>
 #include <ctime>
 #include <cctype>
 #include <dbt.h>
#include <wtsapi32.h>
#include <setupapi.h>
#include <initguid.h>
#include <cfgmgr32.h>
#include <winioctl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <cstring>

#pragma comment(lib, "shell32.lib")
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

#pragma comment(lib, "cfgmgr32.lib")


// USB Device Interface GUID
DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE, 0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);
#define USB_STOR_REG_PATH "SYSTEM\\CurrentControlSet\\Services\\USBSTOR"

// Reported to the server on registration/heartbeat so the Agents dashboard
// can show what's actually deployed (previously hardcoded to "1.0.0"
// everywhere, which was meaningless once auto-update started shipping real
// binary changes — see AutoUpdateLoop()). Bump by hand on notable releases;
// this is a display string only, not consulted by any update logic.
#define AGENT_VERSION "2.5.0"

 
 #pragma comment(lib, "winhttp.lib")
 #pragma comment(lib, "wbemuuid.lib")
 #pragma comment(lib, "ole32.lib")
 #pragma comment(lib, "oleaut32.lib")
 #pragma comment(lib, "user32.lib")
 #pragma comment(lib, "ws2_32.lib")
 #pragma comment(lib, "setupapi.lib")
 
 namespace fs = std::filesystem;

 // RegisterSuspendResumeNotification/UnregisterSuspendResumeNotification are
 // Windows 8+ APIs, gated in the SDK's winuser.h behind
 // _WIN32_WINNT >= _WIN32_WINNT_WIN8 (0x0602). This file deliberately targets
 // 0x0601 (Windows 7) above for broader compatibility, so the SDK header
 // doesn't declare them here even though every real deployment target
 // (Windows 10/11, Server 2019+ — see install-agent.ps1) exports them from
 // User32.dll at runtime. Declare them ourselves rather than bumping the
 // file-wide WINNT target (which would silently change behavior/availability
 // of unrelated APIs throughout this file). See HandlePowerBroadcast() for
 // why this is needed: it's what lets the agent detect wake-from-sleep and
 // reconnect immediately instead of just looking "offline" until the OS's
 // idle-sleep nap ends and the next scheduled heartbeat happens to fire.
 #if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0602
 typedef PVOID HPOWERNOTIFY;
 extern "C" WINUSERAPI HPOWERNOTIFY WINAPI RegisterSuspendResumeNotification(HANDLE hRecipient, DWORD Flags);
 extern "C" WINUSERAPI BOOL WINAPI UnregisterSuspendResumeNotification(HPOWERNOTIFY Handle);
 #endif

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
 
 // Base64-encode raw bytes using the already-linked crypt32 (wincrypt.h is
 // already included, -lcrypt32 already linked in the CI build). Used to send
 // whole binary files (docx/pdf/xlsx/pptx) to the server's /policy/evaluate
 // endpoint for real extraction — see the comment at EvaluatePolicyRealtime()
 // for why this replaced the old byte-escaping-to-spaces approach.
 std::string Base64Encode(const std::string& data) {
     if (data.empty()) return "";
     DWORD outLen = 0;
     if (!CryptBinaryToStringA(
             reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size()),
             CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen) || outLen == 0) {
         return "";
     }
     std::string out(outLen, '\0');
     if (!CryptBinaryToStringA(
             reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size()),
             CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen)) {
         return "";
     }
     // CryptBinaryToStringA includes the trailing NUL in outLen — trim it.
     if (!out.empty() && out.back() == '\0') out.pop_back();
     return out;
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

 std::string ToUpperStr(const std::string& str) {
     std::string result = str;
     std::transform(result.begin(), result.end(), result.begin(), ::toupper);
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

 // Reads the real OS build string from the registry instead of the
 // hardcoded "Windows 10" that RegisterAgent() used to send unconditionally
 // (meaning every endpoint -- Windows 10 or 11, any build -- reported the
 // exact same string). ProductName + DisplayVersion + build/UBR gives
 // something like "Windows 11 Pro 23H2 (Build 22631.3007)".
 //
 // Windows 11 shares the same NT 10.0 kernel version as Windows 10 and is
 // only distinguishable by CurrentBuildNumber (>= 22000) -- some images'
 // registry ProductName value still literally reads "Windows 10 ..." even
 // though the OS is 11, so that's corrected below rather than trusted as-is.
 std::string GetOSVersion() {
     std::string productName;
     std::string displayVersion;
     std::string buildNumber;
     std::string ubr;

     HKEY hKey;
     if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
         auto readString = [&hKey](const char* valueName) -> std::string {
             char buf[256] = {0};
             DWORD size = sizeof(buf);
             DWORD type = 0;
             if (RegQueryValueExA(hKey, valueName, nullptr, &type,
                                  reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS &&
                 (type == REG_SZ || type == REG_EXPAND_SZ)) {
                 size_t len = (size > 0 && buf[size - 1] == '\0') ? size - 1 : size;
                 return std::string(buf, len);
             }
             return "";
         };

         productName = readString("ProductName");
         displayVersion = readString("DisplayVersion");
         if (displayVersion.empty()) {
             // Builds before ~2004 don't have DisplayVersion; ReleaseId was
             // the equivalent field on those older feature updates.
             displayVersion = readString("ReleaseId");
         }
         buildNumber = readString("CurrentBuildNumber");

         DWORD ubrValue = 0;
         DWORD size = sizeof(ubrValue);
         DWORD type = 0;
         if (RegQueryValueExA(hKey, "UBR", nullptr, &type,
                              reinterpret_cast<LPBYTE>(&ubrValue), &size) == ERROR_SUCCESS &&
             type == REG_DWORD) {
             ubr = std::to_string(ubrValue);
         }

         RegCloseKey(hKey);
     }

     if (productName.empty()) {
         productName = "Windows";
     }

     int build = 0;
     try { build = std::stoi(buildNumber); } catch (...) {}
     if (build >= 22000) {
         size_t pos = productName.find("Windows 10");
         if (pos != std::string::npos) {
             productName.replace(pos, std::string("Windows 10").length(), "Windows 11");
         }
     }

     std::string result = productName;
     if (!displayVersion.empty()) {
         result += " " + displayVersion;
     }
     if (!buildNumber.empty()) {
         result += " (Build " + buildNumber;
         if (!ubr.empty()) {
             result += "." + ubr;
         }
         result += ")";
     }
     return result;
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
 
 /**
  * Compute the real SHA-256 hash of a file using Windows CryptoAPI.
  * Returns lowercase hex string (64 chars), or "" on error.
  * Replaces the old weak polynomial hash.
  */
 std::string CalculateFileHash(const std::string& filePath) {
     HCRYPTPROV hProv = 0;
     HCRYPTHASH hHash = 0;
     std::string result;

     if (!CryptAcquireContextW(&hProv, nullptr, nullptr,
                               PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
         return "";
     }

     if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
         CryptReleaseContext(hProv, 0);
         return "";
     }

     std::ifstream file(filePath, std::ios::binary);
     if (file.is_open()) {
         char buf[65536];
         while (file.read(buf, sizeof(buf)) || file.gcount() > 0) {
             CryptHashData(hHash,
                           reinterpret_cast<BYTE*>(buf),
                           static_cast<DWORD>(file.gcount()), 0);
         }

         BYTE hash[32];
         DWORD hashLen = sizeof(hash);
         if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
             std::ostringstream oss;
             oss << std::hex << std::setfill('0');
             for (DWORD i = 0; i < hashLen; ++i)
                 oss << std::setw(2) << static_cast<int>(hash[i]);
             result = oss.str();
         }
     }

     CryptDestroyHash(hHash);
     CryptReleaseContext(hProv, 0);
     return result;
 }

 /**
  * Best-effort path to the physical spooled print job data file, so the
  * actual document content sent to the printer can be hashed (not just its
  * filename) -- lets the server match printed documents against the same
  * hash-based denylists used for file transfers. Windows names spool files
  * FP<jobid zero-padded to 5 digits>.SPL under the print spooler's spool
  * directory, which defaults to %SystemRoot%\System32\spool\PRINTERS and is
  * only rarely relocated by admins. If that guess misses (custom spool
  * directory, or the spooler has already purged the job), returns "" and
  * the print event is simply sent without a hash, exactly as it always has
  * been -- this is additive, not a required field.
  */
 std::string GetPrintSpoolFilePath(int jobId) {
     char sysDir[MAX_PATH] = {0};
     if (GetSystemDirectoryA(sysDir, MAX_PATH) == 0) return "";

     std::ostringstream oss;
     oss << sysDir << "\\spool\\PRINTERS\\FP"
         << std::setfill('0') << std::setw(5) << jobId << ".SPL";
     std::string path = oss.str();

     DWORD attrs = GetFileAttributesA(path.c_str());
     if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
         return "";
     }
     return path;
 }

 /**
  * Download a file from any HTTPS URL using WinHTTP.
  * Returns true on success, false on any error.
  * Used by the auto-update loop to fetch the new binary from GitHub.
  */
 bool DownloadFileHttps(const std::string& url, const std::string& destPath) {
     // Parse URL: https://host/path
     std::regex urlRe(R"(https://([^/]+)(/.+))");
     std::smatch m;
     if (!std::regex_match(url, m, urlRe)) return false;

     std::wstring host(m[1].str().begin(), m[1].str().end());
     std::wstring path(m[2].str().begin(), m[2].str().end());

     HINTERNET hSession = WinHttpOpen(L"SeceoKnight-Updater/1.0",
         WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
     if (!hSession) return false;

     HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(),
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
     if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

     HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
         nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
         WINHTTP_FLAG_SECURE);
     if (!hRequest) {
         WinHttpCloseHandle(hConnect);
         WinHttpCloseHandle(hSession);
         return false;
     }

     bool ok = false;
     if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
         WinHttpReceiveResponse(hRequest, nullptr)) {

         DWORD status = 0, statusSize = sizeof(status);
         WinHttpQueryHeaders(hRequest,
             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
             nullptr, &status, &statusSize, nullptr);

         if (status == 200) {
             std::ofstream out(destPath, std::ios::binary | std::ios::trunc);
             if (out.is_open()) {
                 DWORD read = 0;
                 char buf[65536];
                 while (WinHttpReadData(hRequest, buf, sizeof(buf), &read) && read > 0) {
                     out.write(buf, read);
                 }
                 ok = out.good();
             }
         }
     }

     WinHttpCloseHandle(hRequest);
     WinHttpCloseHandle(hConnect);
     WinHttpCloseHandle(hSession);
     return ok;
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

// ==================== Tesseract OCR (shared) ====================
//
// Extends the OCR capability that already existed only for real-time
// screen-capture blocking (screenClassifier's Stage 4, further below) to
// three more channels the agent already watches: file writes/saves,
// USB file transfers, and clipboard image paste. All three funnel
// through RunTesseractOnFile(), which shells out to the same
// tesseract.exe that install-agent.ps1 Step 4 already auto-installs via
// Chocolatey — no new endpoint dependency is introduced.
//
// Scope: raster image files only (.png/.jpg/.jpeg/.bmp/.tiff/.gif), which
// Tesseract's leptonica backend reads natively. Multi-page scanned PDFs
// are NOT covered here — that needs a PDF rasterizer (e.g. poppler's
// pdftoppm) as an additional endpoint dependency and is a larger,
// separate change.
//
// NOTE: this code has not been compiled or run on a real Windows
// machine — there is no Windows/C++ toolchain available in the
// environment that wrote it. Build and test on a real endpoint before
// shipping to production.

// Runs a command line synchronously and returns its exit code, exactly
// like system() — except system() always risks Windows popping up a
// visible (if brief) console window for the cmd.exe it spawns. That risk
// went from "usually invisible" to "guaranteed, every call" once the
// agent itself switched to the GUI subsystem (see AttachForegroundConsole
// further down): system()'s child cmd.exe used to inherit the agent's own
// (hidden) console, but a GUI-subsystem process has no console to inherit
// at all, so Windows has to create a brand new — visible — one for it.
// This is exactly the "cmd flashes open and closes, titled 'tesseract
// ...'" symptom seen on every OCR run (tesseract / pdftotext / pdftoppm).
//
// Two rounds of "just add more CreateProcess flags" (CREATE_NO_WINDOW,
// then + DETACHED_PROCESS, then + STARTF_USESHOWWINDOW/SW_HIDE) were
// confirmed NOT to fully suppress the flash in the field — likely because
// a console-subsystem child's C runtime requests a console during startup
// whenever its inherited standard handles aren't valid, and that request
// itself can cause a console to flash into existence before any hide
// flag takes effect, on some Windows builds / under some AV-EDR hooks.
//
// This version removes cmd.exe from the picture entirely (invokes
// tesseract.exe/pdftotext.exe/pdftoppm.exe directly — CreateProcess
// resolves the first token against PATH the same way cmd.exe would) and
// gives the child real, valid standard handles pointed at NUL up front,
// so its CRT never has a reason to ask for a console at all. This is the
// standard, most-reliable pattern for "run a console tool with zero
// visible window" — stronger than relying on show-window flags alone.
int RunHiddenCommand(const std::string& command) {
    std::vector<char> cmdBuf(command.begin(), command.end());
    cmdBuf.push_back('\0');

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hNul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, nullptr);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = hNul;
    si.hStdOutput = hNul;
    si.hStdError  = hNul;
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr,
                              /* bInheritHandles */ TRUE,
                              CREATE_NO_WINDOW,
                              nullptr, nullptr, &si, &pi);

    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);

    if (!ok) {
        return -1;  // Mirrors system()'s convention: couldn't launch the process at all.
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exitCode);
}

// Same as RunHiddenCommand(), except stderr is redirected to a real temp
// file instead of NUL and read back into capturedStderr afterwards.
// RunHiddenCommand() alone gives every OCR failure the exact same
// "returned 1" with no way to tell "tessdata missing" apart from "this
// image format isn't supported" apart from "file not found" — this
// exists purely to break that ambiguity for diagnostics. Never throws;
// capturedStderr is left empty on any internal failure.
int RunHiddenCommandCaptureStderr(const std::string& command, std::string& capturedStderr) {
    capturedStderr.clear();

    std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp");
    std::string errPath = tempDir + "\\cs_stderr_" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".txt";

    std::vector<char> cmdBuf(command.begin(), command.end());
    cmdBuf.push_back('\0');

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hNul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, nullptr);
    HANDLE hErr = CreateFileA(errPath.c_str(), GENERIC_WRITE,
                              FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY, nullptr);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = hNul;
    si.hStdOutput = hNul;
    si.hStdError  = (hErr != INVALID_HANDLE_VALUE) ? hErr : hNul;
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr,
                              TRUE, CREATE_NO_WINDOW,
                              nullptr, nullptr, &si, &pi);

    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);
    if (hErr != INVALID_HANDLE_VALUE) CloseHandle(hErr);

    if (!ok) {
        DeleteFileA(errPath.c_str());
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    try {
        std::ifstream ifs(errPath, std::ios::binary);
        if (ifs.is_open()) {
            std::stringstream ss;
            ss << ifs.rdbuf();
            capturedStderr = ss.str();
        }
    } catch (...) {}
    DeleteFileA(errPath.c_str());

    return static_cast<int>(exitCode);
}

// Appends a one-line, timestamped entry to a small dedicated OCR
// diagnostics file under C:\ProgramData\SeceoKnight\logs. RunTesseractOnFile
// / ExtractPdfTextLayer / OcrScannedPdf are free functions with no access to
// DLPAgent's Logger member, and their failures were previously completely
// silent (return "" and move on) — which made a real regression here
// indistinguishable from "no restricted content in the image". This gives
// OCR failures a visible trail independent of the main agent log.
void LogOcrDiagnostic(const std::string& message) {
    try {
        std::string dir = "C:\\ProgramData\\SeceoKnight\\logs";
        fs::create_directories(dir);
        std::ofstream ofs(dir + "\\ocr_diagnostics.log", std::ios::app);
        if (ofs.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto t = std::chrono::system_clock::to_time_t(now);
            std::tm tmv{};
            localtime_s(&tmv, &t);
            char buf[32];
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
            ofs << buf << " - " << message << "\n";
        }
    } catch (...) {
        // Diagnostics must never be able to crash or block OCR itself.
    }
}

// Resolves a Tesseract/Poppler tool name to a full, unambiguous .exe path
// when a known install location exists, instead of handing CreateProcess a
// bare command name to resolve against PATH on its own. In principle
// CreateProcess's PATH search matches cmd.exe's, but this removes that
// dependency entirely for the by-far-most-common install path (this
// project's own install-agent.ps1, which installs both tools via
// Chocolatey). Falls back to the bare name (old behavior, PATH lookup) if
// no known location is found, so manual/non-choco installs still work.
std::string ResolveOcrToolPath(const std::string& toolName) {
    // Chocolatey shims land here regardless of the underlying package's
    // version-specific folder layout, and this directory is what
    // Chocolatey itself adds to the machine PATH.
    std::string chocoShim = "C:\\ProgramData\\chocolatey\\bin\\" + toolName + ".exe";
    if (fs::exists(chocoShim)) return chocoShim;

    if (toolName == "tesseract") {
        std::string tessPath = "C:\\Program Files\\Tesseract-OCR\\tesseract.exe";
        if (fs::exists(tessPath)) return tessPath;
    }

    return toolName; // Fall back to PATH lookup via CreateProcess.
}

// Tesseract's own "find my tessdata directory" auto-detection (relative to
// argv[0], or a compiled-in fallback, depending on how/where it was built)
// is exactly the kind of thing that behaves differently depending on how a
// process is launched — and real-world testing confirmed every single
// tesseract invocation (clipboard AND file-write OCR) failing with exit
// code 1, tesseract's classic "can't find eng.traineddata" error, with no
// TESSDATA_PREFIX set anywhere in this project to fall back on. Passing
// --tessdata-dir explicitly removes that ambiguity entirely. Returns ""
// (omit the flag) if the known Chocolatey install location isn't present,
// so a differently-configured install still falls back to Tesseract's own
// detection rather than being pointed at a directory that doesn't exist.
std::string ResolveTessdataDir() {
    std::string dir = "C:\\Program Files\\Tesseract-OCR\\tessdata";
    if (fs::exists(dir)) return dir;
    return "";
}

// Runs `tesseract <imagePath> <outputBase> --psm 6 -l eng` on an image
// file already on disk and returns the recognized text, or "" if
// tesseract.exe isn't on PATH, the file isn't readable, or OCR finds
// nothing. Never throws — every call site treats "" as "no OCR signal,
// fall back to the existing behavior" rather than an error.
std::string RunTesseractOnFile(const std::string& imagePath) {
    try {
        std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp");
        // Unique per call — file monitor, USB transfer, clipboard, and
        // screen-capture OCR can all fire concurrently on different
        // threads, so a fixed temp filename would let them clobber
        // each other's output.
        std::string uniqueTag = std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
            std::to_string(GetCurrentThreadId());
        std::string outBase = tempDir + "\\cs_ocr_" + uniqueTag;

        // Captures stderr instead of silently discarding it to NUL — every
        // OCR failure previously looked identical ("returned 1") whether
        // the cause was missing tessdata, an unreadable/corrupt image, an
        // image format leptonica can't decode (e.g. a Tesseract install
        // missing PNG support), or something else entirely. Real-world
        // testing showed both clipboard-image OCR and plain screenshot
        // .png files failing consistently even with --tessdata-dir
        // correctly resolved, while a self-constructed 24bpp BMP
        // succeeded — pointing at an image-format-specific decode failure
        // rather than a tessdata problem, but the exit code alone can't
        // distinguish that from a dozen other causes. Logging the actual
        // stderr text removes the guesswork.
        std::string tesseractExe = ResolveOcrToolPath("tesseract");
        std::string tessdataDir = ResolveTessdataDir();
        std::string tessCmd = "\"" + tesseractExe + "\" \"" + imagePath + "\" \"" + outBase +
                               "\" --psm 6 -l eng";
        if (!tessdataDir.empty()) {
            tessCmd += " --tessdata-dir \"" + tessdataDir + "\"";
        }
        std::string tessStderr;
        int tessResult = RunHiddenCommandCaptureStderr(tessCmd, tessStderr);
        if (tessResult != 0) {
            std::string trimmedErr = tessStderr;
            while (!trimmedErr.empty() && std::isspace(static_cast<unsigned char>(trimmedErr.back()))) {
                trimmedErr.pop_back();
            }
            LogOcrDiagnostic("Tesseract failed for '" + imagePath + "': RunHiddenCommand returned " +
                              std::to_string(tessResult) + " (resolved path: " + tesseractExe +
                              ", tessdata-dir: " + (tessdataDir.empty() ? "(not found, omitted)" : tessdataDir) +
                              ", stderr: " + (trimmedErr.empty() ? "(empty)" : trimmedErr) + ")");
        }

        std::string ocrText;
        std::string ocrFile = outBase + ".txt";
        if (tessResult == 0) {
            std::ifstream ifs(ocrFile);
            if (ifs.is_open()) {
                std::stringstream ss;
                ss << ifs.rdbuf();
                ocrText = ss.str();
                ifs.close();
            }
        }
        if (tessResult == 0 && ocrText.empty()) {
            LogOcrDiagnostic("Tesseract ran successfully but produced no text for '" + imagePath + "'");
        }
        DeleteFileA(ocrFile.c_str());
        return ocrText;
    } catch (...) {
        LogOcrDiagnostic("RunTesseractOnFile threw an exception for '" + imagePath + "'");
        return "";
    }
}

// Raster extensions Tesseract/leptonica reads directly without needing
// re-encoding first.
bool IsOcrCandidateExtension(const std::string& ext) {
    std::string lowerExt = ext;
    std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::tolower);
    static const std::set<std::string> kOcrExtensions = {
        ".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".gif"
    };
    return kOcrExtensions.count(lowerExt) > 0;
}

// ── PDF content extraction (text layer + scanned-page OCR fallback) ────
//
// PDFs need different handling than raster images: Tesseract can't read
// a PDF directly, and many PDFs already have a real embedded text layer
// (anything exported from Word, a browser, etc.) where OCR would be both
// slower and less accurate than just reading the text that's already
// there. So the strategy is:
//   1. Try pdftotext (poppler-utils) — fast, exact, works for any PDF
//      with a text layer.
//   2. If that comes back empty/near-empty, the PDF is almost certainly
//      a scan or photo with no text layer — rasterize each page to PNG
//      with pdftoppm (also poppler-utils) and OCR each page with the
//      same RunTesseractOnFile() used everywhere else.
//
// Requires poppler-utils on PATH (pdftotext.exe + pdftoppm.exe) —
// install-agent.ps1 Step 4 installs it via `choco install poppler`
// alongside Tesseract. If poppler isn't installed, both helpers fail
// safely and return "" — the PDF is simply not classified by content
// (existing behavior), nothing crashes.

// Extracts a PDF's embedded text layer via `pdftotext`. Returns "" if
// poppler isn't installed, the file isn't a valid PDF, or there's no
// text layer (i.e. it needs OCR instead — see ExtractPdfContent below).
std::string ExtractPdfTextLayer(const std::string& pdfPath) {
    try {
        std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp");
        std::string uniqueTag = std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
            std::to_string(GetCurrentThreadId());
        std::string outTxt = tempDir + "\\cs_pdf_text_" + uniqueTag + ".txt";

        std::string pdftotextExe = ResolveOcrToolPath("pdftotext");
        std::string cmd = "\"" + pdftotextExe + "\" \"" + pdfPath + "\" \"" + outTxt + "\"";
        int result = RunHiddenCommand(cmd);
        if (result != 0) {
            LogOcrDiagnostic("pdftotext failed for '" + pdfPath + "': RunHiddenCommand returned " +
                              std::to_string(result) + " (resolved path: " + pdftotextExe + ")");
        }

        std::string text;
        if (result == 0) {
            std::ifstream ifs(outTxt);
            if (ifs.is_open()) {
                std::stringstream ss;
                ss << ifs.rdbuf();
                text = ss.str();
                ifs.close();
            }
        }
        DeleteFileA(outTxt.c_str());
        return text;
    } catch (...) {
        LogOcrDiagnostic("ExtractPdfTextLayer threw an exception for '" + pdfPath + "'");
        return "";
    }
}

// OCRs a scanned/image-only PDF: rasterizes up to MAX_OCR_PAGES pages to
// PNG at 150 DPI via `pdftoppm`, then runs RunTesseractOnFile() on each
// page and concatenates the results. Capped so a 500-page scanned
// archive can't stall file/USB monitoring for minutes.
std::string OcrScannedPdf(const std::string& pdfPath) {
    static const int MAX_OCR_PAGES = 10;
    try {
        std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp");
        std::string uniqueTag = std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
            std::to_string(GetCurrentThreadId());
        std::string pageBase = tempDir + "\\cs_pdf_page_" + uniqueTag;

        // 150 DPI is enough for Tesseract to read normal document text
        // without producing unnecessarily huge page images.
        std::string pdftoppmExe = ResolveOcrToolPath("pdftoppm");
        std::string cmd = "\"" + pdftoppmExe + "\" -png -r 150 -f 1 -l " + std::to_string(MAX_OCR_PAGES) +
                           " \"" + pdfPath + "\" \"" + pageBase + "\"";
        int result = RunHiddenCommand(cmd);
        if (result != 0) {
            LogOcrDiagnostic("pdftoppm failed for '" + pdfPath + "': RunHiddenCommand returned " +
                              std::to_string(result) + " (resolved path: " + pdftoppmExe + ")");
        }

        std::string combinedText;
        if (result == 0) {
            // pdftoppm zero-pads page numbers once the document has 10+
            // pages (page-01.png vs page-1.png) — try both forms.
            for (int page = 1; page <= MAX_OCR_PAGES; ++page) {
                std::string unpadded = pageBase + "-" + std::to_string(page) + ".png";
                std::string padded   = pageBase + "-" +
                    (page < 10 ? "0" + std::to_string(page) : std::to_string(page)) + ".png";

                std::string actualPath;
                if (fs::exists(unpadded)) actualPath = unpadded;
                else if (fs::exists(padded)) actualPath = padded;
                else break; // no more pages produced

                std::string pageText = RunTesseractOnFile(actualPath);
                if (!pageText.empty()) {
                    combinedText += pageText + "\n";
                }
                DeleteFileA(actualPath.c_str());
            }
        }
        return combinedText;
    } catch (...) {
        LogOcrDiagnostic("OcrScannedPdf threw an exception for '" + pdfPath + "'");
        return "";
    }
}

// Entry point for PDF content extraction: tries the fast native-text
// path first and only falls back to full page-by-page OCR if that finds
// essentially nothing (a real text layer produces far more than a
// handful of stray characters; a pure scan/photo returns "" or
// whitespace-only).
std::string ExtractPdfContent(const std::string& pdfPath) {
    std::string text = ExtractPdfTextLayer(pdfPath);

    std::string trimmed;
    for (char c : text) {
        if (!std::isspace(static_cast<unsigned char>(c))) trimmed += c;
    }
    if (trimmed.size() >= 20) {
        return text;
    }
    return OcrScannedPdf(pdfPath);
}

// Convenience wrapper for file-based monitors (file-write and USB
// transfer): routes .pdf through ExtractPdfContent (text layer, or OCR
// fallback for scans), OCRs filePath directly if its extension looks
// like a raster image, and returns "" (no-op) for every other file type
// so normal text-based classification (ReadFileContent) is completely
// unaffected.
std::string OcrImageFileIfApplicable(const std::string& filePath) {
    std::string ext;
    try { ext = fs::path(filePath).extension().string(); } catch (...) { return ""; }

    std::string lowerExt = ext;
    std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::tolower);
    if (lowerExt == ".pdf") {
        return ExtractPdfContent(filePath);
    }

    if (!IsOcrCandidateExtension(ext)) return "";
    return RunTesseractOnFile(filePath);
}

// Must be called with the clipboard already open (i.e. from inside a
// successful OpenClipboard(...) block, matching the pattern the existing
// CF_UNICODETEXT handling already uses). Reads a CF_DIB bitmap off the
// clipboard if present and writes it out as a standalone .bmp temp file —
// this is the only part of the old TryOcrClipboardImage() that actually
// needs the clipboard open, and it's fast (memory copy + one WriteFile).
// Returns false if there's no image on the clipboard, or anything about
// the DIB looks malformed. Never throws. Deliberately does NOT run OCR —
// see the split rationale on TryOcrClipboardImage() below.
bool ExtractClipboardDibToBmpFile(std::string& outBmpPath) {
    try {
        HANDLE hDib = GetClipboardData(CF_DIB);
        if (hDib == nullptr) return false;

        BITMAPINFO* pbmi = static_cast<BITMAPINFO*>(GlobalLock(hDib));
        if (pbmi == nullptr) return false;

        bool wrote = false;
        int width  = pbmi->bmiHeader.biWidth;
        int height = std::abs(pbmi->bmiHeader.biHeight);

        DWORD paletteSize = 0;
        if (pbmi->bmiHeader.biBitCount > 0 && pbmi->bmiHeader.biBitCount <= 8) {
            DWORD colors = pbmi->bmiHeader.biClrUsed
                ? pbmi->bmiHeader.biClrUsed
                : (1u << pbmi->bmiHeader.biBitCount);
            paletteSize = colors * sizeof(RGBQUAD);
        } else if (pbmi->bmiHeader.biCompression == BI_BITFIELDS) {
            // BI_BITFIELDS (very common for 16/32-bpp clipboard screen
            // captures — Snipping Tool, browsers, etc.) stores 3 DWORD
            // color-channel masks immediately after the BITMAPINFOHEADER
            // instead of a palette. Without accounting for that here,
            // bfOffBits pointed into the mask table instead of the actual
            // pixel data, producing a structurally invalid BMP file that
            // Tesseract/leptonica couldn't parse — it exited non-zero on
            // every single clipboard-image OCR attempt (confirmed via
            // ocr_diagnostics.log) while foreground-window OCR, which
            // always builds a plain BI_RGB 24-bit bitmap with no masks,
            // worked fine using the exact same RunTesseractOnFile() call.
            paletteSize = 3 * sizeof(DWORD);
        }
        DWORD headerSize = pbmi->bmiHeader.biSize + paletteSize;
        DWORD imageSize  = pbmi->bmiHeader.biSizeImage;
        if (imageSize == 0 && pbmi->bmiHeader.biBitCount > 0) {
            DWORD rowSize = ((static_cast<DWORD>(width) * pbmi->bmiHeader.biBitCount + 31) / 32) * 4;
            imageSize = rowSize * static_cast<DWORD>(height);
        }

        // Sanity bounds + a 50MB cap so a malformed/hostile DIB can't
        // trigger a huge allocation or file write.
        if (width > 0 && height > 0 && imageSize > 0 && imageSize < 50u * 1024u * 1024u) {
            std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp");
            std::string bmpPath = tempDir + "\\cs_ocr_clip_" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".bmp";

            BITMAPFILEHEADER bf = {};
            bf.bfType    = 0x4D42; // 'BM'
            bf.bfOffBits = sizeof(BITMAPFILEHEADER) + headerSize;
            bf.bfSize    = bf.bfOffBits + imageSize;

            HANDLE hF = CreateFileA(bmpPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            if (hF != INVALID_HANDLE_VALUE) {
                DWORD wr;
                WriteFile(hF, &bf, sizeof(bf), &wr, NULL);
                WriteFile(hF, pbmi, headerSize + imageSize, &wr, NULL);
                CloseHandle(hF);
                outBmpPath = bmpPath;
                wrote = true;
            }
        }

        GlobalUnlock(hDib);
        return wrote;
    } catch (...) {
        return false;
    }
}

// CRITICAL FIX: this used to open the clipboard, extract the DIB, run
// Tesseract (an external process — can take seconds) on it, AND (via the
// caller) run full policy classification + an HTTP POST to the server, all
// while still holding OpenClipboard(). The Windows clipboard is a single
// systemwide resource — holding it open for that long blocked copy/paste
// for every other process on the machine (Explorer, Office, browsers...)
// for as long as the slowest step took, up to WinHTTP's ~45s combined
// timeout on a degraded network. This wrapper is kept only for any other
// caller that still wants the old all-in-one behavior; ClipboardMonitor()
// itself now calls ExtractClipboardDibToBmpFile() (fast, clipboard open)
// and RunTesseractOnFile() (slow, clipboard already closed) separately.
std::string TryOcrClipboardImage() {
    std::string bmpPath;
    if (!ExtractClipboardDibToBmpFile(bmpPath)) return "";
    std::string result = RunTesseractOnFile(bmpPath);
    DeleteFileA(bmpPath.c_str());
    return result;
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
     bool useHttps = false;

     // CRITICAL: hConnect (and hSession) are shared across every thread in
     // the agent -- heartbeat, browser-dialog handlers, USB monitor, kernel
     // event forwarding, etc. -- and were being used with ZERO
     // synchronization and NO explicit timeouts. Concurrent unsynchronized
     // use of a single WinHTTP connection handle can leave one thread's
     // request effectively stuck until another thread's request happens to
     // advance the connection's internal state. This was confirmed as the
     // cause of browser-upload alerts only appearing once a *second*,
     // unrelated request (e.g. from opening/cancelling another file dialog)
     // fired concurrently. All requests are now fully serialized.
     std::mutex requestMutex;

 public:
     HttpClient(const std::string& url) : serverUrl(url) {
         ParseUrl(url);
         hSession = WinHttpOpen(L"SeceoKnight/1.0",
             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
             WINHTTP_NO_PROXY_NAME,
             WINHTTP_NO_PROXY_BYPASS, 0);
         
         if (hSession) {
             // Explicit timeouts (ms): resolve, connect, send, receive.
             // Previously unset, meaning a stalled request could block this
             // (serialized) queue indefinitely instead of failing fast.
             WinHttpSetTimeouts(hSession, 10000, 10000, 10000, 15000);

             std::wstring whost(host.begin(), host.end());
             hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
         }
     }
     
     ~HttpClient() {
         if (hConnect) WinHttpCloseHandle(hConnect);
         if (hSession) WinHttpCloseHandle(hSession);
     }
     
     std::pair<int, std::string> Post(const std::string& path, const std::string& jsonData) {
         std::lock_guard<std::mutex> lock(requestMutex);
         return SendRequest(L"POST", path, jsonData);
     }
     
     std::pair<int, std::string> Put(const std::string& path, const std::string& jsonData) {
         std::lock_guard<std::mutex> lock(requestMutex);
         return SendRequest(L"PUT", path, jsonData);
     }
     
     std::pair<int, std::string> Delete(const std::string& path) {
         std::lock_guard<std::mutex> lock(requestMutex);
         return SendRequest(L"DELETE", path, "");
     }

     std::pair<int, std::string> Get(const std::string& path) {
         std::lock_guard<std::mutex> lock(requestMutex);
         return SendRequest(L"GET", path, "");
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
         std::regex urlRegex(R"((https?)://([^:/]+):?(\d+)?(/.*)?$)");
         std::smatch match;
         if (std::regex_search(url, match, urlRegex)) {
             useHttps = (match[1].str() == "https");
             host = match[2].str();
             if (match[3].length() > 0) {
                 port = std::stoi(match[3].str());
             } else {
                 port = useHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
             }
             basePath = match[4].length() > 0 ? match[4].str() : "";
         } else {
             host = "";
             port = 0;
             basePath = "";
             useHttps = false;
         }
     }
     
     std::pair<int, std::string> SendRequest(const wchar_t* method, const std::string& path, const std::string& data) {
         if (!hConnect) return {0, ""};
         
         // Combine base path with request path
         std::string fullPath = basePath + path;
         
         std::wstring wpath(fullPath.begin(), fullPath.end());
         DWORD requestFlags = useHttps ? WINHTTP_FLAG_SECURE : 0;
         HINTERNET hRequest = WinHttpOpenRequest(hConnect, method, wpath.c_str(),
             nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, requestFlags);
         
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
        Logger(const std::string& filename = "seceoknight_agent.log") {
            // Check if custom log directory is specified in environment
            const char* envLogDir = std::getenv("SECEOKNIGHT_LOG_DIR");
            std::string logDir = envLogDir ? envLogDir : "";

            if (logDir.empty()) {
                // Default to C:\ProgramData\SeceoKnight\logs, NOT the
                // current directory. The agent runs as a normal, non-admin
                // user (required for clipboard/screen hooks), and the
                // current directory at launch is C:\Program Files\SeceoKnight
                // (the scheduled task's -WorkingDirectory) — a UAC-protected
                // folder a standard user can't write into. Opening the log
                // there silently failed every time (OpenLogFile()'s warning
                // goes to stderr, which no one sees in background mode), so
                // the log file only ever reflected a one-off run that had
                // write access (e.g. an elevated manual test), never the
                // real long-running background agent. ProgramData is the
                // same writable location already proven to work for the
                // quarantine folder.
                logDir = "C:\\ProgramData\\SeceoKnight\\logs";
            }

            try {
                fs::create_directories(logDir);
            } catch (...) {
                // Fall through — OpenLogFile() below will surface the
                // failure via its own warning if the directory truly
                // can't be created/used.
            }

            logFilePath = logDir + "\\" + filename;

            OpenLogFile();
            lastRotationCheck = std::chrono::system_clock::now();
            
            Info("=================================================");
            Info("SeceoKnight DLP Agent Logger Initialized");
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

                        // WriteLine(), NOT Info()/Log() -- see WriteLine's
                        // comment. CheckAndRotateLog() is only ever called
                        // from inside Log() while it still holds logMutex;
                        // Info() would call back into Log(), which would try
                        // to re-acquire that same non-recursive mutex on the
                        // same thread and deadlock forever.
                        WriteLine("INFO", "Log rotated: Previous log saved to " + rotatedPath);
                        WriteLine("INFO", "Log file size was: " + std::to_string(fileSize) + " bytes");
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Log rotation error: " << e.what() << std::endl;
            }
        }

        // Formats one line and writes it to the console (if visible) and
        // the log file. Does NOT acquire logMutex -- every caller must
        // already hold it. Split out of Log() specifically so
        // CheckAndRotateLog() can announce a rotation without re-entering
        // the mutex it's already inside (see its call site above). Before
        // this split, CheckAndRotateLog() called Info() -> Log() -> tried
        // to lock logMutex a second time on the same thread -- a
        // non-recursive std::mutex doesn't allow that: the thread blocks on
        // a lock it already holds and never wakes up. logMutex is then
        // never released, so EVERY other thread in the agent that calls
        // logger.Info/Warning/Debug/Error() (all of them) blocks forever
        // too -- the whole agent freezes at once (no heartbeat, no USB
        // events, no clipboard events, nothing), not just logging. This was
        // a real, hit-in-production bug: once the log file crosses 10MB and
        // 30 minutes have passed since the last rotation check, the very
        // next log call rotates and silently deadlocks the entire process.
        void WriteLine(const std::string& level, const std::string& message) {
            std::string timestamp = GetCurrentTimestampLocalIST();
            std::string logMsg = timestamp + " - SeceoKnightAgent - " + level + " - " + message;

            // Only output to console if window is visible (not in background mode)
            HWND consoleWindow = GetConsoleWindow();
            if (consoleWindow != NULL && IsWindowVisible(consoleWindow)) {
                std::cout << logMsg << std::endl;
            }

            if (logFile.is_open()) {
                logFile << logMsg << std::endl;
                logFile.flush();
            }
        }

void Log(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);

    // Log timestamps use Asia/Kolkata (IST). Event payloads sent to the
    // server continue to use UTC via GetCurrentTimestampISO().
    WriteLine(level, message);

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
     std::string folder = "C:\\ProgramData\\SeceoKnight\\quarantine";
 };
 
 struct ClassificationConfig {
     bool enabled = true;
     int maxFileSizeMB = 10;
     // What EvaluatePolicyRealtime() should do when it CAN'T get a real
     // answer from the server (unreachable, non-200, timeout, oversized
     // file, encoding failure, any exception) -- true (default) fails
     // CLOSED: the caller falls back to this policy's own configured
     // action (block/quarantine/alert) instead of silently letting the
     // file through. Before this existed, every one of those error paths
     // unconditionally reported "evaluation succeeded, action=allow" --
     // meaning stopping or blocking the DLP server silently disabled USB
     // content inspection entirely, a live enforcement bypass. Settable to
     // false via SECEOKNIGHT_BLOCK_ON_DLP_ERROR=0/false for an operator
     // who explicitly wants the old fail-open behavior (e.g. to avoid
     // disrupting users during a known, planned server outage).
     bool blockOnDlpError = true;
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
        // The server-issued API key from registration (POST /agents ->
        // response.api_key). Historically never captured — RegisterAgent()
        // only checked the HTTP status — so the agent had no credential of
        // its own to hand to anything else that needed to authenticate as
        // this same agent (e.g. the browser extension's native host, which
        // previously required its own, separately-registered identity per
        // machine — impractical at fleet scale). Persisted via
        // SaveApiKeyFile() (NOT SaveToFile() — see that method's comment for
        // why) so install.ps1 for the browser extension can read it and
        // reuse this agent's identity instead of registering a new one.
        std::string apiKey;
        int heartbeatInterval = 3;
        int policySyncInterval = 60;

        // ── Ransomware early-warning tunables ─────────────────────────────
        // Detection/alert only -- the agent cannot attribute a file change to
        // a PID, so it cannot kill an encryptor. This is NOT ransomware
        // prevention: it's two high-signal heuristics (burst-rate + canary
        // tripwire files, see NoteFileChangeForRansomware()/PlantCanaryFile()
        // below) that raise a critical alert fast so a human/EDR/backup
        // process can react. Recovery still depends on EDR + offline
        // backups. Every value is optional in agent_config.json: a config
        // written before this feature existed keeps these defaults. Tune per
        // site -- a fileserver-backed share or a dev box that compiles a lot
        // may need a higher burst threshold.
        //   ransomware_detection_enabled : master switch
        //   ransomware_burst_threshold   : file changes needed to trip
        //   ransomware_window_seconds    : ...within this sliding window
        //   ransomware_cooldown_seconds  : min gap between alerts (anti-flood)
        bool ransomwareDetectionEnabled = true;
        int  ransomwareBurstThreshold   = 15;
        int  ransomwareWindowSeconds    = 10;
        int  ransomwareCooldownSeconds  = 60;

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
            const char* envUrl = std::getenv("SECEOKNIGHT_SERVER_URL");
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
            
            // Quarantine config. C:\ProgramData\SeceoKnight\quarantine matches
            // exactly what install-agent.ps1 pre-creates during install (Step
            // 3) and is writable by the standard, non-elevated user account
            // the agent's scheduled task runs as (RunLevel Limited — required
            // for clipboard/hook monitoring to work at all). The old
            // "C:\Quarantine" default sat at the system drive root, which
            // standard Windows ACLs block non-admin users from creating or
            // writing to — quarantine enforcement would silently fail there
            // (caught and logged, not surfaced to the alert) while the event
            // still correctly reported "blocked" as the *intended* action.
            quarantine.enabled = true;
            quarantine.folder = "C:\\ProgramData\\SeceoKnight\\quarantine";

            // Classification config
            classification.enabled = true;
            classification.maxFileSizeMB = 10;
            {
                const char* envBlockOnError = std::getenv("SECEOKNIGHT_BLOCK_ON_DLP_ERROR");
                classification.blockOnDlpError = !envBlockOnError ||
                    (std::string(envBlockOnError) != "0" && std::string(envBlockOnError) != "false");
            }

            // Ransomware early-warning tunables -- no config file exists yet
            // on this path, so just use the field defaults declared above.
            ransomwareDetectionEnabled = true;
            ransomwareBurstThreshold   = 15;
            ransomwareWindowSeconds    = 10;
            ransomwareCooldownSeconds  = 60;
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
                    const char* envUrl = std::getenv("SECEOKNIGHT_SERVER_URL");
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
                    // agent_config.json (Program Files) has no agent_id key at
                    // all — true for EVERY install created by
                    // install-agent.ps1, which writes this file directly via
                    // PowerShell and has never included this field. Program
                    // Files isn't writable at runtime by the non-elevated
                    // scheduled-task user (see SaveToFile()'s comment above),
                    // so we can't just patch the key back into THIS file.
                    // Instead, check the ProgramData identity file
                    // (C:\ProgramData\SeceoKnight\agent_key.json) that
                    // SaveApiKeyFile() already writes to and IS writable at
                    // runtime — if a previous run already generated and
                    // registered an id, reuse it instead of minting a new one.
                    //
                    // Without this fallback, EVERY agent restart (reboot,
                    // crash recovery via the scheduled task's RestartCount,
                    // manual relaunch) silently generated a brand new random
                    // UUID, re-registered as if it were a different machine,
                    // and orphaned the previous id server-side. That's
                    // harmless as long as the fresh registration round-trips
                    // successfully before the next heartbeat — but any
                    // hiccup in that window (server briefly unreachable
                    // right at boot, a timing race, etc.) leaves the running
                    // process heartbeating with an id the server has never
                    // seen, which shows up as "Agent {id} not found" (404)
                    // on every single heartbeat until the next restart —
                    // exactly the "agent shows Disconnected after reboot"
                    // symptom this was chased down from.
                    std::string persistedId, persistedKey;
                    if (LoadPersistedIdentity(persistedId, persistedKey)) {
                        agentId = persistedId;
                        apiKey = persistedKey;
                    } else {
                        // Truly the first run anywhere for this machine —
                        // generate once and persist immediately, so every
                        // future restart finds it above instead of repeating
                        // this branch.
                        agentId = GenerateUUID();
                        SaveApiKeyFile("C:\\ProgramData\\SeceoKnight\\agent_key.json");
                    }
                }

                // Extract api_key, if this config was previously saved after
                // a successful registration (see RegisterAgent()). Empty on
                // first run / older configs predating this — that's fine,
                // RegisterAgent() will populate and persist it once it gets
                // a successful response from the server. Only overwrite
                // apiKey if this file actually has a non-empty value —
                // agent_config.json never actually contains this key in
                // practice (it lives in agent_key.json instead), and an
                // unconditional overwrite here would blow away an apiKey
                // just loaded from LoadPersistedIdentity() above.
                std::string extractedKey = ExtractJsonValue(content, "api_key");
                if (!extractedKey.empty()) {
                    apiKey = extractedKey;
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

                // Extract quarantine_path — install-agent.ps1 writes this key
                // (Step 7) pointing at C:\ProgramData\SeceoKnight\quarantine,
                // which it pre-creates (Step 3) and which is writable by the
                // standard, non-elevated user the agent runs as. This key was
                // previously never read at all, so the agent always fell back
                // to the "C:\Quarantine" default below — a system-drive-root
                // path a non-admin user typically can't create/write to,
                // meaning quarantine enforcement silently failed (caught and
                // logged, never surfaced) while alerts still correctly
                // reported "blocked" as the intended action.
                std::string extractedQuarantine = ExtractJsonValue(content, "quarantine_path");
                quarantine.enabled = true;
                quarantine.folder = !extractedQuarantine.empty()
                    ? extractedQuarantine
                    : "C:\\ProgramData\\SeceoKnight\\quarantine";

                classification.enabled = true;
                classification.maxFileSizeMB = 10;
                {
                    const char* envBlockOnError = std::getenv("SECEOKNIGHT_BLOCK_ON_DLP_ERROR");
                    classification.blockOnDlpError = !envBlockOnError ||
                        (std::string(envBlockOnError) != "0" && std::string(envBlockOnError) != "false");
                }

                // Ransomware early-warning tunables. All optional -- a config
                // predating the feature keeps the defaults. Values are
                // clamped so a typo can't silently disable detection or turn
                // it into an alert flood.
                ransomwareDetectionEnabled =
                    ExtractJsonBoolWithDefault(content, "ransomware_detection_enabled", true);
                ransomwareBurstThreshold =
                    ExtractJsonIntClamped(content, "ransomware_burst_threshold", 15, 2, 100000);
                ransomwareWindowSeconds =
                    ExtractJsonIntClamped(content, "ransomware_window_seconds", 10, 1, 3600);
                ransomwareCooldownSeconds =
                    ExtractJsonIntClamped(content, "ransomware_cooldown_seconds", 60, 0, 86400);

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

        // ExtractJsonValue() above can't be reused for a true/false literal:
        // its number branch only consumes digit/'.'/'-' characters, so for an
        // unquoted "true"/"false" token it silently returns an empty string
        // instead of the value. Named distinctly (not an overload of the
        // top-level, no-default ExtractJsonBool() used elsewhere in this
        // file) to avoid any ambiguity at the call site.
        int ExtractJsonIntClamped(const std::string& json, const std::string& key,
                                  int defaultValue, int minValue, int maxValue) {
            int v = defaultValue;
            try {
                const std::string raw = ExtractJsonValue(json, key);
                if (!raw.empty()) v = std::stoi(raw);
            } catch (...) {
                v = defaultValue;
            }
            if (v < minValue) v = minValue;
            if (v > maxValue) v = maxValue;
            return v;
        }

        bool ExtractJsonBoolWithDefault(const std::string& json, const std::string& key, bool defaultValue) {
            size_t keyPos = json.find("\"" + key + "\"");
            if (keyPos == std::string::npos) return defaultValue;

            size_t colonPos = json.find(":", keyPos);
            if (colonPos == std::string::npos) return defaultValue;

            size_t valueStart = colonPos + 1;
            while (valueStart < json.length() &&
                   (std::isspace(static_cast<unsigned char>(json[valueStart])) ||
                    json[valueStart] == '"')) {
                valueStart++;
            }
            if (valueStart >= json.length()) return defaultValue;

            if (json.compare(valueStart, 4, "true") == 0) return true;
            if (json.compare(valueStart, 5, "false") == 0) return false;
            return defaultValue;
        }

        void SaveToFile(const std::string& path) {
            std::ofstream file(path);
            if (!file.is_open()) {
                std::cerr << "WARNING: Could not create config file: " << path << std::endl;
                return;
            }
            
            // Deliberately NOT writing api_key here. This method does a full
            // overwrite of `path` — which install-agent.ps1 uses for
            // C:\Program Files\SeceoKnight\agent_config.json, a location the
            // scheduled task runs against as a standard, non-elevated user
            // (RunLevel Limited — same reason the Logger's default path had
            // to move out of Program Files earlier in this project). Two
            // problems with persisting the key here instead of via
            // SaveApiKeyFile(): (1) this write would very likely fail
            // silently (falls into the "Could not create config file"
            // branch above) since Program Files isn't writable by that
            // account, and (2) this method only knows about
            // server_url/agent_id/agent_name/intervals — it doesn't
            // preserve quarantine_path/log_path/cache_path, which
            // install-agent.ps1 also writes into this same file, so any
            // successful call here would silently wipe those out.
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

        // Reads a previously-persisted identity from the ProgramData location
        // that SaveApiKeyFile() (below) writes to — and that the browser
        // extension's install.ps1 also already reads to reuse this same
        // identity. Used by LoadFromFile() as a fallback when
        // agent_config.json itself has no agent_id — see the comment at
        // that call site for why that's the normal case, not an edge case.
        // Returns true and fills outId/outKey only if the file exists AND
        // has a non-empty agent_id; false means this is genuinely the
        // first run anywhere for this machine.
        bool LoadPersistedIdentity(std::string& outId, std::string& outKey) {
            std::ifstream file("C:\\ProgramData\\SeceoKnight\\agent_key.json");
            if (!file.is_open()) return false;
            std::string content((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
            file.close();
            if (content.empty()) return false;
            std::string id = ExtractJsonValue(content, "agent_id");
            if (id.empty()) return false;
            outId = id;
            outKey = ExtractJsonValue(content, "api_key");
            return true;
        }

        // Persists just {agent_id, api_key} to a small, separate file — see
        // the comment in SaveToFile() for why this can't just be folded into
        // that method. install-agent.ps1 pre-creates C:\ProgramData\
        // SeceoKnight\ (and its quarantine/logs/cache subfolders) as
        // writable by the same standard user the agent's scheduled task
        // runs as, so this location is expected to actually succeed where
        // Program Files would not. The browser extension's install.ps1
        // reads this file to reuse this agent's identity instead of
        // requiring its own separate registration per machine.
        void SaveApiKeyFile(const std::string& path) const {
            std::ofstream file(path);
            if (!file.is_open()) {
                std::cerr << "WARNING: Could not write agent key file: " << path << std::endl;
                return;
            }
            file << "{\n";
            file << "  \"agent_id\": \"" << agentId << "\",\n";
            file << "  \"api_key\": \"" << apiKey << "\"\n";
            file << "}\n";
            file.close();
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
    else if (!dataType.empty()) {
        // Unrecognized name — this is a custom pattern from a policy's
        // patterns.custom list (e.g. a "Study Report" keyword rule),
        // not one of the built-in named types handled above. Try it
        // directly as a regex first; if it isn't valid regex syntax,
        // fall back to a plain case-insensitive substring search so
        // simple keyword/phrase rules still work.
        try {
            std::regex pattern(dataType, std::regex::icase);
            std::sregex_iterator iter(content.begin(), content.end(), pattern);
            std::sregex_iterator end;
            for (; iter != end && results.size() < 10; ++iter) {
                results.push_back(iter->str());
            }
        } catch (const std::regex_error&) {
            std::string lowerContent = ToLower(content);
            std::string lowerNeedle = ToLower(dataType);
            if (!lowerNeedle.empty() && lowerContent.find(lowerNeedle) != std::string::npos) {
                results.push_back(dataType);
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
     std::shared_ptr<HttpClient> httpClient;
     // Guards httpClient itself (the pointer), not requests through it.
     // httpClient is reassigned by the heartbeat thread's reconnect logic
     // (see "reinitializing HTTP client" below) while OTHER threads
     // (browser-dialog handlers, USB monitor, kernel event forwarding) may
     // be concurrently calling through the existing pointer.
     //
     // CRITICAL FIX: this used to be a unique_ptr, and every call site held
     // httpClientMutex for the ENTIRE blocking network call (Post/Put can
     // take up to ~45s per WinHttpSetTimeouts before giving up). That meant
     // one slow/hanging event POST (e.g. classifying a large clipboard
     // paste while the network is degraded) fully blocked the heartbeat
     // thread's own attempt to acquire the same mutex — heartbeats stopped
     // reaching the server (agent shows "offline" in the dashboard even
     // though the machine has internet) for as long as that one call was
     // stuck. Now it's a shared_ptr: GetHttpClient() below only holds the
     // lock long enough to copy the pointer (refcount bump, no I/O), so the
     // actual network call always runs unlocked and can never block any
     // other caller — including the heartbeat.
     std::mutex httpClientMutex;

     // Returns the current HttpClient via a fast, non-blocking pointer copy.
     // Callers make their (possibly slow) request on the returned shared_ptr
     // AFTER this returns, never while holding httpClientMutex.
     std::shared_ptr<HttpClient> GetHttpClient() {
         std::lock_guard<std::mutex> lock(httpClientMutex);
         return httpClient;
     }

     // Dedicated HttpClient used ONLY by HeartbeatLoop/SendHeartbeat, never
     // shared with the general-purpose httpClient above.
     //
     // CONFIRMED LIVE, in production: the shared_ptr fix above (see the long
     // comment on httpClientMutex) only solved contention on the OUTER
     // pointer -- it made swapping the client during reconnect non-blocking.
     // It did NOT solve the INNER problem: HttpClient::Post/Put/Get/Delete
     // each take that instance's own private requestMutex for the full
     // network call (Post/Put/Get can take up to ~45s per
     // WinHttpSetTimeouts). Every caller of GetHttpClient() gets the SAME
     // instance, so they all still serialize through that one requestMutex
     // -- heartbeat included. A burst of ordinary traffic through the
     // shared client (clipboard policy checks, USB checks, event
     // submissions -- anything routed through GetHttpClient()) can queue up
     // and starve the heartbeat PUT behind it for as long as the backlog
     // takes to drain. Observed directly: heartbeats succeeded every ~30s
     // from agent startup, then stopped completely for 20+ minutes straight
     // while other threads (baseline scan, clipboard handling) kept
     // logging normally the whole time -- the dashboard showed the agent as
     // Disconnected despite the process being fully alive and otherwise
     // working. Only a full agent restart cleared it, because nothing in
     // HeartbeatLoop's own reconnect logic (3-consecutive-failures ->
     // reinit) can trigger if SendHeartbeat() never gets to run at all.
     //
     // Fix: give the heartbeat loop its own HttpClient instance, with its
     // own independent WinHTTP session/connection and its own private
     // requestMutex, so a heartbeat PUT can never queue behind unrelated
     // traffic on the shared client again. Only HeartbeatLoop ever reads or
     // reassigns this pointer (including its own reconnect-on-failure
     // logic), so unlike httpClient it needs no mutex of its own.
     std::shared_ptr<HttpClient> heartbeatHttpClient;

     std::atomic<bool> running{false};
     std::atomic<bool> hasFilePolices{false};
     std::atomic<bool> hasClipboardPolicies{false};
     std::atomic<bool> hasUsbDevicePolicies{false};
     std::atomic<bool> hasUsbTransferPolicies{false};
     std::atomic<bool> allowEvents{false};

     // USB device allowlist (strict default-deny by serial number), ported
     // from CyberSentinel-DLP — see SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md
     // and GET /agents/{id}/usb-allowlist in agents.py. Refreshed on the same
     // cadence as policy sync (SyncPolicies()) and enforced locally in
     // HandleUsbDeviceArrival() with no per-connect server round trip, so it
     // still works if the network is briefly down.
     std::atomic<bool> usbAllowlistEnforced{false};
     std::string usbAllowlistMode = "off";   // "enforce" | "audit" | "off"
     std::mutex usbAllowlistMutex;
     std::set<std::string> sanctionedUsbSerials;
     
     std::string activePolicyVersion;
     std::string lastClipboard;
     // Windows bumps this on every clipboard *change*, regardless of format
     // (text, DIB, whatever) — see ClipboardMonitor(). Used to skip the
     // whole read-and-classify pass entirely when the clipboard hasn't
     // actually changed since the last poll.
     DWORD lastClipboardSeq = 0;
     std::string lastActiveWindow;
     std::string lastActiveFile;
     std::set<std::string> removableDrives;
     std::vector<std::string> monitoredDirectories;
     std::map<std::pair<std::string, std::string>, std::chrono::steady_clock::time_point> recentEvents;

     // ── Ransomware early-warning state (task #106) ─────────────────────────
     // The burst thresholds live in agent_config.json (ransomware_* keys) so a
     // site can tune them without a recompile — see AgentConfig. Defaults: 15
     // changes in 10s, 60s cooldown. That is far above normal interactive
     // editing but well below an encryptor's rate.
     // Leading '!' so the decoy sorts to the top of a directory listing —
     // encryptors commonly walk files in name order, so it gets hit early.
     static constexpr const char* CANARY_FILENAME =
         "!!!SeceoKnightDLP-CANARY-DO-NOT-DELETE.docx";
     std::mutex ransomMutex;
     std::deque<long long> recentChanges;              // ms epoch, sliding window
     long long lastMassAlertMs = 0;
     std::set<std::string> canaryPaths;                // lowercased full paths
     std::map<std::string, long long> canaryLastAlertMs;

     // ── Network file-share transfer control (task #111) ─────────────────────
     // Synced from GET /agents/{id}/network-share-policy. Covers a real
     // exfiltration path USB device-control and content DLP entirely missed:
     // copying a file to a mapped/UNC network drive instead of a USB stick.
     // All values lowercase except paths (kept as given for prefix matching).
     std::atomic<bool> netShareEnforced{false};
     std::string netShareMode;                        // "block_all" | "content_aware" | "off"
     std::string netShareAction;                      // "audit" (log/event only) | "block" (quarantine+delete)
     std::set<std::string> netShareExceptShares;      // lowercase UNC prefixes
     std::set<std::string> netShareExceptUsers;        // lowercase
     std::vector<std::string> netShareExceptPaths;    // lowercase source-path prefixes
     std::set<std::string> netShareExceptTypes;       // lowercase extensions (no dot)
     std::mutex netShareMutex;
     std::set<std::string> netShareSeededDrives;      // drives whose pre-existing files have
                                                        // already been baselined this agent run

     // ── Managed-application file control (task #112) ────────────────────────
     // Synced from GET /agents/{id}/application-control. Ported from
     // CyberSentinel-DLP. Allow/block a file ACTION (currently: network
     // upload -- CLI transfer tools intercepted by network_exfil_monitor.cpp)
     // based on the APPLICATION performing it, independent of content -- e.g.
     // block curl.exe entirely regardless of what it's uploading, or restrict
     // uploads to only an approved allowlist of tools. IsAppActionAllowed()
     // is consulted via the NetworkExfilMonitor::Config::appAction callback
     // wired up where NetworkExfilMonitor::Start() is called. All values
     // lowercase except paths (kept as given for prefix matching).
     std::atomic<bool> appControlEnforced{false};
     std::string appControlMode;                         // "allowlist" | "blocklist" | "off"
     std::set<std::string> appControlApps;               // managed app exe names
     std::set<std::string> appControlChannels;           // covered channels; empty = all
     std::set<std::string> appControlExceptApps;
     std::set<std::string> appControlExceptUsers;
     std::vector<std::string> appControlExceptPaths;     // path prefixes
     std::set<std::string> appControlExceptTypes;        // extensions, no leading dot
     std::mutex appControlMutex;

     // Synced from GET /agents/{id}/file-identity-denylist (task #152).
     // Blocks/quarantines a file purely by extension or exact SHA-256 hash,
     // independent of content. See FetchFileIdentityDenylist()/
     // IsFileDenylisted() for the fetch/check logic.
     std::atomic<bool> fileDenylistEnforced{false};
     std::string fileDenylistAction;                     // "block" | "quarantine" | "alert" | "log"
     std::set<std::string> fileDenylistExtensions;        // no leading dot, lowercase
     std::set<std::string> fileDenylistHashes;            // lowercase sha256 hex
     std::mutex fileDenylistMutex;

     // ── Messaging / thick-client app attachment control (task #115) ────────
     // Synced from GET /agents/{id}/messaging-app-policy. Ported from
     // CyberSentinel-DLP. The network-exfil monitor's file-dialog detector
     // consults GetMessagingVerdict() when a file-open dialog is raised by
     // a managed app (Teams/WhatsApp/Telegram/Slack/Discord/Signal) and
     // alerts (default) or blocks (terminates the app) on a sensitive
     // attachment. Alert-first: action defaults to "alert" so enabling a
     // policy never kills an app until an admin opts in. All app names /
     // users / extensions stored lowercase.
     std::atomic<bool> messagingEnforced{false};
     std::string messagingAction;                        // "alert" | "block"
     std::set<std::string> messagingApps;                // managed messaging exe names
     std::set<std::string> messagingExceptUsers;          // users exempt
     std::vector<std::string> messagingExemptTypes;      // extensions, no leading dot
     // Typed-message inspection (gap-scan of August 26 2026, ported from
     // CyberSentinel-DLP). messagingAction above (alert/block) is SHARED
     // between the file-attachment path and this one -- an operator sets one
     // action for the messaging_app_control policy, and it governs both
     // surfaces once each is switched on. What's independent is whether the
     // typed-message surface is switched on AT ALL: messagingInspectMessages
     // defaults false and does NOT inherit from an enforced attachment-
     // control policy, because that sits in front of a file dialog and this
     // sits in front of the keyboard -- an operator enabling one should not
     // silently also get the other. See GetMessagingVerdict() and
     // messaging_text_monitor.h's rollout note.
     std::atomic<bool> messagingInspectMessages{false};
     std::vector<std::string> messagingDataTypes;        // empty (server-resolved) = inspection effectively off
     std::mutex messagingMutex;

     // ── Offline event spool (task #116) ─────────────────────────────────────
     // Ported from CyberSentinel-DLP. SendEvent() normally POSTs straight to
     // /events; when that fails (server unreachable, non-200/201, or a thrown
     // exception -- e.g. laptop asleep, VPN drop, server restart) the event is
     // appended to a bounded on-disk spool instead of being silently dropped.
     // FlushSpooledEvents() is called from HeartbeatLoop() the moment a
     // heartbeat actually succeeds (the same "server is reachable again"
     // signal CyberSentinel uses), replaying spooled events in capped batches
     // so a long outage can't turn reconnection into a self-inflicted event
     // storm against a server that may still be warming up.
     static constexpr size_t MAX_SPOOL_BYTES = 16ull * 1024 * 1024;  // 16 MB cap
     static constexpr int MAX_FLUSH_BATCH = 100;                    // per heartbeat
     std::mutex spoolMutex;
     std::atomic<bool> spoolFullWarned{false};

     // ── Wireless / Bluetooth transfer control (task #113) ───────────────────
     // Synced from GET /agents/{id}/wireless-policy. Ported from CyberSentinel-
     // DLP. Blocks Bluetooth file transfer (the built-in fsquirt.exe wizard)
     // and/or Wi-Fi Direct / Nearby Sharing while leaving audio (headphones)
     // and input (mouse/keyboard) devices working. Reconciled each policy
     // sync via a change signature (lastWirelessSig) so ApplyWirelessControls()
     // only touches the registry when the effective enforcement actually
     // changed, not on every sync tick.
     std::string lastWirelessSig;

     // ── Browser extension force-install (gap-scan of CyberSentinel-DLP,
     // August 18, 2026) ───────────────────────────────────────────────────
     // Synced from GET /extension/info every policy-sync cycle. Same
     // unelevated-process problem as wireless control above (confirmed by
     // that task's own live test: RegCreateKeyExA under HKLM\SOFTWARE\
     // Policies\... fails ACCESS_DENIED from this process) -- so this
     // method only FETCHES the extension id and writes it to a state cache;
     // the actual ExtensionInstallForcelist/managed-config registry writes
     // happen in the elevated HandleApplyBrowserExtensionGuard() one-shot,
     // invoked by a repeating SYSTEM/Highest scheduled task ("SeceoKnight
     // DLP Browser Extension Guard", registered by install-agent.ps1),
     // exactly mirroring the Wireless Guard split.
     std::string lastExtensionPolicySig;

     // ── Printer device control + print content inspection (task #114) ──────
     // Synced from GET /agents/{id}/printer-policy. Ported from CyberSentinel-
     // DLP. Closes the "no agent-side enforcement yet" gap flagged in
     // SanctionedPrinter's own docstring -- this is that moment. Two
     // independent, additive layers:
     //   device control  -- ShouldBlockPrinter(): cancel a job by which
     //                       PRINTER it's going to, regardless of content.
     //   content inspect -- EvaluatePrintContent(): read the REAL spooled
     //                       document text (not just the filename) and
     //                       evaluate it via the same real-time
     //                       /policy/evaluate path USB/network-share
     //                       content-aware modes already use.
     std::atomic<bool> printerControlEnforced{false};
     std::string printerControlMode;                     // "enforce" | "audit" | "off"
     std::string printerControlScope;                    // block_all|block_network|block_local|allowlist|none
     std::set<std::string> sanctionedPrinters;           // enabled allow-decision printer names (UPPERCASE)
     // Explicit deny (ported from CyberSentinel commit b7dc3f3): checked in
     // EVERY scope, not just "allowlist" -- lets an admin block one specific
     // printer without moving the whole fleet into allowlist mode. Beats an
     // allow row for the same name. See ShouldBlockPrinter().
     std::set<std::string> deniedPrinters;                // enabled deny-decision printer names (UPPERCASE)
     std::atomic<bool> printContentInspection{false};    // a print_content_prevention policy is active
     std::string printContentMode;                       // "enforce" | "audit" | "off"
     // "allow" | "block" -- enterprise-grade fail-closed option (CONFIRMED
     // LIVE need: a real printer/driver/OS combination where content
     // inspection can NEVER read a job's real data, making fail-open a
     // permanent, silent no-op for that printer rather than a rare edge
     // case). Defaults to "allow" -- matches server default, non-breaking.
     std::string printUnknownContentAction = "allow";
     // CONFIRMED LIVE: an admin set severity="critical" on their
     // print_content_prevention policy (the same top-level severity field
     // every policy type has), but blocked/unverified print events kept
     // showing hardcoded "high"/"medium" regardless -- there was no path
     // for the policy's configured severity to ever reach the agent.
     // Populated from GET /printer-policy's merged "content_severity"
     // (server takes the highest-ranked severity across every active
     // print_content_prevention policy). Defaults to "high", matching the
     // previous hardcoded value, so this is non-breaking until the server
     // side of this fix is deployed too.
     std::string printContentSeverity = "high";
     std::mutex printerPolicyMutex;
     // SHA-256 of the last spooled document read, keyed by job id -- computed
     // once during content inspection and reused by the print event callback
     // instead of a second spool-directory read (the spool file may already
     // be gone by the time the event fires for a cancelled job).
     struct { int jobId = -1; std::string sha256; } lastSpoolHash;

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
     // Suspend/resume (sleep/wake) notification handle — see the
     // WM_POWERBROADCAST handling in UsbWindowProc/HandlePowerBroadcast for
     // why: without this, a machine that goes to sleep from idle (the OS's
     // own power plan, nothing to do with lock/unlock) stops heartbeating
     // for the whole nap, and on wake just sits waiting for the next
     // scheduled heartbeat tick (or the slower 3-consecutive-failure WinHTTP
     // reinit) instead of reconnecting the moment the user is back —
     // exactly the "shows offline after being idle" symptom this fixes.
     HPOWERNOTIFY powerNotify = nullptr;
     // USB file transfer monitoring
     std::map<std::string, std::set<std::string>> usbDriveFiles;  // drive -> set of files
     std::mutex usbFilesMutex;
     std::map<std::string, std::string> usbDriveToDeviceId;  // drive letter -> device ID

     // Debounce for the dashboard-visibility report in HandleUsbDeviceArrival()
     // (see its call site below). Cheap/generic pendrives without a genuine
     // hardware serial get a Windows-synthesized one from
     // ExtractUsbSerialFromDeviceId(), and a single physical insertion can
     // trigger several genuine DBT_DEVICEARRIVAL notifications in quick
     // succession -- a known USB/hub power-negotiation re-enumeration quirk
     // on flaky ports/cheap drives -- each producing a DIFFERENT synthesized
     // serial, since it's derived from that notification's own interface
     // path. Since the server keys USB device identity on serial_number
     // alone, one physical insertion could turn into up to 5 separate
     // "not sanctioned" rows on the USB Devices dashboard page, with no way
     // for an admin to tell which one to approve. Keyed on VID:PID, which
     // (unlike the serial) stays stable across re-enumeration of the same
     // physical device.
     std::map<std::string, std::chrono::steady_clock::time_point> recentUsbArrivals;
     std::mutex usbArrivalMutex;

     // USB File Transfer Monitoring
    std::map<std::string, FileMetadata> monitoredFiles;  // Key: relative path
    std::map<std::string, ShadowEntry> shadowCopies;     // For BLOCK mode
    std::map<std::string, bool> currentUSBFileState;     // Track if file is currently on USB (true = on USB, false = removed)
    std::set<std::string> quarantinedUSBFiles;
    std::vector<USBFileTransferPolicy> usbTransferPolicies;
    std::mutex usbTransferMutex;
    std::atomic<bool> usbBlockingActive{false};  // Track if USB blocking is currently active

    // ── Kernel minifilter integration ──────────────────────────────────────────
    // These are default-constructed; kernelClient_ is only created in Start()
    // if the driver port is actually available.
    cs::ClassificationEngine kernelClassifier_;
    cs::PolicyEngine         kernelPolicyEngine_;
    std::unique_ptr<cs::FilterCommClient> kernelClient_;
    // ──────────────────────────────────────────────────────────────────────────

     static DLPAgent* s_instance;
    
     static LRESULT CALLBACK UsbWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
         if (uMsg == WM_DEVICECHANGE && s_instance) {
             return s_instance->HandleDeviceChange(wParam, lParam);
         }
         // CRITICAL FIX: the agent had zero awareness of the workstation
         // being locked/unlocked. Reported symptom: after a screen lock +
         // unlock, the dashboard kept showing the agent offline, and it
         // never reconnected on its own — only a full reinstall fixed it.
         // WTSRegisterSessionNotification (registered where this window is
         // created) delivers WM_WTSSESSION_CHANGE here on lock/unlock;
         // WTS_SESSION_UNLOCK forces an immediate HTTP client reinit +
         // heartbeat instead of waiting for the next scheduled interval
         // (and its 3-consecutive-failure reinit threshold) to notice.
         if (uMsg == WM_WTSSESSION_CHANGE && s_instance) {
             return s_instance->HandleSessionChange(wParam, lParam);
         }
         // Sleep/wake: the OS's own idle-timeout power plan (not a lock,
         // not a user action) suspends the whole process for however long
         // the machine naps — heartbeats simply can't fire during that
         // window. RegisterSuspendResumeNotification (registered where this
         // window is created) delivers WM_POWERBROADCAST here with
         // PBT_APMRESUMEAUTOMATIC/PBT_APMRESUMESUSPEND on wake; mirror the
         // unlock handling below instead of waiting for the next scheduled
         // heartbeat (or the passive failure-threshold reinit) to notice.
         if (uMsg == WM_POWERBROADCAST && s_instance) {
             return s_instance->HandlePowerBroadcast(wParam, lParam);
         }
         return DefWindowProc(hwnd, uMsg, wParam, lParam);
     }

     LRESULT HandleSessionChange(WPARAM wParam, LPARAM lParam) {
         if (wParam == WTS_SESSION_UNLOCK) {
             logger.Info("Workstation unlocked — forcing immediate reconnect");
             // Off the message-pump thread: reinitializing the HTTP client
             // and sending a heartbeat both do network I/O, and this
             // function runs on the same thread that pumps USB device
             // notifications — don't block that on a slow/degraded network.
             std::thread([this]() { TriggerImmediateReconnect(); }).detach();
         } else if (wParam == WTS_SESSION_LOCK) {
             logger.Info("Workstation locked");
         }
         return 0;
     }

     LRESULT HandlePowerBroadcast(WPARAM wParam, LPARAM lParam) {
         if (wParam == PBT_APMRESUMEAUTOMATIC || wParam == PBT_APMRESUMESUSPEND) {
             logger.Info("System resumed from sleep — forcing immediate reconnect");
             // Same reasoning as the unlock case: don't block the thread
             // that pumps USB/session/power messages on network I/O.
             std::thread([this]() { TriggerImmediateReconnect(); }).detach();
         } else if (wParam == PBT_APMSUSPEND) {
             logger.Info("System entering sleep");
         }
         return TRUE;
     }

     void TriggerImmediateReconnect() {
         try {
             {
                 std::lock_guard<std::mutex> lock(httpClientMutex);
                 httpClient = std::make_shared<HttpClient>(config.serverUrl);
             }
             SendHeartbeat();
             logger.Info("Reconnect after unlock: HTTP client reinitialized, heartbeat sent");
         } catch (...) {
             logger.Error("Reconnect after unlock failed — will retry on next scheduled heartbeat");
         }
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
                     // Same vendor-specific-name resolution used on arrival
                     // (see GetBetterDeviceName / GetUsbStorageChildFriendlyName).
                     // Without this, a disconnect event would overwrite the
                     // "Seen on Endpoints" row's device name back to the raw/
                     // generic GetDeviceDescription() text the moment the user
                     // unplugs the drive, undoing the improved name shown while
                     // it was connected. The device node is usually still
                     // present in the tree at DEVICEREMOVECOMPLETE time, so
                     // this best-effort lookup can still succeed; falls back
                     // gracefully (same as on arrival) if it can't.
                     std::string betterDisconnectName = GetBetterDeviceName(deviceId);
                     if (!betterDisconnectName.empty()) {
                         deviceName = betterDisconnectName;
                     }

                     logger.Info("USB device disconnected: " + deviceName);

                     // Handle disconnect event (classic monitored-event USB
                     // policy pipeline — no-ops if no such policy is active).
                     HandleUsbEvent(deviceName, deviceId, "disconnect");

                     // Independently report disconnect visibility for the
                     // allowlist/device-control feature's live connected/
                     // offline indicator, which must work even when no
                     // classic USB policy exists (HandleUsbEvent() above
                     // silently returns in that case — see its early-return
                     // on an empty policy list). Only mass-storage devices
                     // resolve to a serial; anything else (keyboard, mouse,
                     // etc.) yields an empty string and is skipped.
                     {
                         std::string usbSerial = ExtractUsbSerialFromDeviceId(deviceId);
                         if (!usbSerial.empty()) {
                             ReportUsbDeviceAuthorization(deviceName, usbSerial, "", "", "",
                                                           "disconnect", false, false, "disconnect");
                         }
                     }
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
        // Proceed if EITHER the classic monitored-event USB policies are
        // active OR the (separate) USB device-control allowlist is enforced —
        // an admin may have only the allowlist turned on with no
        // usb_device_monitoring policy at all.
        bool allowlistEnforced = usbAllowlistEnforced.load();
        if (!allowEvents || (!hasUsbDevicePolicies && !allowlistEnforced)) return;

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

        // --- USB device allowlist (strict default-deny by serial number) ---
        // Ported from CyberSentinel-DLP. Independent of the monitored-event
        // policy loop below: an admin can enable this allowlist with or
        // without also having a separate "block on usb_connect" policy.
        std::string usbSerial = ExtractUsbSerialFromDeviceId(deviceId);
        // USBSTOR interface paths (\\?\USBSTOR#Disk&Ven_X&Prod_Y&Rev_Z#serial#{GUID})
        // never contain a numeric "VID_xxxx&PID_yyyy" — that only exists on
        // the PARENT USB device node (e.g. USB\VID_0781&PID_5567\...), one
        // level up in the device tree. Without walking up to it, the USB
        // Devices dashboard page's VID:PID column is always empty for every
        // mass-storage device, even though Seen/Sanctioned otherwise show
        // the right serial and device name.
        std::string usbVendorId, usbProductId;
        GetUsbStorageVidPid(deviceId, usbVendorId, usbProductId);
        bool sanctioned = false;
        std::string allowlistMode;
        {
            std::lock_guard<std::mutex> lock(usbAllowlistMutex);
            allowlistMode = usbAllowlistMode;
            if (!usbSerial.empty()) {
                sanctioned = sanctionedUsbSerials.find(usbSerial) != sanctionedUsbSerials.end();
            }
        }
        bool allowlistShouldBlock = false;
        if (allowlistEnforced && !sanctioned && allowlistMode == "enforce") {
            allowlistShouldBlock = true;
        }
        // An explicitly-approved device is an administrative override: it
        // should be let through regardless of a separate, blanket
        // "block all USB" monitored-event policy also being active.
        // Without this, approving a device here had no effect whenever any
        // such classic block policy existed, since that policy alone was
        // sufficient to set shouldBlock=true below — approval could never
        // un-set it. Applies in either allowlist mode (enforce or audit):
        // an approval is an explicit "this one's fine" from an admin, not
        // something that should depend on the allowlist's own audit/enforce
        // sub-mode (that distinction only governs UNSANCTIONED devices).
        bool allowlistExempt = allowlistEnforced && sanctioned;
        if (allowlistEnforced) {
            logger.Info(std::string("USB allowlist check: serial=") + (usbSerial.empty() ? "(none)" : usbSerial) +
                        " sanctioned=" + (sanctioned ? "true" : "false") +
                        " mode=" + allowlistMode +
                        " decision=" + (allowlistShouldBlock ? "block" : (allowlistExempt ? "allow (exempt)" : "allow")));
        }
        // Debounce the dashboard-visibility report only -- see
        // recentUsbArrivals' member comment for why. This does NOT affect
        // the allowlist decision above or the block/allow enforcement
        // below, which run on every arrival exactly as before; it only
        // suppresses redundant "not sanctioned" rows on the USB Devices
        // page when the same physical device (same VID:PID) re-enumerates
        // several times within a few seconds of its first arrival. A
        // genuinely new insertion of the same drive minutes later is still
        // reported normally. Devices where VID:PID couldn't be determined
        // (empty) skip the debounce entirely rather than risk suppressing
        // a real device with no identity to key on.
        bool isDuplicateArrival = false;
        if (!usbVendorId.empty() && !usbProductId.empty()) {
            std::string vidPidKey = usbVendorId + ":" + usbProductId;
            auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(usbArrivalMutex);
            auto it = recentUsbArrivals.find(vidPidKey);
            if (it != recentUsbArrivals.end()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
                if (elapsed < 8) {
                    isDuplicateArrival = true;
                }
            }
            recentUsbArrivals[vidPidKey] = now;
        }

        // Visibility event for the Events page — fire-and-forget, off this
        // thread (it pumps Windows device-arrival messages and must not
        // block on network I/O).
        if (!isDuplicateArrival) {
            ReportUsbDeviceAuthorization(betterDeviceName, usbSerial, usbVendorId, usbProductId, driveLetter,
                                         allowlistShouldBlock ? "block" : "allow",
                                         sanctioned, allowlistEnforced);
        } else {
            logger.Debug("Suppressed duplicate USB arrival report (re-enumeration of VID:" +
                         usbVendorId + " PID:" + usbProductId + " within debounce window)");
        }

         // Get USB policies (the separate, monitored-event based USB policies)
         std::vector<PolicyRule> policies;
         {
             std::lock_guard<std::mutex> lock(policiesMutex);
             policies = usbPolicies;
         }

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

                     // allowlistExempt: see comment above — an approved
                     // device doesn't get blocked by this even though the
                     // policy matched (still recorded above for logging).
                     if (policyAction == "block" && !allowlistExempt) {
                         shouldBlock = true;
                     }
                     break;
                 }
             }

             if (shouldBlock) break;
         }

         if (allowlistExempt && !matchedPolicyId.empty() && policyAction == "block") {
             logger.Info("USB device " + betterDeviceName + " (serial=" + usbSerial +
                         ") exempted from block policy '" + matchedPolicyName +
                         "' — approved on the USB device-control allowlist");
             // The classic block primitives (registry USBSTOR disable /
             // per-instance device disable) are class-wide, not per-serial
             // — if an earlier, unapproved device already tripped them,
             // they'd still be in effect and would keep this approved
             // device from mounting even though shouldBlock is now false
             // for it. Proactively restore access. Deliberately does NOT
             // touch usbBlockingActive — that flag reflects whether the
             // classic block policy is still configured active and must
             // keep governing the NEXT unapproved device's connect event;
             // this is a one-time "let this specific device through," not
             // a change to the standing policy state.
             EnableAllUSBStorageDevices();
             BlockUSBStorageViaRegistry(false);
         }

         // The allowlist can ALSO independently decide to block, even when no
         // monitored-event policy matched above.
         if (allowlistShouldBlock && !shouldBlock) {
             shouldBlock = true;
             matchedPolicyId = "usb_device_control_allowlist";
             matchedPolicyName = "USB Device Control (Allowlist)";
         }

         if (!shouldBlock && policies.empty() && !allowlistShouldBlock) return;

// BLOCK ACTION
// BLOCK ACTION - only if blocking is currently active (classic policy path)
// OR the allowlist itself just decided to block this specific device.
if (shouldBlock && (usbBlockingActive.load() || allowlistShouldBlock)) {
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
    // CRITICAL FIX: previously this unconditionally reported action="blocked"
    // and a "USB device blocked by policy" description even when every block
    // method above had failed (e.g. agent runs at RunLevel Limited by design,
    // so the HKLM registry write and CM_Disable_DevNode both fail with
    // ACCESS_DENIED unless the agent is elevated) — meaning the dashboard
    // claimed success while the drive stayed fully accessible in Windows.
    // Now the reported action/description/blocked fields reflect what
    // actually happened (blockSuccess), not just what was attempted.
    JsonBuilder json;
    json.AddString("event_id", GenerateUUID());
    json.AddString("event_type", "usb");
    json.AddString("event_subtype", "usb_blocked");
    json.AddString("agent_id", config.agentId);
    json.AddString("source_type", "agent");
    json.AddString("user_email", GetUsername() + "@" + GetHostname());
    json.AddString("description", blockSuccess
        ? ("USB device blocked by policy: " + betterDeviceName)
        : ("USB block FAILED (device may still be accessible — agent likely lacks admin/SYSTEM "
           "privileges required for USB storage block on this endpoint): " + betterDeviceName));
    json.AddString("severity", "critical");
    json.AddString("action", blockSuccess ? "blocked" : "block_failed");
    json.AddBool("blocked", blockSuccess);
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

    // Read-only counterpart to BlockUSBStorageViaRegistry() above -- reports
    // what's ACTUALLY in the registry right now (Start == 4, "Disabled"),
    // instead of trusting in-memory state.
    //
    // Needed because usbBlockingActive (an in-memory std::atomic<bool>,
    // declared {false}) starts false on EVERY process launch, including a
    // cold boot where install-agent.ps1's "SeceoKnight DLP USB Block"
    // scheduled task has ALREADY disabled USB storage via this same
    // registry key, unconditionally, before this agent process even starts
    // -- it doesn't check policy at all, just disables on every boot as a
    // fail-closed-until-the-agent-confirms-otherwise measure. The
    // reconciliation logic that's supposed to restore USB access when a
    // policy says Alert/Log-only (or when no usb_device_monitoring policy
    // exists at all) only fires on a `previousUsbBlocking == true` edge --
    // and since the in-memory flag falsely starts at false every cold
    // boot, that edge can never be observed there, so the restore path
    // never ran: USB storage stayed disabled at the OS level regardless of
    // what the policy said, on every fresh boot, fleet-wide. Fixed by
    // seeding usbBlockingActive from this actual registry read once, right
    // before the first policy reconciliation pass (see its call site).
    // Found in a policy-engine audit, August 28 2026.
    bool IsUSBStorageBlockedInRegistry() {
        HKEY hKey;
        LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, USB_STOR_REG_PATH, 0, KEY_QUERY_VALUE, &hKey);
        if (result != ERROR_SUCCESS) {
            // Can't read it -- don't claim it's blocked when we're not sure;
            // that would make this fix itself capable of introducing a
            // fail-open-by-omission, which is exactly the class of bug this
            // whole audit was hunting for.
            return false;
        }
        DWORD startValue = 3; // default: "Manual" (not blocked) if unreadable
        DWORD dataSize = sizeof(DWORD);
        DWORD valueType = 0;
        result = RegQueryValueExA(hKey, "Start", NULL, &valueType, (BYTE*)&startValue, &dataSize);
        RegCloseKey(hKey);
        if (result != ERROR_SUCCESS || valueType != REG_DWORD) {
            return false;
        }
        return startValue == 4; // 4 = Disabled, matches BlockUSBStorageViaRegistry(true)
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
    // Fallback default must match the actual configured quarantine root
    // (C:\ProgramData\SeceoKnight\quarantine) used everywhere else in the
    // agent — a mismatched fallback of C:\Quarantine here silently sent
    // files to a folder the user never checks, for any policy (e.g. a
    // classification-only "scan everything" policy) that doesn't have an
    // explicit quarantinePath configured on the server.
    std::string quarantinePath = policy.quarantinePath.empty() ? "C:\\ProgramData\\SeceoKnight\\quarantine" : policy.quarantinePath;
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
                    // copy+remove, not rename — rename() maps to MoveFileExW()
                    // without MOVEFILE_COPY_ALLOWED on this build, which fails
                    // across volumes (quarantine on C:\ back to a USB drive).
                    // If the USB drive was removed, copy_file throws and is
                    // caught below, leaving the file safely in quarantine.
                    fs::copy_file(quarantineFile, monitoredFile, fs::copy_options::overwrite_existing);
                    fs::remove(quarantineFile);
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

         httpClient = std::make_shared<HttpClient>(config.serverUrl);
         // Separate connection dedicated to heartbeats -- see the comment on
         // the heartbeatHttpClient member for why this must never share the
         // main httpClient's requestMutex.
         heartbeatHttpClient = std::make_shared<HttpClient>(config.serverUrl);

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
         logger.Info("Starting SeceoKnight DLP Agent...");
         logger.Info("Server URL: " + config.serverUrl);
         logger.Info("Agent ID: " + config.agentId);
         
         running = true;
         
         // Test server connectivity
         logger.Info("Testing server connectivity...");
         RegisterAgent();

         // Load cached policies FIRST so we are already enforcing if the server
         // is unreachable. A successful sync below replaces them; an
         // "up_to_date" reply keeps them (the cache is what makes
         // activePolicyVersion meaningful across restarts). See task #95/#107:
         // policies used to live only in memory, so an agent that started
         // while the server was unreachable enforced NOTHING until the first
         // successful sync -- turning "fail closed on API error" into "fail
         // wide open after a restart" (kill the agent, block the server,
         // restart == free bypass; a laptop booting off-VPN hit the same hole
         // with no malice at all).
         LoadCachedPolicyBundle();

         logger.Info("Fetching initial policies...");
         SyncPolicies(true);

         if (!allowEvents) {
             logger.Warning("==============================================");
             logger.Warning("WARNING: No active policies found!");
             logger.Warning("The agent will continue running but won't");
             logger.Warning("generate events until policies are configured");
             logger.Warning("on the server.");
             logger.Warning("==============================================");
         }
         
         // ── Kernel minifilter: connect to SeceoKnightFilter driver ──────────
         // Sets up PolicyEngine + ClassificationEngine for kernel-level
         // file system enforcement.  Fails gracefully if driver not loaded.
         kernelPolicyEngine_.SetClassifier(&kernelClassifier_);
         kernelClient_ = std::make_unique<cs::FilterCommClient>(
             &kernelPolicyEngine_, &kernelClassifier_);

         // Wire logged kernel events to the server (async, non-blocking)
         kernelClient_->SetEventLogCallback([this](const cs::LoggedEvent& ev) {
             try {
                 // Build a minimal event JSON and POST to /events
                 std::string path = "";
                 int wlen = WideCharToMultiByte(CP_UTF8, 0, ev.eventData.FilePath, -1, nullptr, 0, nullptr, nullptr);
                 if (wlen > 1) {
                     path.resize(wlen - 1);
                     WideCharToMultiByte(CP_UTF8, 0, ev.eventData.FilePath, -1, &path[0], wlen, nullptr, nullptr);
                 }
                 std::string pid = std::to_string(ev.eventData.ProcessId);
                 std::string blocked = (ev.decision.action == cs::Action::Block) ? "true" : "false";
                 std::string evJson = "{\"event_type\":\"kernel_file\","
                     "\"agent_id\":\"" + config.agentId + "\","
                     "\"file_path\":\"" + path + "\","
                     "\"process_id\":" + pid + ","
                     "\"blocked\":" + blocked + "}";
                 GetHttpClient()->Post("/events/kernel", evJson);
             } catch (...) {}
         });

         bool kernelConnected = kernelClient_->Start();
         if (kernelConnected) {
             logger.Info("==============================================");
             logger.Info("Kernel minifilter CONNECTED — kernel-level");
             logger.Info("file system enforcement is ACTIVE.");
             logger.Info("Driver: SeceoKnightFilter (\\SeceoKnightPort)");
             logger.Info("==============================================");
         } else {
             logger.Warning("Kernel minifilter NOT loaded — running in");
             logger.Warning("user-mode-only mode. To enable kernel-level");
             logger.Warning("enforcement, install csfilter.sys (WDK build).");
         }
         // ─────────────────────────────────────────────────────────────────────

         workerThreads.emplace_back(&DLPAgent::HeartbeatLoop, this);
         workerThreads.emplace_back(&DLPAgent::PolicySyncLoop, this);
         workerThreads.emplace_back(&DLPAgent::AutoUpdateLoop, this);
         workerThreads.emplace_back(&DLPAgent::ClipboardMonitor, this);
         workerThreads.emplace_back(&DLPAgent::UsbMonitor, this);
         workerThreads.emplace_back(&DLPAgent::FileSystemMonitor, this);
        // workerThreads.emplace_back(&DLPAgent::RemovableDriveMonitor, this);
         workerThreads.emplace_back(&DLPAgent::UsbFileTransferMonitor, this);
         workerThreads.emplace_back(&DLPAgent::MonitorUSBTransferDirectories, this);
         workerThreads.emplace_back(&DLPAgent::NetworkShareTransferMonitor, this);

         // File-existence baseline scan runs on its OWN thread, started
         // LAST (after every other monitor thread above is already live).
         // It used to run synchronously right here in Start(), before any
         // worker thread existed -- on an endpoint with a large monitored
         // folder (thousands of small files under Documents/Desktop/
         // Downloads, e.g. a portable app or extracted archive) that scan
         // could take minutes, and for that whole time NOTHING was
         // monitored: no clipboard, no USB, no file-system watch, nothing.
         // Real-world symptom: a fresh install/reinstall sat there logging
         // "Stored baseline for existing file" for one file at a time while
         // a clipboard copy on the same machine produced no event at all,
         // because ClipboardMonitor's thread hadn't even been created yet.
         // ScanAndStoreExistingFiles() already takes policiesMutex and
         // originalContentsMutex around every read/write of shared state,
         // so running it concurrently with the monitors above (which touch
         // the same maps) is safe -- this is purely a "start it later,
         // not first" fix, not a locking change.
         if (allowEvents && hasFilePolices) {
             logger.Info("Scanning existing files to establish baselines (background - other monitoring is already active)...");
             workerThreads.emplace_back(&DLPAgent::ScanAndStoreExistingFiles, this);
         }

         // ── Screen Capture Monitor ──
         // Multi-method text extraction + classification:
         //   1) Window title keywords (instant)
         //   2) Window text via WM_GETTEXT + EnumChildWindows (reads ALL visible text)
         //   3) File content from disk (if editor with filename in title)
         // outText: populated with whatever text this function reads
         // (window text via WM_GETTEXT and/or Tesseract OCR output),
         // regardless of what classification level the LOCAL hardcoded
         // pattern set below arrives at. The caller forwards this to the
         // server as the event's "content" field, so the server's full
         // rule engine (custom rules like a user-defined keyword rule,
         // plus Email/Phone/etc.) gets a chance to classify content this
         // function's own small fixed pattern list (Aadhaar/PAN/Credit
         // Card/SSN/private keys/AWS keys/IFSC) doesn't know about.
         auto screenClassifier = [this](const std::string& windowTitle, const std::string& processName,
                                         std::string& outText) -> std::string {

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
                     // Email/phone weren't previously checked at all for screen
                     // capture (only file-write/clipboard/USB paths had them via
                     // ExtractDataType) — same regexes as those paths for consistency.
                     {"EMAIL",       std::regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)")},
                     {"PHONE_IN",    std::regex(R"((?:\+91[\s.-]?|0)[6-9]\d{4}[\s.-]?\d{5})")},
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
                             else if (name == "EMAIL" || name == "PHONE_IN") score += 0.65f;
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
                     outText = allText;
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
                             // Capture the foreground window's pixels (unchanged
                             // from the original implementation), then hand off
                             // to the shared RunTesseractOnFile() helper — same
                             // helper the file-write, USB-transfer, and
                             // clipboard-image OCR paths use — instead of
                             // duplicating the "shell out + read result" logic
                             // inline here.
                             std::string tempDir = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp");
                             std::string tempBmp = tempDir + "\\cs_ocr_fg_" +
                                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".bmp";

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

                             std::string ocrText = RunTesseractOnFile(tempBmp);
                             DeleteFileA(tempBmp.c_str());

                             if (ocrText.length() > 10) {
                                 logger.Debug("Tesseract OCR (foreground window) extracted " +
                                              std::to_string(ocrText.length()) + " chars");
                                 // Reaching Stage 4 at all means Stage 2's WM_GETTEXT read
                                 // (if any) did NOT classify as sensitive — for apps like
                                 // the Snipping Tool, that text is just UI chrome
                                 // ("DesktopWindowXamlSource", "Snipping Tool") while the
                                 // actual captured/previewed content only shows up via OCR
                                 // of the window's pixels. Previously this only overwrote
                                 // outText when Stage 2 found NOTHING at all, so a
                                 // non-matching Stage 2 text silently "locked in" and the
                                 // real OCR-detected content that drove the Restricted
                                 // verdict never made it into the reported event. OCR text
                                 // now always wins once we get this far.
                                 outText = ocrText;
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
                 // Forward whatever window/OCR text the local classifier read so
                 // the server's ClassificationEngine (full rule set — custom
                 // rules, Email, Phone, etc.) can classify it too. Without this,
                 // screen_capture events were only ever evaluated against the
                 // agent's own small hardcoded pattern list (Aadhaar/PAN/Credit
                 // Card/SSN/private keys/AWS keys/IFSC) and nothing else.
                 if (!event.detectedText.empty()) {
                     json.AddString("content", event.detectedText);
                 }
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
                 // blockReason distinguishes a device-control block (wrong
                 // printer) from a content block (sensitive document) on the
                 // same job -- both use actionTaken=="Block", so the
                 // description/reason need to say which one actually fired.
                 // Ported from CyberSentinel-DLP.
                 // CONFIRMED LIVE: before this, a print_content_prevention job
                 // whose real content genuinely couldn't be read (see
                 // EvaluatePrintContent's comment) fell back to a filename-
                 // only decision that looked EXACTLY like a verified-clean
                 // "low" allow -- a real, silent false sense of security for
                 // whoever reviews these events. contentInspectionStatus ==
                 // "unavailable" now surfaces that gap explicitly instead.
                 bool contentUnavailable = (event.contentInspectionStatus == "unavailable");
                 // CONFIRMED LIVE: for some printer/driver classes Windows
                 // itself overwrites the spooler job's document name with
                 // the generic "Local Downlevel Document" before the agent
                 // ever sees it (see print_monitor.h's documentNameInferred
                 // comment). print_monitor.cpp falls back to the foreground
                 // window's title in that case -- likely correct, but a
                 // heuristic. Label it plainly rather than presenting a
                 // guess with the same confidence as a real API-sourced
                 // document name.
                 std::string displayDocName = event.documentName +
                     (event.documentNameInferred ? " (inferred from active window)" : "");
                 std::string desc;
                 if (event.actionTaken == "Block" && event.blockReason == "printer_control")
                     desc = "PRINT BLOCKED (printer control): " + displayDocName + " -> " + event.printerName;
                 else if (event.actionTaken == "Block")
                     desc = "PRINT JOB BLOCKED: " + displayDocName + " — " + event.category + " data";
                 else if (contentUnavailable)
                     desc = "Print job: " + displayDocName + " -> " + event.printerName +
                            " (content NOT verified -- inspection could not read the job's real "
                            "data, this decision is based on filename only)";
                 else
                     desc = "Print job: " + displayDocName + " -> " + event.printerName;
                 json.AddString("description", desc);
                 // CONFIRMED LIVE: an admin set severity="critical" on their
                 // print_content_prevention policy and it was silently
                 // ignored -- every content-driven block/unverified event
                 // showed a hardcoded "high"/"medium" no matter what the
                 // policy actually said. printContentSeverity is synced
                 // from GET /printer-policy's merged content_severity (see
                 // that member's declaration comment). Device-control
                 // blocks (blockReason=="printer_control") are a different
                 // policy type with its own severity semantics not covered
                 // by this fix, so that path keeps its previous "high".
                 std::string printSeverity;
                 if (event.actionTaken == "Block" && event.blockReason == "printer_control") {
                     printSeverity = "high";
                 } else if (event.actionTaken == "Block" || contentUnavailable) {
                     std::lock_guard<std::mutex> lock(printerPolicyMutex);
                     printSeverity = printContentSeverity;
                 } else {
                     printSeverity = "low";   // verified-clean allow -- routine, not a policy hit
                 }
                 json.AddString("severity", printSeverity);
                 json.AddString("action", event.actionTaken == "Block" ? "blocked" : "allowed");
                 json.AddString("classification_level", event.category);
                 json.AddBool("blocked", event.actionTaken == "Block");
                 json.AddString("file_path", displayDocName);
                 json.AddString("printer_name", event.printerName);
                 json.AddString("block_reason", event.blockReason);
                 json.AddString("content_inspection_status", event.contentInspectionStatus);
                 if (!event.fileHash.empty()) {
                     json.AddString("file_hash", event.fileHash);
                 }
                 json.AddString("timestamp", GetCurrentTimestampISO());
                 SendEvent(json.Build());
             },
             [this](const std::string& level, const std::string& msg) {
                 if (level == "WARNING") logger.Warning(msg);
                 else if (level == "ERROR") logger.Error(msg);
                 else logger.Info(msg);
             },
             printClassifier,
             [](int jobId) -> std::string {
                 std::string spoolPath = GetPrintSpoolFilePath(jobId);
                 return spoolPath.empty() ? "" : CalculateFileHash(spoolPath);
             }
         );
         // Printer DEVICE control: cancel jobs on disallowed printers
         // (additive; content-based blocking below is unchanged). Ported
         // from CyberSentinel-DLP -- closes the "no agent enforcement yet"
         // gap in SanctionedPrinter's model.
         printMonitor->SetPrinterControl(
             [this](const std::string& printerName) { return ShouldBlockPrinter(printerName); });
         // Print CONTENT control: inspect the REAL spooled document (not just
         // the filename) via the server. Replaces the printClassifier
         // filename-keyword heuristic above as the primary decision whenever
         // a print_content_prevention policy is active; the keyword
         // classifier remains the fallback when it isn't (see
         // EvaluatePrintContent()'s !printContentInspection.load() early
         // return, and PrintMonitor::MonitorLoop's m_printContent-unset
         // branch). Ported from CyberSentinel-DLP.
         printMonitor->SetPrintContent(
             [this](const std::string& printerName, int jobId, const std::string& docName) {
                 return EvaluatePrintContent(printerName, jobId, docName);
             });
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

             // Managed-application file control for the network channel: block an
             // upload when application_control disallows the acting process. When no
             // application_control policy is active IsAppActionAllowed() returns true,
             // so this is a no-op and existing exfil behaviour is unchanged. Ported
             // from CyberSentinel-DLP.
             nemCfg.appAction = [this](const std::string& proc,
                                       const std::string& path,
                                       const std::string& ext) {
                 return !IsAppActionAllowed("network", proc, GetUsername(), path, ext);
             };

             // Managed messaging / thick-client attachment control: the file-
             // dialog detector asks whether the dialog-owning app (Teams/
             // WhatsApp/Telegram/…) is managed and, if so, whether to block or
             // only alert on a sensitive attachment. Driven from
             // GET /messaging-app-policy each sync; returns managed=false
             // when no policy is active, so this is a no-op then. Ported from
             // CyberSentinel-DLP.
             nemCfg.messagingPolicy = [this](const std::string& exeLower,
                                             const std::string& user) {
                 return GetMessagingVerdict(exeLower, user);
             };

             if (NetworkExfilMonitor::Start(nemCfg)) {
                 logger.Info("Network Exfiltration Monitor started");
             } else {
                 logger.Warning("Network Exfiltration Monitor did not start");
             }

             // ── Typed-message inspection (gap-scan of August 26 2026) ──
             // Separate module, separate hook, but reuses every callback
             // above verbatim -- one classifier, one event sender, one
             // logger, one messaging-policy resolver for both the file-
             // attachment and typed-message surfaces. Always started: the
             // module's own hook only ever holds a keystroke when
             // GetMessagingVerdict() reports inspectMessages=true AND
             // block=true for the foreground app (see messaging_text_
             // monitor.h) -- which requires an operator to have explicitly
             // turned on typed-message inspection AND set the policy action
             // to Block. Everywhere else (feature off, alert mode, an
             // unmanaged app) the hook passes every keystroke straight
             // through untouched, same as if it were never installed.
             MessagingTextMonitor::Config mtmCfg;
             mtmCfg.agentId         = config.agentId;
             mtmCfg.agentName       = config.agentName;
             mtmCfg.username        = nemCfg.username;
             mtmCfg.hostname        = nemCfg.hostname;
             mtmCfg.classify        = nemCfg.classify;
             mtmCfg.sendEvent       = nemCfg.sendEvent;
             mtmCfg.log             = nemCfg.log;
             mtmCfg.messagingPolicy = nemCfg.messagingPolicy;

             if (MessagingTextMonitor::Start(mtmCfg)) {
                 logger.Info("Typed-Message Monitor started (hook installed; "
                             "holds a keystroke only when a policy explicitly "
                             "enables inspection in Block mode)");
             } else {
                 logger.Warning("Typed-Message Monitor did not start -- "
                                "typed-message inspection unavailable this run");
             }

             // NOTE (task #145): do NOT call ApplyCliGuardIfeo() from here.
             // Confirmed live on a real endpoint: this main task runs
             // UNELEVATED on purpose (RunLevel Limited -- see
             // install-agent.ps1's principal comment: clipboard hooks and
             // keyboard/mouse monitoring silently break under UIPI if this
             // process is elevated), and a standard user's token only has
             // ReadKey on the IFEO registry path -- RegCreateKeyExA reliably
             // returns ACCESS_DENIED (rc=5) from this process, every single
             // startup, for every scoped exe. Calling it here would just
             // spam the log with expected, unfixable-from-here failures.
             // install-agent.ps1 instead registers a SEPARATE SYSTEM/Highest
             // one-shot scheduled task ("SeceoKnight DLP CLI Guard") that
             // runs `seceoknight_agent.exe --apply-ifeo-guards`
             // (HandleApplyIfeoGuards() below main()) at startup -- same
             // elevation pattern already used for USB-block. The pipe
             // server started just above still needs to be running
             // regardless of which process performs the registry write,
             // since that's what the elevated one-shot's installed
             // Debugger redirect will connect back to.
             logger.Info("CLI Guard pipe server ready for " +
                         std::to_string(NetworkExfilMonitor::IfeoScopedExecutables().size()) +
                         " executables (IFEO registration handled by the separate "
                         "elevated CLI Guard scheduled task, not this process)");
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

         // Stop kernel minifilter client first (closes filter port)
         if (kernelClient_) {
             try { kernelClient_->Stop(); } catch (...) {}
         }

         // Shut down the isolated network exfil monitor before joining the
         // DLPAgent worker threads so its background threads exit cleanly.
         try { NetworkExfilMonitor::Stop(); } catch (...) {}
         // Same for the typed-message monitor -- MUST run before process exit
         // so its WH_KEYBOARD_LL hook is cleanly uninstalled (UnhookWindowsHookEx
         // in HookThread()) rather than left for Windows to notice the owning
         // thread is gone. A held keystroke at this exact moment is released by
         // the module's own watchdog, not by this call, so shutdown never eats
         // a keypress.
         try { MessagingTextMonitor::Stop(); } catch (...) {}

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
             json.AddString("os_version", GetOSVersion());
             json.AddString("username", GetUsername());
             json.AddString("ip_address", GetRealIPAddress());
             json.AddString("version", AGENT_VERSION);
             
             std::pair<int, std::string> reg = GetHttpClient()->Post("/agents", json.Build());
             auto& [status, response] = reg;

             if (status == 200 || status == 201) {
                 logger.Info("Agent registered with server");

                 // Capture the server-issued api_key (see AgentConfig::apiKey
                 // for why: previously this response was only checked for
                 // status and the key was discarded, so nothing on this
                 // machine had a reusable credential for this agent's
                 // identity — the browser extension's native host needed its
                 // own, separately-registered identity as a workaround,
                 // which doesn't scale past a handful of machines. Only
                 // re-save when the key actually changed, to avoid a
                 // pointless disk write on every agent restart (RegisterAgent()
                 // runs once per Start(), i.e. every process/service start).
                 //
                 // Written to C:\ProgramData\SeceoKnight\agent_key.json, NOT
                 // to agent_config.json in Program Files — see the comment
                 // in AgentConfig::SaveToFile() for why that path isn't safe
                 // to rewrite from here.
                 std::string returnedKey = config.ExtractJsonValue(response, "api_key");
                 if (!returnedKey.empty() && returnedKey != config.apiKey) {
                     config.apiKey = returnedKey;
                     config.SaveApiKeyFile("C:\\ProgramData\\SeceoKnight\\agent_key.json");
                     logger.Info("Agent api_key captured and saved to C:\\ProgramData\\SeceoKnight\\agent_key.json");
                 }
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
             std::pair<int, std::string> res = GetHttpClient()->Delete("/agents/" + config.agentId + "/unregister");
             auto& [status, response] = res;
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
             
             std::pair<int, std::string> sync = GetHttpClient()->Post(
                 "/agents/" + config.agentId + "/policies/sync",
                 requestBody
             );
             auto& [status, response] = sync;
             
             if (status == 200) {
                 logger.Debug("Policy sync response (first 1000 chars): " + response.substr(0, 1000));
                 
                 if (response.find("\"status\":\"up_to_date\"") != std::string::npos) {
                     logger.Info("Agent policy bundle up to date");
                 } else {
                     logger.Info("Policy bundle received from server");
                     ApplyPolicyBundle(response);
                     // Persist the authoritative bundle so a restart while the
                     // server is unreachable still enforces the last known
                     // policy instead of enforcing nothing at all.
                     SavePolicyBundleToCache(response);
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

         // USB device allowlist has its own small, flat endpoint (not part of
         // the general policy bundle above) — refreshed on the same cadence,
         // isolated in its own try/catch so a failure here never blocks the
         // policy sync above (or vice versa).
         SyncUsbAllowlist();
         // Network file-share transfer control -- same reasoning, own endpoint.
         FetchNetworkSharePolicy();
         // Managed-application file control -- same reasoning, own endpoint.
         FetchApplicationControl();
         // Messaging / thick-client app attachment control -- same reasoning, own endpoint.
         FetchMessagingAppPolicy();
         // Wireless / Bluetooth transfer control -- same reasoning, own endpoint.
         FetchWirelessPolicy();
         // Printer device control + print content inspection -- same reasoning, own endpoint.
         FetchPrinterPolicy();
         // File Identity Denylist (task #152) -- same reasoning, own endpoint.
         FetchFileIdentityDenylist();
         // Browser extension force-install (gap-scan of CyberSentinel-DLP,
         // Aug 18 2026) -- same reasoning, own endpoint. Only caches the
         // desired state here; HandleApplyBrowserExtensionGuard() (the
         // elevated one-shot) does the actual registry write.
         FetchBrowserExtensionPolicy();
     }

     // Pulls GET /agents/{id}/network-share-policy and caches it locally.
     // Mirrors SyncUsbAllowlist() above: polled on the policy-sync cadence,
     // enforced locally by NetworkShareTransferMonitor() with no per-file
     // server round trip, so it keeps working through a brief network blip.
     void FetchNetworkSharePolicy() {
         try {
             std::pair<int, std::string> resp = GetHttpClient()->Get(
                 "/agents/" + config.agentId + "/network-share-policy");
             auto& [status, response] = resp;
             if (status != 200) return;   // keep last-known-good on error/outage

             bool enforced = ExtractJsonBool(response, "enforced");
             std::string mode = ToLower(config.ExtractJsonValue(response, "mode"));
             std::string action = ToLower(config.ExtractJsonValue(response, "action"));
             if (action != "block") action = "audit";   // default safe

             auto lc = [](std::vector<std::string> v) { for (auto& s : v) s = ToLower(s); return v; };
             auto shares = lc(ExtractJsonArray(response, "exception_shares"));
             auto users  = lc(ExtractJsonArray(response, "exception_users"));
             auto paths  = lc(ExtractJsonArray(response, "exception_paths"));
             auto types  = lc(ExtractJsonArray(response, "exception_file_types"));

             {
                 std::lock_guard<std::mutex> lock(netShareMutex);
                 netShareMode = mode;
                 netShareAction = action;
                 netShareExceptShares = std::set<std::string>(shares.begin(), shares.end());
                 netShareExceptUsers  = std::set<std::string>(users.begin(), users.end());
                 netShareExceptPaths  = paths;
                 netShareExceptTypes  = std::set<std::string>(types.begin(), types.end());
             }
             netShareEnforced.store(enforced);
             logger.Debug("Network share control: enforced=" + std::string(enforced ? "true" : "false") +
                         " mode=" + (mode.empty() ? "off" : mode) + " action=" + action +
                         " except_shares=" + std::to_string(shares.size()));
         } catch (const std::exception& e) {
             logger.Debug(std::string("FetchNetworkSharePolicy failed: ") + e.what());
         } catch (...) {
             logger.Debug("FetchNetworkSharePolicy failed");
         }
     }

     // Pulls GET /agents/{id}/application-control and caches it locally. Ported
     // from CyberSentinel-DLP. Mirrors FetchNetworkSharePolicy() above: polled
     // on the policy-sync cadence, own try/catch, keeps last-known-good on a
     // transient error/outage rather than failing open or closed on every blip.
     void FetchApplicationControl() {
         try {
             std::pair<int, std::string> resp = GetHttpClient()->Get(
                 "/agents/" + config.agentId + "/application-control");
             auto& [status, response] = resp;
             if (status != 200) return;   // keep last-known-good on error/outage

             bool enforced = ExtractJsonBool(response, "enforced");
             std::string mode = ToLower(config.ExtractJsonValue(response, "mode"));

             auto lc = [](std::vector<std::string> v) { for (auto& s : v) s = ToLower(s); return v; };
             auto apps    = lc(ExtractJsonArray(response, "applications"));
             auto chans   = lc(ExtractJsonArray(response, "channels"));
             auto exApps  = lc(ExtractJsonArray(response, "exception_applications"));
             auto exUsers = lc(ExtractJsonArray(response, "exception_users"));
             auto exPaths = lc(ExtractJsonArray(response, "exception_paths"));
             auto exTypes = lc(ExtractJsonArray(response, "exception_file_types"));

             {
                 std::lock_guard<std::mutex> lock(appControlMutex);
                 appControlMode         = mode;
                 appControlApps         = std::set<std::string>(apps.begin(), apps.end());
                 appControlChannels     = std::set<std::string>(chans.begin(), chans.end());
                 appControlExceptApps   = std::set<std::string>(exApps.begin(), exApps.end());
                 appControlExceptUsers  = std::set<std::string>(exUsers.begin(), exUsers.end());
                 appControlExceptPaths  = exPaths;
                 appControlExceptTypes  = std::set<std::string>(exTypes.begin(), exTypes.end());
             }
             appControlEnforced.store(enforced);
             logger.Debug("Application control: enforced=" + std::string(enforced ? "true" : "false") +
                         " mode=" + (mode.empty() ? "off" : mode) +
                         " apps=" + std::to_string(apps.size()) +
                         " channels=" + std::to_string(chans.size()));
         } catch (const std::exception& e) {
             logger.Debug(std::string("FetchApplicationControl failed: ") + e.what());
         } catch (...) {
             logger.Debug("FetchApplicationControl failed");
         }
     }

     // Local verdict for the managed-application file control. Returns true if
     // the action is ALLOWED, false if it must be BLOCKED. A channel handler
     // (currently: the network_exfil_monitor appAction callback below) calls
     // this with the acting process exe, current user, target path and file
     // extension. Any single exception match allows; otherwise allowlist
     // allows only listed apps and blocklist blocks listed apps. Fails open
     // (allowed) when no application_control policy is active.
     bool IsAppActionAllowed(const std::string& channel, const std::string& processName,
                             const std::string& userName, const std::string& filePath,
                             const std::string& fileExt) {
         if (!appControlEnforced.load()) return true;
         std::string ch = ToLower(channel), proc = ToLower(processName),
                     usr = ToLower(userName), ext = ToLower(fileExt), path = ToLower(filePath);
         if (!ext.empty() && ext[0] == '.') ext.erase(0, 1);
         std::lock_guard<std::mutex> lock(appControlMutex);
         // 1) channel coverage -- empty list means "all channels"
         if (!appControlChannels.empty() && appControlChannels.count(ch) == 0) return true;
         // 2) exceptions -- any match allows
         if (!proc.empty() && appControlExceptApps.count(proc)) return true;
         if (!usr.empty() && appControlExceptUsers.count(usr)) return true;
         if (!ext.empty()  && appControlExceptTypes.count(ext)) return true;
         for (const auto& pfx : appControlExceptPaths)
             if (!pfx.empty() && path.rfind(pfx, 0) == 0) return true;
         // 3) mode
         bool listed = appControlApps.count(proc) > 0;
         if (appControlMode == "blocklist") return !listed;   // block listed apps
         return listed;                                       // allowlist: allow only listed
     }

     // ── File Identity Denylist (task #152) ───────────────────────────────
     // Blocks/quarantines a file purely by extension or exact SHA-256 hash,
     // independent of content -- an antivirus-style denylist, the same way
     // the dashboard/server side already described it (see
     // _transform_file_identity_denylist_config's docstring server-side).
     // Previously had zero agent-side implementation at all: the dashboard
     // form and server config transform existed, but nothing ever fetched
     // or checked a denylist on this binary -- confirmed via a full grep for
     // "denylist"/"file_identity" across this file turning up nothing.
     //
     // Checked from the USB (HandleRemovableDriveFile) and network-share
     // (HandleNetworkShareNewFile) file-arrival hooks -- the two channels
     // that already reliably see a file cross an exfiltration boundary
     // today. NOT wired into FileSystemMonitor: that thread only watches
     // directories sourced from separate File System Monitoring policies
     // (monitoredDirectories), so a denylist-only deployment with no such
     // policy configured would never see any local file-write events at
     // all -- covering that would need a general "watch everything"
     // mechanism this agent doesn't have yet. Known, documented gap (see
     // CHANGELOG), not silently pretended to be full coverage.
     void FetchFileIdentityDenylist() {
         try {
             std::pair<int, std::string> resp = GetHttpClient()->Get(
                 "/agents/" + config.agentId + "/file-identity-denylist");
             auto& [status, response] = resp;
             if (status != 200) return;   // keep last-known-good on error/outage

             bool enforced = ExtractJsonBool(response, "enforced");
             std::string action = ToLower(config.ExtractJsonValue(response, "action"));
             if (action.empty()) action = "block";

             auto lc = [](std::vector<std::string> v) { for (auto& s : v) s = ToLower(s); return v; };
             auto exts   = lc(ExtractJsonArray(response, "extensions"));
             auto hashes = lc(ExtractJsonArray(response, "hashes"));

             {
                 std::lock_guard<std::mutex> lock(fileDenylistMutex);
                 fileDenylistAction     = action;
                 fileDenylistExtensions = std::set<std::string>(exts.begin(), exts.end());
                 fileDenylistHashes     = std::set<std::string>(hashes.begin(), hashes.end());
             }
             fileDenylistEnforced.store(enforced);
             logger.Debug("File identity denylist: enforced=" + std::string(enforced ? "true" : "false") +
                         " action=" + action +
                         " extensions=" + std::to_string(exts.size()) +
                         " hashes=" + std::to_string(hashes.size()));
         } catch (const std::exception& e) {
             logger.Debug(std::string("FetchFileIdentityDenylist failed: ") + e.what());
         } catch (...) {
             logger.Debug("FetchFileIdentityDenylist failed");
         }
     }

     // True if filePath matches the denylist by extension or SHA-256 hash.
     // The hash is only computed when the extension didn't already match
     // AND the hash list is non-empty, so an extension-only policy never
     // pays the cost of hashing every file it sees.
     bool IsFileDenylisted(const std::string& filePath, std::string& matchReason) {
         if (!fileDenylistEnforced.load()) return false;

         std::string ext = ToLower(fs::path(filePath).extension().string());
         if (!ext.empty() && ext[0] == '.') ext.erase(0, 1);

         bool needHash = false;
         {
             std::lock_guard<std::mutex> lock(fileDenylistMutex);
             if (!ext.empty() && fileDenylistExtensions.count(ext)) {
                 matchReason = "extension:" + ext;
                 return true;
             }
             needHash = !fileDenylistHashes.empty();
         }
         if (!needHash) return false;

         std::string hash;
         try {
             hash = ToLower(CalculateFileHash(filePath));
         } catch (...) {
             return false;
         }
         if (hash.empty()) return false;

         std::lock_guard<std::mutex> lock(fileDenylistMutex);
         if (fileDenylistHashes.count(hash)) {
             matchReason = "hash:" + hash;
             return true;
         }
         return false;
     }

     std::string GetFileDenylistAction() {
         std::lock_guard<std::mutex> lock(fileDenylistMutex);
         return fileDenylistAction;
     }

     // Copy-then-delete quarantine for a denylisted file, cross-volume safe
     // -- same reasoning as QuarantineNetworkShareFile() below. Shared by
     // every hook point that checks IsFileDenylisted().
     bool QuarantineDenylistedFile(const std::string& filePath, const std::string& fileName) {
         std::string quarantinePath = "C:\\ProgramData\\SeceoKnight\\quarantine";
         std::string timestamp = std::to_string(time(NULL));
         std::string quarantineFile = quarantinePath + "\\" + fileName + "_denylist_" + timestamp;
         try {
             fs::create_directories(quarantinePath);
             if (!fs::exists(filePath)) return false;
             fs::copy_file(filePath, quarantineFile, fs::copy_options::overwrite_existing);
             fs::remove(filePath);
             logger.Warning("  Quarantined denylisted file: " + filePath + " -> " + quarantineFile);
             return true;
         } catch (const std::exception& e) {
             logger.Error("Failed to quarantine denylisted file " + filePath + ": " + e.what());
             return false;
         }
     }

     void SendFileIdentityDenylistEvent(const std::string& fileName, const std::string& filePath,
                                         const std::string& channel, const std::string& matchReason,
                                         const std::string& action, bool success) {
         try {
             size_t fileSize = 0;
             try { if (fs::exists(filePath)) fileSize = fs::file_size(filePath); } catch (...) {}

             std::string description = "File Identity Denylist match (" + matchReason + ") via " + channel;
             description += "\nFile: " + fileName;
             description += "\nAction: " + action;

             JsonBuilder json;
             json.AddString("event_id", GenerateUUID());
             json.AddString("event_type", "file_identity_denylist");
             json.AddString("event_subtype", "file_identity_denylist");
             json.AddString("agent_id", config.agentId);
             json.AddString("source_type", "agent");
             json.AddString("user_email", GetUsername() + "@" + GetHostname());
             json.AddString("description", description);
             json.AddString("severity", "high");
             json.AddString("action", action);
             json.AddString("file_name", fileName);
             json.AddString("file_path", filePath);
             json.AddInt("file_size", static_cast<int>(fileSize));
             json.AddString("channel", channel);
             json.AddString("match_reason", matchReason);
             json.AddBool("success", success);
             json.AddString("timestamp", GetCurrentTimestampISO());

             SendEvent(json.Build());
             logger.Warning("File identity denylist event sent: " + action + " - " + fileName +
                           " (" + matchReason + ")");
         } catch (const std::exception& e) {
             logger.Error("Failed to send file identity denylist event: " + std::string(e.what()));
         }
     }

     // ── Messaging / thick-client app attachment control ─────────────────────
     // Pulls GET /agents/{id}/messaging-app-policy and caches it locally.
     // Ported from CyberSentinel-DLP. Mirrors FetchApplicationControl() above:
     // polled on the policy-sync cadence, own try/catch, keeps last-known-good
     // on a transient error/outage.
     void FetchMessagingAppPolicy() {
         try {
             std::pair<int, std::string> resp = GetHttpClient()->Get(
                 "/agents/" + config.agentId + "/messaging-app-policy");
             auto& [status, response] = resp;
             if (status != 200) return;   // keep last-known-good on error/outage

             bool enforced = ExtractJsonBool(response, "enforced");
             std::string action = ToLower(config.ExtractJsonValue(response, "action"));
             if (action != "block") action = "alert";   // audit-first default

             auto lc = [](std::vector<std::string> v) { for (auto& s : v) s = ToLower(s); return v; };
             auto apps    = lc(ExtractJsonArray(response, "apps"));
             auto exUsers = lc(ExtractJsonArray(response, "exception_users"));
             auto exTypes = lc(ExtractJsonArray(response, "exempt_file_types"));
             for (auto& t : exTypes) if (!t.empty() && t[0] == '.') t.erase(0, 1);

             // Safety net: an enforced policy that names no apps falls back to
             // the built-in managed set, so the feature works even with a bare
             // policy (mirrors the server's own _DEFAULT_MESSAGING_APPS fallback).
             if (enforced && apps.empty()) {
                 // whatsapp.root.exe: current WhatsApp for Windows is a
                 // WebView2 app whose window belongs to WhatsApp.Root.exe --
                 // such a machine has no whatsapp.exe at all, so the
                 // fallback list silently never matched real installs until
                 // this was added (gap-scan of CyberSentinel-DLP commit
                 // 07ea6ba, August 21 2026).
                 apps = {"teams.exe", "ms-teams.exe", "msteams.exe",
                         "whatsapp.exe", "whatsapp.root.exe",
                         "telegram.exe", "slack.exe",
                         "discord.exe", "signal.exe"};
             }

             // Typed-message inspection (gap-scan of August 26 2026). Reuses
             // `action` above (alert/block) as its own action -- see the
             // field comment on messagingInspectMessages for why it's only
             // the ENABLE flag that's independent. The server has already
             // resolved "operator picked zero data types" down to
             // inspect_messages=false, so an empty array here always means
             // inspection is effectively off, never "everything". Defaults
             // false if the server omits the key entirely (older manager
             // build), which is the safe direction: no keystroke is ever
             // held unless the server explicitly says so.
             bool inspectMessages = ExtractJsonBool(response, "inspect_messages");
             auto dataTypes = ExtractJsonArray(response, "message_data_types");
             for (auto& t : dataTypes) { for (auto& c : t) c = (char)toupper((unsigned char)c); }

             {
                 std::lock_guard<std::mutex> lock(messagingMutex);
                 messagingAction      = action;
                 messagingApps        = std::set<std::string>(apps.begin(), apps.end());
                 messagingExceptUsers = std::set<std::string>(exUsers.begin(), exUsers.end());
                 messagingExemptTypes = exTypes;
                 messagingDataTypes   = dataTypes;
             }
             messagingEnforced.store(enforced);
             messagingInspectMessages.store(inspectMessages);
             // App list and data-type list logged by NAME, not count (gap-scan
             // of CyberSentinel-DLP commits f4a4136/e7179d8, August 25-26
             // 2026). "apps=9" or "message_data_types=10" cannot answer the
             // only question this log line is ever read for -- is the exe/
             // type I am testing with actually one of them -- and the exe
             // name is rarely what an operator assumes (WhatsApp for Windows
             // is whatsapp.root.exe; there is no whatsapp.exe on such a
             // machine).
             std::string appList;
             for (const auto& a : apps) { if (!appList.empty()) appList += ","; appList += a; }
             std::string typeList;
             for (const auto& t : dataTypes) { if (!typeList.empty()) typeList += ","; typeList += t; }
             logger.Debug("Messaging app control: enforced=" + std::string(enforced ? "true" : "false") +
                         " action=" + action + " apps=" + std::to_string(apps.size()) +
                         " [" + appList + "]" +
                         " inspect_messages=" + std::string(inspectMessages ? "true" : "false") +
                         " message_data_types=" +
                         (dataTypes.empty() ? std::string("all") : typeList));
         } catch (const std::exception& e) {
             logger.Debug(std::string("FetchMessagingAppPolicy failed: ") + e.what());
         } catch (...) {
             logger.Debug("FetchMessagingAppPolicy failed");
         }
     }

     // CONFIRMED LIVE: an admin's policy had exactly one app configured --
     // "teams.exe", the only Teams option the dashboard's chip list offers
     // (MessagingAppControlPolicyForm.tsx's defaultApps). But the process
     // Microsoft actually ships for the current "new Teams" client is
     // ms-teams.exe -- a rename an admin has no reason to know about. An
     // exact-string match against the configured set silently missed every
     // real-world Teams attachment as a result (confirmed via log: dialog
     // correctly attributed to ms-teams.exe, but GetMessagingVerdict()
     // still returned managed=false, so nothing after that point ever ran).
     // Canonicalize known same-product exe-name variants to one identity
     // before matching, so whichever name an admin happened to pick still
     // covers every real install of that product.
     static std::string CanonicalMessagingAppName(const std::string& exeLower) {
         if (exeLower == "teams.exe" || exeLower == "ms-teams.exe" || exeLower == "msteams.exe") {
             return "teams.exe";   // canonical identity for "Microsoft Teams", any variant
         }
         if (exeLower == "whatsapp.exe" || exeLower == "whatsapp.root.exe") {
             // Same rename problem as Teams above, different product: current
             // WhatsApp for Windows is a WebView2 app running as
             // WhatsApp.Root.exe, and a machine with it installed has no
             // whatsapp.exe at all. Gap-scan of CyberSentinel-DLP commit
             // 07ea6ba, August 21 2026.
             return "whatsapp.exe";
         }
         return exeLower;
     }

     // General fallback for a same-product rename CanonicalMessagingAppName
     // above does not yet know about by name: compare by STEM -- the part of
     // the image name before the first dot -- so a future rename (or an app
     // this list has never seen) still matches without needing its own alias
     // entry first. Comparing whole stems, never prefixes, is what keeps this
     // from over-matching: "slack" does not match "slackbot", and
     // "msedgewebview2" -- the WebView2/Electron renderer that must never be
     // managed on its own, since it hosts content for a dozen unrelated
     // applications -- matches nothing in any real policy. Gap-scan of
     // CyberSentinel-DLP commit fceb5eb, August 26 2026; kept as a fallback
     // BEHIND the explicit alias table above rather than replacing it, since
     // an explicit alias is a decision someone already made and verified,
     // while a stem match is a heuristic.
     static bool MessagingAppNameStemMatches(const std::string& a, const std::string& b) {
         auto stem = [](const std::string& s) {
             size_t dot = s.find('.');
             return dot == std::string::npos ? s : s.substr(0, dot);
         };
         const std::string sa = stem(a), sb = stem(b);
         return !sa.empty() && sa == sb;
     }

     // Local verdict for the messaging-app attachment detector. Given the
     // dialog-owning process exe (lowercased) and the current user, reports
     // whether it's a managed messaging client, whether to BLOCK (vs alert)
     // on a sensitive attachment, and the exempt file types. Fails closed to
     // "not managed" (managed=false) when no policy is active -- the
     // NetworkExfilMonitor::Config::messagingPolicy callback then treats the
     // dialog as ordinary, ignored traffic, same as before this feature
     // existed. Ported from CyberSentinel-DLP.
     NetworkExfilMonitor::MessagingVerdict GetMessagingVerdict(
             const std::string& exeLower, const std::string& userName) {
         NetworkExfilMonitor::MessagingVerdict v;
         if (!messagingEnforced.load()) return v;   // managed=false => detector ignores it
         std::lock_guard<std::mutex> lock(messagingMutex);
         std::string u = ToLower(userName);
         if (!u.empty() && messagingExceptUsers.count(u)) return v;   // user exempt
         // Symmetric check: canonicalize BOTH the incoming process name and
         // each configured app name before comparing, so it doesn't matter
         // which of the known same-product variants the admin happened to
         // pick versus which variant is actually running.
         std::string canonicalIncoming = CanonicalMessagingAppName(exeLower);
         bool matched = false;
         for (const auto& configured : messagingApps) {
             if (configured == exeLower ||
                 CanonicalMessagingAppName(configured) == canonicalIncoming) {
                 matched = true;
                 break;
             }
         }
         // Neither an exact match nor a known alias -- try a stem match before
         // giving up, so an app whose exe name has drifted (a rename this
         // codebase has not seen and added an alias for yet) still matches
         // instead of the feature silently doing nothing for it.
         if (!matched) {
             for (const auto& configured : messagingApps) {
                 if (MessagingAppNameStemMatches(configured, exeLower)) { matched = true; break; }
             }
         }
         if (matched) {
             v.managed          = true;
             v.block            = (messagingAction == "block");   // shared action -- see struct comment
             v.exemptExtensions = messagingExemptTypes;
             // Typed-message inspection (gap-scan of August 26 2026). Gated on
             // the SAME app match as the attachment path (an operator picks
             // which apps are managed once) and the SAME action as above --
             // only whether it's switched on at all is independent. See the
             // field comment on messagingInspectMessages.
             v.inspectMessages  = messagingInspectMessages.load();
             v.messageDataTypes = messagingDataTypes;
         }
         return v;
     }

     // ── Wireless / Bluetooth transfer control ──────────────────────────────
     // Ported from CyberSentinel-DLP. Set (block=true) or clear an Image File
     // Execution Options "Debugger" that prevents <exeName> from launching.
     // Used to block the built-in Bluetooth file transfer wizard (fsquirt.exe)
     // without touching audio/HID profiles. This is the one genuinely
     // IFEO-based control in the agent (application_control above is NOT
     // IFEO -- see task #112's CHANGELOG entry).
     // Checks + logs every registry API return code -- previously this swallowed
     // failures completely silently, which is exactly the "lies about success"
     // pattern this project has fixed elsewhere (task #15 USB block, #133 print
     // content honesty). Task #142/#143 needs this: without it, a failed IFEO
     // write for a CLI Guard tool looks IDENTICAL in the log to a successful
     // one ("installed for 9 executables" either way), silently leaving that
     // tool completely unprotected with no way to tell from the log alone.
     void SetIFEODebugger(const std::string& exeName, const std::string& debuggerValue, bool block) {
         std::string sub = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                           "Image File Execution Options\\" + exeName;
         if (block) {
             HKEY k;
             LSTATUS rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, nullptr,
                                          REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &k, nullptr);
             if (rc != ERROR_SUCCESS) {
                 try { logger.Error("SetIFEODebugger: RegCreateKeyExA failed for " + exeName +
                                    " rc=" + std::to_string(rc) +
                                    (rc == ERROR_ACCESS_DENIED ?
                                     " (ACCESS DENIED -- antivirus/EDR real-time protection may be "
                                     "blocking this write; IFEO Debugger tampering is a well-known "
                                     "technique (MITRE T1546.012) many AV products flag/block by "
                                     "default, even for a legitimate DLP agent)" : "")); } catch (...) {}
                 return;
             }
             LSTATUS rc2 = RegSetValueExA(k, "Debugger", 0, REG_SZ,
                                          reinterpret_cast<const BYTE*>(debuggerValue.c_str()),
                                          (DWORD)debuggerValue.size() + 1);
             if (rc2 != ERROR_SUCCESS) {
                 try { logger.Error("SetIFEODebugger: RegSetValueExA failed for " + exeName +
                                    " rc=" + std::to_string(rc2)); } catch (...) {}
             } else {
                 try { logger.Debug("SetIFEODebugger: Debugger set for " + exeName); } catch (...) {}
             }
             RegCloseKey(k);
         } else {
             HKEY k;
             if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
                 RegDeleteValueA(k, "Debugger");
                 RegCloseKey(k);
             }
         }
     }

     // ── CLI Guard: zero-race pre-launch interception (task #142/#143) ──────
     // Registers/clears the SAME IFEO Debugger mechanism as fsquirt.exe above,
     // but for NetworkExfilMonitor::IfeoScopedExecutables() (curl.exe,
     // wget.exe, rclone.exe, s3cmd.exe, azcopy.exe, aws.exe, scp.exe,
     // pscp.exe, winscp.com) -- deliberately excludes powershell/python/
     // certutil/bitsadmin, which stay on the WMI-only path (see that
     // function's own comment for why). Debugger = "<selfPath>" --cli-guard,
     // so Windows launches THIS agent in place of the real tool; HandleCliGuard()
     // in main() asks the running service (over \\.\pipe\SeceoKnightCliGuard)
     // for an allow/block verdict BEFORE the real binary ever starts, then
     // either exits immediately (block) or launches a temp-named copy of the
     // real exe and relays its exit code (allow). Idempotent -- safe to call
     // on every agent startup; only actually changes anything the first time
     // or after a manual registry edit.
     void ApplyCliGuardIfeo(bool enforce) {
         char selfPath[MAX_PATH] = {0};
         GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
         std::string dbg = std::string("\"") + selfPath + "\" --cli-guard";
         for (const auto& exeName : NetworkExfilMonitor::IfeoScopedExecutables()) {
             SetIFEODebugger(exeName, dbg, enforce);
         }
     }

     // Set a policy DWORD under HKLM when `set`, else delete it (restore default).
     void SetPolicyDword(const std::string& sub, const std::string& name, DWORD value, bool set) {
         HKEY k;
         if (set) {
             if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, nullptr,
                                 REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
                 RegSetValueExA(k, name.c_str(), 0, REG_DWORD,
                                reinterpret_cast<const BYTE*>(&value), sizeof(value));
                 RegCloseKey(k);
             }
         } else {
             if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
                 RegDeleteValueA(k, name.c_str());
                 RegCloseKey(k);
             }
         }
     }

     // Apply/reconcile the wireless-transfer controls. Reconciled both ways so
     // clearing the policy restores the channels. NOTE: covers the built-in
     // Bluetooth file wizard + the Nearby Sharing/CDP policy.
     //
     // NOT called directly from FetchWirelessPolicy() anymore (task #147):
     // confirmed live that this main agent task runs unelevated (same root
     // cause as task #145's CLI Guard fix), so RegCreateKeyExA on the IFEO
     // path reliably fails ACCESS_DENIED (rc=5) from this process, every
     // sync cycle. Left defined/callable for completeness and for the
     // elevated --apply-wireless-guard path below, which computes the same
     // enforce/blockBt/blockNearby from the cache file and calls this.
     void ApplyWirelessControls(bool enforce, bool blockBt, bool blockNearby) {
         // Bluetooth file transfer -- redirect the fsquirt.exe wizard (via IFEO) to
         // THIS agent with --blocked-launch, so each attempt is logged + raised as a
         // dashboard event and fsquirt never runs. Audio (A2DP/HFP) and input (HID)
         // profiles are untouched, so headphones, keyboards and mice keep working.
         char selfPath[MAX_PATH] = {0};
         GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
         std::string dbg = std::string("\"") + selfPath + "\" --blocked-launch";
         SetIFEODebugger("fsquirt.exe", dbg, enforce && blockBt);

         // Wi-Fi Direct / Nearby Sharing -- disable the Connected Devices Platform
         // policy the feature relies on.
         SetPolicyDword("SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                        "EnableCdp", 0, enforce && blockNearby);
     }

     // Same directory-resolution rule as PolicyCachePath() above -- must be
     // somewhere a STANDARD USER can write (this process's real privilege
     // level), since a directory only SYSTEM can write to would just move
     // the same ACCESS_DENIED problem one step earlier.
     std::string WirelessStateCachePath() const {
         const char* envLogDir = std::getenv("SECEOKNIGHT_LOG_DIR");
         std::string dir = envLogDir ? envLogDir : "C:\\ProgramData\\SeceoKnight\\logs";
         try { fs::create_directories(dir); } catch (...) {}
         return dir + "\\wireless_state.cache";
     }

     // Writes the desired enforcement state for the elevated
     // --apply-wireless-guard one-shot (task #147) to pick up. Deliberately
     // simple pipe-delimited format (not JSON) -- the elevated reader is a
     // minimal standalone function that shouldn't need a JSON parser for
     // three booleans. Written on EVERY successful policy fetch (not just
     // on a signature change) so the elevated task's periodic wake-up --
     // running on its own independent schedule -- always sees the latest
     // known state regardless of exact timing between the two processes.
     void SaveWirelessStateToCache(bool enforce, bool blockBt, bool blockNearby) {
         try {
             std::ofstream f(WirelessStateCachePath(), std::ios::trunc | std::ios::binary);
             if (!f.is_open()) {
                 logger.Warning("Could not write wireless state cache: " + WirelessStateCachePath());
                 return;
             }
             f << (enforce ? "1" : "0") << "|" << (blockBt ? "1" : "0") << "|" << (blockNearby ? "1" : "0");
         } catch (const std::exception& e) {
             logger.Warning(std::string("Failed to cache wireless state: ") + e.what());
         } catch (...) {
             logger.Warning("Failed to cache wireless state");
         }
     }

     // Pulls GET /agents/{id}/wireless-policy and reconciles enforcement each
     // sync. Ported from CyberSentinel-DLP.
     //
     // NOTE (task #147): does NOT call ApplyWirelessControls() from here
     // anymore -- confirmed live this process cannot write the IFEO key
     // (same unelevated-process problem as task #145's CLI Guard). Instead
     // writes the desired state to WirelessStateCachePath() on every
     // successful fetch; a separate SYSTEM/Highest scheduled task
     // ("SeceoKnight DLP Wireless Guard", registered by install-agent.ps1)
     // runs `seceoknight_agent.exe --apply-wireless-guard` on a repeating
     // timer, reads that cache, and does the actual registry write. Still
     // tracks lastWirelessSig purely for the log-noise-reduction purpose it
     // always had (only worth a DEBUG line when something changed).
     void FetchWirelessPolicy() {
         try {
             std::pair<int, std::string> resp = GetHttpClient()->Get(
                 "/agents/" + config.agentId + "/wireless-policy");
             auto& [status, response] = resp;
             if (status != 200) return;   // keep last-known-good on error/outage

             bool enforced    = ExtractJsonBool(response, "enforced");
             std::string mode = ToLower(config.ExtractJsonValue(response, "mode"));
             bool blockBt      = ExtractJsonBool(response, "block_bluetooth_file_transfer");
             bool blockNearby  = ExtractJsonBool(response, "block_nearby_sharing");
             bool enforce      = enforced && mode == "enforce";   // audit => don't apply

             SaveWirelessStateToCache(enforce, blockBt, blockNearby);

             std::string sig = std::string(enforce ? "1" : "0") +
                               (blockBt ? "b" : "-") + (blockNearby ? "n" : "-");
             if (sig != lastWirelessSig) {
                 logger.Info("Wireless control state changed -- cached for the elevated "
                             "Wireless Guard task to apply (enforce=" +
                             std::string(enforce ? "true" : "false") + " bt=" +
                             std::string(blockBt ? "block" : "allow") + " nearby=" +
                             std::string(blockNearby ? "block" : "allow") + ")");
                 lastWirelessSig = sig;
             }
             logger.Debug("Wireless control: enforced=" + std::string(enforced ? "true" : "false") +
                         " mode=" + (mode.empty() ? "off" : mode) +
                         " bt_file_transfer=" + std::string(blockBt ? "block" : "allow") +
                         " nearby_sharing=" + std::string(blockNearby ? "block" : "allow"));
         } catch (const std::exception& e) {
             logger.Debug(std::string("FetchWirelessPolicy failed: ") + e.what());
         } catch (...) {
             logger.Debug("FetchWirelessPolicy failed");
         }
     }

     // Same directory-resolution rule as WirelessStateCachePath() above --
     // must be somewhere a STANDARD USER can write.
     std::string BrowserExtensionStateCachePath() const {
         const char* envLogDir = std::getenv("SECEOKNIGHT_LOG_DIR");
         std::string dir = envLogDir ? envLogDir : "C:\\ProgramData\\SeceoKnight\\logs";
         try { fs::create_directories(dir); } catch (...) {}
         return dir + "\\browser_extension_state.cache";
     }

     // Pulls GET /extension/info and caches (extension_id, update feed URL,
     // agent id) for the elevated Browser Extension Guard one-shot to pick
     // up. Gap-scan of CyberSentinel-DLP (August 18, 2026): SeceoKnight's
     // browser extension was previously only documented as a manual
     // "Load unpacked" dev-mode install -- something an end user can switch
     // off in two clicks at chrome://extensions, and its id is derived from
     // the folder path so it differs on every endpoint. Force-installing via
     // enterprise policy (ExtensionInstallForcelist) fixes both, but that
     // needs a STABLE id from a packed, signed CRX -- see
     // scripts/pack-extension.py and server/app/api/v1/extension.py.
     //
     // Four-line cache (id / update URL / agent id / server URL), not
     // JSON -- same "no parser dependency for a handful of fields"
     // reasoning as SaveWirelessStateToCache(). Both halves (which extension, which
     // server) come from THIS agent's live config, so changing the server
     // in agent_config.json and restarting moves the force-install with it
     // on the next sync -- no separate installer step to remember.
     void FetchBrowserExtensionPolicy() {
         try {
             std::pair<int, std::string> resp = GetHttpClient()->Get("/extension/info");
             auto& [status, response] = resp;
             if (status == 404) {
                 // Nothing published on this server -- not an error, a
                 // deployment that doesn't use the browser extension is a
                 // perfectly normal deployment. Leave any existing cache
                 // alone rather than deleting it: if this is a transient
                 // misconfiguration, force-install should keep the last
                 // known-good extension rather than silently dropping it.
                 return;
             }
             if (status != 200) return;   // keep last-known on error/outage

             std::string extId = config.ExtractJsonValue(response, "extension_id");
             if (extId.size() != 32) {
                 logger.Debug("FetchBrowserExtensionPolicy: extension_id missing or malformed "
                              "in /extension/info response");
                 return;
             }

             std::string updateUrl = config.serverUrl;
             while (!updateUrl.empty() && updateUrl.back() == '/') updateUrl.pop_back();
             updateUrl += "/extension/update.xml";

             // The currently-published version -- see WriteExtensionMinimumVersion()
             // below for why this is cached and applied alongside the forcelist
             // entry (gap-scan of CyberSentinel-DLP, August 19, 2026: force-install
             // alone never makes an already-installed extension update itself).
             // Blank is fine -- it just means an older server build's /extension/info
             // response, and the guard skips the minimum-version write for that run.
             std::string version = config.ExtractJsonValue(response, "version");

             std::string sig = extId + "|" + config.serverUrl + "|" + config.agentId + "|" + version;
             bool changed = (sig != lastExtensionPolicySig);

             std::ofstream f(BrowserExtensionStateCachePath(), std::ios::trunc | std::ios::binary);
             if (!f.is_open()) {
                 logger.Warning("Could not write browser extension state cache: " +
                                BrowserExtensionStateCachePath());
                 return;
             }
             f << extId << "\n" << updateUrl << "\n" << config.agentId << "\n" << config.serverUrl << "\n" << version << "\n";
             f.close();

             if (changed) {
                 logger.Info("Browser extension policy changed -- cached for the elevated "
                             "Browser Extension Guard task to apply (id=" + extId +
                             " server=" + config.serverUrl + ")");
                 lastExtensionPolicySig = sig;
             }
         } catch (const std::exception& e) {
             logger.Debug(std::string("FetchBrowserExtensionPolicy failed: ") + e.what());
         } catch (...) {
             logger.Debug("FetchBrowserExtensionPolicy failed");
         }
     }

     // ── Printer device control + print content inspection ──────────────────
     // Ported from CyberSentinel-DLP.
     static std::string NormalizePrinter(const std::string& name) {
         return ToUpperStr(name);
     }

     // A printer is "network" if it's marked PRINTER_ATTRIBUTE_NETWORK or its
     // port name looks like a UNC path / IP / WSD / TCP port (covers printers
     // added without the network flag set, which happens more often than
     // you'd expect with third-party print drivers).
     bool IsNetworkPrinter(const std::string& printerName) {
         HANDLE hPrinter = NULL;
         if (!OpenPrinterA(const_cast<LPSTR>(printerName.c_str()), &hPrinter, NULL))
             return false;
         bool network = false;
         DWORD needed = 0;
         GetPrinterA(hPrinter, 2, NULL, 0, &needed);
         if (needed > 0) {
             std::vector<BYTE> buf(needed);
             if (GetPrinterA(hPrinter, 2, buf.data(), needed, &needed)) {
                 PRINTER_INFO_2A* pi = reinterpret_cast<PRINTER_INFO_2A*>(buf.data());
                 if (pi->Attributes & PRINTER_ATTRIBUTE_NETWORK) network = true;
                 std::string port = ToUpperStr(pi->pPortName ? pi->pPortName : "");
                 if (port.rfind("\\\\", 0) == 0 || port.find("IP_") != std::string::npos ||
                     port.find("WSD") != std::string::npos || port.find("TCP") != std::string::npos)
                     network = true;
             }
         }
         ClosePrinter(hPrinter);
         return network;
     }

     // Decision consumed by the PrintMonitor callback: should this printer's
     // job be blocked by the printer_control policy? In audit mode we log
     // "would block" but return false (don't cancel).
     bool ShouldBlockPrinter(const std::string& printerName) {
         if (!printerControlEnforced.load()) return false;
         std::string mode, scope;
         bool sanctioned = false;
         bool denied = false;
         {
             std::lock_guard<std::mutex> lock(printerPolicyMutex);
             mode = printerControlMode;
             scope = printerControlScope;
             std::string normalized = NormalizePrinter(printerName);
             sanctioned = sanctionedPrinters.count(normalized) > 0;
             denied = deniedPrinters.count(normalized) > 0;
         }
         // Explicit deny beats everything else and applies in EVERY scope
         // (ported from CyberSentinel commit b7dc3f3) -- checked before the
         // scope-based `matches` logic below, which only ever looks at
         // allow-decision rows and only in "allowlist" scope.
         bool matches = denied;
         if (!matches) {
             if (scope == "block_all")          matches = true;
             else if (scope == "block_network") matches = IsNetworkPrinter(printerName);
             else if (scope == "block_local")   matches = !IsNetworkPrinter(printerName);
             else if (scope == "allowlist")     matches = !sanctioned;   // block anything not sanctioned
         }
         if (!matches) return false;
         if (mode == "audit") {
             logger.Info("PRINT_DEVICE_AUDIT: would block printer " + printerName +
                         " (scope " + scope + (denied ? ", explicit deny" : "") + ")");
             return false;
         }
         return true;   // enforce
     }

     // Pulls GET /agents/{id}/printer-policy and caches it locally. Combined
     // device-control + content-inspection response (see the server endpoint's
     // own docstring for why they're one call). Mirrors FetchNetworkSharePolicy()
     // above: polled on the policy-sync cadence, own try/catch.
     void FetchPrinterPolicy() {
         try {
             std::pair<int, std::string> resp = GetHttpClient()->Get(
                 "/agents/" + config.agentId + "/printer-policy");
             auto& [status, response] = resp;
             if (status != 200) return;   // keep last-known-good on error/outage

             bool enforced = ExtractJsonBool(response, "enforced");
             std::string mode  = ToLower(config.ExtractJsonValue(response, "mode"));
             std::string scope = ToLower(config.ExtractJsonValue(response, "scope"));
             auto rawPrinters = ExtractJsonArray(response, "printers");
             std::set<std::string> printers;
             for (const auto& p : rawPrinters) printers.insert(NormalizePrinter(p));

             auto rawDenied = ExtractJsonArray(response, "denied_printers");
             std::set<std::string> denied;
             for (const auto& p : rawDenied) denied.insert(NormalizePrinter(p));

             bool contentInspection = ExtractJsonBool(response, "content_inspection");
             std::string contentMode = ToLower(config.ExtractJsonValue(response, "content_mode"));
             std::string unknownContentAction = ToLower(config.ExtractJsonValue(response, "unknown_content_action"));
             if (unknownContentAction != "block") unknownContentAction = "allow";   // safe default on missing/garbled field
             std::string contentSeverity = ToLower(config.ExtractJsonValue(response, "content_severity"));
             if (contentSeverity != "low" && contentSeverity != "medium" &&
                 contentSeverity != "high" && contentSeverity != "critical" && contentSeverity != "info") {
                 contentSeverity = "high";   // safe default on missing/garbled field, matches prior hardcoded value
             }

             {
                 std::lock_guard<std::mutex> lock(printerPolicyMutex);
                 printerControlMode = mode;
                 printerControlScope = scope;
                 sanctionedPrinters = printers;
                 deniedPrinters = denied;
                 printContentMode = contentMode;
                 printUnknownContentAction = unknownContentAction;
                 printContentSeverity = contentSeverity;
             }
             printerControlEnforced.store(enforced);
             printContentInspection.store(contentInspection);
             // CONFIRMED LIVE need: this line previously omitted
             // content_mode and unknown_content_action entirely, so there
             // was no way to directly confirm what the agent actually
             // cached for the new fail-closed setting versus guessing from
             // downstream behavior. Added while live-diagnosing exactly
             // that ambiguity.
             logger.Debug("Printer control: enforced=" + std::string(enforced ? "true" : "false") +
                         " mode=" + (mode.empty() ? "off" : mode) +
                         " scope=" + (scope.empty() ? "none" : scope) +
                         " allowed=" + std::to_string(printers.size()) +
                         " denied=" + std::to_string(denied.size()) +
                         " content_inspection=" + std::string(contentInspection ? "true" : "false") +
                         " content_mode=" + (contentMode.empty() ? "off" : contentMode) +
                         " unknown_content_action=" + unknownContentAction +
                         " content_severity=" + contentSeverity);
         } catch (const std::exception& e) {
             logger.Debug(std::string("FetchPrinterPolicy failed: ") + e.what());
         } catch (...) {
             logger.Debug("FetchPrinterPolicy failed");
         }
     }

     // ── Print CONTENT inspection (real spooled-document content) ───────────
     static std::string ReadFileBytesAllForPrint(const std::string& path) {
         std::ifstream f(path, std::ios::binary);
         if (!f) return "";
         return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
     }

     // Newest *.SPL in the spool dir (fallback when the job-id-based filename
     // guesses below don't match -- e.g. a non-default print processor).
     std::string NewestSpoolFile(const std::string& dir) {
         WIN32_FIND_DATAA fd;
         HANDLE h = FindFirstFileA((dir + "*.SPL").c_str(), &fd);
         if (h == INVALID_HANDLE_VALUE) {
             // DIAGNOSTIC: distinguish "directory has no matching files right
             // now" (ERROR_FILE_NOT_FOUND -- benign, can happen between
             // polls) from "can't even list the directory"
             // (ERROR_ACCESS_DENIED -- the real, confirmed-live root cause:
             // this agent process runs unelevated by design, see Step 9c in
             // install-agent.ps1, and the spool directory's default ACL
             // doesn't grant regular users read access).
             DWORD err = GetLastError();
             logger.Debug("PRINT_SPOOL_DIR: FindFirstFileA(" + dir +
                 "*.SPL) failed, GetLastError=" + std::to_string(err) +
                 (err == ERROR_ACCESS_DENIED ?
                     " (ACCESS DENIED -- run install-agent.ps1's Step 9c, or "
                     "manually: icacls \"" + dir + "\" /grant \"%USERNAME%:(OI)(CI)RX\")" :
                     ""));
             return "";
         }
         std::string best;
         FILETIME bestT{0, 0};
         do {
             if (CompareFileTime(&fd.ftLastWriteTime, &bestT) > 0) {
                 bestT = fd.ftLastWriteTime;
                 best = dir + fd.cFileName;
             }
         } while (FindNextFileA(h, &fd));
         FindClose(h);
         return best;
     }

     // Resolve the spooled document's actual file path for this job. Tries
     // GetPrintSpoolFilePath()'s "FP<jobid>.SPL" convention first (already
     // used by the existing per-job hash callback below), then the plain
     // "<jobid>.SPL" convention CyberSentinel-DLP uses, then falls back to
     // the newest *.SPL in the spool directory -- covers both naming schemes
     // observed across different Windows print-processor configurations
     // instead of betting on just one.
     std::string ResolveSpoolFilePath(int jobId) {
         std::string path = GetPrintSpoolFilePath(jobId);
         if (!path.empty()) return path;

         char sysdir[MAX_PATH] = {0};
         GetSystemDirectoryA(sysdir, MAX_PATH);
         std::string dir = std::string(sysdir) + "\\spool\\PRINTERS\\";
         char name[32];
         snprintf(name, sizeof(name), "%05d.SPL", jobId);
         std::string plain = dir + name;
         if (fs::exists(plain)) return plain;

         return NewestSpoolFile(dir);
     }

     // Best-effort text extraction from raw spool bytes: pull ASCII runs AND
     // UTF-16LE runs (EMF ExtTextOutW stores document text as UTF-16). Works
     // across EMF/RAW/PS/PCL to varying degrees -- enough to feed the
     // classifier. Ported from CyberSentinel-DLP.
     static std::string ExtractSpoolStrings(const std::string& data) {
         std::string out, run;
         for (unsigned char c : data) {
             if (c >= 0x20 && c < 0x7f) run += (char)c;
             else { if (run.size() >= 4) { out += run; out += ' '; } run.clear(); }
         }
         if (run.size() >= 4) { out += run; out += ' '; }
         run.clear();
         for (size_t i = 0; i + 1 < data.size(); i += 2) {
             unsigned char lo = (unsigned char)data[i], hi = (unsigned char)data[i + 1];
             if (hi == 0 && lo >= 0x20 && lo < 0x7f) run += (char)lo;
             else { if (run.size() >= 4) { out += run; out += ' '; } run.clear(); }
         }
         if (run.size() >= 4) { out += run; out += ' '; }
         return out;
     }

     // Real text of the spooled document for this job -- replaces the old
     // filename-keyword-only classifier with the actual content sent to the
     // printer. Stashes the document's SHA-256 (via the existing
     // CalculateFileHash(), not a new hash implementation) for the print
     // event to log; the content-inspection path already resolved the path,
     // so this avoids a second directory scan when the event callback runs.
     std::string ReadSpoolText(int jobId) {
         std::string path = ResolveSpoolFilePath(jobId);
         // DIAGNOSTIC (temporary): the last several live print tests all
         // extracted exactly the same character count (24) regardless of
         // which app printed or what the document content was -- that's
         // only possible if either (a) the real per-job content is opaque
         // to ExtractSpoolStrings and all that's left is constant driver
         // boilerplate, or (b) this is resolving to the same wrong/stale
         // file every time instead of each job's real spool data. Logging
         // the resolved path + byte count makes that distinguishable: if
         // the path is identical across different jobs, that's (b).
         if (path.empty()) {
             logger.Debug("PRINT_SPOOL_PATH: job " + std::to_string(jobId) +
                 " -- no spool file resolved (FP-prefix, plain, and newest-in-dir all missed)");
             return "";
         }
         std::string bytes = ReadFileBytesAllForPrint(path);
         logger.Debug("PRINT_SPOOL_PATH: job " + std::to_string(jobId) + " -> " +
             path + " (" + std::to_string(bytes.size()) + " bytes on disk)");
         if (bytes.empty()) return "";
         lastSpoolHash.jobId = jobId;
         try { lastSpoolHash.sha256 = CalculateFileHash(path); } catch (...) {}

         // CONFIRMED LIVE: some applications (observed with Microsoft Word)
         // print through Windows' XPS-based pipeline rather than the older
         // EMF/RAW path -- the spool file is then a ZIP/OPC container (XPS
         // page content lives inside DEFLATE-compressed XML, as <Glyphs
         // UnicodeString="..."> runs), not a stream with plain ASCII/UTF-16
         // text runs sitting directly in the raw bytes the way EMF/RAW/PS/
         // PCL do. ExtractSpoolStrings() below can't see into a compressed
         // ZIP entry, so it silently returns ~nothing for these jobs --
         // and worse, jobs.pDocument for this pipeline is often the generic
         // literal string "Local Downlevel Document", not the real
         // filename, so even the docName fallback in EvaluatePrintContent()
         // is uninformative. Net effect without this check: a genuinely
         // sensitive Word document printed through this pipeline gets
         // silently classified Public/low with zero visibility that
         // inspection never actually happened.
         //
         // Properly parsing XPS content would mean shipping a ZIP/DEFLATE
         // decompressor into this agent -- real memory-unsafe binary-parsing
         // territory that needs a compiler and test harness to verify
         // safely, neither of which was available while making this fix.
         // Rather than guess at that blind, this at least makes the gap
         // LOUD instead of silent: detect the ZIP local-file-header magic
         // bytes ("PK\x03\x04") and log clearly when hit, so it's
         // immediately diagnosable (not a multi-round mystery) instead of
         // looking identical to a genuinely clean, low-risk print job.
         if (bytes.size() >= 4 && bytes[0] == 'P' && bytes[1] == 'K' &&
             (unsigned char)bytes[2] == 0x03 && (unsigned char)bytes[3] == 0x04) {
             logger.Warning("Print job spool file is a ZIP/XPS container (job " +
                 std::to_string(jobId) + ") -- content text extraction is not "
                 "implemented for this format, so this job's classification "
                 "cannot be trusted. Known trigger: printing from Word (and "
                 "other apps using Windows' XPS print pipeline) to a driver "
                 "that routes through the XPS-to-downlevel conversion path.");
         }

         return ExtractSpoolStrings(bytes);
     }

     // Callback for PrintMonitor: inspect the spooled document via the same
     // real-time /policy/evaluate endpoint the USB and network-share
     // content-aware paths already use, and return the block decision PLUS
     // an honest status of whether real content was actually read. Only
     // runs when a print_content_prevention policy is active. Fail-open
     // (allow) on any error so printing is never bricked by a DLP server
     // outage -- but "allow" and "we couldn't verify" must never look the
     // same to an admin; see PrintMonitor::PrintContentResult.
     // Ported from CyberSentinel-DLP, extended with the inspected/status
     // distinction after a real production investigation found this
     // silently returning "allow" on jobs it had never actually been able
     // to read (confirmed live: a real SHARP AR-6020N MFP where no spool
     // file was ever observable on disk under this agent's normal,
     // unelevated, correctly-ACL'd operating conditions -- root cause
     // undetermined after exhausting every remotely-diagnosable
     // possibility; see CHANGELOG for the full investigation).
     PrintMonitor::PrintContentResult EvaluatePrintContent(const std::string& printerName, int jobId, const std::string& docName) {
         if (!printContentInspection.load()) return {false, "unavailable"};
         std::string text = ReadSpoolText(jobId);
         bool realContentRead = !text.empty();
         if (text.size() < 20) text = docName;   // fall back to the document name

         // DIAGNOSTIC (temporary, pairs with the PRINT_SPOOL_PATH log in
         // ReadSpoolText): show the actual bytes that ended up feeding the
         // classifier. Recognizable driver/PJL boilerplate (e.g. "PJL",
         // "SHARP", resolution/paper strings) here would confirm the real
         // page content is opaque to this scanner; garbled/binary-looking
         // output would instead point at a wrong-file resolution bug.
         logger.Debug("PRINT_SPOOL_TEXT: job " + std::to_string(jobId) +
             " extracted=[" + text.substr(0, 300) + "]");

         JsonBuilder j;
         j.AddString("file_name", docName);
         j.AddString("file_content", text.substr(0, 200000));
         j.AddString("event_type", "print");
         j.AddString("destination_type", "printer");
         j.AddString("destination_path", printerName);
         // Honest signal to the server (additive field -- safe even before
         // any server-side code reads it) distinguishing a verified read
         // from the filename-only fallback above.
         j.AddBool("content_inspected", realContentRead);
         // Send the spooled document's hash so the server's file-hash denylist
         // rule can match (the print channel sends extracted text, not raw
         // bytes, so the server can't compute this itself).
         if (lastSpoolHash.jobId == jobId && !lastSpoolHash.sha256.empty()) {
             j.AddString("file_hash", lastSpoolHash.sha256);
         }

         std::string inspectionStatus = realContentRead ? "inspected" : "unavailable";

         std::pair<int, std::string> resp = GetHttpClient()->Post(
             "/agents/" + config.agentId + "/policy/evaluate", j.Build());
         auto& [status, response] = resp;
         if (status != 200) {
             logger.Warning("Print content evaluate HTTP " + std::to_string(status) + " -- allowing");
             return {false, "unavailable"};   // couldn't even complete the check
         }

         bool block = config.ExtractJsonValue(response, "action") == "block";
         std::string cmode;
         std::string ucAction;
         {
             std::lock_guard<std::mutex> lock(printerPolicyMutex);
             cmode = printContentMode;
             ucAction = printUnknownContentAction;
         }
         // Enterprise-grade fail-closed option (CONFIRMED LIVE need -- see
         // this function's class comment). When content genuinely couldn't
         // be read, the server verdict above was necessarily computed from
         // the docName fallback, not real document text -- effectively "we
         // don't know, not verified-clean". Default (ucAction=="allow")
         // preserves today's behavior exactly. An admin running a stricter
         // posture can flip this so an unverifiable job is treated as a
         // precautionary block instead of a silent pass -- matching
         // CyberSentinel's own stated principle for file extraction
         // ("content we could not fully inspect must never be treated as
         // clean") applied to the print channel. Deliberately scoped to
         // "content unreadable locally" only, NOT server-unreachable
         // (status != 200 above) -- that's governed separately from
         // wherever the general DLP-server-outage fail-open policy lives,
         // and conflating the two would make this setting mean two very
         // different things at once.
         if (!realContentRead && ucAction == "block" && !block) {
             block = true;
             logger.Warning("PRINT_CONTENT_UNKNOWN_BLOCKED: " + docName + " on " + printerName +
                 " -- content could not be verified and unknownContentAction=block is configured; "
                 "blocking as a precaution rather than passing unverified content.");
         }
         if (block && cmode == "audit") {
             logger.Info("PRINT_CONTENT_AUDIT: would block " + docName +
                         " -- sensitive content (" + std::to_string(text.size()) + " chars)");
             return {false, inspectionStatus};   // audit: log, don't cancel
         }
         logger.Info("Print content inspection: " + docName + " -> " +
                     (block ? "BLOCK" : "allow") + " (" + std::to_string(text.size()) + " chars, " +
                     inspectionStatus + ")");
         return {block, inspectionStatus};
     }

     // Same directory-resolution rule as Logger (SECEOKNIGHT_LOG_DIR env var,
     // default C:\ProgramData\SeceoKnight\logs) -- NOT exe-relative. The agent
     // runs as a non-admin user out of C:\Program Files\SeceoKnight, which a
     // standard user can't write into (see the Logger default-path fix); the
     // policy cache would silently fail to write in the exact same way if it
     // used a different, exe-relative rule instead of reusing this one.
     std::string PolicyCachePath() const {
         const char* envLogDir = std::getenv("SECEOKNIGHT_LOG_DIR");
         std::string dir = envLogDir ? envLogDir : "C:\\ProgramData\\SeceoKnight\\logs";
         try {
             fs::create_directories(dir);
         } catch (...) {
             // OpenLogFile()/the write below will surface the failure.
         }
         return dir + "\\seceoknight_policies.cache";
     }

     void SavePolicyBundleToCache(const std::string& bundleJson) {
         try {
             std::ofstream f(PolicyCachePath(), std::ios::trunc | std::ios::binary);
             if (!f.is_open()) {
                 logger.Warning("Could not write policy cache: " + PolicyCachePath());
                 return;
             }
             f << bundleJson;
             logger.Debug("Policy bundle cached to " + PolicyCachePath());
         } catch (const std::exception& e) {
             logger.Warning(std::string("Failed to cache policy bundle: ") + e.what());
         } catch (...) {
             logger.Warning("Failed to cache policy bundle");
         }
     }

     // Load the last bundle the server gave us, so the agent starts enforcing
     // BEFORE (or without) a successful sync. See the comment on the call site
     // in Start() for the full rationale (task #95/#107).
     //
     // The server already versions bundles (activePolicyVersion -> "up_to_date"
     // on the next sync), so a cached bundle costs one comparison on the next
     // sync and is replaced the moment the server answers.
     void LoadCachedPolicyBundle() {
         try {
             const std::string path = PolicyCachePath();
             std::error_code ec;
             if (!fs::exists(path, ec) || ec) {
                 logger.Info("No cached policy bundle (first run?) — the agent cannot "
                             "enforce until it reaches the server at least once");
                 return;
             }
             std::ifstream f(path, std::ios::binary);
             if (!f.is_open()) return;
             std::string bundle((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
             if (bundle.empty()) return;

             logger.Info("Loading cached policy bundle from " + path);
             ApplyPolicyBundle(bundle);
             if (allowEvents) {
                 logger.Info("Enforcing CACHED policies until the server confirms a newer bundle");
             } else {
                 logger.Warning("Cached policy bundle contained no active policies");
             }
         } catch (const std::exception& e) {
             logger.Warning(std::string("Could not load cached policy bundle: ") + e.what());
         } catch (...) {
             logger.Warning("Could not load cached policy bundle");
         }
     }

     // Pulls GET /agents/{id}/usb-allowlist and caches it locally. See the
     // usbAllowlistEnforced/usbAllowlistMode/sanctionedUsbSerials members and
     // HandleUsbDeviceArrival() below, which is where this is actually
     // enforced — deliberately no per-connect server round trip, so a brief
     // network blip can't leave a USB port unprotected or, worse, stuck open
     // waiting on a stalled HTTP call in the same thread that pumps Windows
     // device-arrival messages.
     void SyncUsbAllowlist() {
         try {
             std::pair<int, std::string> resp = GetHttpClient()->Get(
                 "/agents/" + config.agentId + "/usb-allowlist"
             );
             auto& [status, response] = resp;

             if (status != 200) {
                 if (status == 0) {
                     logger.Debug("Cannot reach server for USB allowlist sync");
                 } else {
                     logger.Debug("USB allowlist sync failed: HTTP " + std::to_string(status));
                 }
                 return; // Keep the last-known-good allowlist rather than clearing it.
             }

             bool enforced = ExtractJsonBool(response, "enforced");
             std::string mode = config.ExtractJsonValue(response, "mode");
             if (mode.empty()) mode = "off";
             std::vector<std::string> serials = ExtractJsonArray(response, "serials");

             // Was this allowlist actually capable of blocking BEFORE this
             // sync? Needed below to detect "enforcement just turned off" so
             // we can restore USB access — mirrors ApplyPolicyBundle()'s own
             // previousUsbBlocking/newUsbBlocking restore logic for the
             // separate usb_device_monitoring policy path.
             bool wasBlocking = usbAllowlistEnforced.load() && usbAllowlistMode == "enforce";
             bool nowBlocking = enforced && mode == "enforce";

             {
                 std::lock_guard<std::mutex> lock(usbAllowlistMutex);
                 sanctionedUsbSerials.clear();
                 for (const auto& s : serials) {
                     sanctionedUsbSerials.insert(NormalizeUsbSerial(s));
                 }
                 usbAllowlistMode = mode;
             }
             usbAllowlistEnforced.store(enforced);

             // If the allowlist was the ONLY thing keeping USB storage
             // blocked (no separate usb_device_monitoring block policy is
             // active) and it just got turned off/switched to audit mode,
             // restore access — otherwise a device blocked purely by the
             // allowlist would stay blocked forever with no code path to
             // undo it, since BlockUSBStorageViaRegistry()/
             // DisableAllUSBStorageDevices() act globally, not per-serial.
             if (wasBlocking && !nowBlocking && !usbBlockingActive.load()) {
                 logger.Warning("USB allowlist enforcement turned off/switched to audit — restoring USB access");
                 EnableAllUSBStorageDevices();
                 BlockUSBStorageViaRegistry(false);
             }

             logger.Info("USB allowlist synced: enforced=" + std::string(enforced ? "true" : "false") +
                         " mode=" + mode + " sanctioned_count=" + std::to_string(serials.size()));
         } catch (const std::exception& e) {
             logger.Error(std::string("Failed to sync USB allowlist: ") + e.what());
         } catch (...) {
             logger.Error("Unknown error syncing USB allowlist");
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

// usbBlockingActive starts false on every process launch, but
// install-agent.ps1 registers an unconditional boot-time scheduled task
// ("SeceoKnight DLP USB Block") that disables the USBSTOR registry key
// BEFORE this agent process even starts -- regardless of what policy
// actually says. Without this seeding, the very first policy-sync pass
// after a cold boot always believes "previously not blocking", so if the
// current policy says USB should be ALLOWED, the restore-to-allowed path
// never fires and the registry is left disabled indefinitely. Seed the
// in-memory tracker from actual registry state once per process so the
// first pass can correctly detect a needed restore. Found in a
// policy-engine audit, August 28 2026.
static bool usbBlockingSeededFromRegistry = false;
if (!usbBlockingSeededFromRegistry) {
    usbBlockingActive.store(IsUSBStorageBlockedInRegistry());
    usbBlockingSeededFromRegistry = true;
}
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
                    
                }

                // Extract monitoredPaths for ALL policy types (file_system_monitoring, usb_file_transfer_monitoring, etc.)
                rule.monitoredPaths = ExtractJsonArray(configObj, "monitoredPaths");

                // file_transfer_monitoring's config never had a "monitoredPaths"
                // key at all -- the dashboard form (FileTransferPolicyForm.tsx)
                // and FileTransferConfig write "protectedPaths" (source paths to
                // watch) and "monitoredDestinations" (where a transfer TO is
                // watched) instead. The Linux agent already reads the right key
                // (agent.py's transfer_protected_paths, key="protectedPaths").
                // This Windows agent read the wrong key for this one policy
                // type only, so rule.monitoredPaths was ALWAYS empty for it --
                // ShouldMonitorFile()/HandleFileEvent() require a non-empty
                // match against monitoredPaths, so file_transfer_monitoring
                // silently never enforced anything on Windows, ever, on any
                // path. Found in a policy-engine audit, August 28 2026.
                // (monitoredDestinations / destination-specific matching isn't
                // wired into PolicyRule at all yet -- that's a separate,
                // larger gap; this restores the baseline "does this policy
                // ever fire" behavior that Linux already had.)
                if (policyType == "file_transfer_monitoring") {
                    std::vector<std::string> protectedPaths = ExtractJsonArray(configObj, "protectedPaths");
                    rule.monitoredPaths.insert(rule.monitoredPaths.end(),
                                                protectedPaths.begin(), protectedPaths.end());
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

                            // patterns.custom is an array of OBJECTS
                            // ({"regex": "...", "description": "..."}),
                            // not plain strings — needs the object-aware
                            // parser, not ExtractJsonArray().
                            std::vector<std::string> custom = ExtractJsonObjectArrayField(patternsObj, "custom", "regex");
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

     // Parses an array of JSON objects — e.g. patterns.custom =
     // [{"regex":"...","description":"..."}] — and returns the string
     // value of fieldName from each object. ExtractJsonArray() below only
     // understands arrays of plain quoted strings; an array of objects
     // (each element starting with '{') was silently skipped by it, which
     // meant custom regex patterns configured via the Clipboard/File
     // System policy forms never actually reached rule.dataTypes at all.
     //
     // Uses its own string-literal-aware brace counter rather than the
     // shared FindMatchingBracket helper, because custom regex text
     // commonly contains literal '{'/'}' characters (e.g. \d{4}
     // quantifiers) which would otherwise miscount object boundaries.
     std::vector<std::string> ExtractJsonObjectArrayField(const std::string& json,
                                                           const std::string& arrayKey,
                                                           const std::string& fieldName) {
         std::vector<std::string> result;
         size_t keyPos = json.find("\"" + arrayKey + "\"");
         if (keyPos == std::string::npos) return result;

         size_t colonPos = json.find(":", keyPos);
         if (colonPos == std::string::npos) return result;

         size_t pos = colonPos + 1;
         while (pos < json.length() && std::isspace(json[pos])) pos++;
         if (pos >= json.length() || json[pos] != '[') return result;

         size_t arrayStart = pos;
         int depth = 0;
         bool inStr = false;
         bool esc = false;
         size_t arrayEnd = std::string::npos;
         for (size_t i = arrayStart; i < json.length(); i++) {
             char c = json[i];
             if (inStr) {
                 if (esc) { esc = false; }
                 else if (c == '\\') { esc = true; }
                 else if (c == '"') { inStr = false; }
                 continue;
             }
             if (c == '"') { inStr = true; continue; }
             if (c == '[') depth++;
             else if (c == ']') { depth--; if (depth == 0) { arrayEnd = i; break; } }
         }
         if (arrayEnd == std::string::npos) return result;

         size_t i = arrayStart + 1;
         while (i < arrayEnd) {
             while (i < arrayEnd && (std::isspace(json[i]) || json[i] == ',')) i++;
             if (i >= arrayEnd || json[i] != '{') break;

             int objDepth = 0;
             bool objInStr = false;
             bool objEsc = false;
             size_t objStart = i;
             size_t objEnd = std::string::npos;
             for (size_t j = objStart; j < arrayEnd; j++) {
                 char c = json[j];
                 if (objInStr) {
                     if (objEsc) { objEsc = false; }
                     else if (c == '\\') { objEsc = true; }
                     else if (c == '"') { objInStr = false; }
                     continue;
                 }
                 if (c == '"') { objInStr = true; continue; }
                 if (c == '{') objDepth++;
                 else if (c == '}') { objDepth--; if (objDepth == 0) { objEnd = j; break; } }
             }
             if (objEnd == std::string::npos) break;

             std::string obj = json.substr(objStart, objEnd - objStart + 1);
             std::string value = ExtractJsonString(obj, fieldName);
             if (!value.empty()) result.push_back(value);

             i = objEnd + 1;
         }
         return result;
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
        int consecutiveFailures = 0;
        int heartbeatCount = 0;
        while (running) {
            // SendHeartbeat() used to be void and swallowed every failure
            // internally (network error, non-200 status, exception) without
            // ever rethrowing — which meant this loop's own try/catch could
            // never observe a failed heartbeat, consecutiveFailures could
            // never rise above 0, and the "reinitialize a stale HTTP client"
            // recovery below was permanently unreachable dead code. That's
            // exactly the scenario its own comment describes handling —
            // stale WinHTTP sessions after sleep/wake or a lock/unlock cycle
            // — so an agent whose connection went stale after unlocking (or
            // any other network blip) would keep silently "sending"
            // heartbeats forever with no real chance of ever reconnecting,
            // showing Disconnected on the dashboard until the process was
            // fully restarted. SendHeartbeat() now returns whether it
            // actually succeeded, so this loop can track real failures.
            bool heartbeatOk = false;
            try {
                heartbeatOk = SendHeartbeat();
            } catch (...) {
                heartbeatOk = false;
            }

            if (heartbeatOk) {
                consecutiveFailures = 0;
                heartbeatCount++;

                // A successful heartbeat is the "server is reachable again"
                // signal -- the same one CyberSentinel-DLP replays its spool
                // on. Cheap no-op when nothing is spooled (SpoolFilePath()
                // won't exist).
                try {
                    FlushSpooledEvents();
                } catch (...) {
                    // FlushSpooledEvents() already catches internally; this
                    // is belt-and-suspenders so a flush issue never takes
                    // down the heartbeat loop itself.
                }

                /* Log evaluation performance stats every 10 heartbeats
                 * (~5 min at default 30s interval).
                 * This proves the sub-10ms local evaluation guarantee. */
                if (heartbeatCount % 10 == 0 && kernelClient_) {
                    auto stats = kernelPolicyEngine_.GetEvalStats();
                    if (stats.count > 0) {
                        logger.Info("=== Policy Evaluation Stats ===");
                        logger.Info("  Evaluations : " + std::to_string(stats.count));
                        logger.Info("  Avg latency : " + std::to_string(stats.avgMs).substr(0,5) + " ms");
                        logger.Info("  Peak latency: " + std::to_string(stats.maxMs).substr(0,5) + " ms");
                        logger.Info(std::string("  Sub-10ms    : ") + (stats.within10ms ? "YES ✓" : "NO — investigate"));
                        logger.Info("===============================");
                    }
                }
            } else {
                consecutiveFailures++;
                logger.Error("Heartbeat error (consecutive failures: " + std::to_string(consecutiveFailures) + ")");
            }

            // After 3 consecutive failures, re-initialize the HTTP client.
            // This handles stale WinHTTP sessions after network drops, sleep/wake,
            // or IP address changes — all of which invalidate open connections.
            //
            // This reinitializes heartbeatHttpClient specifically, NOT the
            // shared httpClient used by every other caller (browser-dialog
            // handlers, USB monitor, event submission, etc.) -- swapping
            // that one out from under unrelated in-flight callers here would
            // be its own bug. heartbeatHttpClient is exclusively owned by
            // this thread, so no mutex is needed to reassign it.
            if (consecutiveFailures >= 3) {
                logger.Warning("3 consecutive heartbeat failures - reinitializing heartbeat HTTP client");
                try {
                    heartbeatHttpClient = std::make_shared<HttpClient>(config.serverUrl);
                    consecutiveFailures = 0;
                    logger.Info("Heartbeat HTTP client reinitialized - will retry heartbeat");
                } catch (...) {
                    logger.Error("Failed to reinitialize heartbeat HTTP client - will retry next cycle");
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(config.heartbeatInterval));
        }
     }
     
     // Returns true only on a genuine HTTP 200 from the server. Every other
     // outcome (unreachable, non-200 status, a thrown exception) returns
     // false instead of just logging and returning — see the comment in
     // HeartbeatLoop() for why that distinction is the whole point: the
     // loop's stale-connection recovery can only trigger if failures are
     // actually visible to it.
     bool SendHeartbeat() {
         try {
             JsonBuilder json;
             json.AddString("timestamp", GetCurrentTimestampISO());
             json.AddString("ip_address", GetRealIPAddress());
             // Refreshed every heartbeat (not just at registration) so a
             // shared workstation or RDP handoff shows the currently
             // logged-in user rather than whoever was logged in when the
             // agent last (re)started.
             json.AddString("username", GetUsername());
             json.AddString("os_version", GetOSVersion());
             json.AddString("version", AGENT_VERSION);
             if (!activePolicyVersion.empty()) {
                 json.AddString("policy_version", activePolicyVersion);
             }

             // Deliberately NOT GetHttpClient() -- see heartbeatHttpClient's
             // declaration for why the heartbeat must never share a
             // requestMutex with the rest of the agent's HTTP traffic.
             std::pair<int, std::string> hb = heartbeatHttpClient->Put(
                 "/agents/" + config.agentId + "/heartbeat",
                 json.Build()
             );
             auto& [status, response] = hb;

             if (status == 200) {
                 logger.Debug("Heartbeat sent successfully");
                 return true;
             } else if (status == 0) {
                 logger.Debug("Cannot reach server for heartbeat");
                 return false;
             } else {
                 logger.Debug("Heartbeat response: HTTP " + std::to_string(status));
                 return false;
             }
         } catch (const std::exception& e) {
             logger.Debug(std::string("Heartbeat failed: ") + e.what());
             return false;
         } catch (...) {
             logger.Debug("Heartbeat error");
             return false;
         }
     }
     
     /* ── Auto-Update Loop ────────────────────────────────────────────────────
      *
      * Every 5 minutes:
      *   1. Fetch SHA-256 sidecar from GitHub (tiny text file, ~66 bytes)
      *   2. Compute SHA-256 of the currently running binary
      *   3. If they differ → new version available:
      *        a. Download new binary to TEMP folder
      *        b. Verify its SHA-256 matches what GitHub said
      *        c. Write a .bat updater script that replaces the binary and
      *           restarts the scheduled task after the current process exits
      *        d. Launch the .bat detached and exit — the scheduled task
      *           watchdog brings up the new version automatically
      *
      * Fail-open: any error (no internet, bad hash, disk full) is logged
      * and silently skipped — the agent keeps running on the current version.
      * ─────────────────────────────────────────────────────────────────────── */
     void AutoUpdateLoop() {
         static const std::string SHA256_URL =
             "https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/"
             "main/agents/endpoint/windows/seceoknight_agent.exe.sha256";
         static const std::string EXE_URL =
             "https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/"
             "main/agents/endpoint/windows/seceoknight_agent.exe";
         static const int CHECK_INTERVAL_SEC = 300; /* 5 minutes */

         /* Stagger first check by 60s so startup completes first */
         std::this_thread::sleep_for(std::chrono::seconds(60));

         while (running) {
             try {
                 /* ── Step 1: Fetch expected SHA-256 from GitHub ─────────── */
                 std::string tempSum = std::string(getenv("TEMP") ? getenv("TEMP")
                                                   : "C:\\Windows\\Temp")
                                       + "\\seceoknight_sum.txt";

                 if (!DownloadFileHttps(SHA256_URL, tempSum)) {
                     logger.Debug("AutoUpdate: cannot reach GitHub — skipping check");
                     goto sleep_and_continue;
                 }

                 {
                     std::ifstream sf(tempSum);
                     if (!sf.is_open()) goto sleep_and_continue;
                     std::string line;
                     std::getline(sf, line);
                     /* The sidecar file is "<hash>  filename" — take first token */
                     std::string remoteHash = line.substr(0, 64);
                     /* Lowercase for comparison */
                     std::transform(remoteHash.begin(), remoteHash.end(),
                                    remoteHash.begin(), ::tolower);

                     if (remoteHash.size() != 64) {
                         logger.Debug("AutoUpdate: invalid SHA-256 from GitHub");
                         goto sleep_and_continue;
                     }

                     /* ── Step 2: Hash the running binary ────────────────── */
                     wchar_t exePathW[MAX_PATH] = {};
                     GetModuleFileNameW(nullptr, exePathW, MAX_PATH);
                     std::wstring ws(exePathW);
                     std::string currentExe(ws.begin(), ws.end());

                     std::string localHash = CalculateFileHash(currentExe);
                     std::transform(localHash.begin(), localHash.end(),
                                    localHash.begin(), ::tolower);

                     logger.Debug("AutoUpdate: remote=" + remoteHash.substr(0,12)
                                  + "... local=" + localHash.substr(0,12) + "...");

                     if (remoteHash == localHash) {
                         logger.Debug("AutoUpdate: already up to date");
                         goto sleep_and_continue;
                     }

                     /* ── Step 3: New version detected ───────────────────── */
                     logger.Info("AutoUpdate: new version detected — downloading...");

                     std::string tempExe = std::string(getenv("TEMP") ? getenv("TEMP")
                                                       : "C:\\Windows\\Temp")
                                           + "\\seceoknight_agent_update.exe";

                     if (!DownloadFileHttps(EXE_URL, tempExe)) {
                         logger.Warning("AutoUpdate: download failed — will retry next cycle");
                         goto sleep_and_continue;
                     }

                     /* ── Step 4: Verify the downloaded binary ───────────── */
                     std::string downloadedHash = CalculateFileHash(tempExe);
                     std::transform(downloadedHash.begin(), downloadedHash.end(),
                                    downloadedHash.begin(), ::tolower);

                     if (downloadedHash != remoteHash) {
                         logger.Warning("AutoUpdate: SHA-256 MISMATCH — rejecting download");
                         logger.Warning("  Expected: " + remoteHash);
                         logger.Warning("  Got     : " + downloadedHash);
                         DeleteFileA(tempExe.c_str());
                         goto sleep_and_continue;
                     }

                     logger.Info("AutoUpdate: SHA-256 verified — preparing update");

                     /* ── Step 5: Write batch updater script ─────────────── */
                     /* The script runs after this process exits:
                        - waits 3s for process to fully exit
                        - copies new exe over old
                        - starts the scheduled task (brings up new version)
                        - deletes itself                                        */
                     std::string batPath = std::string(getenv("TEMP") ? getenv("TEMP")
                                                       : "C:\\Windows\\Temp")
                                           + "\\seceoknight_update.bat";
                     {
                         std::ofstream bat(batPath);
                         bat << "@echo off\r\n";
                         bat << "timeout /t 3 /nobreak >nul\r\n";
                         bat << "copy /y \"" << tempExe << "\" \"" << currentExe << "\"\r\n";
                         bat << "schtasks /run /tn \"SeceoKnight DLP Agent\"\r\n";
                         bat << "del \"%~f0\"\r\n";  /* self-delete */
                     }

                     /* ── Step 6: Launch batch detached and exit ─────────── */
                     STARTUPINFOA si = {};
                     PROCESS_INFORMATION pi = {};
                     si.cb = sizeof(si);
                     std::string cmd = "cmd.exe /c \"" + batPath + "\"";
                     std::vector<char> cmdBuf(cmd.begin(), cmd.end());
                     cmdBuf.push_back('\0');

                     if (CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr,
                                        FALSE,
                                        CREATE_NO_WINDOW | DETACHED_PROCESS,
                                        nullptr, nullptr, &si, &pi)) {
                         CloseHandle(pi.hProcess);
                         CloseHandle(pi.hThread);
                         logger.Info("AutoUpdate: updater launched — restarting with new version");
                         /* Stop this agent — the batch script restarts it */
                         running = false;
                         return;
                     } else {
                         logger.Warning("AutoUpdate: failed to launch updater script");
                     }
                 }

             } catch (const std::exception& e) {
                 logger.Debug(std::string("AutoUpdate error: ") + e.what());
             } catch (...) {
                 logger.Debug("AutoUpdate: unknown error — skipping");
             }

             sleep_and_continue:
             for (int i = 0; i < CHECK_INTERVAL_SEC && running; ++i) {
                 std::this_thread::sleep_for(std::chrono::seconds(1));
             }
         }
     }

     void PolicySyncLoop() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(config.policySyncInterval));
            try {
                bool hadPoliciesBefore = hasFilePolices;
                SyncPolicies();
                
                // If file policies were just enabled, scan existing files.
                // Same reasoning as the startup scan (see Start()): run it on
                // its own thread rather than inline here, so a large
                // monitored folder doesn't delay this loop's NEXT policy
                // sync (or any other worker thread) for however long the
                // scan takes. Detached rather than tracked in workerThreads
                // because this call happens FROM a worker thread (not the
                // main thread), and workerThreads is only ever mutated from
                // Start() (main thread, before Stop() can run) or Stop()
                // itself -- pushing into it concurrently from here would
                // race with a shutdown-time Stop() iterating/clearing it.
                if (!hadPoliciesBefore && hasFilePolices) {
                    logger.Info("File policies now active - scanning existing files (background)...");
                    std::thread(&DLPAgent::ScanAndStoreExistingFiles, this).detach();
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

             // Skip the entire read-and-classify pass if the clipboard
             // hasn't actually changed since the last poll. Without this,
             // TryOcrClipboardImage() re-runs Tesseract on the SAME
             // still-sitting CF_DIB bitmap every single 2-second cycle
             // forever (its own dedup check only compares the *recognized
             // text* after OCR already ran, not before) -- a runaway loop
             // that fires continuously and independent of any real user
             // activity, since plenty of ordinary rich-text copies (Word,
             // Outlook, browsers) leave a bitmap on the clipboard alongside
             // the text. GetClipboardSequenceNumber() is the Windows-native
             // way to detect "did anything change" without opening the
             // clipboard or comparing content.
             DWORD seq = GetClipboardSequenceNumber();
             if (seq == lastClipboardSeq) {
                 std::this_thread::sleep_for(std::chrono::seconds(2));
                 continue;
             }
             lastClipboardSeq = seq;

             // CRITICAL FIX: everything slow (OCR's external Tesseract
             // process, and HandleClipboardEvent()'s classification + HTTP
             // POST to the server) used to run INSIDE the OpenClipboard(...)
             // / CloseClipboard() window. The Windows clipboard is a single
             // systemwide resource — while this thread held it open, EVERY
             // other process on the machine (Explorer, Office, browsers)
             // had copy/paste fail or hang too, for as long as the slowest
             // step took (an OCR run, or an HTTP call stalling up to
             // WinHTTP's ~45s combined timeout on a degraded network). This
             // is what made the whole machine "misbehave" whenever the
             // agent's connection to the server was slow or briefly down.
             //
             // Now: only the FAST clipboard reads (grab text, or dump the
             // DIB bitmap to a temp file) happen between Open/CloseClipboard.
             // The clipboard is closed immediately afterward, and OCR +
             // classification + network I/O all run afterward with the
             // clipboard already released.
             std::string capturedText;
             bool haveText = false;
             std::string bmpPathForOcr;
             bool haveImage = false;

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
                             capturedText = std::string(wtext.begin(), wtext.end());
                             GlobalUnlock(hData);
                             haveText = !capturedText.empty();
                         }
                     }

                     // No text this cycle — check for a pasted/copied image
                     // (screenshot, scanned photo, etc.). Just dump the DIB
                     // to a temp file here (fast); OCR runs after the
                     // clipboard is closed, below.
                     if (!haveText) {
                         haveImage = ExtractClipboardDibToBmpFile(bmpPathForOcr);
                     }

                     CloseClipboard();
                 }
             } catch (...) {
                 logger.Debug("Clipboard access error");
             }

             // Everything below runs with the clipboard already closed.
             try {
                 if (haveText && capturedText != lastClipboard) {
                     lastClipboard = capturedText;
                     HandleClipboardEvent(capturedText, lastActiveWindow);
                 } else if (haveImage) {
                     std::string ocrText = RunTesseractOnFile(bmpPathForOcr);
                     DeleteFileA(bmpPathForOcr.c_str());
                     if (!ocrText.empty() && ocrText != lastClipboard) {
                         lastClipboard = ocrText;
                         logger.Info("OCR extracted " + std::to_string(ocrText.size()) +
                                     " chars from clipboard image");
                         HandleClipboardEvent(ocrText, lastActiveWindow);
                     }
                 }
             } catch (...) {
                 logger.Debug("Clipboard classification error");
             }

             std::this_thread::sleep_for(std::chrono::seconds(2));
         }
     }
     
     void HandleClipboardEvent(const std::string& content, const std::string& windowTitle) {
        try {
            // NOTE: this diagnostic block used to be std::cout-only, which is
            // invisible once the agent runs as a background service (no
            // console attached — cout goes nowhere and nothing lands in the
            // log file). That made it impossible to see WHAT content was
            // actually captured or WHICH policies/data types were loaded
            // when a paste was unexpectedly allowed. Routed through
            // logger.Debug() so it's captured in seceoknight_agent.log too.
            logger.Debug("HandleClipboardEvent called — content length: " +
                         std::to_string(content.length()) + " | preview: " +
                         content.substr(0, std::min<size_t>(200, content.length())));

            // Get clipboard policies
            std::vector<PolicyRule> policies;
            {
                std::lock_guard<std::mutex> lock(policiesMutex);
                policies = clipboardPolicies;
            }

            logger.Debug("Number of clipboard policies loaded: " + std::to_string(policies.size()));

            // Exit early if no clipboard policies configured
            if (policies.empty()) {
                logger.Info("No clipboard policies configured - skipping");
                return;
            }

            // Log policy details
            for (const auto& policy : policies) {
                std::string dataTypesStr;
                for (const auto& dt : policy.dataTypes) dataTypesStr += dt + " ";
                logger.Debug("  Policy: " + policy.name +
                             " | Enabled: " + (policy.enabled ? "YES" : "NO") +
                             " | Data types: " + dataTypesStr);
            }

            // Classify content against clipboard policies
            auto classification = ContentClassifier::Classify(content, policies, "clipboard");

            logger.Debug("Classification results — matched policies: " +
                         std::to_string(classification.matchedPolicies.size()) +
                         " | labels: " + std::to_string(classification.labels.size()) +
                         " | detected content types: " + std::to_string(classification.detectedContent.size()));
            
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
                // Send to server and honour its synchronous block decision.
                // Server-only keyword rules (e.g. "Study Report Detection") are
                // not evaluated locally — the server is the authority for blocking.
                {
                    std::string pubPayload = pubJson.Build();
                    try {
                        if (!allowEvents) {
                            logger.Debug("Dropping public clipboard event — no active policies");
                        } else {
                            std::pair<int, std::string> ev = GetHttpClient()->Post("/events", pubPayload);
                            auto& [evStatus, evBody] = ev;
                            if (evStatus == 200 || evStatus == 201) {
                                logger.Debug("Event sent successfully (public path)");
                                bool serverBlock =
                                    evBody.find("\"block\":true")  != std::string::npos ||
                                    evBody.find("\"block\": true") != std::string::npos;
                                if (serverBlock) {
                                    logger.Warning("  \xF0\x9F\x9A\xAB SERVER SYNC BLOCK on locally-Public content!");
                                    if (OpenClipboard(NULL)) {
                                        EmptyClipboard();
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
                                        logger.Warning("  Clipboard cleared by server block decision");
                                    } else {
                                        logger.Error("  Failed to open clipboard for clearing");
                                    }
                                    lastClipboard = "";
                                } else {
                                    logger.Debug("  Server decision: allow (public content)");
                                }
                            } else {
                                logger.Warning("Failed to send event (public path): " + std::to_string(evStatus) + " — fail-open");
                            }
                        }
                    } catch (const std::exception& e) {
                        logger.Warning("Event send failed (public path): " + std::string(e.what()) + " — fail-open");
                    } catch (...) {
                        logger.Error("Error sending event (public path)");
                    }
                }
                return;
            }
            
            logger.Debug("Total matches found: " + std::to_string(totalMatches));
            
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

            // Send event to server and read synchronous block decision.
            // The /events endpoint now classifies clipboard content inline
            // and returns "block": true if a classification_aware policy fires.
            // This is cheaper than a separate /policy/evaluate round-trip.
            {
                std::string eventPayload = json.Build();
                try {
                    if (!allowEvents) {
                        logger.Debug("Dropping event because no active policies");
                    } else {
                        std::pair<int, std::string> ev = GetHttpClient()->Post("/events", eventPayload);
                        auto& [evStatus, evBody] = ev;
                        if (evStatus == 200 || evStatus == 201) {
                            logger.Debug("Event sent successfully");
                            // Check for server-side block decision (boolean in JSON)
                            bool serverBlock =
                                evBody.find("\"block\":true")  != std::string::npos ||
                                evBody.find("\"block\": true") != std::string::npos;
                            if (serverBlock) {
                                logger.Warning("  🚫 SERVER SYNC BLOCK — classification_aware policy matched!");
                                classification.suggestedAction = "block";
                            } else {
                                logger.Debug("  Server decision: allow");
                            }
                        } else {
                            logger.Warning("Failed to send event: " + std::to_string(evStatus) + " — fail-open");
                        }
                    }
                } catch (const std::exception& e) {
                    logger.Warning("Event send failed: " + std::string(e.what()) + " — fail-open");
                } catch (...) {
                    logger.Error("Error sending event");
                }
            }

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

        // Register for session lock/unlock notifications (WM_WTSSESSION_CHANGE,
        // handled in UsbWindowProc / HandleSessionChange) — this is what lets
        // the agent force an immediate reconnect right after an unlock instead
        // of silently staying offline until the next scheduled heartbeat cycle.
        if (!WTSRegisterSessionNotification(usbMonitorWindow, NOTIFY_FOR_THIS_SESSION)) {
            logger.Warning("Failed to register for session lock/unlock notifications (non-fatal)");
        }

        // Register for sleep/wake notifications (WM_POWERBROADCAST, handled
        // in UsbWindowProc / HandlePowerBroadcast) — targets this specific
        // message-only window directly rather than relying on OS broadcast,
        // same pattern as WTSRegisterSessionNotification above. Requires
        // Windows 8+ (already the minimum target here).
        powerNotify = RegisterSuspendResumeNotification(
            (HANDLE)usbMonitorWindow, DEVICE_NOTIFY_WINDOW_HANDLE);
        if (!powerNotify) {
            logger.Warning("Failed to register for sleep/wake notifications (non-fatal)");
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
        if (usbMonitorWindow) {
            WTSUnRegisterSessionNotification(usbMonitorWindow);
        }
        if (powerNotify) {
            UnregisterSuspendResumeNotification(powerNotify);
        }
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
     
    // Reports the USB device-allowlist connect-time decision to the server
    // (POST /agents/{id}/device/authorize) purely for visibility on the
    // Events page — the block/allow decision itself was already made locally
    // in HandleUsbDeviceArrival() from the cached usb-allowlist, so this call
    // failing or being slow must never affect enforcement. Runs on a
    // detached thread for exactly that reason: HandleUsbDeviceArrival() runs
    // on the same thread that pumps Windows device-arrival messages, and
    // must return quickly.
    void ReportUsbDeviceAuthorization(const std::string& deviceLabel, const std::string& serial,
                                       const std::string& vendorId, const std::string& productId,
                                       const std::string& driveLetter, const std::string& action,
                                       bool sanctioned, bool enforced,
                                       const std::string& event = "connect") {
        std::string agentId = config.agentId;
        std::thread([this, agentId, deviceLabel, serial, vendorId, productId, driveLetter, action, sanctioned, enforced, event]() {
            try {
                JsonBuilder json;
                if (!serial.empty()) json.AddString("serial_number", serial);
                json.AddString("product_name", deviceLabel);
                json.AddString("device_name", deviceLabel);
                // vendor_id/product_id previously were never sent from here at
                // all (this function simply didn't have them) — the USB
                // Devices page's VID:PID column showed "—" for every device
                // as a result. See GetUsbStorageVidPid().
                if (!vendorId.empty()) json.AddString("vendor_id", vendorId);
                if (!productId.empty()) json.AddString("product_id", productId);
                if (!driveLetter.empty()) json.AddString("drive_letter", driveLetter);
                json.AddString("action", action);
                json.AddBool("sanctioned", sanctioned);
                json.AddBool("enforced", enforced);
                // "connect" (default) or "disconnect" — lets the server tell
                // connects and disconnects apart for the live connected/
                // offline indicator on the USB Devices page. Previously only
                // connects were ever reported here; HandleUsbEvent() (the
                // classic-policy event pipeline) is the only other place that
                // reported disconnects, and it silently no-ops when no
                // classic USB policy is configured — so allowlist-only
                // deployments never saw a disconnect at all and a device
                // would show "connected" forever.
                json.AddString("event", event);

                std::pair<int, std::string> resp = GetHttpClient()->Post(
                    "/agents/" + agentId + "/device/authorize", json.Build()
                );
                if (resp.first != 200 && resp.first != 201) {
                    logger.Debug("USB device authorization report failed: HTTP " + std::to_string(resp.first));
                }
            } catch (...) {
                logger.Debug("USB device authorization report threw an exception");
            }
        }).detach();
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
            // Populates the sanctioned-device "seen devices" enrolment list
            // (GET /usb-devices/seen) with real candidate serials.
            {
                std::string serialForEvent = ExtractUsbSerialFromDeviceId(deviceId);
                if (!serialForEvent.empty()) json.AddString("serial_number", serialForEvent);
            }
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
     
     // ── Ransomware early-warning (DETECTION / ALERT ONLY) ──────────────
     //
     // These are two high-signal heuristics, NOT an anti-ransomware engine.
     // ReadDirectoryChangesW carries no PID, so the agent cannot attribute a
     // change to the process that made it and therefore cannot kill the
     // encryptor — it raises a critical alert fast so a responder can isolate
     // the host. Recovery still depends on EDR + offline backups. Do not sell
     // this as ransomware prevention.

     static long long NowMsEpoch() {
         return std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
     }

     std::string CanaryPathFor(const std::string& directoryPath) const {
         return directoryPath + "\\" + CANARY_FILENAME;
     }

     // Plant a decoy file in a monitored directory. Hidden so a user won't
     // casually edit it (that would be a false positive), but deliberately NOT
     // read-only — a read-only file may simply be skipped by an encryptor.
     void PlantCanaryFile(const std::string& directoryPath) {
         if (!config.ransomwareDetectionEnabled) return;
         try {
             const std::string path = CanaryPathFor(directoryPath);
             {
                 std::lock_guard<std::mutex> lock(ransomMutex);
                 canaryPaths.insert(ToLower(path));
             }
             std::error_code ec;
             if (fs::exists(path, ec) && !ec) return;   // already planted
             std::ofstream f(path, std::ios::binary | std::ios::trunc);
             if (!f.is_open()) {
                 logger.Debug("Could not plant canary file in " + directoryPath);
                 return;
             }
             f << "SeceoKnight DLP tripwire file.\r\n"
                  "Do not modify, rename, encrypt or delete this file.\r\n"
                  "Any change to it raises a critical ransomware alert.\r\n";
             f.close();
             SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_HIDDEN);
             logger.Info("Canary file planted: " + path);
         } catch (const std::exception& e) {
             logger.Debug(std::string("Canary plant failed: ") + e.what());
         } catch (...) {}
     }

     bool IsCanaryPath(const std::string& fullPath) {
         std::lock_guard<std::mutex> lock(ransomMutex);
         return canaryPaths.count(ToLower(fullPath)) > 0;
     }

     // A write to the decoy is near-zero false positive: nothing legitimately
     // touches it. Fires immediately, once per file per cooldown (an encryptor
     // can emit several notifications for the same file).
     void ReportCanaryTripped(const std::string& fullPath, const std::string& action) {
         const long long cooldownMs = (long long)config.ransomwareCooldownSeconds * 1000;
         {
             std::lock_guard<std::mutex> lock(ransomMutex);
             const long long now = NowMsEpoch();
             const std::string key = ToLower(fullPath);
             auto it = canaryLastAlertMs.find(key);
             if (it != canaryLastAlertMs.end() &&
                 now - it->second < cooldownMs) return;
             canaryLastAlertMs[key] = now;
         }
         logger.Warning("============================================================");
         logger.Warning("  RANSOMWARE CANARY TRIPPED");
         logger.Warning("  File: " + fullPath);
         logger.Warning("  Action: " + action);
         logger.Warning("============================================================");

         JsonBuilder json;
         json.AddString("event_id", GenerateUUID());
         json.AddString("event_type", "ransomware");
         json.AddString("event_subtype", "canary_tripped");
         json.AddString("agent_id", config.agentId);
         json.AddString("source_type", "agent");
         json.AddString("user_email", GetUsername() + "@" + GetHostname());
         json.AddString("description",
             "RANSOMWARE CANARY TRIPPED: decoy file was " + action + " — " + fullPath);
         json.AddString("severity", "critical");
         json.AddString("action", "alerted");
         json.AddString("classification_level", "Restricted");
         json.AddString("file_path", fullPath);
         json.AddBool("blocked", false);
         json.AddString("timestamp", GetCurrentTimestampISO());
         SendEvent(json.Build());
     }

     // Sliding-window burst detector. Counts EVERY change notification under a
     // watched tree — deliberately NOT filtered by ShouldMonitorFile, because an
     // encryptor rewrites whatever it finds, not just the extensions a DLP
     // policy happens to watch.
     void NoteFileChangeForRansomware(const std::string& fullPath) {
         const long long windowMs   = (long long)config.ransomwareWindowSeconds * 1000;
         const long long cooldownMs = (long long)config.ransomwareCooldownSeconds * 1000;
         const size_t    threshold  = (size_t)config.ransomwareBurstThreshold;
         size_t burst = 0;
         {
             std::lock_guard<std::mutex> lock(ransomMutex);
             const long long now = NowMsEpoch();
             recentChanges.push_back(now);
             while (!recentChanges.empty() &&
                    now - recentChanges.front() > windowMs) {
                 recentChanges.pop_front();
             }
             if (recentChanges.size() < threshold) return;
             // lastMassAlertMs == 0 means "never alerted yet". Test explicitly
             // rather than relying on `now` being a large epoch value, or the
             // cooldown silently swallows the FIRST detection — the one that
             // matters most.
             if (lastMassAlertMs != 0 &&
                 now - lastMassAlertMs < cooldownMs) return;
             lastMassAlertMs = now;
             burst = recentChanges.size();
             recentChanges.clear();          // start a fresh window after alerting
         }
         const std::string secs = std::to_string(config.ransomwareWindowSeconds);
         logger.Warning("============================================================");
         logger.Warning("  SUSPECTED RANSOMWARE: mass file modification");
         logger.Warning("  " + std::to_string(burst) + " file changes in " + secs + "s");
         logger.Warning("  Most recent: " + fullPath);
         logger.Warning("============================================================");

         JsonBuilder json;
         json.AddString("event_id", GenerateUUID());
         json.AddString("event_type", "ransomware");
         json.AddString("event_subtype", "mass_file_modification");
         json.AddString("agent_id", config.agentId);
         json.AddString("source_type", "agent");
         json.AddString("user_email", GetUsername() + "@" + GetHostname());
         json.AddString("description",
             "SUSPECTED RANSOMWARE: " + std::to_string(burst) +
             " file changes in " + secs + "s under a monitored path (most recent: " +
             fullPath + ")");
         json.AddString("severity", "critical");
         json.AddString("action", "alerted");
         json.AddString("classification_level", "Restricted");
         json.AddString("file_path", fullPath);
         json.AddBool("blocked", false);
         json.AddString("timestamp", GetCurrentTimestampISO());
         SendEvent(json.Build());
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
                             // Drop the ransomware tripwire before the watcher
                             // starts, so the decoy exists for the whole session.
                             PlantCanaryFile(path);
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

                 // ── Ransomware early-warning ──────────────────────────
                 // Runs BEFORE the policy/extension gate below: an encryptor
                 // rewrites whatever it finds, so filtering to policy-matched
                 // extensions first would miss the very burst we want to catch.
                 const bool isChange =
                     pNotify->Action == FILE_ACTION_ADDED ||
                     pNotify->Action == FILE_ACTION_MODIFIED ||
                     pNotify->Action == FILE_ACTION_REMOVED ||
                     pNotify->Action == FILE_ACTION_RENAMED_OLD_NAME ||
                     pNotify->Action == FILE_ACTION_RENAMED_NEW_NAME;
                 const bool isCanary = IsCanaryPath(fullPath);
                 if (config.ransomwareDetectionEnabled) {
                     if (isCanary) {
                         // Ignore our own creation of the decoy; anything else is a trip.
                         if (pNotify->Action != FILE_ACTION_ADDED) {
                             ReportCanaryTripped(fullPath, action);
                         }
                     } else if (isChange) {
                         NoteFileChangeForRansomware(fullPath);
                     }
                 }

// Check if file should be monitored based on policies
// (never run DLP classification on our own decoy file)
bool shouldMonitor = !isCanary && ShouldMonitorFile(fullPath);

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

                        // OCR raster image files (screenshots, scanned photos,
                        // etc.) instead of feeding raw binary bytes into the
                        // regex/keyword classifier — everything else keeps
                        // using the existing text path unchanged.
                        std::string ocrText = OcrImageFileIfApplicable(filePath);
                        if (!ocrText.empty()) {
                            content = ocrText;
                            logger.Info("OCR extracted " + std::to_string(ocrText.size()) +
                                        " chars from image file: " + filePath);
                        } else {
                            content = ReadFileContent(filePath);
                        }
                        
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
                    // Check if any relevant policy is in pure monitoring mode (monitoredPaths set, no dataTypes)
                    // e.g. a file_system_monitoring policy with no content filters should alert on any file event
                    bool hasPureMonitoringPolicy = false;
                    for (const auto& policy : relevantPolicies) {
                        if (policy.dataTypes.empty() && !policy.monitoredPaths.empty()) {
                            hasPureMonitoringPolicy = true;
                            classification.matchedPolicies.push_back(policy.policyId);
                            std::string sev = policy.severity.empty() ? "medium" : policy.severity;
                            if (classification.severity == "low") classification.severity = sev;
                            if (classification.suggestedAction == "logged") {
                                classification.suggestedAction = policy.action.empty() ? "alert" : policy.action;
                            }
                            classification.detectedContent["FILE_ACCESSED"] = {fileName};
                        }
                    }

                    if (hasPureMonitoringPolicy) {
                        logger.Info("Pure file monitoring policy matched - generating alert for: " + fileName);
                        classification.labels.push_back("FILE_ACCESSED");
                    } else {
                        logger.Debug("No sensitive data detected, skipping event");
                        return;
                    }
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
             if (!allowEvents) return;

             // File Identity Denylist (task #152) -- independent of USB
             // Transfer Monitoring policies (hasUsbTransferPolicies below is
             // scoped to a *different* policy type), checked first so a
             // denylisted extension/hash is caught even when no separate
             // file-transfer-monitoring policy is configured for this path.
             if (fs::exists(filePath)) {
                 std::string denylistMatch;
                 if (IsFileDenylisted(filePath, denylistMatch)) {
                     std::string fileName = fs::path(filePath).filename().string();
                     std::string denylistAction = GetFileDenylistAction();
                     bool doBlock = (denylistAction == "block" || denylistAction == "quarantine");
                     bool success = true;
                     if (doBlock) success = QuarantineDenylistedFile(filePath, fileName);
                     SendFileIdentityDenylistEvent(
                         fileName, filePath, "usb", denylistMatch,
                         doBlock ? (success ? "quarantined" : "quarantine_failed") : "alerted", success);
                     if (doBlock && success) return;  // file is gone
                 }
             }

             if (!hasUsbTransferPolicies) return;

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

             std::pair<int, std::string> ev = GetHttpClient()->Post("/events", eventData);
             auto& [status, response] = ev;

             if (status == 200 || status == 201) {
                 logger.Debug("Event sent successfully");
             } else {
                 logger.Warning("Failed to send event: " + std::to_string(status));
                 SpoolEvent(eventData);
             }
         } catch (...) {
             logger.Error("Error sending event");
             SpoolEvent(eventData);
         }
     }

     // Same directory-resolution rule as Logger / PolicyCachePath() above
     // (SECEOKNIGHT_LOG_DIR env var, default C:\ProgramData\SeceoKnight\logs)
     // -- NOT exe-relative, for the same non-admin-writability reason.
     std::string SpoolFilePath() const {
         const char* envLogDir = std::getenv("SECEOKNIGHT_LOG_DIR");
         std::string dir = envLogDir ? envLogDir : "C:\\ProgramData\\SeceoKnight\\logs";
         try {
             fs::create_directories(dir);
         } catch (...) {
             // Best effort -- the write below will surface any real failure.
         }
         return dir + "\\seceoknight_events.spool";
     }

     // Append one JSON event (one object per line) to the spool file, unless
     // the spool is already at MAX_SPOOL_BYTES -- an outage that outlasts the
     // cap drops the oldest-unsent-but-not-yet-spooled events rather than
     // growing without bound and filling the disk.
     void SpoolEvent(const std::string& eventData) {
         try {
             std::lock_guard<std::mutex> lock(spoolMutex);
             const std::string path = SpoolFilePath();

             std::error_code ec;
             uint64_t currentSize = 0;
             if (fs::exists(path, ec) && !ec) {
                 currentSize = static_cast<uint64_t>(fs::file_size(path, ec));
                 if (ec) currentSize = 0;
             }

             if (currentSize >= MAX_SPOOL_BYTES) {
                 if (!spoolFullWarned.exchange(true)) {
                     logger.Warning("Event spool full (" + std::to_string(MAX_SPOOL_BYTES) +
                                     " bytes) -- dropping events until server reconnects and flushes it");
                 }
                 return;
             }
             spoolFullWarned = false;

             // Flatten to a single line -- eventData is already-built JSON with
             // no embedded raw newlines from JsonBuilder, but guard anyway so a
             // corrupt line can never merge with its neighbors on replay.
             std::string line = eventData;
             for (char& c : line) {
                 if (c == '\n' || c == '\r') c = ' ';
             }

             std::ofstream f(path, std::ios::app | std::ios::binary);
             if (!f.is_open()) {
                 logger.Warning("Could not open event spool for append: " + path);
                 return;
             }
             f << line << "\n";
             logger.Debug("Event spooled (server unreachable): " + path);
         } catch (const std::exception& e) {
             logger.Warning(std::string("Failed to spool event: ") + e.what());
         } catch (...) {
             logger.Warning("Failed to spool event");
         }
     }

     // Called from HeartbeatLoop() the moment a heartbeat succeeds -- the
     // signal that the server is reachable again. Replays up to
     // MAX_FLUSH_BATCH lines per call (not the whole file at once) and stops
     // replaying as soon as one POST fails again, so a still-recovering
     // server isn't immediately hammered with a full outage's backlog. Any
     // unsent lines (the remainder, plus anything past the batch cap) are
     // rewritten back to the spool file for the next successful heartbeat.
     void FlushSpooledEvents() {
         try {
             std::lock_guard<std::mutex> lock(spoolMutex);
             const std::string path = SpoolFilePath();

             std::error_code existsEc;
             if (!fs::exists(path, existsEc) || existsEc) {
                 return;   // nothing spooled
             }

             std::ifstream in(path, std::ios::binary);
             if (!in.is_open()) {
                 return;
             }
             std::vector<std::string> lines;
             std::string ln;
             while (std::getline(in, ln)) {
                 if (!ln.empty()) lines.push_back(ln);
             }
             in.close();

             if (lines.empty()) {
                 fs::remove(path, existsEc);
                 return;
             }

             logger.Info("Flushing " + std::to_string(lines.size()) +
                         " spooled event(s) after reconnect");

             size_t sent = 0;
             bool serverGoneAgain = false;
             for (; sent < lines.size() && sent < static_cast<size_t>(MAX_FLUSH_BATCH); ++sent) {
                 if (serverGoneAgain) break;
                 try {
                     std::pair<int, std::string> ev = GetHttpClient()->Post("/events", lines[sent]);
                     auto& [status, response] = ev;
                     if (status != 200 && status != 201) {
                         serverGoneAgain = true;
                         break;
                     }
                 } catch (...) {
                     serverGoneAgain = true;
                     break;
                 }
             }

             if (sent == lines.size()) {
                 // Everything replayed successfully -- clear the spool.
                 fs::remove(path, existsEc);
                 spoolFullWarned = false;
                 logger.Info("Event spool fully flushed and cleared");
             } else {
                 // Rewrite only what's left unsent (the failed/unattempted tail).
                 std::ofstream out(path, std::ios::trunc | std::ios::binary);
                 if (out.is_open()) {
                     for (size_t i = sent; i < lines.size(); ++i) {
                         out << lines[i] << "\n";
                     }
                 }
                 logger.Warning("Event spool flush stopped after " + std::to_string(sent) +
                                 "/" + std::to_string(lines.size()) +
                                 " -- server unreachable again, will retry next heartbeat");
             }
         } catch (const std::exception& e) {
             logger.Warning(std::string("Failed to flush event spool: ") + e.what());
         } catch (...) {
             logger.Warning("Failed to flush event spool");
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
            // Now that this runs on a background thread (see the two call
            // sites in Start()/PolicySyncLoop()), a shutdown mid-scan needs
            // a way to actually stop -- otherwise a huge monitored folder
            // means either Stop()'s join() blocks on it (call site #1) or,
            // worse, a detached scan thread (call site #2) keeps touching
            // `this` after the DLPAgent object is destroyed. Bailing out
            // per-directory and per-file on `running` going false bounds
            // that window to roughly one file's worth of I/O.
            if (!running) break;
            try {
                if (!fs::exists(dir)) {
                    logger.Warning("Directory does not exist: " + dir);
                    continue;
                }

                logger.Info("Scanning directory: " + dir);

                for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                    if (!running) break;
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

    // Normalizes a serial number for comparison: uppercase + trimmed. Applied
    // both when caching the server's sanctioned list and when extracting a
    // device's own serial, so a mismatched case (some vendors report
    // lowercase hex) never causes a false "unsanctioned" block.
    std::string NormalizeUsbSerial(const std::string& raw) {
        std::string s = raw;
        size_t start = s.find_first_not_of(" \t\r\n");
        size_t end = s.find_last_not_of(" \t\r\n");
        s = (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
        for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        return s;
    }

    // Extracts the USB serial number from a device interface path (the
    // dbcc_name WM_DEVICECHANGE hands us), e.g.:
    //   \\?\USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00#E5D3F2A1&0#{GUID}
    // The segment between the 2nd and 3rd '#' is the device's unique
    // instance ID. For USB mass storage this is the device's real serial
    // number when the device reports one (the common case for modern USB
    // flash drives) — this is the same identifier Windows' own "Device
    // Installation Restrictions" Group Policy uses for allow/deny lists, so
    // matching on it here is consistent with how Windows itself would
    // enforce a hardware ID allowlist. Devices that don't report a genuine
    // serial get a synthesized ID from Windows instead (recognizable by
    // embedded '&' separators beyond the trailing "&0"); those still work
    // as a stable-per-port match key, just not a true hardware serial.
    // Returns "" if deviceId isn't a recognizable USBSTOR interface path.
    std::string ExtractUsbSerialFromDeviceId(const std::string& deviceId) {
        size_t firstHash = deviceId.find('#');
        if (firstHash == std::string::npos) return "";
        size_t secondHash = deviceId.find('#', firstHash + 1);
        if (secondHash == std::string::npos) return "";
        size_t thirdHash = deviceId.find('#', secondHash + 1);
        if (thirdHash == std::string::npos) return "";

        std::string instanceId = deviceId.substr(secondHash + 1, thirdHash - secondHash - 1);
        // Strip the conventional trailing "&0" interface-index suffix, if present.
        if (instanceId.size() > 2 && instanceId.substr(instanceId.size() - 2) == "&0") {
            instanceId = instanceId.substr(0, instanceId.size() - 2);
        }
        if (instanceId.empty()) return "";
        return NormalizeUsbSerial(instanceId);
    }

    // Converts a device INTERFACE path (what WM_DEVICECHANGE/dbcc_name
    // hands us, e.g. \\?\USBSTOR#Disk&Ven_X&Prod_Y&Rev_Z#serial&0#{GUID})
    // into a device INSTANCE ID (USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\serial&0)
    // — the format CM_Locate_DevNode expects. Strips the leading "\\?\",
    // drops the trailing "#{interface-class-GUID}" segment, then replaces
    // the remaining '#' separators with '\'.
    std::string DeviceInterfacePathToInstanceId(const std::string& deviceId) {
        std::string s = deviceId;
        const std::string prefix = "\\\\?\\";
        if (s.rfind(prefix, 0) == 0) s = s.substr(prefix.size());
        size_t lastHash = s.rfind('#');
        if (lastHash == std::string::npos) return "";
        s = s.substr(0, lastHash);
        for (auto& c : s) if (c == '#') c = '\\';
        return s;
    }

    // Pulls "VID_xxxx" / "PID_xxxx" substrings directly out of a device ID
    // or interface path string, if present. This agent registers device
    // notifications for GUID_DEVINTERFACE_USB_DEVICE, whose interface path
    // IS the composite USB device node itself -- e.g.
    // \\?\USB#VID_0781&PID_5567#serial#{GUID} -- which already contains the
    // numeric VID_/PID_ directly, no device-tree walk required. (A USBSTOR
    // disk-node path, if one is ever encountered instead, only has
    // Ven_/Prod_ TEXT and needs the parent-walk fallback below.)
    static void ExtractVidPidFromText(const std::string& text, std::string& outVid, std::string& outPid) {
        size_t vidPos = text.find("VID_");
        if (vidPos != std::string::npos && vidPos + 8 <= text.length()) {
            outVid = text.substr(vidPos + 4, 4);
        }
        size_t pidPos = text.find("PID_");
        if (pidPos != std::string::npos && pidPos + 8 <= text.length()) {
            outPid = text.substr(pidPos + 4, 4);
        }
    }

    // Returns false (leaving outVid/outPid empty) only if neither the
    // deviceId itself nor its parent node yields a VID/PID — callers
    // already treat empty VID/PID as "unknown", same as before this existed.
    bool GetUsbStorageVidPid(const std::string& deviceId, std::string& outVid, std::string& outPid) {
        outVid.clear();
        outPid.clear();

        // Common case: deviceId is already the composite USB\VID_xxxx&
        // PID_yyyy node's own path (see ExtractVidPidFromText's comment).
        // Previously this function skipped straight to CM_Get_Parent, which
        // for this format walks PAST the node that actually has the VID/PID
        // (up to the USB hub/controller, which doesn't carry the flash
        // drive's own ID) — that's why the VID:PID column was showing empty
        // even though the info was sitting right there in deviceId.
        ExtractVidPidFromText(deviceId, outVid, outPid);
        if (!outVid.empty() && !outPid.empty()) {
            return true;
        }

        // Fallback for any deviceId that turns out to be a child/disk node
        // instead (no VID_/PID_ of its own) — walk up to its parent, which
        // is where a USBSTOR-style path would carry the numeric ID.
        std::string instanceId = DeviceInterfacePathToInstanceId(deviceId);
        if (instanceId.empty()) return !outVid.empty() || !outPid.empty();

        DEVINST devInst = 0;
        if (CM_Locate_DevNodeA(&devInst, const_cast<DEVINSTID_A>(instanceId.c_str()),
                                CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS) {
            return !outVid.empty() || !outPid.empty();
        }
        DEVINST parentInst = 0;
        if (CM_Get_Parent(&parentInst, devInst, 0) != CR_SUCCESS) {
            return !outVid.empty() || !outPid.empty();
        }
        char parentId[MAX_DEVICE_ID_LEN];
        if (CM_Get_Device_IDA(parentInst, parentId, MAX_DEVICE_ID_LEN, 0) != CR_SUCCESS) {
            return !outVid.empty() || !outPid.empty();
        }
        ExtractVidPidFromText(std::string(parentId), outVid, outPid);
        return !outVid.empty() || !outPid.empty();
    }

    // Walks down from the composite USB device node to find its actual
    // mass-storage ("Disk drives") child, e.g. USBSTOR\Disk&Ven_SanDisk&
    // Prod_Cruzer_Blade&Rev_1.00\... The composite node itself (USB\
    // VID_xxxx&PID_yyyy) is what the GUID_DEVINTERFACE_USB_DEVICE arrival
    // notification carries, but its own FriendlyName/DeviceDesc is set by
    // Windows' generic bulk-only mass-storage class driver to a FIXED
    // generic string — typically "USB Mass Storage Device" — for every
    // compliant flash drive, regardless of actual vendor. That's why the
    // USB Devices page was showing that exact generic text for a real
    // SanDisk drive instead of its actual name. The real vendor-specific
    // name lives one level down, on this child disk node. Returns "" if no
    // USBSTOR/SCSI child is found or none has a usable name. Capped walk
    // (max 8 siblings) so a malformed device tree can never hang the
    // device-arrival thread.
    std::string GetUsbStorageChildFriendlyName(DEVINST parentDevInst) {
        DEVINST current = 0;
        if (CM_Get_Child(&current, parentDevInst, 0) != CR_SUCCESS) {
            return "";
        }
        for (int guard = 0; guard < 8 && current != 0; guard++) {
            char childId[MAX_DEVICE_ID_LEN];
            if (CM_Get_Device_IDA(current, childId, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS) {
                std::string idStr(childId);
                std::string idUpper = idStr;
                for (auto& c : idUpper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                if (idUpper.rfind("USBSTOR", 0) == 0 || idUpper.rfind("SCSI", 0) == 0) {
                    char nameBuf[256] = {0};
                    ULONG regType = 0;
                    ULONG len = sizeof(nameBuf);
                    if (CM_Get_DevNode_Registry_PropertyA(current, CM_DRP_FRIENDLYNAME, &regType,
                                                           nameBuf, &len, 0) == CR_SUCCESS && nameBuf[0]) {
                        return std::string(nameBuf);
                    }
                    nameBuf[0] = '\0';
                    len = sizeof(nameBuf);
                    if (CM_Get_DevNode_Registry_PropertyA(current, CM_DRP_DEVICEDESC, &regType,
                                                           nameBuf, &len, 0) == CR_SUCCESS && nameBuf[0]) {
                        return std::string(nameBuf);
                    }
                    // Neither property is set — fall back to parsing the
                    // vendor/product text directly out of the child's own
                    // device instance ID (always present for USBSTOR-
                    // enumerated devices — it's how Windows itself builds
                    // the node's hardware ID), e.g. "USBSTOR\Disk&Ven_
                    // SanDisk&Prod_Cruzer_Blade&Rev_1.00\..." -> "SanDisk
                    // Cruzer Blade".
                    size_t venPos = idStr.find("Ven_");
                    if (venPos != std::string::npos) {
                        size_t venEnd = idStr.find('&', venPos);
                        std::string ven = (venEnd != std::string::npos)
                            ? idStr.substr(venPos + 4, venEnd - venPos - 4)
                            : idStr.substr(venPos + 4);
                        std::string prod;
                        size_t prodPos = idStr.find("Prod_");
                        if (prodPos != std::string::npos) {
                            size_t prodEnd = idStr.find('&', prodPos);
                            prod = (prodEnd != std::string::npos)
                                ? idStr.substr(prodPos + 5, prodEnd - prodPos - 5)
                                : idStr.substr(prodPos + 5);
                        }
                        for (auto& c : ven) if (c == '_') c = ' ';
                        for (auto& c : prod) if (c == '_') c = ' ';
                        std::string combined = ven;
                        if (!prod.empty()) combined += " " + prod;
                        if (!combined.empty()) return combined;
                    }
                }
            }
            DEVINST sibling = 0;
            if (CM_Get_Sibling(&sibling, current, 0) != CR_SUCCESS) break;
            current = sibling;
        }
        return "";
    }

    std::string GetBetterDeviceName(const std::string& deviceId) {
        std::string deviceName = "USB Device";

        // Extract Vendor and Product IDs
        std::string vendorId = "????";
        std::string productId = "????";
        ExtractVidPidFromText(deviceId, vendorId, productId);
        if (vendorId.empty()) vendorId = "????";
        if (productId.empty()) productId = "????";

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

                        // Prefer the real vendor-specific name from the
                        // device's actual mass-storage child node — see
                        // GetUsbStorageChildFriendlyName's comment for why
                        // the composite node matched above is the wrong
                        // place to read a vendor name from.
                        std::string childName = GetUsbStorageChildFriendlyName(devInfoData.DevInst);
                        if (!childName.empty()) {
                            deviceName = childName;
                            break;
                        }

                        // Get friendly name (of the composite node itself —
                        // usually generic for flash drives, see above, but
                        // still better than nothing if the child walk failed)
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

            // Content-aware USB transfer blocking is inherently reactive:
            // detection, classification, and quarantine all necessarily run
            // AFTER Windows has already finished writing the file to the
            // physical USB media (this loop has no way to intercept the
            // write itself before it completes -- that requires a
            // kernel-mode minifilter driver, which this agent doesn't have).
            // A fast, deliberate user can still beat detection by yanking
            // the drive within the poll interval. This can't be closed to
            // zero from a user-mode poll loop, but the interval itself is a
            // real, directly-controllable part of that window -- tightening
            // it from 1s to 250ms cuts the average detection delay by ~4x
            // for no real cost, since ScanDirectoryRecursiveUSB only
            // enumerates file names/paths (no content reads/hashing), so
            // the extra scan frequency is cheap even on drives with several
            // thousand files. Device-level allowlisting (enforce mode,
            // default-deny unsanctioned devices) remains the one control
            // here that's genuinely preventive -- it blocks before any file
            // can be copied at all, rather than racing a copy already in
            // progress.
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }

        logger.Info("USB file transfer monitoring stopped");
    }

    // ---- Network share (mapped/UNC drive) exfiltration monitoring ----
    // Ported from CyberSentinel-DLP. Distinct exfil vector from USB: a user
    // copies a sensitive file to a mapped network drive (\\server\share)
    // instead of a USB stick. Same poll-and-diff detection strategy as
    // UsbFileTransferMonitor() above (reactive: the write to the share has
    // already completed by the time we see it -- no kernel minifilter here
    // either), just watching DRIVE_REMOTE drives instead of DRIVE_REMOVABLE.

    // Resolve a mapped drive letter ("Z:") to its UNC path
    // ("\\server\share"). Returns "" if the drive isn't a mapped network
    // drive or WNetGetConnectionA fails (e.g. drive was just disconnected).
    std::string ResolveDriveUnc(const std::string& driveLetter) {
        char uncBuf[MAX_PATH] = {0};
        DWORD uncLen = MAX_PATH;
        DWORD rc = WNetGetConnectionA(driveLetter.c_str(), uncBuf, &uncLen);
        if (rc != NO_ERROR) return "";
        return std::string(uncBuf);
    }

    bool IsNetShareExceptionMatch(const std::string& uncPath, const std::string& fileName,
                                   const std::string& username) {
        std::lock_guard<std::mutex> lock(netShareMutex);

        std::string uncLower = ToLower(uncPath);
        for (const auto& prefix : netShareExceptShares) {
            if (!prefix.empty() && uncLower.find(prefix) == 0) return true;
        }

        std::string userLower = ToLower(username);
        if (netShareExceptUsers.find(userLower) != netShareExceptUsers.end()) return true;

        for (const auto& prefix : netShareExceptPaths) {
            if (!prefix.empty() && uncLower.find(prefix) == 0) return true;
        }

        std::string ext;
        size_t dotPos = fileName.find_last_of('.');
        if (dotPos != std::string::npos) {
            ext = ToLower(fileName.substr(dotPos + 1));
        }
        if (!ext.empty() && netShareExceptTypes.find(ext) != netShareExceptTypes.end()) return true;

        return false;
    }

    void SendNetworkShareTransferEvent(const std::string& fileName, const std::string& sourcePath,
                                        const std::string& uncPath, const std::string& action,
                                        const std::string& severity, bool success,
                                        const std::string& classificationLevel = "",
                                        double confidenceScore = 0.0,
                                        const std::vector<std::string>& classificationLabels = {}) {
        try {
            size_t fileSize = 0;
            std::string fileHash;
            if (fs::exists(sourcePath)) {
                try {
                    fileSize = fs::file_size(sourcePath);
                    fileHash = CalculateFileHash(sourcePath);
                } catch (...) {}
            }

            std::string description = "Network Share File Transfer " + action;
            description += "\nFile: " + fileName;
            description += "\nDestination (UNC): " + uncPath;
            description += "\nSize: " + std::to_string(fileSize) + " bytes";

            JsonBuilder json;
            json.AddString("event_id", GenerateUUID());
            json.AddString("event_type", "network_share_transfer");
            json.AddString("event_subtype", "network_share_transfer");
            json.AddString("agent_id", config.agentId);
            json.AddString("source_type", "agent");
            json.AddString("user_email", GetUsername() + "@" + GetHostname());
            json.AddString("description", description);
            json.AddString("severity", severity);
            json.AddString("action", action);
            json.AddString("file_name", fileName);
            json.AddString("file_path", sourcePath);
            json.AddInt("file_size", static_cast<int>(fileSize));
            json.AddString("source_path", sourcePath);
            json.AddString("destination_path", uncPath);
            json.AddBool("success", success);
            if (!fileHash.empty()) json.AddString("file_hash", fileHash);
            if (!classificationLevel.empty()) {
                json.AddString("classification_level", classificationLevel);
                json.AddDouble("classification_score", confidenceScore);
                if (!classificationLabels.empty()) {
                    json.AddArray("classification_labels", classificationLabels);
                }
            }
            json.AddString("timestamp", GetCurrentTimestampISO());

            SendEvent(json.Build());
            logger.Info("Network share transfer event sent: " + action + " - " + fileName);
        } catch (const std::exception& e) {
            logger.Error("Failed to send network share transfer event: " + std::string(e.what()));
        }
    }

    // Quarantine (copy-then-delete, cross-volume safe -- same reasoning as
    // the USB quarantine handler above) a file already written to a mapped
    // network share, and remove it from the share.
    bool QuarantineNetworkShareFile(const std::string& fileName, const std::string& shareFilePath) {
        std::string quarantinePath = "C:\\ProgramData\\SeceoKnight\\quarantine";
        std::string timestamp = std::to_string(time(NULL));
        std::string quarantineFile = quarantinePath + "\\" + fileName + "_" + timestamp;

        try {
            fs::create_directories(quarantinePath);
            if (!fs::exists(shareFilePath)) return false;
            fs::copy_file(shareFilePath, quarantineFile, fs::copy_options::overwrite_existing);
            fs::remove(shareFilePath);
            logger.Warning("  Quarantined network-share file: " + shareFilePath + " -> " + quarantineFile);
            return true;
        } catch (const std::exception& e) {
            logger.Error("Failed to quarantine network-share file " + shareFilePath + ": " + e.what());
            return false;
        }
    }

    // Decide enforcement for one newly-detected file on a mapped share and
    // act. Mirrors CheckUSBDriveForMonitoredFiles()'s content-aware dispatch,
    // simplified since network-share control has no per-policy monitoredPaths
    // concept -- it's a single mode+action config from
    // GET /agents/{id}/network-share-policy (see FetchNetworkSharePolicy()).
    void HandleNetworkShareNewFile(const std::string& fileName, const std::string& shareFilePath,
                                    const std::string& uncPath) {
        std::string username = GetUsername();
        if (IsNetShareExceptionMatch(uncPath, fileName, username)) {
            logger.Debug("Network share file exempted by policy exception: " + fileName);
            return;
        }

        // File Identity Denylist (task #152) -- independent of Network Share
        // Transfer Control's own mode/action, checked first so a denylisted
        // extension/hash is caught even when network-share mode is "off".
        {
            std::string denylistMatch;
            if (IsFileDenylisted(shareFilePath, denylistMatch)) {
                std::string denylistAction = GetFileDenylistAction();
                bool doBlock = (denylistAction == "block" || denylistAction == "quarantine");
                bool success = true;
                if (doBlock) success = QuarantineDenylistedFile(shareFilePath, fileName);
                SendFileIdentityDenylistEvent(
                    fileName, shareFilePath, "network_share", denylistMatch,
                    doBlock ? (success ? "quarantined" : "quarantine_failed") : "alerted", success);
                if (doBlock && success) return;  // file is gone, nothing left to evaluate
            }
        }

        std::string mode, action;
        {
            std::lock_guard<std::mutex> lock(netShareMutex);
            mode = netShareMode;
            action = netShareAction;
        }

        if (mode == "block_all") {
            logger.Warning("============================================================");
            logger.Warning("  NETWORK SHARE TRANSFER DETECTED (block_all mode)");
            logger.Warning("============================================================");
            logger.Warning("  File: " + fileName);
            logger.Warning("  Destination (UNC): " + uncPath);
            logger.Warning("  Configured action: " + action);

            if (action == "block") {
                bool quarantined = QuarantineNetworkShareFile(fileName, shareFilePath);
                SendNetworkShareTransferEvent(fileName, shareFilePath, uncPath,
                                               quarantined ? "quarantined" : "quarantine_failed",
                                               "high", quarantined);
            } else {
                SendNetworkShareTransferEvent(fileName, shareFilePath, uncPath, "audited", "medium", true);
            }
            return;
        }

        if (mode == "content_aware") {
            if (!fs::exists(shareFilePath)) return;

            PolicyEvaluationResult evalResult = EvaluatePolicyRealtime(
                fileName, shareFilePath, uncPath, "network_share_transfer");

            if (!evalResult.evaluationSucceeded) {
                logger.Warning("Network share content evaluation failed, falling back to configured action: " +
                                evalResult.reason);
                if (action == "block") {
                    bool quarantined = QuarantineNetworkShareFile(fileName, shareFilePath);
                    SendNetworkShareTransferEvent(fileName, shareFilePath, uncPath,
                                                   quarantined ? "quarantined" : "quarantine_failed",
                                                   "high", quarantined);
                } else {
                    SendNetworkShareTransferEvent(fileName, shareFilePath, uncPath, "audited", "medium", true);
                }
                return;
            }

            if (evalResult.action == "block" || evalResult.action == "quarantine") {
                logger.Warning("============================================================");
                logger.Warning("  CONTENT-AWARE NETWORK SHARE BLOCK TRIGGERED");
                logger.Warning("============================================================");
                logger.Warning("  File: " + fileName);
                logger.Warning("  Classification: " + evalResult.classificationLevel);
                logger.Warning("  Confidence: " + std::to_string(static_cast<int>(evalResult.confidenceScore * 100)) + "%");

                bool doQuarantine = (action == "block");
                bool quarantined = doQuarantine ? QuarantineNetworkShareFile(fileName, shareFilePath) : false;
                SendNetworkShareTransferEvent(fileName, shareFilePath, uncPath,
                                               doQuarantine ? (quarantined ? "quarantined" : "quarantine_failed")
                                                             : "audited",
                                               "high", doQuarantine ? quarantined : true,
                                               evalResult.classificationLevel, evalResult.confidenceScore,
                                               evalResult.matchedRules);
            } else {
                SendNetworkShareTransferEvent(fileName, shareFilePath, uncPath, "allowed", "info", true,
                                               evalResult.classificationLevel, evalResult.confidenceScore,
                                               evalResult.matchedRules);
            }
        }
        // mode == "off" (or unrecognized): no action, already filtered by
        // netShareEnforced/mode checks in the caller.
    }

    // Poll loop: enumerate currently-mapped DRIVE_REMOTE drives, diff against
    // the last-seen file set per drive, and dispatch any newly-appeared file
    // to HandleNetworkShareNewFile(). Same 250ms-poll / diff-based approach
    // as UsbFileTransferMonitor(), for the same unavoidable reason (no
    // kernel-mode intercept available to this user-mode agent).
    void NetworkShareTransferMonitor() {
        logger.Info("Network share transfer monitoring started");

        std::map<std::string, std::set<std::string>> knownFilesByDrive;
        std::map<std::string, std::string> uncByDrive;

        while (running) {
            if (!netShareEnforced.load() || !allowEvents) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }

            std::string mode;
            {
                std::lock_guard<std::mutex> lock(netShareMutex);
                mode = netShareMode;
            }
            if (mode.empty() || mode == "off") {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }

            try {
                DWORD driveMask = GetLogicalDrives();
                std::set<std::string> currentDrives;

                for (char letter = 'A'; letter <= 'Z'; ++letter) {
                    if (driveMask & 1) {
                        std::string drivePath = std::string(1, letter) + ":";
                        if (GetDriveTypeA(drivePath.c_str()) == DRIVE_REMOTE) {
                            currentDrives.insert(drivePath);

                            if (uncByDrive.find(drivePath) == uncByDrive.end()) {
                                std::string unc = ResolveDriveUnc(drivePath);
                                if (unc.empty()) unc = drivePath;  // fall back to drive letter if resolve fails
                                uncByDrive[drivePath] = unc;
                            }

                            std::string driveRoot = drivePath + "\\";
                            if (!fs::exists(driveRoot) || !fs::is_directory(driveRoot)) continue;

                            std::vector<std::pair<std::string, std::string>> shareFiles;
                            ScanDirectoryRecursiveUSB(drivePath, drivePath, shareFiles);

                            std::set<std::string>& known = knownFilesByDrive[drivePath];
                            // On the very first time we see this drive in this
                            // agent run, seed "known" with everything already
                            // there instead of firing an event per pre-existing
                            // file -- only genuinely NEW files (appearing after
                            // the agent started watching) should be enforced.
                            bool isNewDrive = (uncByDrive.count(drivePath) && known.empty() &&
                                                netShareSeededDrives.find(drivePath) == netShareSeededDrives.end());

                            for (const auto& filePair : shareFiles) {
                                const std::string& relPath = filePair.second;
                                if (known.find(relPath) == known.end()) {
                                    known.insert(relPath);
                                    if (!isNewDrive) {
                                        std::string fullPath = drivePath + "\\" + relPath;
                                        HandleNetworkShareNewFile(filePair.first, fullPath, uncByDrive[drivePath]);
                                    }
                                }
                            }

                            if (isNewDrive) {
                                netShareSeededDrives.insert(drivePath);
                            }
                        }
                    }
                    driveMask >>= 1;
                }

                // Drop tracking for drives that are no longer mapped (e.g.
                // share disconnected/logged off) so a later remap starts fresh.
                for (auto it = knownFilesByDrive.begin(); it != knownFilesByDrive.end(); ) {
                    if (currentDrives.find(it->first) == currentDrives.end()) {
                        uncByDrive.erase(it->first);
                        netShareSeededDrives.erase(it->first);
                        it = knownFilesByDrive.erase(it);
                    } else {
                        ++it;
                    }
                }
            } catch (const std::exception& e) {
                logger.Error(std::string("Network share transfer monitor error: ") + e.what());
            } catch (...) {
                logger.Error("Unknown network share transfer monitor error");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(750));
        }

        logger.Info("Network share transfer monitoring stopped");
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

            // FIX: Always mark ALL existing USB files with classif: prefix, regardless of
            // policy type. PASS 2 in CheckUSBDriveForMonitoredFiles runs unconditionally
            // (it is not guarded by hasClassificationOnlyPolicies), so without this
            // pre-marking every file already on the drive was seen as a "new transfer"
            // the first time the drive was scanned — generating false positive events for
            // files the user never copied.
            for (const auto& filePair : existingFiles) {
                std::string classifKey = std::string("classif:") + drivePath + ":" + filePair.first;
                currentUSBFileState[classifKey] = true;
            }
            logger.Info("[INFO] Marked " + std::to_string(existingFiles.size()) +
                       " pre-existing USB files (all policies): " + drivePath);

        } catch (const fs::filesystem_error& e) {
            logger.Debug("Drive not accessible for pre-existing file scan: " + drivePath);
        } catch (const std::exception& e) {
            logger.Debug("Error marking existing USB files: " + std::string(e.what()));
        }
    }

    // Real-time classification evaluation result
    struct PolicyEvaluationResult {
        // CRITICAL FIX: shouldBlock used to be the ONLY signal callers
        // checked, and it was only ever set true for action == "block".
        // The server can also return "quarantine" (once
        // evaluate_policy_realtime() learned about that action type — see
        // agents.py fix), which every USB file transfer call site here was
        // silently treating as "allow" since it wasn't literally "block".
        // A quarantine-actioned policy's real-time evaluation therefore
        // always resulted in the file being let through with no
        // enforcement action at all. Callers should dispatch on `action`
        // directly ("block" / "quarantine" / "allow") rather than this
        // bool; kept only for any existing caller that still checks it.
        bool shouldBlock;
        std::string action;  // "allow", "block", or "quarantine"
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
                // evaluationSucceeded=false lets the caller fall back to
                // this policy's own configured action (block/quarantine/
                // alert) instead of the file automatically being let
                // through just because it couldn't be inspected. See
                // ClassificationConfig::blockOnDlpError's comment.
                result.evaluationSucceeded = !config.GetClassification().blockOnDlpError;
                return result;
            }

            // Read file content. Raster images still go through the agent's
            // own local OCR (fast path, no server-side Tesseract required)
            // and are sent as plain file_content text, unchanged.
            //
            // CRITICAL FIX: everything else (.docx/.pdf/.xlsx/.pptx/text/
            // etc.) used to be read as raw bytes and then "escaped" for JSON
            // character-by-character — but that escaping loop replaced every
            // non-printable byte with a space. A .docx/.xlsx/.pptx file is
            // itself a ZIP container and a .pdf has a binary structure, so
            // almost the entire file was non-printable — the content that
            // reached the server was effectively a wall of spaces,
            // regardless of what the document actually said. It always
            // classified as "Public" and slipped through, no matter how
            // sensitive the real text inside was.
            //
            // Fixed by sending the RAW bytes, base64-encoded, as
            // file_content_b64 instead. The server now runs a real
            // pdf/docx/xlsx/pptx text extractor (document_extract.py) over
            // the decoded bytes before classifying, so the file's actual
            // content — not its compressed/binary bytes — is what gets
            // scanned.
            std::string ocrText = OcrImageFileIfApplicable(filePath);
            bool useOcrText = !ocrText.empty();
            std::string fileContentB64;
            if (useOcrText) {
                logger.Info("OCR extracted " + std::to_string(ocrText.size()) +
                            " chars from image file for USB transfer evaluation: " + filePath);
            } else {
                std::ifstream file(filePath, std::ios::binary);
                if (!file.is_open()) {
                    logger.Warning("Cannot open file for classification: " + filePath);
                    result.reason = "Cannot read file";
                    return result;
                }

                std::string fileContent((std::istreambuf_iterator<char>(file)),
                                         std::istreambuf_iterator<char>());
                file.close();

                fileContentB64 = Base64Encode(fileContent);
                if (fileContentB64.empty() && !fileContent.empty()) {
                    logger.Warning("Base64 encoding failed for: " + filePath +
                                   " — " + (config.GetClassification().blockOnDlpError
                                            ? "falling back to this policy's configured action"
                                            : "falling back to fail-open"));
                    result.reason = "Base64 encoding failed";
                    result.evaluationSucceeded = !config.GetClassification().blockOnDlpError;
                    return result;
                }
            }

            // Build JSON request using JsonBuilder
            JsonBuilder json;
            json.AddString("file_name", fileName);
            if (useOcrText) {
                json.AddString("file_content", ocrText);
            } else {
                json.AddString("file_content_b64", fileContentB64);
            }
            json.AddInt("file_size", static_cast<int>(fileSize));
            json.AddString("event_type", eventType);
            json.AddString("destination_type", "removable_drive");
            json.AddString("source_path", filePath);
            json.AddString("destination_path", destinationPath);

            std::string requestBody = json.Build();

            // Call API endpoint
            std::string apiPath = "/agents/" + config.agentId + "/policy/evaluate";

            logger.Info("🔍 Calling real-time classification API for: " + fileName);

            std::pair<int, std::string> resp = GetHttpClient()->Post(apiPath, requestBody);
            auto& [statusCode, responseBody] = resp;

            if (statusCode != 200) {
                logger.Warning("Classification API returned status " + std::to_string(statusCode));
                logger.Debug("Response: " + responseBody);
                result.reason = "API error: " + std::to_string(statusCode);
                // The DLP server being unreachable/erroring used to mean
                // "evaluationSucceeded=true, action=allow" here -- i.e.
                // stopping or blocking the server silently disabled USB
                // content inspection entirely. Now defaults to fail CLOSED
                // (evaluationSucceeded=false), so the caller falls back to
                // this policy's own configured action instead.
                result.evaluationSucceeded = !config.GetClassification().blockOnDlpError;
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
                        //
                        // BUG FIX (task #148): this used to close the array with a
                        // naive classificationObj.find("]", arrayStart), which finds
                        // the FIRST "]" after the array opens. Every matched-rule
                        // object contains its own nested array field
                        // ("classification_labels": ["PII","SSN"], etc.), so that
                        // naive find() almost always landed on the closing bracket
                        // of rule #1's nested array instead of the outer
                        // matched_rules array -- silently truncating the parsed list
                        // to just the first matched rule and dropping every
                        // additional rule matched in the same evaluation (confirmed
                        // live: a file matching both "US Social Security Number
                        // (SSN)" and "Credit Card Number" only ever logged "Credit
                        // Card Number"). Doesn't affect the block/allow decision --
                        // that comes from the separate top-level "action" field --
                        // but it under-reported detected data types in the agent
                        // log. Now uses the same depth-aware FindMatchingBracket
                        // helper already used for the outer classification object.
                        size_t rulesPos = classificationObj.find("\"matched_rules\"");
                        if (rulesPos != std::string::npos) {
                            size_t arrayStart = classificationObj.find("[", rulesPos);
                            size_t arrayEnd = (arrayStart != std::string::npos)
                                ? FindMatchingBracket(classificationObj, arrayStart, '[', ']')
                                : std::string::npos;
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
            result.evaluationSucceeded = !config.GetClassification().blockOnDlpError;
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
                        // CRITICAL FIX: dispatch on the actual action string
                        // ("block" / "quarantine" / "allow"), not just the
                        // shouldBlock bool — that only recognized "block",
                        // so a quarantine-actioned policy always fell into
                        // the "allowed" branch below with zero enforcement.
                        if (evalResult.action == "block") {
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
                        } else if (evalResult.action == "quarantine") {
                            logger.Warning("============================================================");
                            logger.Warning("  ⚠️ CONTENT-AWARE QUARANTINE TRIGGERED!");
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

                            HandleUSBFileTransferQuarantineNoTimestamp(fileName, meta.relativePath, drivePath,
                                                           matchedMonitoredPath, policy);
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

        // PASS 2: Classify ALL new files on USB — only for policies that have no
        // monitoredPaths (classification-only / "scan everything" policies).
        // Path-based policies are handled exclusively in PASS 1 above.
        // Without this guard PASS 2 was firing for path-based policies too,
        // producing duplicate / false-positive events.
        if (hasClassificationOnlyPolicies)
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
                    } else if (evalResult.action == "block") {
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
                    } else if (evalResult.action == "quarantine") {
                        // CRITICAL FIX: this branch didn't exist before —
                        // "quarantine" was falling through to the ALLOWED
                        // branch below (evalResult.shouldBlock only ever
                        // recognized "block"), so a quarantine policy's
                        // real-time evaluation never actually quarantined
                        // anything.
                        logger.Warning("⚠️ CONTENT-AWARE QUARANTINE: " + fileName +
                                      " (" + evalResult.classificationLevel + " " +
                                      std::to_string(static_cast<int>(evalResult.confidenceScore * 100)) + "%)");
                        HandleUSBFileTransferQuarantineNoTimestamp(
                            fileName, fileName, drivePath, drivePath, policy);
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

// Windows Explorer (and some antivirus real-time scanners) briefly hold a
// file handle open immediately after a copy operation completes -- observed
// directly in production: a file freshly copied to a USB drive is detected
// by the directory watcher and a block attempted within ~1ms of the copy
// finishing, well within the window Explorer can still hold the handle.
// fs::remove()/fs::copy_file() then throw "The process cannot access the
// file because it is being used by another process" (ERROR_SHARING_VIOLATION,
// win32 code 32) even though the file is completely free a couple hundred
// milliseconds later. Without a retry this is a PERMANENT enforcement
// failure on every single block/quarantine of a just-copied file, not a
// rare edge case -- the race is the common case, not the exception, because
// the whole point of this code path is to react to a copy the instant it's
// detected. Retrying briefly turns this into a transparent, near-instant
// success in the overwhelming majority of cases while still surfacing a
// real error (via the thrown filesystem_error, same as before) if the file
// is genuinely stuck locked for longer than ~1 second.
static void RemoveFileWithRetry(const fs::path& path, int maxAttempts = 5, int delayMs = 200) {
    std::error_code lastError;
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        fs::remove(path, lastError);
        if (!lastError) return;
        if (attempt < maxAttempts) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    }
    throw fs::filesystem_error("cannot remove after " + std::to_string(maxAttempts) + " retries", path, lastError);
}

static void CopyFileWithRetry(const fs::path& from, const fs::path& to, fs::copy_options options,
                               int maxAttempts = 5, int delayMs = 200) {
    std::error_code lastError;
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        fs::copy_file(from, to, options, lastError);
        if (!lastError) return;
        if (attempt < maxAttempts) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    }
    throw fs::filesystem_error("cannot copy after " + std::to_string(maxAttempts) + " retries", from, to, lastError);
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
            RemoveFileWithRetry(usbFile);
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
            CopyFileWithRetry(usbFile, monitoredFile, fs::copy_options::overwrite_existing);
            logger.Warning("  ✅ Restored to monitored directory");

            RemoveFileWithRetry(usbFile);
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
    // Fallback default must match the actual configured quarantine root
    // (C:\ProgramData\SeceoKnight\quarantine) used everywhere else in the
    // agent — a mismatched fallback of C:\Quarantine here silently sent
    // files to a folder the user never checks, for any policy (e.g. a
    // classification-only "scan everything" policy, which is the one that
    // fires for a fresh screenshot with no monitoredPaths) that doesn't
    // have an explicit quarantinePath configured on the server.
    std::string quarantinePath = policy.quarantinePath.empty() ? "C:\\ProgramData\\SeceoKnight\\quarantine" : policy.quarantinePath;
    std::string quarantineFile = quarantinePath + "\\" + fileName + "_" + timestamp;

    if (!fs::exists(usbFile)) return;

    bool existsInMonitored = fs::exists(monitoredFile);

    logger.Warning("============================================================");
    logger.Warning("  ⚠️ USB FILE TRANSFER QUARANTINED!");
    logger.Warning("============================================================");
    logger.Warning("  File: " + relativePath);
    logger.Warning("  Policy: " + policy.name);
    logger.Warning("  Severity: " + policy.severity);
    logger.Warning("  Quarantine destination: " + quarantineFile);

    // DO NOT SET TIMESTAMP HERE - already set in CheckUSBDriveForMonitoredFiles

    try {
        // Ensure quarantine directory exists
        fs::create_directories(quarantinePath);

        std::string transferType;
        if (existsInMonitored) {
            // File was COPIED
            transferType = "copy";
            logger.Warning("  Transfer Type: COPY");

            // CRITICAL FIX: fs::rename() maps to MoveFileExW() on this MinGW
            // build without MOVEFILE_COPY_ALLOWED, which FAILS across volumes
            // (e.g. USB drive E:\ -> local C:\ quarantine folder) with
            // ERROR_NOT_SAME_DEVICE, throwing here silently for the common
            // case of a classification-only policy (no monitoredPaths), where
            // monitoredFile and usbFile are literally the same USB-drive path.
            // copy_file + remove works reliably regardless of volume, and
            // matches the pattern already used by the BLOCK handler's MOVE
            // case for the same reason.
            CopyFileWithRetry(monitoredFile, quarantineFile, fs::copy_options::overwrite_existing);
            RemoveFileWithRetry(monitoredFile);
            logger.Warning("  ✅ Moved to quarantine from monitored dir");

            // Delete from USB (no-op if monitoredFile == usbFile, already removed above)
            if (fs::exists(usbFile)) {
                RemoveFileWithRetry(usbFile);
            }
            logger.Warning("  ✅ Deleted from USB");
        } else {
            // File was MOVED
            transferType = "move";
            logger.Warning("  Transfer Type: MOVE");

            // Move from USB to quarantine (see comment above — copy+remove,
            // not rename, for cross-volume safety)
            CopyFileWithRetry(usbFile, quarantineFile, fs::copy_options::overwrite_existing);
            RemoveFileWithRetry(usbFile);
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
                    // copy+remove, not rename — rename() maps to MoveFileExW()
                    // without MOVEFILE_COPY_ALLOWED on this build, which fails
                    // across volumes (quarantine on C:\ back to a USB drive).
                    // If the USB drive was removed, copy_file throws and is
                    // caught below, leaving the file safely in quarantine.
                    fs::copy_file(quarantineFile, monitoredFile, fs::copy_options::overwrite_existing);
                    fs::remove(quarantineFile);
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

// The binary is built with the Windows GUI subsystem (see build.sh /
// build-windows-agent.yml, -mwindows) specifically so that no console
// window is ever created automatically when the OS starts the process.
//
// This used to be built as a console-subsystem app that relied on
// GetConsoleWindow() + ShowWindow(SW_HIDE) to *hide* a window after the
// fact — but Windows creates and shows a console-subsystem process's
// console the instant the process starts, before main() ever runs. That
// meant --bg mode always had a real, visible console window for at least
// a moment (longer if startup was slowed by antivirus, or if the hide
// call raced GetConsoleWindow() returning NULL before the console had
// finished attaching under Task Scheduler). Because it was the process's
// own console, a user who saw and closed that window fired
// CTRL_CLOSE_EVENT, which tore down the whole agent — exactly the
// "closing the log window disconnects the agent" symptom this fixes.
//
// With the GUI subsystem, no console exists at all unless we explicitly
// ask for one — which we now only do in foreground/manual-run mode, for
// debugging. Background mode (the scheduled-task launch path) never
// allocates one, so there is no window for a user to ever see or close.
void AttachForegroundConsole() {
    if (AllocConsole()) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        freopen("CONIN$", "r", stdin);
        std::ios::sync_with_stdio(true);
    }
}

void ShowUsage() {
    std::cout << "Usage: seceoknight_agent.exe [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -background, --background, -bg, --bg, bg\n";
    std::cout << "                        Run agent in background mode (no console output)\n";
    std::cout << "  -h, --help            Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  seceoknight_agent.exe\n";
    std::cout << "  seceoknight_agent.exe -background\n";
    std::cout << "  seceoknight_agent.exe --bg\n\n";
}

// Resolve a filename relative to THIS executable's own directory, not the
// current working directory. Needed by HandleBlockedLaunch() below: it may
// run with an unpredictable CWD (launched via the IFEO Debugger mechanism in
// place of fsquirt.exe, not by our own service/scheduled-task launcher that
// normally sets the working directory), so the plain relative
// "agent_config.json" default AgentConfig() otherwise uses cannot be trusted
// here. Ported from CyberSentinel-DLP's equivalent helper.
std::string ExeRelativePath(const std::string& filename) {
    char exePath[MAX_PATH] = {0};
    DWORD len = GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    if (len == 0 || len == MAX_PATH) return filename;   // fall back to relative
    std::string path(exePath, len);
    size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) return filename;
    return path.substr(0, slash + 1) + filename;
}

// Invoked when Windows launches us in place of fsquirt.exe (the Bluetooth file
// transfer wizard) via the IFEO Debugger set by the wireless-control policy
// (see ApplyWirelessControls()/SetIFEODebugger() above). That means a user
// tried a Bluetooth file transfer while it is blocked. Log it + raise a
// dashboard event, then return WITHOUT running fsquirt so the transfer is
// blocked. Runs briefly as the user who launched fsquirt; must never hang or
// crash -- any failure here should silently fall through to "blocked, no
// event" rather than let fsquirt run. Ported from CyberSentinel-DLP.
int HandleBlockedLaunch(int argc, char* argv[]) {
    try {
        // Everything after --blocked-launch is the original fsquirt path + args.
        std::string attempt;
        for (int i = 1; i < argc; i++) {
            if (std::string(argv[i]) == "--blocked-launch") {
                for (int j = i + 1; j < argc; j++) { if (!attempt.empty()) attempt += " "; attempt += argv[j]; }
                break;
            }
        }
        char uname[256]; DWORD un = sizeof(uname);
        std::string username = GetUserNameA(uname, &un) ? std::string(uname) : "unknown";

        // Local audit line (best-effort -- may be unwritable for a standard user).
        try {
            Logger logger;
            logger.Warning("BLUETOOTH_TRANSFER_BLOCKED user=" + username +
                           " attempt=" + (attempt.empty() ? "fsquirt" : attempt));
        } catch (...) {}

        // Dashboard event (the reliable audit record -- HTTP needs no file perms).
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);   // GenerateUUID -> CoCreateGuid
        AgentConfig cfg(ExeRelativePath("agent_config.json"));
        JsonBuilder json;
        json.AddString("event_id", GenerateUUID());
        json.AddString("event_type", "bluetooth_file_transfer");
        json.AddString("event_subtype", "bluetooth_file_transfer");
        json.AddString("severity", "high");
        json.AddString("agent_id", cfg.agentId);
        json.AddString("source_type", "endpoint");
        json.AddString("action", "blocked");
        json.AddString("block_reason", "wireless_control");
        json.AddString("destination_type", "bluetooth");
        json.AddString("user_email", username);
        json.AddString("description",
                       "Bluetooth file transfer blocked by wireless control policy (user " + username + ")");
        try {
            HttpClient client(cfg.serverUrl);
            client.Post("/events", json.Build());
        } catch (...) {}
        CoUninitialize();
    } catch (...) {}
    return 0;   // never run fsquirt
}

// Invoked when Windows launches us in place of a CLI Guard-scoped tool
// (curl.exe, wget.exe, rclone.exe, s3cmd.exe, azcopy.exe, aws.exe, scp.exe,
// pscp.exe, winscp.com) via the IFEO Debugger set by ApplyCliGuardIfeo()
// (task #142/#143). Unlike HandleBlockedLaunch() above (fsquirt is ALWAYS
// blocked), most invocations here must actually run: we ask the running
// agent service for a verdict over \\.\pipe\SeceoKnightCliGuard, then either
// exit immediately without ever starting the real binary (block -- zero
// bytes ever leave the machine, no race window at all) or launch a
// randomly-named TEMP COPY of the real binary with the original arguments
// and relay its exit code (allow -- transparent to the calling script).
//
// The temp-copy step exists solely to avoid infinite IFEO recursion: IFEO
// redirects by filename only, so calling CreateProcess on the ORIGINAL path
// again would just redirect back to us. A copy under a different name is
// not intercepted.
//
// MUST fail open (launch the real binary, unmodified) on every error path --
// pipe unreachable, timeout, unexpected exception -- so a problem with the
// agent service (stopped, restarting, etc.) can never leave the user unable
// to run these tools. Only a failure to even STAGE the copy (disk full,
// permissions) genuinely fails the call, with a clear error to stderr,
// rather than risk looping back through IFEO again.
int HandleCliGuard(int argc, char* argv[]) {
    // Everything after --cli-guard is: <real exe full path> <original args...>
    std::vector<std::string> parts;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--cli-guard") {
            for (int j = i + 1; j < argc; j++) parts.push_back(argv[j]);
            break;
        }
    }
    if (parts.empty()) return 1;   // nothing to do -- shouldn't happen

    std::string realExePath = parts[0];

    auto quoteIfNeeded = [](const std::string& s) {
        if (s.find_first_of(" \t\"") == std::string::npos) return s;
        std::string out = "\"";
        for (char c : s) { if (c == '"') out += "\\\""; else out += c; }
        out += "\"";
        return out;
    };

    std::string exeNameOnly = realExePath;
    {
        size_t slash = exeNameOnly.find_last_of("\\/");
        if (slash != std::string::npos) exeNameOnly = exeNameOnly.substr(slash + 1);
    }
    std::string exeNameLower = exeNameOnly;
    std::transform(exeNameLower.begin(), exeNameLower.end(), exeNameLower.begin(), ::tolower);

    std::string fullArgs = quoteIfNeeded(realExePath);
    for (size_t i = 1; i < parts.size(); i++) { fullArgs += " "; fullArgs += quoteIfNeeded(parts[i]); }

    // --- Ask the running agent service for a verdict (fail OPEN on any error) ---
    bool block = false;
    {
        const char* pipeName = "\\\\.\\pipe\\SeceoKnightCliGuard";
        std::string msg = exeNameLower + '\x01' + fullArgs;
        HANDLE hPipe = INVALID_HANDLE_VALUE;
        DWORD start = GetTickCount();
        const DWORD kConnectTimeoutMs = 800;
        while (true) {
            hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
            if (hPipe != INVALID_HANDLE_VALUE) break;
            if (GetLastError() != ERROR_PIPE_BUSY) break;   // no server -> fail open
            if (GetTickCount() - start > kConnectTimeoutMs) break;
            if (!WaitNamedPipeA(pipeName, 200)) break;
        }

        if (hPipe != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);
            DWORD written = 0;
            if (WriteFile(hPipe, msg.data(), (DWORD)msg.size(), &written, nullptr)) {
                char reply = 'A';
                DWORD bytesRead = 0;
                if (ReadFile(hPipe, &reply, 1, &bytesRead, nullptr) && bytesRead == 1) {
                    block = (reply == 'B');
                }
            }
            CloseHandle(hPipe);
        }
        // else: pipe unreachable (service not running/starting up yet) -- fail open
    }

    if (block) {
        return 0;   // zero-race block: the real binary never starts
    }

    // --- Allow: launch a temp-named copy of the real binary, relay its exit code ---
    char tempDir[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, tempDir);
    std::string tempCopyPath = std::string(tempDir) + "sk_" +
                               std::to_string(GetCurrentProcessId()) + "_" + exeNameOnly;

    if (!CopyFileA(realExePath.c_str(), tempCopyPath.c_str(), FALSE)) {
        DWORD err = GetLastError();
        std::cerr << "seceoknight_agent (cli-guard): failed to stage " << exeNameOnly
                  << " for execution (error " << err << "). This is a SeceoKnight DLP "
                  << "agent issue, not a problem with " << exeNameOnly << " itself."
                  << std::endl;
        return (int)err;
    }

    std::string cmdLine = quoteIfNeeded(tempCopyPath);
    for (size_t i = 1; i < parts.size(); i++) { cmdLine += " "; cmdLine += quoteIfNeeded(parts[i]); }

    STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    std::vector<char> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back('\0');

    DWORD exitCode = 1;
    if (CreateProcessA(tempCopyPath.c_str(), cmdBuf.data(), nullptr, nullptr,
                        TRUE /* inherit our (already-inherited) console/stdio handles */,
                        0, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        std::cerr << "seceoknight_agent (cli-guard): failed to launch " << exeNameOnly
                  << " (error " << GetLastError() << ")" << std::endl;
    }

    DeleteFileA(tempCopyPath.c_str());   // best-effort cleanup
    return (int)exitCode;
}

// Elevated one-shot mode (task #142/#145): registers the CLI Guard IFEO
// "Debugger" redirects. Exists because the main "SeceoKnight DLP Agent"
// scheduled task runs UNELEVATED on purpose (clipboard hooks/keyboard-mouse
// monitoring/UIA all silently break under Windows UIPI if it runs elevated
// -- see install-agent.ps1's principal comment), so it can never itself
// write these HKLM keys: confirmed live, RegCreateKeyExA returns
// ACCESS_DENIED from that process every time, because a standard user's
// token only has ReadKey on that registry path. Mirrors the existing
// USB-block fix for the identical problem: a SEPARATE SYSTEM/Highest
// one-shot scheduled task ("SeceoKnight DLP CLI Guard") runs
// `seceoknight_agent.exe --apply-ifeo-guards` at startup instead of
// elevating the main task.
int HandleApplyIfeoGuards(int /*argc*/, char* /*argv*/[]) {
    Logger logger;
    int okCount = 0, failCount = 0;
    try {
        char selfPath[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
        std::string dbg = std::string("\"") + selfPath + "\" --cli-guard";

        for (const auto& exeName : NetworkExfilMonitor::IfeoScopedExecutables()) {
            std::string sub = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                              "Image File Execution Options\\" + exeName;
            HKEY k;
            LSTATUS rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, nullptr,
                                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &k, nullptr);
            if (rc != ERROR_SUCCESS) {
                try { logger.Error("apply-ifeo-guards: RegCreateKeyExA failed for " + exeName +
                                   " rc=" + std::to_string(rc) +
                                   " (this task should be running as SYSTEM/Highest -- check "
                                   "the scheduled task's principal if this persists)"); } catch (...) {}
                failCount++;
                continue;
            }
            LSTATUS rc2 = RegSetValueExA(k, "Debugger", 0, REG_SZ,
                                         reinterpret_cast<const BYTE*>(dbg.c_str()),
                                         (DWORD)dbg.size() + 1);
            RegCloseKey(k);
            if (rc2 != ERROR_SUCCESS) {
                try { logger.Error("apply-ifeo-guards: RegSetValueExA failed for " + exeName +
                                   " rc=" + std::to_string(rc2)); } catch (...) {}
                failCount++;
            } else {
                try { logger.Info("apply-ifeo-guards: Debugger set for " + exeName); } catch (...) {}
                okCount++;
            }
        }
        try {
            logger.Info("apply-ifeo-guards: complete -- " + std::to_string(okCount) +
                        " succeeded, " + std::to_string(failCount) + " failed");
        } catch (...) {}
    } catch (const std::exception& e) {
        try { logger.Error(std::string("apply-ifeo-guards: exception: ") + e.what()); } catch (...) {}
        return 1;
    } catch (...) {
        try { logger.Error("apply-ifeo-guards: unknown exception"); } catch (...) {}
        return 1;
    }
    return failCount > 0 ? 1 : 0;
}

// Elevated periodic mode (task #147): applies the Bluetooth fsquirt.exe IFEO
// redirect + Nearby Sharing/CDP policy DWORD from the state cache the main
// (unelevated) process writes in FetchWirelessPolicy(). Exists for the exact
// same reason as HandleApplyIfeoGuards() above -- the main task cannot write
// these HKLM keys itself (confirmed live: ACCESS_DENIED rc=5) -- but unlike
// CLI Guard's static, set-once-at-startup registration, wireless control is
// policy-driven and can change at any time, so this needs to run
// PERIODICALLY (registered as a repeating SYSTEM/Highest scheduled task,
// "SeceoKnight DLP Wireless Guard") rather than once at startup.
//
// Reads a simple "enforce|blockBt|blockNearby" (1/0 chars) line rather than
// JSON -- deliberately minimal, no parser dependency for three booleans.
// If the cache file doesn't exist yet (agent hasn't completed its first
// sync since install), does nothing and exits cleanly -- applying a
// guessed/default state would risk enforcing (or failing to enforce) the
// wrong thing before the real policy is even known.
int HandleApplyWirelessGuard(int /*argc*/, char* /*argv*/[]) {
    Logger logger;
    try {
        const char* envLogDir = std::getenv("SECEOKNIGHT_LOG_DIR");
        std::string dir = envLogDir ? envLogDir : "C:\\ProgramData\\SeceoKnight\\logs";
        std::string cachePath = dir + "\\wireless_state.cache";

        std::error_code ec;
        if (!fs::exists(cachePath, ec) || ec) {
            logger.Info("apply-wireless-guard: no state cache yet (agent hasn't synced "
                        "with the server since install) -- nothing to apply this run");
            return 0;
        }

        std::ifstream f(cachePath, std::ios::binary);
        if (!f.is_open()) {
            logger.Warning("apply-wireless-guard: could not open state cache " + cachePath);
            return 1;
        }
        std::string line;
        std::getline(f, line);
        if (line.size() < 5 || line[1] != '|' || line[3] != '|') {
            logger.Warning("apply-wireless-guard: malformed state cache content: " + line);
            return 1;
        }
        bool enforce     = line[0] == '1';
        bool blockBt     = line[2] == '1';
        bool blockNearby = line[4] == '1';

        // --- fsquirt.exe IFEO redirect ---
        char selfPath[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
        std::string dbg = std::string("\"") + selfPath + "\" --blocked-launch";
        bool blockBtNow = enforce && blockBt;

        std::string ifeoSub = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                              "Image File Execution Options\\fsquirt.exe";
        if (blockBtNow) {
            HKEY k;
            LSTATUS rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, ifeoSub.c_str(), 0, nullptr,
                                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &k, nullptr);
            if (rc != ERROR_SUCCESS) {
                logger.Error("apply-wireless-guard: RegCreateKeyExA failed for fsquirt.exe rc=" +
                            std::to_string(rc) + " (this task should be running as SYSTEM/Highest "
                            "-- check the scheduled task's principal if this persists)");
            } else {
                LSTATUS rc2 = RegSetValueExA(k, "Debugger", 0, REG_SZ,
                                             reinterpret_cast<const BYTE*>(dbg.c_str()),
                                             (DWORD)dbg.size() + 1);
                RegCloseKey(k);
                if (rc2 != ERROR_SUCCESS) {
                    logger.Error("apply-wireless-guard: RegSetValueExA failed for fsquirt.exe rc=" +
                                std::to_string(rc2));
                } else {
                    logger.Info("apply-wireless-guard: fsquirt.exe IFEO block applied");
                }
            }
        } else {
            HKEY k;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ifeoSub.c_str(), 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
                RegDeleteValueA(k, "Debugger");
                RegCloseKey(k);
                logger.Info("apply-wireless-guard: fsquirt.exe IFEO block cleared (allowed)");
            }
        }

        // --- Nearby Sharing / Connected Devices Platform policy ---
        std::string cdpSub = "SOFTWARE\\Policies\\Microsoft\\Windows\\System";
        bool blockNearbyNow = enforce && blockNearby;
        if (blockNearbyNow) {
            HKEY k;
            LSTATUS rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, cdpSub.c_str(), 0, nullptr,
                                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &k, nullptr);
            if (rc != ERROR_SUCCESS) {
                logger.Error("apply-wireless-guard: RegCreateKeyExA failed for EnableCdp rc=" +
                            std::to_string(rc));
            } else {
                DWORD zero = 0;
                LSTATUS rc2 = RegSetValueExA(k, "EnableCdp", 0, REG_DWORD,
                                             reinterpret_cast<const BYTE*>(&zero), sizeof(zero));
                RegCloseKey(k);
                if (rc2 != ERROR_SUCCESS) {
                    logger.Error("apply-wireless-guard: RegSetValueExA failed for EnableCdp rc=" +
                                std::to_string(rc2));
                } else {
                    logger.Info("apply-wireless-guard: Nearby Sharing (CDP) blocked");
                }
            }
        } else {
            HKEY k;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, cdpSub.c_str(), 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
                RegDeleteValueA(k, "EnableCdp");
                RegCloseKey(k);
                logger.Info("apply-wireless-guard: Nearby Sharing (CDP) restored (allowed)");
            }
        }

        logger.Debug("apply-wireless-guard: complete -- enforce=" + std::string(enforce ? "true" : "false") +
                    " bt=" + std::string(blockBt ? "block" : "allow") +
                    " nearby=" + std::string(blockNearby ? "block" : "allow"));
    } catch (const std::exception& e) {
        try { logger.Error(std::string("apply-wireless-guard: exception: ") + e.what()); } catch (...) {}
        return 1;
    } catch (...) {
        try { logger.Error("apply-wireless-guard: unknown exception"); } catch (...) {}
        return 1;
    }
    return 0;
}

// Elevated watchdog hook (ported from CyberSentinel-DLP gap-scan, Aug 18
// 2026): the repeating SYSTEM/Highest "SeceoKnight DLP Watchdog" scheduled
// task install-agent.ps1 registers now invokes THIS EXE with this flag,
// replacing the old `wscript.exe watchdog_launcher.vbs` action.
//
// Why the .vbs had to go entirely, not just get patched again: it was
// already on its fourth console-flash fix (see install-agent.ps1's Step 9b
// history) and STILL silently failed end to end on real Windows 11
// endpoints running Application Control / Smart App Control, which block
// script hosts (wscript.exe/cscript.exe) by default -- "An Application
// Control policy has blocked this file" (0x800711C7), the exact same
// symptom CyberSentinel-DLP hit and fixed on ITS main launch task. There
// was no console flash to observe in that failure mode -- the task simply
// never ran, which meant the hang-detector this task exists to provide had
// been silently disabled on every endpoint under that policy, with no
// symptom short of noticing a hung agent stayed hung. A script host was
// never actually necessary here; the same "run the exe directly" fix
// applies once the exe itself has somewhere to put the check.
//
// This exe is already the one binary Application Control has to allow on
// this endpoint, and it's GUI-subsystem already (see
// AttachForegroundConsole further up), so invoking it in place of the
// script host produces the same "zero console, ever" property the .vbs was
// built four times over to get, with no script interpreter left for a
// policy to block. RunHiddenCommand() below still shells out to
// taskkill.exe/schtasks.exe on the rare unhealthy path -- both are
// Microsoft-signed System32 utilities, not script hosts, and were never
// what any of these policies target.
//
// Logic is a direct port of watchdog_launcher.vbs's: not running -> no-op;
// within a startup grace period -> no-op; otherwise stale main-agent log
// (no write in kStaleThresholdMinutes) -> force-kill + re-trigger the main
// task. The one deliberate behavior change is using the found process's
// own creation time for the grace check instead of the scheduled task's
// LastRunTime (avoids a dependency on Task Scheduler bookkeeping being
// accurate) and killing by exact PID instead of `taskkill /IM` (precise to
// the one hung instance instead of every process sharing the image name).
int HandleWatchdogCheck(int /*argc*/, char* /*argv*/[]) {
    // Deliberately NOT the default Logger() -- that opens
    // seceoknight_agent.log, which is the exact file this function reads
    // the mtime of to decide whether the main agent has hung. Writing to
    // it here would refresh its mtime on every 5-minute watchdog tick,
    // making the log look perpetually "fresh" and permanently defeating
    // the staleness check it exists to make. Uses its own separate file,
    // same as the .vbs launcher this replaces did.
    Logger logger("watchdog.log");

    try {
        const char* envLogDir = std::getenv("SECEOKNIGHT_LOG_DIR");
        std::string logDir = envLogDir ? envLogDir : "C:\\ProgramData\\SeceoKnight\\logs";
        std::string mainLogPath = logDir + "\\seceoknight_agent.log";

        const std::string kTaskName = "SeceoKnight DLP Agent";
        const std::string kExeName  = "seceoknight_agent.exe";
        const double kStaleThresholdMinutes = 3.0;
        const double kGraceMinutesAfterStart = 2.0;

        DWORD selfPid = GetCurrentProcessId();

        // Find the (single) OTHER seceoknight_agent.exe process -- the
        // main, long-running instance. This invocation is also named
        // seceoknight_agent.exe (--watchdog-check), so selfPid is excluded.
        DWORD mainPid = 0;
        FILETIME mainCreationTime = {};
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = {};
            pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) {
                do {
                    if (pe.th32ProcessID != selfPid &&
                        _stricmp(pe.szExeFile, kExeName.c_str()) == 0) {
                        mainPid = pe.th32ProcessID;
                        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, mainPid);
                        if (hp) {
                            FILETIME ftExit = {}, ftKernel = {}, ftUser = {};
                            GetProcessTimes(hp, &mainCreationTime, &ftExit, &ftKernel, &ftUser);
                            CloseHandle(hp);
                        }
                        break;
                    }
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }

        if (mainPid == 0) {
            // Not running at all -- the main task's own logon/startup/
            // 10-minute-repeat triggers own recovery here, not this check.
            return 0;
        }

        FILETIME nowFt = {};
        GetSystemTimeAsFileTime(&nowFt);
        ULARGE_INTEGER now = {};
        now.LowPart = nowFt.dwLowDateTime;
        now.HighPart = nowFt.dwHighDateTime;

        bool withinGrace = false;
        if (mainCreationTime.dwLowDateTime || mainCreationTime.dwHighDateTime) {
            ULARGE_INTEGER start = {};
            start.LowPart = mainCreationTime.dwLowDateTime;
            start.HighPart = mainCreationTime.dwHighDateTime;
            double minutesSinceStart = static_cast<double>(now.QuadPart - start.QuadPart) / 10000000.0 / 60.0;
            withinGrace = minutesSinceStart < kGraceMinutesAfterStart;
        }

        // FILETIME arithmetic throughout (not std::filesystem's clock,
        // which isn't reliably comparable against wall-clock time pre-
        // C++20) -- same idiom CompareFileTime() usage elsewhere in this
        // file already relies on.
        bool isStale = false;
        WIN32_FILE_ATTRIBUTE_DATA fad = {};
        if (!GetFileAttributesExA(mainLogPath.c_str(), GetFileExInfoStandard, &fad)) {
            // Hasn't written its first log line yet -- only suspicious
            // once it's had long enough to do so.
            isStale = !withinGrace;
        } else {
            ULARGE_INTEGER lw = {};
            lw.LowPart = fad.ftLastWriteTime.dwLowDateTime;
            lw.HighPart = fad.ftLastWriteTime.dwHighDateTime;
            double minutesStale = static_cast<double>(now.QuadPart - lw.QuadPart) / 10000000.0 / 60.0;
            isStale = minutesStale >= kStaleThresholdMinutes && !withinGrace;
        }

        if (!isStale) {
            return 0;
        }

        logger.Warning("agent appeared hung (pid " + std::to_string(mainPid) +
                        ", log stale >= " + std::to_string(static_cast<int>(kStaleThresholdMinutes)) +
                        " min); force-restarting");

        // Kill by PID, not `/IM` -- precise to the one hung instance,
        // doesn't risk taking out this watchdog-check invocation or a
        // legitimate second instance mid-handover. Restart goes through
        // Task Scheduler (schtasks /Run) rather than launching the exe
        // directly, so the main task's own bookkeeping (RestartCount,
        // LastRunTime, "already running" state) stays consistent.
        RunHiddenCommand("taskkill.exe /F /PID " + std::to_string(mainPid));
        std::this_thread::sleep_for(std::chrono::seconds(2));
        RunHiddenCommand("schtasks.exe /Run /TN \"" + kTaskName + "\"");

        logger.Info("force-restart issued for pid " + std::to_string(mainPid));
    } catch (const std::exception& e) {
        try { logger.Error(std::string("watchdog-check: exception: ") + e.what()); } catch (...) {}
        return 1;
    } catch (...) {
        try { logger.Error("watchdog-check: unknown exception"); } catch (...) {}
        return 1;
    }
    return 0;
}

// Put "<id>;<update_url>" in the browser's force-install list, reusing our
// own slot if we already own one.
//
// Chrome reads every value under the key regardless of its name, but the
// documented convention is small integers and other tooling assumes it. So:
// find the entry that already starts with our extension id and overwrite
// it, otherwise take the lowest free integer. Blindly appending would leave
// a stale entry behind on every server change, and the browser would then
// try to install both.
static void SetExtensionForcelistEntry(Logger& logger, const std::string& policyRoot,
                                       const std::string& extId, const std::string& updateUrl) {
    std::string sub = policyRoot + "\\ExtensionInstallForcelist";
    HKEY k;
    LSTATUS rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, nullptr,
                                 REG_OPTION_NON_VOLATILE, KEY_READ | KEY_SET_VALUE,
                                 nullptr, &k, nullptr);
    if (rc != ERROR_SUCCESS) {
        logger.Error("apply-browser-extension-guard: RegCreateKeyExA failed for " + sub +
                    " rc=" + std::to_string(rc) + " (this task should be running as "
                    "SYSTEM/Highest -- check the scheduled task's principal if this persists)");
        return;
    }

    std::string slot;
    std::set<std::string> used;
    char nameBuf[256];
    BYTE dataBuf[1024];
    for (DWORD i = 0; ; i++) {
        DWORD nameLen = sizeof(nameBuf);
        DWORD dataLen = sizeof(dataBuf);
        DWORD type = 0;
        if (RegEnumValueA(k, i, nameBuf, &nameLen, nullptr, &type,
                          dataBuf, &dataLen) != ERROR_SUCCESS) {
            break;
        }
        std::string vname(nameBuf, nameLen);
        used.insert(vname);
        if (type == REG_SZ && dataLen > 0) {
            std::string vdata(reinterpret_cast<char*>(dataBuf));
            if (vdata.rfind(extId + ";", 0) == 0) slot = vname;
        }
    }
    if (slot.empty()) {
        for (int n = 1; n < 500; n++) {
            std::string cand = std::to_string(n);
            if (used.find(cand) == used.end()) { slot = cand; break; }
        }
    }
    if (slot.empty()) slot = "1";

    std::string entry = extId + ";" + updateUrl;
    LSTATUS rc2 = RegSetValueExA(k, slot.c_str(), 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(entry.c_str()),
                                 (DWORD)entry.size() + 1);
    RegCloseKey(k);
    if (rc2 != ERROR_SUCCESS) {
        logger.Error("apply-browser-extension-guard: RegSetValueExA failed for " + sub +
                    " rc=" + std::to_string(rc2));
    } else {
        logger.Info("apply-browser-extension-guard: force-install entry set under " +
                    policyRoot + " (slot " + slot + ")");
    }
}

// Set a REG_SZ policy string under HKLM\<root>\3rdparty\extensions\<id>\policy,
// which the extension reads through chrome.storage.managed. agentId is what
// keeps a device running both the endpoint agent and the extension as ONE
// row on the dashboard instead of two.
static void SetExtensionManagedString(Logger& logger, const std::string& sub,
                                      const std::string& name, const std::string& value) {
    if (value.empty()) return;
    HKEY k;
    LSTATUS rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, nullptr,
                                 REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &k, nullptr);
    if (rc != ERROR_SUCCESS) {
        logger.Error("apply-browser-extension-guard: RegCreateKeyExA failed for " + sub +
                    " rc=" + std::to_string(rc));
        return;
    }
    LSTATUS rc2 = RegSetValueExA(k, name.c_str(), 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(value.c_str()),
                                 (DWORD)value.size() + 1);
    RegCloseKey(k);
    if (rc2 != ERROR_SUCCESS) {
        logger.Error("apply-browser-extension-guard: RegSetValueExA failed for " + sub +
                    "\\" + name + " rc=" + std::to_string(rc2));
    }
}

// Writes the native-messaging host manifest (com.seceoknightdlp.dlp.json)
// and registers it for Chrome + Edge (HKLM, machine-wide), pointing at the
// skdlp_host.exe that install-agent.ps1 now downloads alongside the main
// agent binary (see Step 5 of install-agent.ps1). This is the C++ port of
// the manual agents/browser-extension/native-host/install.ps1 flow -- that
// script (and its README Step 5.4) documented a per-machine, by-hand run
// requiring Python + PyInstaller on every endpoint; this makes the same
// registration happen automatically, from the same elevated, repeating
// Browser Extension Guard task as the forcelist entry below. A republished
// extension (new id) or a changed server URL propagates here within one
// tick of that task too, same as the forcelist entry -- no separate script
// to remember to re-run.
static void WriteNativeMessagingHostRegistration(Logger& logger, const std::string& extId) {
    const std::string dir = "C:\\ProgramData\\SeceoKnight";
    std::error_code ec;
    fs::create_directories(dir, ec);

    const std::string hostExePath = "C:\\Program Files\\SeceoKnight\\skdlp_host.exe";
    const std::string manifestPath = dir + "\\com.seceoknightdlp.dlp.json";

    std::error_code existsEc;
    if (!fs::exists(hostExePath, existsEc) || existsEc) {
        // install-agent.ps1 downloads this alongside seceoknight_agent.exe;
        // if it's missing (an install/update that predates this feature and
        // hasn't run manage-agent.ps1's Update yet), skip rather than
        // registering a manifest that points at nothing -- the next
        // successful Update-Agent run fixes this and this function will
        // pick it up on its next 2-minute tick.
        logger.Debug("apply-browser-extension-guard: skdlp_host.exe not present at " +
                     hostExePath + " yet -- skipping native-host registration this run");
        return;
    }

    JsonBuilder jb;
    jb.AddString("name", "com.seceoknightdlp.dlp");
    jb.AddString("description", "SeceoKnight DLP native messaging host");
    jb.AddString("path", hostExePath);
    jb.AddString("type", "stdio");
    std::vector<std::string> origins = { "chrome-extension://" + extId + "/" };
    jb.AddArray("allowed_origins", origins);
    std::string manifestJson = jb.Build();

    std::ofstream mf(manifestPath, std::ios::trunc | std::ios::binary);
    if (!mf.is_open()) {
        logger.Warning("apply-browser-extension-guard: could not write " + manifestPath);
        return;
    }
    mf << manifestJson;
    mf.close();

    const std::string roots[] = {
        "SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\com.seceoknightdlp.dlp",
        "SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\com.seceoknightdlp.dlp"
    };
    for (const auto& sub : roots) {
        HKEY k;
        LSTATUS rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, nullptr,
                                     REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &k, nullptr);
        if (rc != ERROR_SUCCESS) {
            logger.Error("apply-browser-extension-guard: RegCreateKeyExA failed for " +
                        sub + " rc=" + std::to_string(rc));
            continue;
        }
        LSTATUS rc2 = RegSetValueExA(k, nullptr, 0, REG_SZ,
                                     reinterpret_cast<const BYTE*>(manifestPath.c_str()),
                                     (DWORD)manifestPath.size() + 1);
        RegCloseKey(k);
        if (rc2 != ERROR_SUCCESS) {
            logger.Error("apply-browser-extension-guard: RegSetValueExA failed for " +
                        sub + " rc=" + std::to_string(rc2));
        }
    }
    logger.Debug("apply-browser-extension-guard: native-host manifest + registry set (id=" + extId + ")");
}

// Writes the native host's own server/agent config (dlp-host.json), read by
// skdlp_host.py's load_config() on every launch. agent_id here is only ever
// a fallback -- skdlp_host.py prefers a LIVE read of this same machine's
// C:\ProgramData\SeceoKnight\agent_key.json (see _load_live_agent_identity()
// there), which is what keeps cloud-upload/web-activity events tagged with
// the agent's CURRENT identity across reinstalls without ever needing this
// file rewritten by hand. Written here too only so a brand-new machine has
// something valid before agent_key.json exists at all.
static void WriteDlpHostConfig(Logger& logger, const std::string& agentId, const std::string& serverUrl) {
    if (serverUrl.empty()) return;
    const std::string dir = "C:\\ProgramData\\SeceoKnight";
    std::error_code ec;
    fs::create_directories(dir, ec);
    const std::string cfgPath = dir + "\\dlp-host.json";

    JsonBuilder jb;
    jb.AddString("server_url", serverUrl);
    if (!agentId.empty()) jb.AddString("agent_id", agentId);
    std::string json = jb.Build();

    std::ofstream f(cfgPath, std::ios::trunc | std::ios::binary);
    if (!f.is_open()) {
        logger.Warning("apply-browser-extension-guard: could not write " + cfgPath);
        return;
    }
    f << json;
}

// Forces an out-of-date, already-force-installed extension to actually
// update, instead of sitting on whatever version happened to be current the
// day it first installed. Gap-scan of CyberSentinel-DLP (August 19, 2026):
// they found ExtensionInstallForcelist (SetExtensionForcelistEntry above)
// only guarantees the extension is PRESENT -- Chrome/Edge check the update
// feed on their own multi-hour timer regardless, so a real endpoint sat on
// an old version for days with a newer one published and reachable, every
// server-side check (update.xml, the CRX itself, the id) correct the whole
// time. Restarting the browser doesn't help either; that isn't what
// schedules the check.
//
// ExtensionSettings' minimum_version_required is the fix: telling the
// browser the installed copy is TOO OLD is a statement it has to act on
// (disables + reinstalls from update_url), not a hint it can defer like the
// forcelist. See agents/browser-extension/src/background.js's own
// requestUpdateCheck()/onUpdateAvailable additions for the complementary
// half -- that closes the gap for a browser that's already running and
// never restarts or hits this policy refresh; this closes it for one that's
// stuck badly enough that even that doesn't help.
//
// NOTE: this key is a single JSON blob per browser root, keyed by extension
// id, and there's no JSON parser in this codebase to safely read-modify-
// merge an existing value that might belong to something else (a real IT
// Group Policy managing a different extension's settings under the same
// key). This product's entry fully replaces whatever was there. On every
// fleet this has been deployed to, nothing else writes this key -- the log
// line below is the signal to notice if that's ever not true somewhere.
static void WriteExtensionMinimumVersion(Logger& logger, const std::string& policyRoot,
                                         const std::string& extId, const std::string& updateUrl,
                                         const std::string& version) {
    if (version.empty()) return;   // older server, no version in /extension/info yet -- skip, not an error

    HKEY k;
    LSTATUS rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, policyRoot.c_str(), 0, nullptr,
                                 REG_OPTION_NON_VOLATILE, KEY_READ | KEY_SET_VALUE,
                                 nullptr, &k, nullptr);
    if (rc != ERROR_SUCCESS) {
        logger.Error("apply-browser-extension-guard: RegCreateKeyExA failed for " + policyRoot +
                    " (ExtensionSettings) rc=" + std::to_string(rc));
        return;
    }

    char existingBuf[8192] = {};
    DWORD existingLen = sizeof(existingBuf) - 1;
    DWORD existingType = 0;
    if (RegQueryValueExA(k, "ExtensionSettings", nullptr, &existingType,
                          reinterpret_cast<BYTE*>(existingBuf), &existingLen) == ERROR_SUCCESS &&
        existingType == REG_SZ) {
        std::string existing(existingBuf, existingLen > 0 ? existingLen - 1 : 0);
        if (!existing.empty() && existing.find("\"" + extId + "\"") == std::string::npos) {
            logger.Warning("apply-browser-extension-guard: an existing ExtensionSettings policy "
                           "under " + policyRoot + " is being replaced -- this product owns that "
                           "key exclusively today (no JSON merge support here); if something else "
                           "on this fleet also manages ExtensionSettings, that policy is now gone.");
        }
    }

    // extId is always exactly 32 lowercase [a-z] characters (verified by the
    // caller) and version/updateUrl never contain a JSON-special character
    // in practice (dotted digits; a plain http(s) URL) -- hand-built rather
    // than through JsonBuilder, which has no nested-object support anyway.
    std::string json = "{\"" + extId + "\":{"
        "\"installation_mode\":\"force_installed\","
        "\"update_url\":\"" + updateUrl + "\","
        "\"minimum_version_required\":\"" + version + "\""
        "}}";

    LSTATUS rc2 = RegSetValueExA(k, "ExtensionSettings", 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(json.c_str()),
                                 (DWORD)json.size() + 1);
    RegCloseKey(k);
    if (rc2 != ERROR_SUCCESS) {
        logger.Error("apply-browser-extension-guard: RegSetValueExA failed for ExtensionSettings "
                    "under " + policyRoot + " rc=" + std::to_string(rc2));
    } else {
        logger.Debug("apply-browser-extension-guard: minimum_version_required=" + version +
                    " set under " + policyRoot);
    }
}

// Elevated periodic mode: applies the ExtensionInstallForcelist entry +
// managed config (serverUrl, agentId) from the state cache the main
// (unelevated) process writes in FetchBrowserExtensionPolicy(). Exists for
// the exact same reason as HandleApplyWirelessGuard() above -- the main
// task cannot write these HKLM keys itself -- and runs on the same
// repeating-task shape (registered as "SeceoKnight DLP Browser Extension
// Guard", SYSTEM/Highest, every 2 minutes) since which extension/server is
// force-installed is policy-driven and can change at any time.
//
// Also registers the native-messaging host (WriteNativeMessagingHostRegistration)
// and its config (WriteDlpHostConfig) on the same tick -- see those
// functions' comments. Together with the forcelist entry below, this is
// the entire browser-extension + native-host setup: nothing about the
// extension needs a separate manual step anymore once install-agent.ps1
// has downloaded skdlp_host.exe (Step 5 there).
//
// Reads a simple 4-line cache (extension id / update URL / agent id /
// server URL) rather than JSON -- same "no parser dependency for a handful
// of fields" reasoning as apply-wireless-guard. If the cache file doesn't
// exist yet (agent hasn't completed its first sync since install, or this
// server has never published an extension), does nothing and exits cleanly.
int HandleApplyBrowserExtensionGuard(int /*argc*/, char* /*argv*/[]) {
    Logger logger;
    try {
        const char* envLogDir = std::getenv("SECEOKNIGHT_LOG_DIR");
        std::string dir = envLogDir ? envLogDir : "C:\\ProgramData\\SeceoKnight\\logs";
        std::string cachePath = dir + "\\browser_extension_state.cache";

        std::error_code ec;
        if (!fs::exists(cachePath, ec) || ec) {
            logger.Info("apply-browser-extension-guard: no state cache yet (agent hasn't "
                        "synced with the server since install, or no extension is "
                        "published) -- nothing to apply this run");
            return 0;
        }

        std::ifstream f(cachePath, std::ios::binary);
        if (!f.is_open()) {
            logger.Warning("apply-browser-extension-guard: could not open state cache " + cachePath);
            return 1;
        }
        std::string extId, updateUrl, agentId, serverUrl, version;
        std::getline(f, extId);
        std::getline(f, updateUrl);
        std::getline(f, agentId);
        std::getline(f, serverUrl);
        std::getline(f, version);   // added Aug 19, 2026 -- absent on an older cache file
                                    // written before this existed; that's fine, see
                                    // WriteExtensionMinimumVersion()'s empty-version guard.

        if (extId.size() != 32 || updateUrl.empty()) {
            logger.Warning("apply-browser-extension-guard: malformed state cache "
                           "(id=" + extId + ")");
            return 1;
        }

        const std::string roots[] = {
            "SOFTWARE\\Policies\\Google\\Chrome",
            "SOFTWARE\\Policies\\Microsoft\\Edge"
        };
        for (const auto& root : roots) {
            SetExtensionForcelistEntry(logger, root, extId, updateUrl);

            std::string mp = root + "\\3rdparty\\extensions\\" + extId + "\\policy";
            if (!serverUrl.empty()) {
                SetExtensionManagedString(logger, mp, "serverUrl", serverUrl);
            }
            if (!agentId.empty()) {
                SetExtensionManagedString(logger, mp, "agentId", agentId);
            }
            // Gap-scan of CyberSentinel-DLP's 2.9.1 (August 24, 2026): the
            // published version, pushed the SAME safe way serverUrl/agentId
            // already are (chrome.storage.managed, not the ExtensionSettings
            // mechanism reverted above). background.js compares this against
            // its own manifest version to skip an unnecessary throttled
            // requestUpdateCheck() call when already current, and reacts to
            // it changing via chrome.storage.onChanged instead of waiting for
            // its hourly alarm -- the safe half of what
            // WriteExtensionMinimumVersion() was trying to achieve via a much
            // riskier path. This is advisory only (background.js decides what
            // to do with it); unlike ExtensionSettings it cannot force Chrome
            // itself to touch the extension, so it can't repeat that failure.
            if (!version.empty()) {
                SetExtensionManagedString(logger, mp, "wantVersion", version);
            }

            // WriteExtensionMinimumVersion(logger, root, extId, updateUrl, version);
            // ^ REVERTED same day it was added (August 19, 2026): confirmed on a
            // real endpoint to make Microsoft Edge stop opening at all -- Edge
            // sat there indefinitely (not a crash, just never showed a window)
            // until the ExtensionSettings registry value this wrote was removed
            // by hand. Root cause not fully confirmed, but the leading theory is
            // that ExtensionInstallForcelist + an ExtensionSettings entry with
            // installation_mode=force_installed for the SAME extension id is a
            // combination Chromium doesn't handle cleanly -- possibly blocking
            // startup on a forced reinstall that never completed. A DLP agent
            // must never be able to do this to the browser it's protecting, so
            // this is disabled rather than guessed-and-redeployed without a way
            // to verify the fix is actually safe. The function is left in place,
            // unused, for whoever revisits this -- do not re-enable without
            // testing on a real Chrome AND Edge install first, ideally with
            // ExtensionInstallForcelist removed for the same id so the two
            // policies are never combined for one extension at once.
        }

        WriteNativeMessagingHostRegistration(logger, extId);
        WriteDlpHostConfig(logger, agentId, serverUrl);

        logger.Debug("apply-browser-extension-guard: complete -- id=" + extId);
    } catch (const std::exception& e) {
        try { logger.Error(std::string("apply-browser-extension-guard: exception: ") + e.what()); } catch (...) {}
        return 1;
    } catch (...) {
        try { logger.Error("apply-browser-extension-guard: unknown exception"); } catch (...) {}
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    // Elevated Wireless Guard hook (task #147): the repeating SYSTEM/Highest
    // scheduled task install-agent.ps1 registers invokes us with this flag
    // purely to reconcile the fsquirt.exe/Nearby-Sharing registry state from
    // the cache file, then exits -- this is not a normal agent run.
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--apply-wireless-guard") {
            return HandleApplyWirelessGuard(argc, argv);
        }
    }

    // Elevated Browser Extension Guard hook (gap-scan of CyberSentinel-DLP,
    // Aug 18 2026): the repeating SYSTEM/Highest scheduled task
    // install-agent.ps1 registers invokes us with this flag purely to
    // reconcile the ExtensionInstallForcelist + managed-config registry
    // state from the cache file, then exits -- this is not a normal agent run.
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--apply-browser-extension-guard") {
            return HandleApplyBrowserExtensionGuard(argc, argv);
        }
    }

    // Watchdog hook (gap-scan of CyberSentinel-DLP, Aug 18 2026): the
    // repeating SYSTEM/Highest "SeceoKnight DLP Watchdog" scheduled task
    // install-agent.ps1 registers invokes us with this flag in place of the
    // old wscript.exe watchdog_launcher.vbs action -- see HandleWatchdogCheck
    // for why the script host had to go entirely, not just get patched
    // again. Not a normal agent run.
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--watchdog-check") {
            return HandleWatchdogCheck(argc, argv);
        }
    }

    // Elevated CLI Guard registration hook (task #142/#145): the separate
    // SYSTEM/Highest scheduled task install-agent.ps1 registers invokes us
    // with this flag purely to write the IFEO Debugger keys, then exits --
    // this is not a normal agent run.
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--apply-ifeo-guards") {
            return HandleApplyIfeoGuards(argc, argv);
        }
    }

    // CLI Guard hook: we were run in place of a scoped CLI tool (curl.exe
    // etc.) because ApplyCliGuardIfeo() redirected it via IFEO. Decide
    // allow/block against the running service, then either exit (block) or
    // relay to a temp-copy of the real binary (allow). Handle this BEFORE
    // any normal startup, same as --blocked-launch below.
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--cli-guard") {
            return HandleCliGuard(argc, argv);
        }
    }

    // Blocked-launch hook: we were run in place of fsquirt.exe (Bluetooth file
    // transfer) because the wireless policy blocks it. Log + emit an event,
    // then exit without running fsquirt. Handle this BEFORE any normal
    // startup (help flag, background-mode detection, the whole DLPAgent
    // lifecycle) -- this invocation isn't a real agent run at all.
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--blocked-launch") {
            return HandleBlockedLaunch(argc, argv);
        }
    }

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

    if (!backgroundMode) {
        // Foreground/manual run — attach a real console so std::cout is
        // actually visible. In background mode we deliberately do nothing
        // here: see AttachForegroundConsole() above for why.
        AttachForegroundConsole();

        // Show startup banner only in foreground mode
        std::cout << "============================================================\n";
        std::cout << "SeceoKnight DLP - Windows Agent (C++)\n";
        std::cout << "============================================================\n\n";
        
        // Check for server URL environment variable
        const char* envUrl = std::getenv("SECEOKNIGHT_SERVER_URL");
        if (envUrl) {
            std::cout << "Using server URL from environment: " << envUrl << "\n";
        } else {
            std::cout << "Using default server URL: http://localhost:55000/api/v1\n";
            std::cout << "To change server URL, set environment variable:\n";
            std::cout << "  set SECEOKNIGHT_SERVER_URL=http://your-server:port/api/v1\n\n";
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
            bgLogger.Info("SeceoKnight DLP Agent started in BACKGROUND MODE");
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
            bgLogger.Error("1. Ensure the SeceoKnight server is running");
            bgLogger.Error("2. Check network connectivity to the server");
            bgLogger.Error("3. Verify firewall settings allow connections");
            bgLogger.Error("4. Check server URL in agent_config.json or environment variable");
        } else {
            // Show error in console in foreground mode
            std::cerr << "\nFatal error: " << e.what() << std::endl;
            std::cerr << "\nTroubleshooting:\n";
            std::cerr << "1. Ensure the SeceoKnight server is running\n";
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
