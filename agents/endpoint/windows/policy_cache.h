/**
 * CyberSentinel DLP — Production Policy Cache (v2)
 *
 * Atomic policy sync with versioning and integrity validation.
 *
 * Sync protocol:
 *   1. GET /policy/latest → {version, checksum}
 *   2. Compare with local version
 *   3. If newer: GET /policy/download?version=X → full bundle
 *   4. Validate SHA-256 checksum
 *   5. Write to temp file → validate → atomic rename
 *   6. Load into PolicyEngine via atomic pointer swap
 *   7. Keep previous version for rollback
 *
 * Offline mode:
 *   - Uses last valid policy from disk cache
 *   - Decision cache (in-memory, TTL-based)
 *   - Offline event queue (bounded, 50K max)
 *   - Fail-open: ALLOW when no cached decision available
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <functional>
#include <atomic>
#include <filesystem>
#include "policy_engine.h"

namespace cs {

/* ────────────────────────────────────────────────────────────────────────────
 * SHA-256 Utility (minimal, header-only implementation for checksum validation)
 * In production, link against OpenSSL or Windows CNG.
 * ──────────────────────────────────────────────────────────────────────────── */

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

inline std::string ComputeSHA256(const std::string& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    UCHAR hash[32];
    ULONG hashLen = 0, resultLen = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return "";

    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &resultLen, 0);

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    char hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    }
    hex[64] = '\0';
    return std::string(hex);
}
#else
inline std::string ComputeSHA256(const std::string& data) {
    /* Stub for non-Windows — implement with OpenSSL */
    (void)data;
    return "stub";
}
#endif

/* ────────────────────────────────────────────────────────────────────────────
 * Cached Decision Entry
 * ──────────────────────────────────────────────────────────────────────────── */

struct CachedDecision {
    Action      action = Action::Allow;
    std::string reason;
    std::string policyId;
    std::string policyName;
    int         ttlSeconds = 300;
    std::chrono::steady_clock::time_point cachedAt;

    bool IsExpired() const {
        auto elapsed = std::chrono::steady_clock::now() - cachedAt;
        return std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > ttlSeconds;
    }
};

/* ────────────────────────────────────────────────────────────────────────────
 * Policy Version Info (from /policy/latest response)
 * ──────────────────────────────────────────────────────────────────────────── */

struct PolicyVersionInfo {
    uint64_t    version = 0;
    std::string checksum;
    std::string timestamp;
};

/* ────────────────────────────────────────────────────────────────────────────
 * Production Policy Cache
 * ──────────────────────────────────────────────────────────────────────────── */

class ProductionPolicyCache {
public:
    static constexpr size_t MAX_DECISIONS = 10000;
    static constexpr size_t MAX_OFFLINE_QUEUE = 50000;
    static constexpr size_t MAX_BUNDLE_HISTORY = 5;

    ProductionPolicyCache(
        const std::string& cacheDir = "C:\\ProgramData\\CyberSentinel\\cache",
        PolicyEngine* engine = nullptr
    ) : cacheDir_(cacheDir), engine_(engine) {
        /* Ensure cache directory exists */
        try {
            std::filesystem::create_directories(cacheDir_);
        } catch (...) {}
    }

    /* ──────────────────────────────────────────────────────────────────────
     * ATOMIC POLICY UPDATE
     *
     * Steps:
     * 1. Write bundle to temp file
     * 2. Validate SHA-256 checksum
     * 3. Rename temp → active (atomic on NTFS)
     * 4. Load into PolicyEngine via atomic swap
     * 5. Archive previous version
     * ────────────────────────────────────────────────────────────────────── */

    enum class UpdateResult {
        Success,
        ChecksumMismatch,
        ParseError,
        WriteError,
        EngineLoadError,
    };

    UpdateResult AtomicUpdate(
        const std::string& bundleJson,
        uint64_t expectedVersion,
        const std::string& expectedChecksum,
        std::function<bool(const std::string&, PolicyBundle&)> parseFunc
    ) {
        /* Step 1: Validate checksum */
        std::string actualChecksum = ComputeSHA256(bundleJson);
        if (!expectedChecksum.empty() && actualChecksum != expectedChecksum) {
            return UpdateResult::ChecksumMismatch;
        }

        /* Step 2: Parse into PolicyBundle */
        PolicyBundle newBundle;
        if (!parseFunc(bundleJson, newBundle)) {
            return UpdateResult::ParseError;
        }
        newBundle.version = expectedVersion;
        newBundle.checksum = actualChecksum;
        newBundle.timestamp = g_timezone.Now();

        /* Step 3: Write to temp file */
        std::string tempPath = cacheDir_ + "\\policy_bundle.tmp";
        std::string activePath = cacheDir_ + "\\policy_bundle.json";
        {
            std::ofstream tmp(tempPath, std::ios::binary | std::ios::trunc);
            if (!tmp.is_open()) return UpdateResult::WriteError;
            tmp.write(bundleJson.data(), bundleJson.size());
            tmp.flush();
            if (!tmp.good()) return UpdateResult::WriteError;
        }

        /* Step 4: Validate the temp file (re-read and check) */
        {
            std::ifstream verify(tempPath, std::ios::binary);
            if (!verify.is_open()) return UpdateResult::WriteError;
            std::stringstream ss;
            ss << verify.rdbuf();
            if (ComputeSHA256(ss.str()) != actualChecksum) {
                std::filesystem::remove(tempPath);
                return UpdateResult::ChecksumMismatch;
            }
        }

        /* Step 5: Archive current bundle (keep MAX_BUNDLE_HISTORY versions) */
        ArchiveCurrentBundle();

        /* Step 6: Atomic rename (temp → active) */
        try {
            std::filesystem::rename(tempPath, activePath);
        } catch (...) {
            /* Fallback: copy + delete */
            try {
                std::filesystem::copy_file(tempPath, activePath,
                    std::filesystem::copy_options::overwrite_existing);
                std::filesystem::remove(tempPath);
            } catch (...) {
                return UpdateResult::WriteError;
            }
        }

        /* Step 7: Load into engine via atomic pointer swap */
        if (engine_) {
            if (!engine_->LoadBundle(std::move(newBundle))) {
                return UpdateResult::EngineLoadError;
            }
        }

        /* Step 8: Invalidate decision cache (policies changed) */
        {
            std::lock_guard<std::mutex> lock(mutex_);
            decisions_.clear();
            currentVersion_ = expectedVersion;
            currentChecksum_ = actualChecksum;
        }

        return UpdateResult::Success;
    }

    /* ──────────────────────────────────────────────────────────────────────
     * SYNC LOGIC — called periodically by agent
     * ────────────────────────────────────────────────────────────────────── */

    bool NeedsUpdate(const PolicyVersionInfo& serverVersion) const {
        return serverVersion.version > currentVersion_;
    }

    uint64_t CurrentVersion() const { return currentVersion_; }
    std::string CurrentChecksum() const { return currentChecksum_; }

    /* ──────────────────────────────────────────────────────────────────────
     * DECISION CACHE
     * ────────────────────────────────────────────────────────────────────── */

    bool GetCachedDecision(const std::string& key, CachedDecision& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = decisions_.find(key);
        if (it != decisions_.end() && !it->second.IsExpired()) {
            out = it->second;
            return true;
        }
        if (it != decisions_.end()) decisions_.erase(it);
        return false;
    }

    void CacheDecision(const std::string& key, const CachedDecision& decision) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (decisions_.size() >= MAX_DECISIONS) {
            /* Evict oldest 10% */
            auto it = decisions_.begin();
            for (size_t i = 0; i < MAX_DECISIONS / 10 && it != decisions_.end(); i++) {
                it = decisions_.erase(it);
            }
        }
        decisions_[key] = decision;
    }

    static std::string ComputeEventKey(const std::string& channel,
                                        const std::string& fileHash,
                                        const std::string& fileName) {
        std::string combined = channel + "|" + fileHash + "|" + fileName;
        std::hash<std::string> hasher;
        return std::to_string(hasher(combined));
    }

    /* ──────────────────────────────────────────────────────────────────────
     * OFFLINE MODE
     * ────────────────────────────────────────────────────────────────────── */

    bool IsBackendAvailable() const { return backendAvailable_.load(); }
    void SetBackendAvailable(bool available) { backendAvailable_.store(available); }

    CachedDecision GetOfflineDecision(const std::string& key) {
        CachedDecision cached;
        if (GetCachedDecision(key, cached)) return cached;

        /* Fail-open */
        CachedDecision failOpen;
        failOpen.action = Action::Allow;
        failOpen.reason = "Backend unavailable - fail-open";
        failOpen.ttlSeconds = 60;
        failOpen.cachedAt = std::chrono::steady_clock::now();
        return failOpen;
    }

    void QueueOfflineEvent(const std::string& eventJson) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (offlineQueue_.size() < MAX_OFFLINE_QUEUE) {
            offlineQueue_.push_back(eventJson);
        }
    }

    std::vector<std::string> DrainOfflineQueue(size_t batchSize = 100) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = std::min(batchSize, offlineQueue_.size());
        std::vector<std::string> batch(offlineQueue_.begin(), offlineQueue_.begin() + count);
        offlineQueue_.erase(offlineQueue_.begin(), offlineQueue_.begin() + count);
        return batch;
    }

    size_t OfflineQueueSize() const { return offlineQueue_.size(); }

    /* ──────────────────────────────────────────────────────────────────────
     * STARTUP — Load cached bundle from disk
     * ────────────────────────────────────────────────────────────────────── */

    bool LoadFromDisk(std::function<bool(const std::string&, PolicyBundle&)> parseFunc) {
        std::string path = cacheDir_ + "\\policy_bundle.json";
        try {
            std::ifstream file(path, std::ios::binary);
            if (!file.is_open()) return false;
            std::stringstream ss;
            ss << file.rdbuf();
            std::string content = ss.str();
            if (content.empty()) return false;

            PolicyBundle bundle;
            if (!parseFunc(content, bundle)) return false;

            bundle.checksum = ComputeSHA256(content);
            bundle.timestamp = g_timezone.Now();

            if (engine_) {
                engine_->LoadBundle(std::move(bundle));
            }

            currentChecksum_ = bundle.checksum;
            return true;
        } catch (...) {
            return false;
        }
    }

    /* ──────────────────────────────────────────────────────────────────────
     * ROLLBACK
     * ────────────────────────────────────────────────────────────────────── */

    bool RollbackToPrevious(std::function<bool(const std::string&, PolicyBundle&)> parseFunc) {
        /* Try loading the most recent archived bundle */
        for (int i = (int)MAX_BUNDLE_HISTORY; i >= 1; i--) {
            std::string archivePath = cacheDir_ + "\\policy_bundle.v" + std::to_string(i) + ".json";
            try {
                std::ifstream file(archivePath, std::ios::binary);
                if (!file.is_open()) continue;
                std::stringstream ss;
                ss << file.rdbuf();
                std::string content = ss.str();

                PolicyBundle bundle;
                if (parseFunc(content, bundle)) {
                    bundle.checksum = ComputeSHA256(content);
                    if (engine_) engine_->LoadBundle(std::move(bundle));

                    /* Also restore as active bundle */
                    std::string activePath = cacheDir_ + "\\policy_bundle.json";
                    std::ofstream out(activePath, std::ios::binary | std::ios::trunc);
                    out << content;
                    return true;
                }
            } catch (...) {
                continue;
            }
        }

        /* Engine-level rollback as last resort */
        if (engine_) return engine_->Rollback();
        return false;
    }

private:
    void ArchiveCurrentBundle() {
        std::string activePath = cacheDir_ + "\\policy_bundle.json";
        if (!std::filesystem::exists(activePath)) return;

        /* Shift archives: v5 → delete, v4 → v5, ..., v1 → v2, current → v1 */
        for (int i = (int)MAX_BUNDLE_HISTORY; i >= 2; i--) {
            std::string from = cacheDir_ + "\\policy_bundle.v" + std::to_string(i - 1) + ".json";
            std::string to   = cacheDir_ + "\\policy_bundle.v" + std::to_string(i) + ".json";
            try {
                if (std::filesystem::exists(from)) {
                    std::filesystem::rename(from, to);
                }
            } catch (...) {}
        }

        try {
            std::string v1 = cacheDir_ + "\\policy_bundle.v1.json";
            std::filesystem::copy_file(activePath, v1,
                std::filesystem::copy_options::overwrite_existing);
        } catch (...) {}
    }

    std::string cacheDir_;
    PolicyEngine* engine_ = nullptr;
    std::mutex mutex_;
    std::unordered_map<std::string, CachedDecision> decisions_;
    std::vector<std::string> offlineQueue_;
    std::atomic<bool> backendAvailable_{true};
    uint64_t currentVersion_ = 0;
    std::string currentChecksum_;
};

} /* namespace cs */
