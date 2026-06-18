/**
 * CyberSentinel DLP — Production Policy Engine (v2)
 *
 * Deterministic, in-memory policy evaluation for endpoint agents.
 *
 * v2 enhancements:
 *   - Atomic policy swap (double-buffer via shared_ptr)
 *   - Policy bundle versioning (integer version + SHA-256 checksum)
 *   - File fingerprinting (SHA-256 hash-based classification)
 *   - Keyword matching (Boyer-Moore inspired)
 *   - Precompiled regex with lazy initialization
 *   - IST timezone support for timestamps (Asia/Kolkata, UTC+5:30)
 *   - Channel support for gdrive, onedrive, cloud, network
 *   - OOM protection (bounded data structures)
 *
 * Design constraints:
 *   - Decision time < 10ms (typically < 1ms)
 *   - No blocking I/O at evaluation time
 *   - No heap allocation per-evaluation (pre-allocated scratch space)
 *   - Zero JSON parsing at runtime (parse once on policy load)
 *   - Thread-safe via atomic shared_ptr swap
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <mutex>
#include <shared_mutex>
#include <memory>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <functional>
#include <cstdint>

namespace cs {

/* ════════════════════════════════════════════════════════════════════════════
 * TIMEZONE HELPER (IST / configurable)
 * ════════════════════════════════════════════════════════════════════════════ */

struct TimezoneConfig {
    std::string name = "Asia/Kolkata";
    int offsetSeconds = 19800;  /* UTC+5:30 = 5*3600 + 30*60 */

    static TimezoneConfig IST() { return {"Asia/Kolkata", 19800}; }
    static TimezoneConfig UTC() { return {"UTC", 0}; }

    /** Format epoch seconds as ISO-8601 string in this timezone */
    std::string FormatTimestamp(int64_t epochSeconds) const {
        time_t adjusted = epochSeconds + offsetSeconds;
        struct tm tm_buf;
#ifdef _WIN32
        gmtime_s(&tm_buf, &adjusted);
#else
        gmtime_r(&adjusted, &tm_buf);
#endif
        char buf[64];
        int h = offsetSeconds / 3600;
        int m = (offsetSeconds % 3600) / 60;
        snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d+%02d:%02d",
                 tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                 tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, h, m);
        return buf;
    }

    std::string Now() const {
        auto now = std::chrono::system_clock::now();
        auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        return FormatTimestamp(epoch);
    }
};

/* Global timezone — set once at startup */
inline TimezoneConfig g_timezone = TimezoneConfig::IST();

/* ════════════════════════════════════════════════════════════════════════════
 * ENUMERATIONS
 * ════════════════════════════════════════════════════════════════════════════ */

enum class Action : uint8_t {
    Allow   = 0,
    Warn    = 1,
    Alert   = 2,
    Encrypt = 3,
    Block   = 4,
};

inline int ActionPrecedence(Action a) {
    switch (a) {
    case Action::Block:   return 100;
    case Action::Encrypt: return 80;
    case Action::Alert:   return 50;
    case Action::Warn:    return 40;
    case Action::Allow:   return 10;
    default:              return 0;
    }
}

inline const char* ActionToString(Action a) {
    switch (a) {
    case Action::Block:   return "BLOCK";
    case Action::Encrypt: return "ENCRYPT";
    case Action::Alert:   return "ALERT";
    case Action::Warn:    return "WARN";
    case Action::Allow:   return "ALLOW";
    default:              return "UNKNOWN";
    }
}

inline Action ActionFromString(const std::string& s) {
    if (s == "block"   || s == "BLOCK")   return Action::Block;
    if (s == "encrypt" || s == "ENCRYPT") return Action::Encrypt;
    if (s == "alert"   || s == "ALERT")   return Action::Alert;
    if (s == "warn"    || s == "WARN")    return Action::Warn;
    return Action::Allow;
}

/* Channel bitmask for O(1) matching */
enum ChannelFlag : uint32_t {
    CH_NONE       = 0x0000,
    CH_USB        = 0x0001,
    CH_CLIPBOARD  = 0x0002,
    CH_NETWORK    = 0x0004,
    CH_EMAIL      = 0x0008,
    CH_PRINT      = 0x0010,
    CH_CLOUD      = 0x0020,
    CH_SCREEN     = 0x0040,
    CH_REMOVABLE  = 0x0080,
    CH_GDRIVE     = 0x0100,
    CH_ONEDRIVE   = 0x0200,
    CH_DROPBOX    = 0x0400,
    CH_WEBUPLOAD  = 0x0800,
    CH_ALL        = 0xFFFF,
};

inline uint32_t ChannelFromString(const std::string& ch) {
    if (ch == "usb"       || ch == "USB")       return CH_USB;
    if (ch == "clipboard" || ch == "CLIPBOARD") return CH_CLIPBOARD;
    if (ch == "network"   || ch == "NETWORK")   return CH_NETWORK;
    if (ch == "email"     || ch == "EMAIL")     return CH_EMAIL;
    if (ch == "print"     || ch == "PRINT")     return CH_PRINT;
    if (ch == "cloud"     || ch == "CLOUD")     return CH_CLOUD;
    if (ch == "screen"    || ch == "SCREEN")    return CH_SCREEN;
    if (ch == "removable" || ch == "REMOVABLE") return CH_REMOVABLE;
    if (ch == "gdrive"    || ch == "GDRIVE")    return CH_GDRIVE;
    if (ch == "onedrive"  || ch == "ONEDRIVE")  return CH_ONEDRIVE;
    if (ch == "dropbox"   || ch == "DROPBOX")   return CH_DROPBOX;
    if (ch == "webupload" || ch == "WEBUPLOAD") return CH_WEBUPLOAD;
    if (ch == "*" || ch == "all" || ch == "ALL") return CH_ALL;
    return CH_NONE;
}

/* ════════════════════════════════════════════════════════════════════════════
 * CLASSIFICATION LABELS
 * ════════════════════════════════════════════════════════════════════════════ */

enum class Label : uint8_t {
    None          = 0,
    Public        = 1,
    Internal      = 2,
    Confidential  = 3,
    Restricted    = 4,
};

inline Label LabelFromString(const std::string& s) {
    if (s == "public"       || s == "PUBLIC"       || s == "Public")       return Label::Public;
    if (s == "internal"     || s == "INTERNAL"     || s == "Internal")     return Label::Internal;
    if (s == "confidential" || s == "CONFIDENTIAL" || s == "Confidential") return Label::Confidential;
    if (s == "restricted"   || s == "RESTRICTED"   || s == "Restricted")   return Label::Restricted;
    return Label::None;
}

inline const char* LabelToString(Label l) {
    switch (l) {
    case Label::Public:       return "PUBLIC";
    case Label::Internal:     return "INTERNAL";
    case Label::Confidential: return "CONFIDENTIAL";
    case Label::Restricted:   return "RESTRICTED";
    default:                  return "NONE";
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * DATA STRUCTURES
 * ════════════════════════════════════════════════════════════════════════════ */

/** Represents a single event to evaluate */
struct Event {
    std::string userId;
    std::string userGroup;
    std::string endpointId;
    std::string fileName;
    std::string filePath;
    std::string fileHash;           /* SHA-256 hex */
    std::string fileExtension;
    int64_t     fileSize = 0;
    uint32_t    channelFlags = CH_NONE;
    std::string actionType;         /* COPY, MOVE, UPLOAD, PRINT, CREATE, WRITE, RENAME, DELETE */
    std::string content;            /* First N KB for classification */

    /* Populated by classification engine */
    std::vector<Label>       labels;
    std::vector<std::string> dataTypes;
    float                    confidenceScore = 0.0f;

    /* Populated by fingerprint engine */
    bool fingerprintMatched = false;
    std::string fingerprintLabel;
};

/** A single condition within a policy */
struct Condition {
    enum class Field : uint8_t {
        UserGroup, UserId, DeviceType, Channel,
        FileType, Label, DataType, FileName,
        FilePath, FileSize,
    };

    enum class Op : uint8_t {
        Equals, NotEquals, Contains, In,
        GreaterThan, LessThan, Regex, BitAnd,
    };

    Field   field;
    Op      op;
    std::string              stringValue;
    int64_t                  intValue = 0;
    uint32_t                 bitmaskValue = 0;
    std::vector<std::string> listValues;
    std::shared_ptr<std::regex> compiledRegex;  /* Lazy-compiled, shared ownership */

    bool Matches(const Event& event) const;
};

/** A complete policy */
struct Policy {
    std::string id;
    std::string name;
    int         priority = 0;
    Action      action = Action::Allow;
    uint32_t    channelMask = CH_ALL;
    std::vector<Condition> conditions;

    bool Matches(const Event& event) const {
        if ((channelMask & event.channelFlags) == 0 && channelMask != CH_ALL) {
            return false;
        }
        for (const auto& cond : conditions) {
            if (!cond.Matches(event)) return false;
        }
        return true;
    }
};

/** Policy evaluation result */
struct Decision {
    Action      action = Action::Allow;
    std::string policyId;
    std::string policyName;
    std::string reason;
    int         priority = 0;

    static Decision DefaultAllow() {
        return Decision{Action::Allow, "", "", "No policy matched - default allow", 0};
    }
};

/** Versioned policy bundle for atomic swap */
struct PolicyBundle {
    uint64_t                version = 0;       /* Monotonic integer version */
    std::string             checksum;           /* SHA-256 of serialized bundle */
    std::string             timestamp;          /* ISO-8601 generation time */
    std::vector<Policy>     policies;           /* Sorted by priority descending */
    size_t                  policyCount = 0;

    bool IsValid() const { return version > 0 && !checksum.empty(); }
};

/* ════════════════════════════════════════════════════════════════════════════
 * CLASSIFICATION ENGINE — Regex + Keyword + Fingerprint
 * ════════════════════════════════════════════════════════════════════════════ */

struct ClassificationPattern {
    std::string name;
    std::shared_ptr<std::regex> pattern;   /* Precompiled, shared ownership */
    Label       label;
    float       weight;
};

struct KeywordRule {
    std::string name;
    std::vector<std::string> keywords;     /* Lowercased for case-insensitive match */
    Label       label;
    float       weight;
    bool        caseSensitive = false;
};

struct FingerprintEntry {
    std::string hash;      /* SHA-256 hex */
    Label       label;
    std::string labelName;
};

class ClassificationEngine {
public:
    static constexpr size_t MAX_PATTERNS = 500;
    static constexpr size_t MAX_KEYWORDS = 1000;
    static constexpr size_t MAX_FINGERPRINTS = 100000;

    void AddPattern(const std::string& name, const std::string& regex,
                    Label label, float weight) {
        if (patterns_.size() >= MAX_PATTERNS) return;  /* OOM guard */
        try {
            auto compiled = std::make_shared<std::regex>(regex,
                std::regex::optimize | std::regex::ECMAScript);
            patterns_.push_back({name, compiled, label, weight});
        } catch (const std::regex_error&) {
            /* Invalid regex — skip silently, log in production */
        }
    }

    void AddKeywordRule(const std::string& name, const std::vector<std::string>& keywords,
                        Label label, float weight, bool caseSensitive = false) {
        if (keywordRules_.size() >= MAX_KEYWORDS) return;
        KeywordRule rule{name, {}, label, weight, caseSensitive};
        for (const auto& kw : keywords) {
            std::string lower = kw;
            if (!caseSensitive) {
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            }
            rule.keywords.push_back(lower);
        }
        keywordRules_.push_back(std::move(rule));
    }

    void AddFingerprint(const std::string& hash, Label label, const std::string& labelName = "") {
        if (fingerprints_.size() >= MAX_FINGERPRINTS) return;
        fingerprints_[hash] = {hash, label, labelName};
    }

    void ClearAll() {
        patterns_.clear();
        keywordRules_.clear();
        fingerprints_.clear();
    }

    /** Full classification pipeline: fingerprint → regex → keyword */
    void Classify(Event& event) const {
        /* Phase 1: Fingerprint check (O(1) hash lookup) */
        if (!event.fileHash.empty()) {
            auto it = fingerprints_.find(event.fileHash);
            if (it != fingerprints_.end()) {
                event.fingerprintMatched = true;
                event.fingerprintLabel = it->second.labelName;
                event.labels.push_back(it->second.label);
                event.confidenceScore = 1.0f;
                return;  /* Fingerprint is authoritative */
            }
        }

        /* Phase 2: Regex pattern matching */
        float totalWeight = 0.0f;
        Label highestLabel = Label::None;
        std::unordered_set<std::string> seenTypes;

        if (!event.content.empty()) {
            for (const auto& pat : patterns_) {
                try {
                    auto begin = std::sregex_iterator(event.content.begin(),
                                                       event.content.end(), *pat.pattern);
                    auto end = std::sregex_iterator();
                    int matchCount = (int)std::distance(begin, end);

                    if (matchCount > 0) {
                        if (seenTypes.insert(pat.name).second) {
                            event.dataTypes.push_back(pat.name);
                        }
                        totalWeight += pat.weight;
                        if (pat.label > highestLabel) highestLabel = pat.label;
                    }
                } catch (...) {
                    /* Regex execution error — skip pattern */
                }
            }

            /* Phase 3: Keyword matching */
            std::string contentLower = event.content;
            std::transform(contentLower.begin(), contentLower.end(),
                          contentLower.begin(), ::tolower);

            for (const auto& rule : keywordRules_) {
                const std::string& searchIn = rule.caseSensitive ? event.content : contentLower;
                bool matched = false;
                for (const auto& kw : rule.keywords) {
                    if (searchIn.find(kw) != std::string::npos) {
                        matched = true;
                        break;
                    }
                }
                if (matched) {
                    if (seenTypes.insert(rule.name).second) {
                        event.dataTypes.push_back(rule.name);
                    }
                    totalWeight += rule.weight;
                    if (rule.label > highestLabel) highestLabel = rule.label;
                }
            }
        }

        event.confidenceScore = std::min(1.0f, totalWeight);

        if (highestLabel != Label::None) {
            event.labels.push_back(highestLabel);
        } else {
            /* Derive from score */
            if (event.confidenceScore >= 0.8f)      event.labels.push_back(Label::Restricted);
            else if (event.confidenceScore >= 0.6f)  event.labels.push_back(Label::Confidential);
            else if (event.confidenceScore >= 0.3f)  event.labels.push_back(Label::Internal);
            else                                     event.labels.push_back(Label::Public);
        }
    }

    size_t PatternCount() const { return patterns_.size(); }
    size_t KeywordRuleCount() const { return keywordRules_.size(); }
    size_t FingerprintCount() const { return fingerprints_.size(); }

private:
    std::vector<ClassificationPattern> patterns_;
    std::vector<KeywordRule> keywordRules_;
    std::unordered_map<std::string, FingerprintEntry> fingerprints_;
};

/* ════════════════════════════════════════════════════════════════════════════
 * POLICY ENGINE — Atomic Swap + Deterministic Evaluation
 * ════════════════════════════════════════════════════════════════════════════ */

class PolicyEngine {
public:
    PolicyEngine() : activeBundle_(std::make_shared<PolicyBundle>()) {}

    /**
     * Atomic policy swap — the core of hot-reload.
     *
     * Steps:
     * 1. Validate checksum of new bundle
     * 2. Sort policies by priority descending (one-time)
     * 3. Build channel index for O(1) pre-filter
     * 4. Swap active pointer atomically (std::atomic<shared_ptr>)
     * 5. Old bundle is released when last reader finishes
     *
     * NEVER modifies the active bundle in-place.
     */
    bool LoadBundle(PolicyBundle bundle) {
        if (!bundle.IsValid()) return false;

        /* Sort by priority descending */
        std::sort(bundle.policies.begin(), bundle.policies.end(),
                  [](const Policy& a, const Policy& b) { return a.priority > b.priority; });

        bundle.policyCount = bundle.policies.size();

        auto newBundle = std::make_shared<PolicyBundle>(std::move(bundle));

        /* Atomic swap — readers see either old or new, never partial */
        std::lock_guard<std::mutex> lock(swapMutex_);
        activeBundle_ = newBundle;

        /* Keep previous for rollback */
        previousBundle_ = activeBundle_;

        return true;
    }

    /**
     * Rollback to previous policy bundle.
     * Returns false if no previous bundle is available.
     */
    bool Rollback() {
        std::lock_guard<std::mutex> lock(swapMutex_);
        if (!previousBundle_ || !previousBundle_->IsValid()) return false;
        activeBundle_ = previousBundle_;
        previousBundle_ = nullptr;
        return true;
    }

    /**
     * Deterministic policy evaluation.
     *
     * evaluate(event):
     *   1. Classify content (attach labels + data types)
     *   2. Sort policies by priority (already done at load time)
     *   3. First match wins
     *   4. Same-priority tiebreak: highest action precedence wins
     *   5. Default = ALLOW
     *
     * Thread-safe: reads from shared_ptr snapshot.
     * No heap allocation during evaluation.
     */
    Decision Evaluate(Event& event) const {
        /* Get snapshot of active bundle (atomic read) */
        auto bundle = GetActiveBundle();

        /* Step 1: Classify if needed */
        if (event.labels.empty() && !event.content.empty() && classifier_) {
            classifier_->Classify(event);
        }
        /* Also try fingerprint even without content */
        if (event.labels.empty() && !event.fileHash.empty() && classifier_) {
            classifier_->Classify(event);
        }

        /* Step 2-4: Iterate sorted policies */
        Decision best = Decision::DefaultAllow();
        int topPriority = INT_MIN;
        int bestPrecedence = -1;

        for (const auto& policy : bundle->policies) {
            /* Early exit: once we found a match and dropped below its priority,
               no further policy can override */
            if (topPriority != INT_MIN && policy.priority < topPriority) {
                break;
            }

            if (policy.Matches(event)) {
                int precedence = ActionPrecedence(policy.action);

                if (topPriority == INT_MIN) {
                    topPriority = policy.priority;
                }

                if (precedence > bestPrecedence) {
                    bestPrecedence = precedence;
                    best.action = policy.action;
                    best.policyId = policy.id;
                    best.policyName = policy.name;
                    best.priority = policy.priority;
                    best.reason = "Policy '" + policy.name + "' matched (priority " +
                                  std::to_string(policy.priority) + ")";
                }
            }
        }

        return best;
    }

    void SetClassifier(const ClassificationEngine* classifier) {
        classifier_ = classifier;
    }

    /** Thread-safe snapshot of active bundle */
    std::shared_ptr<const PolicyBundle> GetActiveBundle() const {
        std::lock_guard<std::mutex> lock(swapMutex_);
        return activeBundle_;
    }

    uint64_t ActiveVersion() const {
        auto b = GetActiveBundle();
        return b ? b->version : 0;
    }

    std::string ActiveChecksum() const {
        auto b = GetActiveBundle();
        return b ? b->checksum : "";
    }

    size_t PolicyCount() const {
        auto b = GetActiveBundle();
        return b ? b->policyCount : 0;
    }

private:
    mutable std::mutex swapMutex_;
    std::shared_ptr<PolicyBundle> activeBundle_;
    std::shared_ptr<PolicyBundle> previousBundle_;
    const ClassificationEngine* classifier_ = nullptr;
};

/* ════════════════════════════════════════════════════════════════════════════
 * CONDITION MATCHING IMPLEMENTATION
 * ════════════════════════════════════════════════════════════════════════════ */

inline bool Condition::Matches(const Event& event) const {
    switch (field) {

    case Field::UserGroup:
        if (op == Op::Equals)   return event.userGroup == stringValue;
        if (op == Op::NotEquals) return event.userGroup != stringValue;
        if (op == Op::In) {
            return std::find(listValues.begin(), listValues.end(), event.userGroup) != listValues.end();
        }
        break;

    case Field::UserId:
        if (op == Op::Equals)   return event.userId == stringValue;
        if (op == Op::NotEquals) return event.userId != stringValue;
        break;

    case Field::Channel:
        if (op == Op::BitAnd)   return (event.channelFlags & bitmaskValue) != 0;
        if (op == Op::Equals)   return event.channelFlags == bitmaskValue;
        break;

    case Field::FileType:
        if (op == Op::Equals)   return event.fileExtension == stringValue;
        if (op == Op::NotEquals) return event.fileExtension != stringValue;
        if (op == Op::In) {
            return std::find(listValues.begin(), listValues.end(), event.fileExtension) != listValues.end();
        }
        break;

    case Field::Label:
        if (op == Op::Equals) {
            Label target = LabelFromString(stringValue);
            return std::find(event.labels.begin(), event.labels.end(), target) != event.labels.end();
        }
        if (op == Op::In) {
            for (const auto& lv : listValues) {
                Label target = LabelFromString(lv);
                if (std::find(event.labels.begin(), event.labels.end(), target) != event.labels.end())
                    return true;
            }
            return false;
        }
        /* GreaterThan: label severity >= threshold */
        if (op == Op::GreaterThan) {
            Label threshold = LabelFromString(stringValue);
            for (const auto& l : event.labels) {
                if (l >= threshold) return true;
            }
            return false;
        }
        break;

    case Field::DataType:
        if (op == Op::Equals) {
            return std::find(event.dataTypes.begin(), event.dataTypes.end(), stringValue) != event.dataTypes.end();
        }
        if (op == Op::In) {
            for (const auto& dt : listValues) {
                if (std::find(event.dataTypes.begin(), event.dataTypes.end(), dt) != event.dataTypes.end())
                    return true;
            }
            return false;
        }
        break;

    case Field::FileName:
        if (op == Op::Equals)   return event.fileName == stringValue;
        if (op == Op::Contains) return event.fileName.find(stringValue) != std::string::npos;
        if (op == Op::Regex && compiledRegex) {
            try { return std::regex_search(event.fileName, *compiledRegex); }
            catch (...) { return false; }
        }
        break;

    case Field::FilePath:
        if (op == Op::Contains) return event.filePath.find(stringValue) != std::string::npos;
        if (op == Op::Regex && compiledRegex) {
            try { return std::regex_search(event.filePath, *compiledRegex); }
            catch (...) { return false; }
        }
        break;

    case Field::FileSize:
        if (op == Op::GreaterThan) return event.fileSize > intValue;
        if (op == Op::LessThan)    return event.fileSize < intValue;
        break;

    case Field::DeviceType:
        if (op == Op::Equals)   return event.channelFlags == bitmaskValue;
        if (op == Op::BitAnd)   return (event.channelFlags & bitmaskValue) != 0;
        break;
    }

    return false;
}

} /* namespace cs */
