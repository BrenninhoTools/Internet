#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "av.hpp"
#include "guard.hpp"
#include "quarantine.hpp"

namespace internet {

struct SecuritySettings {
    bool realtime = true;
    bool blockDownloads = true;
    bool scanOnSave = true;
    bool autoQuarantine = true;
    bool guardHosting = true;
    bool firewall = true;
};

struct ThreatEvent {
    std::int64_t time = 0;
    std::string source;
    std::string target;
    std::string verdict;
    std::string rule;
    std::string action;
    std::string sha256;
    int score = 0;
};

struct ScanRecord {
    std::string path;
    ScanResult result;
    std::string action;
};

struct ScanProgress {
    std::atomic<std::uint64_t> files{0};
    std::atomic<std::uint64_t> bytes{0};
    std::atomic<std::uint64_t> malicious{0};
    std::atomic<std::uint64_t> suspicious{0};
    std::atomic<bool> cancel{false};
    std::atomic<bool> done{false};
    std::mutex mutex;
    std::string current;
    std::vector<ScanRecord> records;
};

struct SecurityCounters {
    std::uint64_t scanned = 0;
    std::uint64_t threats = 0;
    std::uint64_t blocked = 0;
    std::uint64_t quarantined = 0;
};

class Security {
public:
    explicit Security(std::filesystem::path dataDirectory);

    ScanResult scanBuffer(const std::string& name, const std::string& data, const std::string& source);
    ScanResult scanFile(const std::filesystem::path& path, const std::string& source);
    void scanTree(const std::vector<std::filesystem::path>& roots, const std::string& source, ScanProgress& progress,
                  std::optional<bool> quarantine = std::nullopt);
    GuardDecision guard(const std::filesystem::path& path);

    bool quarantineFile(const std::filesystem::path& path, const ScanResult& result, std::string& error);
    std::vector<QuarantineItem> quarantineItems() const;
    bool restoreQuarantined(const std::string& id, const std::filesystem::path& destination, std::string& error);
    bool deleteQuarantined(const std::string& id, std::string& error);

    std::vector<ThreatEvent> events(std::size_t limit = 100) const;
    void clearEvents();
    SecurityCounters counters() const;
    void noteBlocked(const std::string& source, const std::string& target, const std::string& reason);

    bool updateDefinitions(const std::string& text, std::string& error);
    std::string definitionsVersion() const;
    std::size_t ruleCount() const;
    std::shared_ptr<const Scanner> scanner() const;

    SecuritySettings settings() const;
    void setSettings(const SecuritySettings& settings);
    const std::filesystem::path& dataDirectory() const;

private:
    struct GuardEntry {
        std::int64_t modified = 0;
        std::uint64_t size = 0;
        bool allowed = true;
        std::string reason;
    };

    void record(const std::string& source, const std::string& target, const ScanResult& result, const std::string& action);
    void appendLog(const ThreatEvent& event);
    void loadLog();
    void loadSettings();
    void saveSettings() const;

    std::filesystem::path dataDir_;
    Quarantine quarantine_;
    mutable std::mutex mutex_;
    std::shared_ptr<const Scanner> scanner_;
    SecuritySettings settings_;
    std::vector<ThreatEvent> events_;
    std::unordered_map<std::string, GuardEntry> guardCache_;
    std::atomic<std::uint64_t> scanned_{0};
    std::atomic<std::uint64_t> threats_{0};
    std::atomic<std::uint64_t> blocked_{0};
    std::atomic<std::uint64_t> quarantined_{0};
};

}
