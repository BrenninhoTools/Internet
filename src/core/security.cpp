#include "security.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <sstream>
#include <system_error>

namespace fs = std::filesystem;

namespace internet {

namespace {

constexpr std::size_t kMaxEvents = 500;

std::int64_t nowSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string cleanField(std::string text) {
    std::replace_if(text.begin(), text.end(), [](char c) { return c == '\t' || c == '\n' || c == '\r'; }, ' ');
    return text;
}

bool readWhole(const fs::path& path, std::size_t limit, std::string& data, std::uint64_t& size) {
    std::error_code error;
    size = fs::file_size(path, error);
    if (error) return false;
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(size, limit));
    data.resize(take);
    stream.read(&data[0], static_cast<std::streamsize>(take));
    data.resize(static_cast<std::size_t>(stream.gcount()));
    return true;
}

std::int64_t modifiedSeconds(const fs::path& path) {
    std::error_code error;
    auto time = fs::last_write_time(path, error);
    if (error) return 0;
    return std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count();
}

}

Security::Security(fs::path dataDirectory) : dataDir_(std::move(dataDirectory)), quarantine_(dataDir_ / "quarantine") {
    std::error_code error;
    fs::create_directories(dataDir_, error);
    loadSettings();
    std::string custom;
    {
        std::ifstream stream(dataDir_ / "definitions.txt");
        if (stream) custom.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    }
    std::string problem;
    scanner_ = makeScanner(custom, problem);
    if (!scanner_) scanner_ = makeScanner("", problem);
    loadLog();
}

const fs::path& Security::dataDirectory() const { return dataDir_; }

std::shared_ptr<const Scanner> Security::scanner() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return scanner_;
}

std::string Security::definitionsVersion() const {
    std::shared_ptr<const Scanner> scanner = this->scanner();
    return scanner ? scanner->definitions().version : std::string();
}

std::size_t Security::ruleCount() const {
    std::shared_ptr<const Scanner> scanner = this->scanner();
    return scanner ? scanner->ruleCount() : 0;
}

SecuritySettings Security::settings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return settings_;
}

void Security::setSettings(const SecuritySettings& settings) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        settings_ = settings;
    }
    saveSettings();
}

void Security::loadSettings() {
    std::ifstream stream(dataDir_ / "security.txt");
    std::string line;
    while (std::getline(stream, line)) {
        std::size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        std::string key = line.substr(0, equals);
        bool value = line.substr(equals + 1) == "1";
        if (key == "realtime") settings_.realtime = value;
        if (key == "blockDownloads") settings_.blockDownloads = value;
        if (key == "scanOnSave") settings_.scanOnSave = value;
        if (key == "autoQuarantine") settings_.autoQuarantine = value;
        if (key == "guardHosting") settings_.guardHosting = value;
        if (key == "firewall") settings_.firewall = value;
    }
}

void Security::saveSettings() const {
    SecuritySettings copy = settings();
    std::ofstream stream(dataDir_ / "security.txt", std::ios::trunc);
    stream << "realtime=" << copy.realtime << '\n'
           << "blockDownloads=" << copy.blockDownloads << '\n'
           << "scanOnSave=" << copy.scanOnSave << '\n'
           << "autoQuarantine=" << copy.autoQuarantine << '\n'
           << "guardHosting=" << copy.guardHosting << '\n'
           << "firewall=" << copy.firewall << '\n';
}

void Security::loadLog() {
    std::ifstream stream(dataDir_ / "threats.log");
    std::string line;
    while (std::getline(stream, line)) {
        std::vector<std::string> fields;
        std::stringstream parts(line);
        std::string field;
        while (std::getline(parts, field, '\t')) fields.push_back(field);
        if (fields.size() < 8) continue;
        ThreatEvent event;
        try {
            event.time = std::stoll(fields[0]);
            event.score = std::stoi(fields[4]);
        } catch (const std::exception&) {
            continue;
        }
        event.source = fields[1];
        event.target = fields[2];
        event.verdict = fields[3];
        event.rule = fields[5];
        event.action = fields[6];
        event.sha256 = fields[7];
        events_.push_back(std::move(event));
    }
    if (events_.size() > kMaxEvents) events_.erase(events_.begin(), events_.end() - static_cast<std::ptrdiff_t>(kMaxEvents));
}

void Security::appendLog(const ThreatEvent& event) {
    std::ofstream stream(dataDir_ / "threats.log", std::ios::app);
    stream << event.time << '\t' << cleanField(event.source) << '\t' << cleanField(event.target) << '\t' << event.verdict << '\t'
           << event.score << '\t' << cleanField(event.rule) << '\t' << cleanField(event.action) << '\t' << event.sha256 << '\n';
}

void Security::record(const std::string& source, const std::string& target, const ScanResult& result, const std::string& action) {
    ++scanned_;
    if (result.verdict == Verdict::Clean) return;
    ++threats_;
    const Finding* strongest = strongestFinding(result);
    ThreatEvent event;
    event.time = nowSeconds();
    event.source = source;
    event.target = target;
    event.verdict = verdictName(result.verdict);
    event.rule = strongest ? strongest->rule : "";
    event.action = action;
    event.sha256 = result.sha256;
    event.score = result.score;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(event);
        if (events_.size() > kMaxEvents) events_.erase(events_.begin());
    }
    appendLog(event);
}

void Security::noteBlocked(const std::string& source, const std::string& target, const std::string& reason) {
    ++blocked_;
    ThreatEvent event;
    event.time = nowSeconds();
    event.source = source;
    event.target = target;
    event.verdict = "blocked";
    event.rule = reason;
    event.action = "blocked";
    {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(event);
        if (events_.size() > kMaxEvents) events_.erase(events_.begin());
    }
    appendLog(event);
}

ScanResult Security::scanBuffer(const std::string& name, const std::string& data, const std::string& source) {
    std::shared_ptr<const Scanner> scanner = this->scanner();
    ScanResult result = scanner->scan(name, data);
    record(source, name, result, result.verdict == Verdict::Clean ? "" : "detected");
    return result;
}

ScanResult Security::scanFile(const fs::path& path, const std::string& source) {
    std::shared_ptr<const Scanner> scanner = this->scanner();
    ScanOptions options;
    std::string data;
    std::uint64_t size = 0;
    if (!readWhole(path, options.maxBytes, data, size)) {
        ScanResult result;
        result.name = path.filename().string();
        result.verdict = Verdict::Unscannable;
        result.note = "The file could not be read";
        return result;
    }
    ScanResult result = scanner->scan(path.filename().string(), data, options);
    if (size > data.size()) {
        result.truncated = true;
        result.size = size;
        result.note = "Only the first part of the file was scanned";
    }
    record(source, path.string(), result, result.verdict == Verdict::Clean ? "" : "detected");
    return result;
}

bool Security::quarantineFile(const fs::path& path, const ScanResult& result, std::string& error) {
    std::string data;
    std::uint64_t size = 0;
    if (!readWhole(path, 512u * 1024u * 1024u, data, size)) {
        error = "Cannot read the file";
        return false;
    }
    QuarantineItem item;
    if (!quarantine_.add(path.string(), data, result, item, error)) return false;
    std::error_code code;
    fs::remove(path, code);
    if (code) {
        error = "The file was copied to quarantine but could not be deleted";
        return false;
    }
    ++quarantined_;
    return true;
}

std::vector<QuarantineItem> Security::quarantineItems() const { return quarantine_.list(); }

bool Security::restoreQuarantined(const std::string& id, const fs::path& destination, std::string& error) {
    return quarantine_.restore(id, destination, error);
}

bool Security::deleteQuarantined(const std::string& id, std::string& error) { return quarantine_.remove(id, error); }

void Security::scanTree(const std::vector<fs::path>& roots, const std::string& source, ScanProgress& progress,
                        std::optional<bool> quarantine) {
    SecuritySettings current = settings();
    fs::path quarantineDir = quarantine_.directory();
    std::error_code error;
    for (const fs::path& root : roots) {
        if (progress.cancel) break;
        std::vector<fs::path> files;
        if (fs::is_regular_file(root, error)) {
            files.push_back(root);
        } else if (fs::is_directory(root, error)) {
            fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, error);
            fs::recursive_directory_iterator end;
            for (; !error && it != end; it.increment(error)) {
                std::error_code entryError;
                if (!it->is_regular_file(entryError)) continue;
                if (it->path().lexically_normal().generic_string().rfind(quarantineDir.lexically_normal().generic_string(), 0) == 0) continue;
                files.push_back(it->path());
                if (files.size() >= 200000) break;
            }
        }
        for (const fs::path& file : files) {
            if (progress.cancel) break;
            {
                std::lock_guard<std::mutex> lock(progress.mutex);
                progress.current = file.string();
            }
            ScanResult result = scanFile(file, source);
            ++progress.files;
            progress.bytes += result.size;
            if (result.verdict == Verdict::Clean) continue;
            ScanRecord entry;
            entry.path = file.string();
            entry.action = "reported";
            if (result.verdict == Verdict::Malicious) {
                ++progress.malicious;
                if (quarantine.value_or(current.autoQuarantine)) {
                    std::string problem;
                    if (quarantineFile(file, result, problem)) {
                        entry.action = "quarantined";
                    } else {
                        entry.action = "could not quarantine: " + problem;
                    }
                }
            } else if (result.verdict == Verdict::Suspicious) {
                ++progress.suspicious;
            }
            entry.result = std::move(result);
            std::lock_guard<std::mutex> lock(progress.mutex);
            progress.records.push_back(std::move(entry));
        }
    }
    {
        std::lock_guard<std::mutex> lock(progress.mutex);
        progress.current.clear();
    }
    progress.done = true;
}

GuardDecision Security::guard(const fs::path& path) {
    SecuritySettings current = settings();
    if (!current.guardHosting) return GuardDecision{};
    std::string key = path.generic_string();
    std::int64_t modified = modifiedSeconds(path);
    std::error_code error;
    std::uint64_t size = fs::file_size(path, error);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto found = guardCache_.find(key);
        if (found != guardCache_.end() && found->second.modified == modified && found->second.size == size) {
            return GuardDecision{found->second.allowed, found->second.reason};
        }
    }
    ScanResult result = scanFile(path, "hosting");
    GuardEntry entry;
    entry.modified = modified;
    entry.size = size;
    if (result.verdict == Verdict::Malicious) {
        const Finding* strongest = strongestFinding(result);
        entry.allowed = false;
        entry.reason = strongest ? strongest->rule + ": " + strongest->description : "Malicious file";
        noteBlocked("hosting", path.string(), entry.reason);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        guardCache_[key] = entry;
    }
    return GuardDecision{entry.allowed, entry.reason};
}

std::vector<ThreatEvent> Security::events(std::size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ThreatEvent> copy(events_.rbegin(), events_.rend());
    if (copy.size() > limit) copy.resize(limit);
    return copy;
}

void Security::clearEvents() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.clear();
    }
    std::error_code error;
    fs::remove(dataDir_ / "threats.log", error);
}

SecurityCounters Security::counters() const {
    SecurityCounters counters;
    counters.scanned = scanned_;
    counters.threats = threats_;
    counters.blocked = blocked_;
    counters.quarantined = quarantined_;
    return counters;
}

bool Security::updateDefinitions(const std::string& text, std::string& error) {
    std::shared_ptr<const Scanner> updated = makeScanner(text, error);
    if (!updated) return false;
    std::ofstream stream(dataDir_ / "definitions.txt", std::ios::trunc | std::ios::binary);
    stream << text;
    if (!stream) {
        error = "Cannot save the definitions";
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    scanner_ = std::move(updated);
    guardCache_.clear();
    return true;
}

}
