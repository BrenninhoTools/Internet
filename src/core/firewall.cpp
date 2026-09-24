#include "firewall.hpp"

#include <algorithm>
#include <chrono>

namespace internet {

Firewall::Firewall(FirewallConfig config) : config_(config) {}

void Firewall::setConfig(const FirewallConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

FirewallConfig Firewall::config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

void Firewall::setClock(std::function<double()> clock) {
    std::lock_guard<std::mutex> lock(mutex_);
    clock_ = std::move(clock);
}

void Firewall::setListener(std::function<void(const std::string&)> listener) {
    std::lock_guard<std::mutex> lock(mutex_);
    listener_ = std::move(listener);
}

double Firewall::now() const {
    if (clock_) return clock_();
    using Clock = std::chrono::steady_clock;
    return std::chrono::duration<double>(Clock::now().time_since_epoch()).count();
}

bool Firewall::exempt(const std::string& host) const {
    return !config_.enabled || (config_.exemptLoopback && (host == "127.0.0.1" || host == "::1" || host == "localhost"));
}

bool Firewall::bannedLocked(Host& entry, double time) {
    if (entry.bannedUntil <= 0.0) return false;
    if (time >= entry.bannedUntil) {
        entry.bannedUntil = 0.0;
        entry.violations = 0;
        return false;
    }
    return true;
}

void Firewall::banLocked(const std::string& host, Host& entry, int seconds, const std::string& reason, double time) {
    entry.bannedUntil = time + static_cast<double>(seconds);
    entry.reason = reason;
    entry.violations = 0;
    ++stats_.bans;
    if (listener_) listener_("Blocked " + host + " for " + std::to_string(seconds) + " seconds: " + reason);
}

void Firewall::purgeLocked(double time) {
    if (hosts_.size() < 4096) return;
    for (auto it = hosts_.begin(); it != hosts_.end();) {
        const Host& entry = it->second;
        bool idle = entry.connections == 0 && entry.bannedUntil <= time && time - entry.last > 120.0;
        it = idle ? hosts_.erase(it) : std::next(it);
    }
}

bool Firewall::allowConnection(const std::string& host) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (exempt(host)) {
        ++stats_.allowed;
        return true;
    }
    double time = now();
    purgeLocked(time);
    Host& entry = hosts_[host];
    if (!entry.seen) {
        entry.seen = true;
        entry.tokens = config_.burst;
        entry.last = time;
    }
    if (bannedLocked(entry, time)) {
        ++stats_.refused;
        return false;
    }
    if (entry.connections >= config_.maxConnectionsPerHost) {
        ++stats_.refused;
        entry.lastViolation = time;
        if (++entry.violations >= config_.violationsToBan) banLocked(host, entry, config_.banSeconds, "too many connections", time);
        return false;
    }
    ++entry.connections;
    ++stats_.allowed;
    return true;
}

void Firewall::releaseConnection(const std::string& host) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = hosts_.find(host);
    if (found != hosts_.end() && found->second.connections > 0) --found->second.connections;
}

bool Firewall::allowRequest(const std::string& host) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (exempt(host)) return true;
    double time = now();
    Host& entry = hosts_[host];
    if (!entry.seen) {
        entry.seen = true;
        entry.tokens = config_.burst;
        entry.last = time;
    }
    if (bannedLocked(entry, time)) {
        ++stats_.refused;
        return false;
    }
    entry.tokens = std::min(config_.burst, entry.tokens + (time - entry.last) * config_.ratePerSecond);
    entry.last = time;
    if (entry.tokens >= 1.0) {
        entry.tokens -= 1.0;
        return true;
    }
    ++stats_.rateLimited;
    if (time - entry.lastViolation > 60.0) entry.violations = 0;
    entry.lastViolation = time;
    if (++entry.violations >= config_.violationsToBan) banLocked(host, entry, config_.banSeconds, "request flood", time);
    return false;
}

void Firewall::violation(const std::string& host, const std::string& reason, int weight) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (exempt(host)) return;
    double time = now();
    Host& entry = hosts_[host];
    if (time - entry.lastViolation > 60.0) entry.violations = 0;
    entry.lastViolation = time;
    entry.violations += weight;
    if (!bannedLocked(entry, time) && entry.violations >= config_.violationsToBan)
        banLocked(host, entry, config_.banSeconds, reason, time);
}

void Firewall::ban(const std::string& host, int seconds, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    banLocked(host, hosts_[host], seconds, reason, now());
}

bool Firewall::unban(const std::string& host) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = hosts_.find(host);
    if (found == hosts_.end() || found->second.bannedUntil <= 0.0) return false;
    found->second.bannedUntil = 0.0;
    found->second.violations = 0;
    return true;
}

bool Firewall::isBanned(const std::string& host) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = hosts_.find(host);
    return found != hosts_.end() && bannedLocked(found->second, now());
}

FirewallStats Firewall::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

std::vector<BanInfo> Firewall::bans() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<BanInfo> result;
    double time = now();
    for (const auto& [host, entry] : hosts_) {
        if (entry.bannedUntil > time) {
            result.push_back(BanInfo{host, entry.reason, static_cast<int>(entry.bannedUntil - time)});
        }
    }
    std::sort(result.begin(), result.end(), [](const BanInfo& a, const BanInfo& b) { return a.host < b.host; });
    return result;
}

}
