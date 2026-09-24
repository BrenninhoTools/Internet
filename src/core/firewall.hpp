#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace internet {

struct FirewallConfig {
    bool enabled = true;
    bool exemptLoopback = true;
    double ratePerSecond = 25.0;
    double burst = 60.0;
    int maxConnectionsPerHost = 64;
    int violationsToBan = 12;
    int banSeconds = 300;
};

struct FirewallStats {
    std::uint64_t allowed = 0;
    std::uint64_t rateLimited = 0;
    std::uint64_t refused = 0;
    std::uint64_t bans = 0;
};

struct BanInfo {
    std::string host;
    std::string reason;
    int remainingSeconds = 0;
};

class Firewall {
public:
    explicit Firewall(FirewallConfig config = FirewallConfig());

    void setConfig(const FirewallConfig& config);
    FirewallConfig config() const;
    void setClock(std::function<double()> clock);
    void setListener(std::function<void(const std::string&)> listener);

    bool allowConnection(const std::string& host);
    void releaseConnection(const std::string& host);
    bool allowRequest(const std::string& host);
    void violation(const std::string& host, const std::string& reason, int weight = 1);
    void ban(const std::string& host, int seconds, const std::string& reason);
    bool unban(const std::string& host);
    bool isBanned(const std::string& host);

    FirewallStats stats() const;
    std::vector<BanInfo> bans() const;

private:
    struct Host {
        double tokens = 0.0;
        double last = 0.0;
        double lastViolation = 0.0;
        double bannedUntil = 0.0;
        int connections = 0;
        int violations = 0;
        std::string reason;
        bool seen = false;
    };

    double now() const;
    bool exempt(const std::string& host) const;
    bool bannedLocked(Host& entry, double time);
    void banLocked(const std::string& host, Host& entry, int seconds, const std::string& reason, double time);
    void purgeLocked(double time);

    mutable std::mutex mutex_;
    FirewallConfig config_;
    std::function<double()> clock_;
    std::function<void(const std::string&)> listener_;
    std::unordered_map<std::string, Host> hosts_;
    FirewallStats stats_;
};

}
