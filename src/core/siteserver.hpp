#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "firewall.hpp"
#include "json.hpp"
#include "node.hpp"
#include "protocol.hpp"
#include "registry.hpp"
#include "security.hpp"

namespace internet {

struct ServerConfig {
    std::filesystem::path dataDir = "data";
    std::filesystem::path sitesDir = "sites";
    std::uint16_t registryPort = kDefaultRegistryPort;
    bool hostRegistry = true;
    Endpoint externalRegistry{"127.0.0.1", kDefaultRegistryPort};
    std::string token;
    FirewallConfig firewall;
    int rescanSeconds = 300;
    bool scanOnStart = true;
    std::function<void(const std::string&)> log;
};

struct SiteInfo {
    std::string name;
    bool online = false;
    std::string endpoint;
    std::uint64_t requests = 0;
    std::uint64_t files = 0;
};

class SiteServer {
public:
    explicit SiteServer(ServerConfig config);
    ~SiteServer();
    SiteServer(const SiteServer&) = delete;
    SiteServer& operator=(const SiteServer&) = delete;

    void start();
    void stop();
    bool running() const;

    const std::string& token() const;
    Security& security();
    Firewall& firewall();
    Registry& registry();
    Endpoint registryEndpoint() const;
    std::int64_t uptimeSeconds() const;

    std::vector<SiteInfo> sites();
    bool validSite(const std::string& name) const;
    std::filesystem::path sitePath(const std::string& name) const;
    bool createSite(const std::string& name, std::string& error);
    bool deleteSite(const std::string& name, std::string& error);
    void scanNow();
    Json status();
    void log(const std::string& text);

private:
    bool handleApi(const Message& request, const std::string& peer, Message& reply);
    Message route(const std::string& method, const std::string& path, const std::string& body, const std::string& peer);
    void manage();
    void syncSites();
    std::string loadToken();

    ServerConfig config_;
    std::string token_;
    Security security_;
    Firewall firewall_;
    Registry registry_;
    std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Node>> nodes_;
    std::unique_ptr<Node> api_;
    std::thread thread_;
    std::mutex wakeMutex_;
    std::condition_variable wake_;
    bool stopping_ = false;
    std::atomic<bool> running_{false};
    std::chrono::steady_clock::time_point started_;
    std::chrono::steady_clock::time_point lastScan_;
};

struct ApiResponse {
    bool reachable = false;
    bool ok = false;
    std::string code;
    std::string body;
};

Json scanResultJson(const ScanResult& result);
ApiResponse apiCall(const Endpoint& registry, const std::string& method, const std::string& path, const std::string& token,
                    const std::string& body);

}
