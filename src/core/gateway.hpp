#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

#include "firewall.hpp"
#include "protocol.hpp"
#include "security.hpp"
#include "server.hpp"

namespace internet {

std::string gatewayUrl(std::uint16_t port, const std::string& internetUrl);
bool parseInternetTarget(const std::string& text, std::string& name, std::string& path);

class Gateway {
public:
    Gateway() = default;
    Gateway(const Gateway&) = delete;
    Gateway& operator=(const Gateway&) = delete;
    ~Gateway();

    void setRegistry(const Endpoint& registry);
    void setSecurity(Security* security);
    void setFirewall(Firewall* firewall);
    void setAllowScripts(bool allow);
    void setLoopbackOnly(bool loopbackOnly);
    void setLog(std::function<void(const std::string&)> log);

    void start(std::uint16_t port);
    void stop();
    bool running() const;
    std::uint16_t port() const;
    std::uint64_t requests() const;

    std::string indexUrl() const;
    std::string urlFor(const std::string& internetUrl) const;

private:
    struct Request;
    struct Response;

    void handle(Socket& socket, const std::string& peer);
    Response route(const Request& request, const std::string& peer);
    Response serveIndex(const Request& request);
    Response serveSite(const Request& request, const std::string& name);
    Response nodeList();
    Response redirectTo(const Request& request);
    bool hostAllowed(const std::string& host) const;
    Endpoint registry() const;
    void note(const std::string& text);

    mutable std::mutex mutex_;
    Endpoint registry_{"127.0.0.1", kDefaultRegistryPort};
    Security* security_ = nullptr;
    bool allowScripts_ = false;
    bool loopbackOnly_ = true;
    std::function<void(const std::string&)> log_;
    std::atomic<std::uint64_t> requests_{0};
    Server server_;
};

}
