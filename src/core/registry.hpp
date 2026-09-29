#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "firewall.hpp"
#include "protocol.hpp"
#include "server.hpp"
#include "socket.hpp"

namespace internet {

bool reservedName(const std::string& name);

class Registry {
public:
    void setFirewall(Firewall* firewall);
    void setPublicHost(std::string host);
    void setLocalRegistrationOnly(bool enabled);
    void start(std::uint16_t port);
    void stop();
    bool running() const;
    std::uint16_t port() const;
    std::vector<NodeInfo> snapshot();

private:
    struct Entry {
        Endpoint endpoint;
        std::string owner;
        std::chrono::steady_clock::time_point seen;
    };

    void handle(Socket& socket, const std::string& peer);
    Message registerName(const Message& request, const std::string& peer);
    Message unregisterName(const Message& request, const std::string& peer);
    Message resolveName(const Message& request, const std::string& peer);
    Message listNames(const std::string& peer);
    void expire();

    std::mutex mutex_;
    std::map<std::string, Entry> entries_;
    Firewall* firewall_ = nullptr;
    std::string publicHost_;
    bool localRegistrationOnly_ = false;
    Server server_;
};

}
