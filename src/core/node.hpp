#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "firewall.hpp"
#include "guard.hpp"
#include "protocol.hpp"
#include "server.hpp"
#include "socket.hpp"

namespace internet {

using NodeExtension = std::function<bool(const Message& request, const std::string& peer, Message& reply)>;

class Node {
public:
    Node(std::string name, const std::filesystem::path& root, Endpoint registry);
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;
    ~Node();

    void setGuard(GuardFunction guard);
    void setFirewall(Firewall* firewall);
    void setExtension(NodeExtension extension);
    void setFileServing(bool enabled);

    void start(std::uint16_t port);
    void stop();
    bool running() const;
    bool registered() const;
    std::uint16_t port() const;
    std::uint64_t requests() const;
    const std::string& name() const;

private:
    void handle(Socket& socket, const std::string& peer);
    Message respond(const Message& request, const std::string& peer);
    Message listing(const std::filesystem::path& directory, const std::string& path) const;
    std::optional<std::filesystem::path> locate(const std::string& path) const;
    bool announce(std::uint16_t port) const;
    void withdraw(std::uint16_t port) const;
    void heartbeat(std::uint16_t port);

    std::string name_;
    std::filesystem::path root_;
    Endpoint registry_;
    GuardFunction guard_;
    Firewall* firewall_ = nullptr;
    NodeExtension extension_;
    bool files_ = true;
    std::atomic<bool> registered_{false};
    std::atomic<std::uint64_t> requests_{0};
    bool stopping_ = false;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::thread heartbeat_;
    Server server_;
};

}
