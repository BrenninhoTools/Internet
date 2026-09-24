#include "server.hpp"

#include <stdexcept>
#include <utility>

#include "protocol.hpp"

namespace internet {

namespace {

constexpr int kAcceptPollMs = 100;

}

Server::~Server() { stop(); }

void Server::start(std::uint16_t port, ConnectionHandler handler) {
    if (running_) throw std::logic_error("server already running");
    Socket listener = Socket::listen(port);
    port_ = listener.port();
    listener_ = std::move(listener);
    handler_ = std::move(handler);
    running_ = true;
    thread_ = std::thread([this] { acceptLoop(); });
}

void Server::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    listener_.close();
    std::unique_lock<std::mutex> lock(mutex_);
    idle_.wait(lock, [this] { return active_ == 0; });
}

bool Server::running() const { return running_; }

std::uint16_t Server::port() const { return port_; }

void Server::acceptLoop() {
    while (running_) {
        if (!listener_.waitReadable(kAcceptPollMs)) continue;
        std::string peer;
        Socket client = listener_.accept(peer);
        if (!client.valid()) continue;
        client.setTimeout(kIoTimeoutMs);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++active_;
        }
        std::thread([this, connection = std::move(client), peer]() mutable {
            try {
                handler_(connection, peer);
            } catch (...) {
            }
            connection.close();
            std::lock_guard<std::mutex> lock(mutex_);
            --active_;
            idle_.notify_all();
        }).detach();
    }
}

}
