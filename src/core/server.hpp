#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "socket.hpp"

namespace internet {

using ConnectionHandler = std::function<void(Socket&, const std::string&)>;

class Server {
public:
    Server() = default;
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    ~Server();

    void start(std::uint16_t port, ConnectionHandler handler);
    void stop();
    bool running() const;
    std::uint16_t port() const;

private:
    void acceptLoop();

    Socket listener_;
    ConnectionHandler handler_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::uint16_t port_ = 0;
    std::mutex mutex_;
    std::condition_variable idle_;
    int active_ = 0;
};

}
