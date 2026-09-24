#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace internet {

class Socket {
public:
    Socket();
    explicit Socket(std::intptr_t handle);
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket();

    static Socket listen(std::uint16_t port);
    static Socket connect(const std::string& host, std::uint16_t port);

    Socket accept(std::string& peer);
    bool valid() const;
    void close();
    void setTimeout(int milliseconds);
    bool waitReadable(int milliseconds);
    std::uint16_t port() const;

    bool sendAll(const std::string& data);
    bool recvLine(std::string& line);
    bool recvExact(std::string& data, std::size_t size);

private:
    bool fill();

    std::intptr_t handle_;
    std::string buffer_;
};

}
