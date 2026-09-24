#include "socket.hpp"

#include <cstring>
#include <stdexcept>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace internet {

namespace {

constexpr std::intptr_t kInvalid = -1;
constexpr std::size_t kMaxLine = 8192;
constexpr std::size_t kChunk = 65536;

#ifdef _WIN32
using NativeSocket = SOCKET;
using SockLen = int;

struct Startup {
    Startup() {
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
    }
    ~Startup() { WSACleanup(); }
};

const Startup startup;

void closeNative(std::intptr_t handle) { closesocket(static_cast<NativeSocket>(handle)); }
#else
using NativeSocket = int;
using SockLen = socklen_t;

void closeNative(std::intptr_t handle) { ::close(static_cast<NativeSocket>(handle)); }
#endif

NativeSocket native(std::intptr_t handle) { return static_cast<NativeSocket>(handle); }

void suppressSigpipe(NativeSocket fd) {
#ifdef SO_NOSIGPIPE
    int enabled = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof enabled);
#else
    (void)fd;
#endif
}

long sendRaw(std::intptr_t handle, const char* data, std::size_t size) {
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0;
#endif
#ifdef _WIN32
    return ::send(native(handle), data, static_cast<int>(size), flags);
#else
    return static_cast<long>(::send(native(handle), data, size, flags));
#endif
}

long recvRaw(std::intptr_t handle, char* data, std::size_t size) {
#ifdef _WIN32
    return ::recv(native(handle), data, static_cast<int>(size), 0);
#else
    return static_cast<long>(::recv(native(handle), data, size, 0));
#endif
}

}

Socket::Socket() : handle_(kInvalid) {}

Socket::Socket(std::intptr_t handle) : handle_(handle) {}

Socket::Socket(Socket&& other) noexcept
    : handle_(std::exchange(other.handle_, kInvalid)), buffer_(std::move(other.buffer_)) {}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, kInvalid);
        buffer_ = std::move(other.buffer_);
    }
    return *this;
}

Socket::~Socket() { close(); }

Socket Socket::listen(std::uint16_t port) {
    NativeSocket fd = ::socket(AF_INET, SOCK_STREAM, 0);
    Socket socket(static_cast<std::intptr_t>(fd));
    if (!socket.valid()) throw std::runtime_error("cannot create socket");
    suppressSigpipe(fd);

    int reuse = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof reuse);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0)
        throw std::runtime_error("cannot bind port " + std::to_string(port));
    if (::listen(fd, 128) != 0) throw std::runtime_error("cannot listen on port " + std::to_string(port));
    return socket;
}

Socket Socket::connect(const std::string& host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* results = nullptr;
    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &results) != 0) return Socket();

    Socket socket;
    for (addrinfo* item = results; item != nullptr; item = item->ai_next) {
        NativeSocket fd = ::socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        Socket candidate(static_cast<std::intptr_t>(fd));
        if (!candidate.valid()) continue;
        suppressSigpipe(fd);
        if (::connect(fd, item->ai_addr, static_cast<SockLen>(item->ai_addrlen)) == 0) {
            socket = std::move(candidate);
            break;
        }
    }
    ::freeaddrinfo(results);
    return socket;
}

Socket Socket::accept(std::string& peer) {
    sockaddr_in address{};
    SockLen length = sizeof address;
    NativeSocket fd = ::accept(native(handle_), reinterpret_cast<sockaddr*>(&address), &length);
    Socket client(static_cast<std::intptr_t>(fd));
    if (client.valid()) {
        suppressSigpipe(fd);
        char text[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &address.sin_addr, text, sizeof text);
        peer = text;
    }
    return client;
}

bool Socket::valid() const { return handle_ != kInvalid; }

void Socket::close() {
    if (valid()) {
        closeNative(handle_);
        handle_ = kInvalid;
    }
    buffer_.clear();
}

void Socket::setTimeout(int milliseconds) {
#ifdef _WIN32
    DWORD value = static_cast<DWORD>(milliseconds);
    ::setsockopt(native(handle_), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&value), sizeof value);
    ::setsockopt(native(handle_), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&value), sizeof value);
#else
    timeval value{};
    value.tv_sec = milliseconds / 1000;
    value.tv_usec = (milliseconds % 1000) * 1000;
    ::setsockopt(native(handle_), SOL_SOCKET, SO_RCVTIMEO, &value, sizeof value);
    ::setsockopt(native(handle_), SOL_SOCKET, SO_SNDTIMEO, &value, sizeof value);
#endif
}

bool Socket::waitReadable(int milliseconds) {
    pollfd descriptor{};
    descriptor.fd = native(handle_);
    descriptor.events = POLLIN;
#ifdef _WIN32
    int ready = ::WSAPoll(&descriptor, 1, milliseconds);
#else
    int ready = ::poll(&descriptor, 1, milliseconds);
#endif
    return ready > 0;
}

std::uint16_t Socket::port() const {
    sockaddr_in address{};
    SockLen length = sizeof address;
    if (::getsockname(native(handle_), reinterpret_cast<sockaddr*>(&address), &length) != 0) return 0;
    return ntohs(address.sin_port);
}

bool Socket::sendAll(const std::string& data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        long count = sendRaw(handle_, data.data() + sent, data.size() - sent);
        if (count <= 0) return false;
        sent += static_cast<std::size_t>(count);
    }
    return true;
}

bool Socket::fill() {
    char chunk[kChunk];
    long count = recvRaw(handle_, chunk, sizeof chunk);
    if (count <= 0) return false;
    buffer_.append(chunk, static_cast<std::size_t>(count));
    return true;
}

bool Socket::recvLine(std::string& line) {
    for (;;) {
        std::size_t position = buffer_.find('\n');
        if (position != std::string::npos) {
            line = buffer_.substr(0, position);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            buffer_.erase(0, position + 1);
            return true;
        }
        if (buffer_.size() > kMaxLine) return false;
        if (!fill()) return false;
    }
}

bool Socket::recvExact(std::string& data, std::size_t size) {
    while (buffer_.size() < size) {
        if (!fill()) return false;
    }
    data = buffer_.substr(0, size);
    buffer_.erase(0, size);
    return true;
}

}
