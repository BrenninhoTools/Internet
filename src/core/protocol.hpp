#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "socket.hpp"

namespace internet {

constexpr std::size_t kMaxBody = 64 * 1024 * 1024;
constexpr int kIoTimeoutMs = 10000;
constexpr int kHeartbeatSeconds = 60;
constexpr int kRetrySeconds = 3;
constexpr int kRegistrationTtlSeconds = 180;
constexpr std::uint16_t kDefaultRegistryPort = 4000;

struct Endpoint {
    std::string host;
    std::uint16_t port = 0;
};

struct NodeInfo {
    std::string name;
    Endpoint endpoint;
};

struct Message {
    std::vector<std::string> fields;
    std::string body;
};

Endpoint parseEndpoint(const std::string& text);
std::string formatEndpoint(const Endpoint& endpoint);
bool validName(const std::string& name);
std::string describeCode(const std::string& code);

std::string percentEncode(const std::string& text, const std::string& safe);
bool percentDecode(const std::string& text, std::string& decoded);

Message okMessage(std::vector<std::string> fields = {}, std::string body = {});
Message errorMessage(const std::string& code);
bool writeMessage(Socket& socket, const Message& message);
bool readMessage(Socket& socket, Message& message);
Message exchange(const Endpoint& endpoint, const Message& request);

}
