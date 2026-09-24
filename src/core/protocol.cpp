#include "protocol.hpp"

#include <charconv>
#include <stdexcept>
#include <utility>

namespace internet {

namespace {

std::vector<std::string> split(const std::string& line) {
    std::vector<std::string> tokens;
    std::size_t start = 0;
    while (start < line.size()) {
        std::size_t end = line.find(' ', start);
        if (end == std::string::npos) end = line.size();
        if (end > start) tokens.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    return tokens;
}

bool parseNumber(const std::string& text, std::size_t& value) {
    const char* first = text.data();
    const char* last = first + text.size();
    auto result = std::from_chars(first, last, value);
    return result.ec == std::errc() && result.ptr == last;
}

}

Endpoint parseEndpoint(const std::string& text) {
    std::size_t colon = text.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= text.size())
        throw std::invalid_argument("expected host:port, got '" + text + "'");
    std::size_t port = 0;
    if (!parseNumber(text.substr(colon + 1), port) || port == 0 || port > 65535)
        throw std::invalid_argument("invalid port in '" + text + "'");
    return Endpoint{text.substr(0, colon), static_cast<std::uint16_t>(port)};
}

std::string formatEndpoint(const Endpoint& endpoint) { return endpoint.host + ":" + std::to_string(endpoint.port); }

std::string describeCode(const std::string& code) {
    if (code == "400") return "Bad Request";
    if (code == "404") return "Not Found";
    if (code == "401") return "Unauthorized";
    if (code == "403") return "Forbidden";
    if (code == "405") return "Method Not Allowed";
    if (code == "409") return "Name Already Taken";
    if (code == "422") return "Rejected";
    if (code == "429") return "Too Many Requests";
    if (code == "451") return "Blocked By Security Policy";
    if (code == "413") return "Content Too Large";
    if (code == "500") return "Internal Error";
    return "Unknown Error";
}

std::string percentEncode(const std::string& text, const std::string& safe) {
    static const char digits[] = "0123456789ABCDEF";
    std::string encoded;
    for (unsigned char c : text) {
        bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                     c == '.' || c == '_' || c == '~' || safe.find(static_cast<char>(c)) != std::string::npos;
        if (plain) {
            encoded += static_cast<char>(c);
        } else {
            encoded += '%';
            encoded += digits[c >> 4];
            encoded += digits[c & 15];
        }
    }
    return encoded;
}

bool percentDecode(const std::string& text, std::string& decoded) {
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    decoded.clear();
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '%') {
            decoded += text[i];
            continue;
        }
        if (i + 2 >= text.size()) return false;
        int high = hex(text[i + 1]);
        int low = hex(text[i + 2]);
        if (high < 0 || low < 0) return false;
        decoded += static_cast<char>(high * 16 + low);
        i += 2;
    }
    return true;
}

bool validName(const std::string& name) {
    if (name.empty() || name.size() > 63) return false;
    for (char c : name) {
        bool allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
        if (!allowed) return false;
    }
    return true;
}

Message okMessage(std::vector<std::string> fields, std::string body) {
    Message message;
    message.fields.push_back("OK");
    for (auto& field : fields) message.fields.push_back(std::move(field));
    message.body = std::move(body);
    return message;
}

Message errorMessage(const std::string& code, const std::string& detail) {
    Message message;
    message.fields = {"ERR", code};
    message.body = detail;
    return message;
}

bool writeMessage(Socket& socket, const Message& message) {
    std::string wire;
    for (const auto& field : message.fields) {
        wire += field;
        wire += ' ';
    }
    wire += std::to_string(message.body.size());
    wire += '\n';
    wire += message.body;
    return socket.sendAll(wire);
}

bool readMessage(Socket& socket, Message& message) {
    std::string line;
    if (!socket.recvLine(line)) return false;
    std::vector<std::string> tokens = split(line);
    if (tokens.size() < 2) return false;
    std::size_t length = 0;
    if (!parseNumber(tokens.back(), length) || length > kMaxBody) return false;
    tokens.pop_back();
    message.fields = std::move(tokens);
    message.body.clear();
    if (length == 0) return true;
    return socket.recvExact(message.body, length);
}

Message exchange(const Endpoint& endpoint, const Message& request) {
    Socket socket = Socket::connect(endpoint.host, endpoint.port);
    if (!socket.valid())
        throw std::runtime_error("cannot connect to " + endpoint.host + ":" + std::to_string(endpoint.port));
    socket.setTimeout(kIoTimeoutMs);
    if (!writeMessage(socket, request)) throw std::runtime_error("connection lost while sending request");
    Message reply;
    if (!readMessage(socket, reply)) throw std::runtime_error("connection lost while reading reply");
    return reply;
}

}
