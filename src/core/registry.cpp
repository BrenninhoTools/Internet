#include "registry.hpp"

#include <algorithm>
#include <charconv>

namespace internet {

namespace {

constexpr int kMaxNamesPerHost = 20;

bool parsePort(const std::string& text, std::uint16_t& port) {
    unsigned int value = 0;
    auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc() || result.ptr != text.data() + text.size() || value == 0 || value > 65535)
        return false;
    port = static_cast<std::uint16_t>(value);
    return true;
}

bool isReserved(const std::string& name) {
    static const char* names[] = {"api",      "admin",  "registry", "defs",   "internet", "root",
                                  "localhost", "www",   "security", "update", "updates",  "system"};
    for (const char* reserved : names) {
        if (name == reserved) return true;
    }
    return false;
}

bool isLocal(const std::string& peer) { return peer == "127.0.0.1" || peer == "::1"; }

}

void Registry::setFirewall(Firewall* firewall) { firewall_ = firewall; }

void Registry::start(std::uint16_t port) {
    server_.setFirewall(firewall_);
    server_.start(port, [this](Socket& socket, const std::string& peer) { handle(socket, peer); });
}

void Registry::stop() {
    server_.stop();
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

bool Registry::running() const { return server_.running(); }

std::uint16_t Registry::port() const { return server_.port(); }

std::vector<NodeInfo> Registry::snapshot() {
    std::lock_guard<std::mutex> lock(mutex_);
    expire();
    std::vector<NodeInfo> nodes;
    for (const auto& [name, entry] : entries_) nodes.push_back(NodeInfo{name, entry.endpoint});
    return nodes;
}

void Registry::handle(Socket& socket, const std::string& peer) {
    if (firewall_ && !firewall_->allowRequest(peer)) {
        writeMessage(socket, errorMessage("429", "Too many requests"));
        return;
    }
    Message request;
    if (!readMessage(socket, request) || request.fields.empty()) {
        if (firewall_) firewall_->violation(peer, "malformed request");
        writeMessage(socket, errorMessage("400"));
        return;
    }
    const std::string& verb = request.fields[0];
    Message reply;
    if (verb == "REGISTER") {
        reply = registerName(request, peer);
    } else if (verb == "UNREGISTER") {
        reply = unregisterName(request, peer);
    } else if (verb == "RESOLVE") {
        reply = resolveName(request);
    } else if (verb == "LIST") {
        reply = listNames();
    } else {
        if (firewall_) firewall_->violation(peer, "unknown request");
        reply = errorMessage("400");
    }
    writeMessage(socket, reply);
}

Message Registry::registerName(const Message& request, const std::string& peer) {
    std::uint16_t port = 0;
    if (request.fields.size() != 3 || !validName(request.fields[1]) || !parsePort(request.fields[2], port))
        return errorMessage("400");
    const std::string& name = request.fields[1];
    if (isReserved(name) && !isLocal(peer)) {
        if (firewall_) firewall_->violation(peer, "tried to register a reserved name");
        return errorMessage("403", "This name is reserved");
    }

    std::lock_guard<std::mutex> lock(mutex_);
    expire();
    auto existing = entries_.find(name);
    if (existing != entries_.end() && existing->second.endpoint.host != peer) return errorMessage("409");
    if (existing == entries_.end()) {
        int owned = static_cast<int>(std::count_if(entries_.begin(), entries_.end(), [&](const auto& item) {
            return item.second.endpoint.host == peer;
        }));
        if (owned >= kMaxNamesPerHost && !isLocal(peer)) {
            if (firewall_) firewall_->violation(peer, "too many names");
            return errorMessage("403", "Too many names for one host");
        }
    }
    entries_[name] = Entry{Endpoint{peer, port}, std::chrono::steady_clock::now()};
    return okMessage();
}

Message Registry::unregisterName(const Message& request, const std::string& peer) {
    std::uint16_t port = 0;
    if (request.fields.size() != 3 || !parsePort(request.fields[2], port)) return errorMessage("400");

    std::lock_guard<std::mutex> lock(mutex_);
    auto existing = entries_.find(request.fields[1]);
    if (existing == entries_.end()) return errorMessage("404");
    if (existing->second.endpoint.host != peer || existing->second.endpoint.port != port)
        return errorMessage("409");
    entries_.erase(existing);
    return okMessage();
}

Message Registry::resolveName(const Message& request) {
    if (request.fields.size() != 2) return errorMessage("400");
    std::lock_guard<std::mutex> lock(mutex_);
    expire();
    auto found = entries_.find(request.fields[1]);
    if (found == entries_.end()) return errorMessage("404");
    return okMessage({found->second.endpoint.host, std::to_string(found->second.endpoint.port)});
}

Message Registry::listNames() {
    std::lock_guard<std::mutex> lock(mutex_);
    expire();
    std::string body;
    for (const auto& [name, entry] : entries_) {
        body += name + ' ' + entry.endpoint.host + ' ' + std::to_string(entry.endpoint.port) + '\n';
    }
    return okMessage({}, std::move(body));
}

void Registry::expire() {
    auto now = std::chrono::steady_clock::now();
    auto ttl = std::chrono::seconds(kRegistrationTtlSeconds);
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (now - it->second.seen > ttl) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

}
