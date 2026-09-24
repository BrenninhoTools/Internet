#include "client.hpp"

#include <charconv>
#include <sstream>
#include <utility>

namespace internet {

namespace {

const std::string kScheme = "internet://";

struct Url {
    std::string name;
    std::string path;
};

Url parseUrl(const std::string& url) {
    if (!isInternetUrl(url)) throw std::invalid_argument("url must start with " + kScheme);
    std::string rest = url.substr(kScheme.size());
    std::size_t cut = rest.find_first_of("#?");
    if (cut != std::string::npos) rest.erase(cut);
    std::size_t slash = rest.find('/');
    Url parsed;
    parsed.name = rest.substr(0, slash);
    parsed.path = slash == std::string::npos ? "/" : percentEncode(rest.substr(slash), "/%");
    if (!validName(parsed.name)) throw std::invalid_argument("invalid node name '" + parsed.name + "'");
    return parsed;
}

std::string normalizePath(const std::string& path) {
    std::vector<std::string> parts;
    std::stringstream stream(path);
    std::string part;
    while (std::getline(stream, part, '/')) {
        if (part.empty() || part == ".") continue;
        if (part == "..") {
            if (!parts.empty()) parts.pop_back();
            continue;
        }
        parts.push_back(part);
    }
    std::string result;
    for (const std::string& item : parts) result += "/" + item;
    if (result.empty() || path.back() == '/') result += "/";
    return result;
}

Message requireOk(const Message& reply, const std::string& context) {
    if (reply.fields.empty() || reply.fields[0] != "OK") {
        std::string code = reply.fields.size() > 1 ? reply.fields[1] : "500";
        throw FetchError(code, context + ": " + code + " " + describeCode(code));
    }
    return reply;
}

Message request(const Endpoint& endpoint, const Message& message, const std::string& context) {
    try {
        return requireOk(exchange(endpoint, message), context);
    } catch (const FetchError&) {
        throw;
    } catch (const std::exception& error) {
        throw FetchError("", context + ": " + error.what());
    }
}

Endpoint resolve(const Endpoint& registry, const std::string& name) {
    Message reply = request(registry, Message{{"RESOLVE", name}, {}}, "resolving '" + name + "'");
    unsigned int port = 0;
    if (reply.fields.size() != 3) throw FetchError("500", "malformed registry reply");
    const std::string& text = reply.fields[2];
    auto result = std::from_chars(text.data(), text.data() + text.size(), port);
    if (result.ec != std::errc() || port == 0 || port > 65535) throw FetchError("500", "malformed registry reply");
    return Endpoint{reply.fields[1], static_cast<std::uint16_t>(port)};
}

}

FetchError::FetchError(std::string code, const std::string& message)
    : std::runtime_error(message), code_(std::move(code)) {}

const std::string& FetchError::code() const { return code_; }

bool isInternetUrl(const std::string& url) { return url.compare(0, kScheme.size(), kScheme) == 0; }

std::string resolveUrl(const std::string& base, const std::string& href) {
    if (href.find("://") != std::string::npos) return href;
    std::string target = href.substr(0, href.find_first_of("#"));
    if (target.empty()) return base;

    Url parsed;
    try {
        parsed = parseUrl(base);
    } catch (const std::exception&) {
        return href;
    }
    std::string path;
    if (target[0] == '/') {
        path = target;
    } else {
        path = parsed.path.substr(0, parsed.path.rfind('/') + 1) + target;
    }
    return kScheme + parsed.name + normalizePath(path);
}

Page fetch(const Endpoint& registry, const std::string& url) {
    Url parsed;
    try {
        parsed = parseUrl(url);
    } catch (const std::invalid_argument& error) {
        throw FetchError("400", error.what());
    }
    Endpoint node = resolve(registry, parsed.name);
    Message reply = request(node, Message{{"GET", parsed.path}, {}}, "fetching '" + url + "'");
    Page page;
    page.url = url;
    page.contentType = reply.fields.size() > 1 ? reply.fields[1] : "application/octet-stream";
    page.body = std::move(reply.body);
    return page;
}

std::vector<NodeInfo> listNodes(const Endpoint& registry) {
    Message reply = request(registry, Message{{"LIST"}, {}}, "listing nodes");
    std::vector<NodeInfo> nodes;
    std::stringstream lines(reply.body);
    std::string line;
    while (std::getline(lines, line)) {
        std::stringstream fields(line);
        std::string name, host;
        unsigned int port = 0;
        if (fields >> name >> host >> port && port > 0 && port <= 65535)
            nodes.push_back(NodeInfo{name, Endpoint{host, static_cast<std::uint16_t>(port)}});
    }
    return nodes;
}

}
