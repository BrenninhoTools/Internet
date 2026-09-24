#include "node.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace internet {

namespace {

std::string mimeType(const fs::path& file) {
    std::string extension = file.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (extension == ".html" || extension == ".htm") return "text/html";
    if (extension == ".txt" || extension == ".md") return "text/plain";
    if (extension == ".css") return "text/css";
    if (extension == ".js") return "text/javascript";
    if (extension == ".json") return "application/json";
    if (extension == ".xml") return "application/xml";
    if (extension == ".png") return "image/png";
    if (extension == ".jpg" || extension == ".jpeg") return "image/jpeg";
    if (extension == ".gif") return "image/gif";
    if (extension == ".svg") return "image/svg+xml";
    if (extension == ".ico") return "image/x-icon";
    if (extension == ".pdf") return "application/pdf";
    if (extension == ".zip") return "application/zip";
    return "application/octet-stream";
}

std::string escapeHtml(const std::string& text) {
    std::string escaped;
    for (char c : text) {
        switch (c) {
            case '&': escaped += "&amp;"; break;
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '"': escaped += "&quot;"; break;
            default: escaped += c;
        }
    }
    return escaped;
}

}

Node::Node(std::string name, const fs::path& root, Endpoint registry)
    : name_(std::move(name)), registry_(std::move(registry)) {
    if (!validName(name_)) throw std::invalid_argument("invalid node name '" + name_ + "'");
    std::error_code error;
    root_ = fs::canonical(root, error);
    if (error || !fs::is_directory(root_)) throw std::invalid_argument("not a directory: " + root.string());
}

Node::~Node() { stop(); }

void Node::start(std::uint16_t port) {
    if (server_.running()) throw std::logic_error("node already running");
    server_.start(port, [this](Socket& socket, const std::string&) { handle(socket); });
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = false;
    }
    std::uint16_t bound = server_.port();
    heartbeat_ = std::thread([this, bound] { heartbeat(bound); });
}

void Node::stop() {
    if (!server_.running()) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
    }
    wake_.notify_all();
    if (heartbeat_.joinable()) heartbeat_.join();
    std::uint16_t bound = server_.port();
    server_.stop();
    withdraw(bound);
    registered_ = false;
}

bool Node::running() const { return server_.running(); }

bool Node::registered() const { return registered_; }

std::uint16_t Node::port() const { return server_.port(); }

std::uint64_t Node::requests() const { return requests_; }

const std::string& Node::name() const { return name_; }

void Node::heartbeat(std::uint16_t port) {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!stopping_) {
        lock.unlock();
        bool ok = announce(port);
        registered_ = ok;
        lock.lock();
        if (stopping_) break;
        wake_.wait_for(lock, std::chrono::seconds(ok ? kHeartbeatSeconds : kRetrySeconds),
                       [this] { return stopping_; });
    }
}

bool Node::announce(std::uint16_t port) const {
    try {
        Message reply = exchange(registry_, Message{{"REGISTER", name_, std::to_string(port)}, {}});
        return !reply.fields.empty() && reply.fields[0] == "OK";
    } catch (const std::exception&) {
        return false;
    }
}

void Node::withdraw(std::uint16_t port) const {
    try {
        exchange(registry_, Message{{"UNREGISTER", name_, std::to_string(port)}, {}});
    } catch (const std::exception&) {
    }
}

void Node::handle(Socket& socket) {
    Message request;
    if (!readMessage(socket, request)) {
        writeMessage(socket, errorMessage("400"));
        return;
    }
    writeMessage(socket, respond(request));
}

Message Node::respond(const Message& request) {
    if (request.fields.size() != 2 || request.fields[0] != "GET") return errorMessage("400");
    ++requests_;

    std::string path;
    if (!percentDecode(request.fields[1], path)) return errorMessage("400");
    std::optional<fs::path> target = locate(path);
    if (!target) return errorMessage("404");

    std::error_code error;
    if (fs::is_directory(*target, error)) {
        fs::path index = *target / "index.html";
        if (!fs::is_regular_file(index, error)) return listing(*target, path);
        target = index;
    }

    std::uintmax_t size = fs::file_size(*target, error);
    if (error) return errorMessage("404");
    if (size > kMaxBody) return errorMessage("413");

    std::ifstream stream(*target, std::ios::binary);
    if (!stream) return errorMessage("500");
    std::string body((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    return okMessage({mimeType(*target)}, std::move(body));
}

Message Node::listing(const fs::path& directory, const std::string& path) const {
    struct Item {
        std::string name;
        bool directory;
    };
    std::vector<Item> items;
    std::error_code error;
    for (fs::directory_iterator it(directory, error), end; !error && it != end; it.increment(error)) {
        std::error_code entryError;
        items.push_back(Item{it->path().filename().string(), it->is_directory(entryError)});
    }
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        if (a.directory != b.directory) return a.directory;
        return a.name < b.name;
    });

    std::string base = path;
    if (base.empty() || base.back() != '/') base += '/';

    std::string html = "<!DOCTYPE html>\n<html><head><title>Index of " + escapeHtml(base) +
                       "</title></head><body>\n<h1>Index of " + escapeHtml(base) + "</h1>\n<ul>\n";
    if (base != "/") {
        std::string parent = base.substr(0, base.size() - 1);
        parent = parent.substr(0, parent.rfind('/') + 1);
        html += "<li><a href=\"" + percentEncode(parent, "/") + "\">..</a></li>\n";
    }
    for (const Item& item : items) {
        std::string link = percentEncode(base + item.name, "/") + (item.directory ? "/" : "");
        html += "<li><a href=\"" + link + "\">" + escapeHtml(item.name) + (item.directory ? "/" : "") +
                "</a></li>\n";
    }
    html += "</ul>\n</body></html>\n";
    return okMessage({"text/html"}, std::move(html));
}

std::optional<fs::path> Node::locate(const std::string& path) const {
    if (path.empty() || path[0] != '/') return std::nullopt;
    for (unsigned char c : path) {
        if (c < 0x20 || c == '\\' || c == ':') return std::nullopt;
    }

    std::string relative = path.substr(1);
    std::error_code error;
    fs::path full = fs::weakly_canonical(root_ / fs::u8path(relative), error);
    if (error) return std::nullopt;

    fs::path inside = full.lexically_relative(root_);
    if (inside.empty() || *inside.begin() == "..") return std::nullopt;
    if (!fs::exists(full, error) || error) return std::nullopt;
    return full;
}

}
