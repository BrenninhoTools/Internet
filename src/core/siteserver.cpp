#include "siteserver.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <random>
#include <set>
#include <sstream>
#include <system_error>

#include "client.hpp"
#include "sha256.hpp"
#include "sitefiles.hpp"

namespace fs = std::filesystem;

namespace internet {

namespace {

const char kJsonType[] = "application/json";

Message okJson(const Json& json) { return okMessage({kJsonType}, json.dump()); }

Message failJson(const std::string& code, const std::string& message) {
    return errorMessage(code, Json::object().set("error", message).dump());
}

std::vector<std::string> segments(const std::string& path) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= path.size()) {
        std::size_t end = path.find('/', start);
        if (end == std::string::npos) end = path.size();
        if (end > start) parts.push_back(path.substr(start, end - start));
        start = end + 1;
    }
    return parts;
}

std::string joinFrom(const std::vector<std::string>& parts, std::size_t first) {
    std::string joined;
    for (std::size_t i = first; i < parts.size(); ++i) {
        if (i > first) joined += '/';
        joined += parts[i];
    }
    return joined;
}

Json scanJson(const ScanResult& result) {
    Json findings = Json::array();
    for (const Finding& finding : result.findings) {
        findings.push(Json::object()
                          .set("rule", finding.rule)
                          .set("category", finding.category)
                          .set("severity", finding.severity)
                          .set("description", finding.description)
                          .set("location", finding.location));
    }
    return Json::object()
        .set("name", result.name)
        .set("sha256", result.sha256)
        .set("type", result.type)
        .set("size", static_cast<std::uint64_t>(result.size))
        .set("verdict", verdictName(result.verdict))
        .set("score", result.score)
        .set("entropy", result.entropy)
        .set("truncated", result.truncated)
        .set("note", result.note)
        .set("findings", std::move(findings));
}

Json eventJson(const ThreatEvent& event) {
    return Json::object()
        .set("time", event.time)
        .set("source", event.source)
        .set("target", event.target)
        .set("verdict", event.verdict)
        .set("rule", event.rule)
        .set("action", event.action)
        .set("score", event.score)
        .set("sha256", event.sha256);
}

std::string generateToken() {
    std::random_device device;
    std::string seed;
    for (int i = 0; i < 16; ++i) {
        unsigned int value = device();
        seed.append(reinterpret_cast<const char*>(&value), sizeof value);
    }
    seed += std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    return sha256Hex(seed).substr(0, 40);
}

}

SiteServer::SiteServer(ServerConfig config)
    : config_(std::move(config)), security_(config_.dataDir / "security"), firewall_(config_.firewall) {
    token_ = loadToken();
}

SiteServer::~SiteServer() { stop(); }

const std::string& SiteServer::token() const { return token_; }

Security& SiteServer::security() { return security_; }

Firewall& SiteServer::firewall() { return firewall_; }

Registry& SiteServer::registry() { return registry_; }

bool SiteServer::running() const { return running_; }

Endpoint SiteServer::registryEndpoint() const {
    if (config_.hostRegistry) return Endpoint{"127.0.0.1", registry_.port()};
    return config_.externalRegistry;
}

std::int64_t SiteServer::uptimeSeconds() const {
    if (!running_) return 0;
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started_).count();
}

void SiteServer::log(const std::string& text) {
    if (config_.log) config_.log(text);
}

std::string SiteServer::loadToken() {
    std::error_code error;
    fs::create_directories(config_.dataDir, error);
    if (!config_.token.empty()) return config_.token;
    fs::path file = config_.dataDir / "token.txt";
    std::ifstream stream(file);
    std::string token;
    if (stream && std::getline(stream, token) && token.size() >= 16) return token;
    token = generateToken();
    std::ofstream out(file, std::ios::trunc);
    out << token << '\n';
    return token;
}

void SiteServer::start() {
    if (running_) return;
    std::error_code error;
    fs::create_directories(config_.sitesDir, error);
    fs::create_directories(config_.dataDir, error);
    firewall_.setListener([this](const std::string& text) { log("[firewall] " + text); });
    registry_.setFirewall(&firewall_);
    if (config_.hostRegistry) registry_.start(config_.registryPort);
    if (config_.scanOnStart) scanNow();

    api_ = std::make_unique<Node>("api", config_.dataDir, registryEndpoint());
    api_->setFileServing(false);
    api_->setFirewall(&firewall_);
    api_->setExtension([this](const Message& request, const std::string& peer, Message& reply) {
        return handleApi(request, peer, reply);
    });
    api_->start(0);

    started_ = std::chrono::steady_clock::now();
    lastScan_ = started_;
    stopping_ = false;
    running_ = true;
    syncSites();
    thread_ = std::thread([this] { manage(); });
}

void SiteServer::stop() {
    if (!running_) return;
    {
        std::lock_guard<std::mutex> lock(wakeMutex_);
        stopping_ = true;
    }
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
    running_ = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        nodes_.clear();
    }
    api_.reset();
    if (config_.hostRegistry) registry_.stop();
}

void SiteServer::manage() {
    std::unique_lock<std::mutex> lock(wakeMutex_);
    while (!stopping_) {
        wake_.wait_for(lock, std::chrono::seconds(2), [this] { return stopping_; });
        if (stopping_) break;
        lock.unlock();
        syncSites();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - lastScan_).count();
        if (config_.rescanSeconds > 0 && elapsed >= config_.rescanSeconds) scanNow();
        lock.lock();
    }
}

void SiteServer::syncSites() {
    std::set<std::string> present;
    std::error_code error;
    for (fs::directory_iterator it(config_.sitesDir, error), end; !error && it != end; it.increment(error)) {
        std::error_code entryError;
        if (!it->is_directory(entryError)) continue;
        std::string name = it->path().filename().string();
        if (validName(name) && !(name == "api")) present.insert(name);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = nodes_.begin(); it != nodes_.end();) {
        if (present.count(it->first) == 0) {
            log("Stopped hosting internet://" + it->first + "/");
            it = nodes_.erase(it);
        } else {
            ++it;
        }
    }
    for (const std::string& name : present) {
        if (nodes_.count(name) != 0) continue;
        try {
            auto node = std::make_unique<Node>(name, config_.sitesDir / name, registryEndpoint());
            node->setGuard([this](const fs::path& path) { return security_.guard(path); });
            node->setFirewall(&firewall_);
            node->start(0);
            nodes_[name] = std::move(node);
            log("Hosting internet://" + name + "/");
        } catch (const std::exception& problem) {
            log("Cannot host " + name + ": " + problem.what());
        }
    }
}

void SiteServer::scanNow() {
    ScanProgress progress;
    security_.scanTree({config_.sitesDir}, "server", progress);
    lastScan_ = std::chrono::steady_clock::now();
    for (const ScanRecord& record : progress.records) {
        const Finding* strongest = strongestFinding(record.result);
        log(std::string("[security] ") + record.path + ": " + verdictName(record.result.verdict) + " (" +
            (strongest ? strongest->rule : "") + ") " + record.action);
    }
}

std::vector<SiteInfo> SiteServer::sites() {
    std::vector<SiteInfo> result;
    std::map<std::string, Endpoint> endpoints;
    if (config_.hostRegistry) {
        for (const NodeInfo& info : registry_.snapshot()) endpoints[info.name] = info.endpoint;
    }
    std::error_code error;
    std::lock_guard<std::mutex> lock(mutex_);
    for (fs::directory_iterator it(config_.sitesDir, error), end; !error && it != end; it.increment(error)) {
        std::error_code entryError;
        if (!it->is_directory(entryError)) continue;
        std::string name = it->path().filename().string();
        if (!validName(name)) continue;
        SiteInfo info;
        info.name = name;
        auto node = nodes_.find(name);
        info.online = node != nodes_.end() && node->second->registered();
        if (node != nodes_.end()) info.requests = node->second->requests();
        auto endpoint = endpoints.find(name);
        if (endpoint != endpoints.end()) info.endpoint = formatEndpoint(endpoint->second);
        for (const SiteFile& file : listSiteFiles(it->path())) info.files += file.directory ? 0 : 1;
        result.push_back(std::move(info));
    }
    std::sort(result.begin(), result.end(), [](const SiteInfo& a, const SiteInfo& b) { return a.name < b.name; });
    return result;
}

fs::path SiteServer::sitePath(const std::string& name) const { return config_.sitesDir / name; }

bool SiteServer::validSite(const std::string& name) const {
    if (!validName(name) || name == "api") return false;
    std::error_code error;
    return fs::is_directory(sitePath(name), error);
}

bool SiteServer::createSite(const std::string& name, std::string& error) {
    if (!validName(name) || name == "api") {
        error = "Invalid site name";
        return false;
    }
    std::error_code code;
    if (fs::exists(sitePath(name), code)) {
        error = "A site with that name already exists";
        return false;
    }
    fs::create_directories(sitePath(name), code);
    if (code) {
        error = "Cannot create the site folder";
        return false;
    }
    if (!writeSiteFile(sitePath(name), "index.html", siteTemplate(2, name, name), error)) return false;
    syncSites();
    return true;
}

bool SiteServer::deleteSite(const std::string& name, std::string& error) {
    if (!validSite(name)) {
        error = "Site not found";
        return false;
    }
    std::error_code code;
    fs::remove_all(sitePath(name), code);
    if (code) {
        error = "Cannot delete the site: " + code.message();
        return false;
    }
    syncSites();
    return true;
}

Json SiteServer::status() {
    FirewallStats stats = firewall_.stats();
    SecurityCounters counters = security_.counters();
    std::vector<SiteInfo> list = sites();
    std::uint64_t online = 0;
    for (const SiteInfo& site : list) online += site.online ? 1 : 0;
    return Json::object()
        .set("service", "Internet API")
        .set("version", "1")
        .set("uptime", uptimeSeconds())
        .set("sites", static_cast<std::uint64_t>(list.size()))
        .set("online", online)
        .set("definitions", security_.definitionsVersion())
        .set("rules", static_cast<std::uint64_t>(security_.ruleCount()))
        .set("threats", counters.threats)
        .set("blocked", counters.blocked)
        .set("rateLimited", stats.rateLimited)
        .set("bans", stats.bans);
}

bool SiteServer::handleApi(const Message& request, const std::string& peer, Message& reply) {
    if (request.fields.empty()) return false;
    const std::string& verb = request.fields[0];
    if (verb == "GET" && request.fields.size() == 2) {
        std::string path;
        if (!percentDecode(request.fields[1], path)) return false;
        if (path == "/v1/status") {
            reply = okJson(status());
            return true;
        }
        if (path.rfind("/v1/", 0) == 0) {
            reply = failJson("401", "Send an API request with a token");
            return true;
        }
        return false;
    }
    if (verb != "API") return false;
    if (request.fields.size() != 4) {
        reply = failJson("400", "Expected: API <method> <path> <token>");
        return true;
    }
    std::string path;
    if (!percentDecode(request.fields[2], path)) {
        reply = failJson("400", "Invalid path");
        return true;
    }
    if (!constantTimeEquals(token_, request.fields[3])) {
        firewall_.violation(peer, "invalid API token", 2);
        reply = failJson("401", "Invalid token");
        return true;
    }
    std::string method = request.fields[1];
    std::transform(method.begin(), method.end(), method.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    reply = route(method, path, request.body, peer);
    return true;
}

Message SiteServer::route(const std::string& method, const std::string& path, const std::string& body, const std::string& peer) {
    (void)peer;
    std::vector<std::string> parts = segments(path);
    if (parts.size() < 2 || parts[0] != "v1") return failJson("404", "Unknown endpoint");
    const std::string& area = parts[1];

    if (area == "status" && parts.size() == 2) {
        if (method != "GET") return failJson("405", "Use GET");
        return okJson(status());
    }

    if (area == "sites") {
        if (parts.size() == 2) {
            if (method == "GET") {
                Json list = Json::array();
                for (const SiteInfo& site : sites()) {
                    list.push(Json::object()
                                  .set("name", site.name)
                                  .set("online", site.online)
                                  .set("endpoint", site.endpoint)
                                  .set("requests", site.requests)
                                  .set("files", site.files)
                                  .set("url", "internet://" + site.name + "/"));
                }
                return okJson(Json::object().set("sites", std::move(list)));
            }
            if (method == "POST") {
                Json input;
                std::string problem;
                if (!Json::parse(body, input, problem)) return failJson("400", "Invalid JSON: " + problem);
                std::string name = input.stringOr("name", "");
                if (!createSite(name, problem)) return failJson("422", problem);
                log("Created site " + name + " through the API");
                return okJson(Json::object().set("name", name).set("url", "internet://" + name + "/"));
            }
            return failJson("405", "Use GET or POST");
        }
        const std::string& name = parts[2];
        if (!validSite(name)) return failJson("404", "Site not found");
        if (parts.size() == 3) {
            if (method == "GET") {
                for (const SiteInfo& site : sites()) {
                    if (site.name == name) {
                        return okJson(Json::object()
                                          .set("name", site.name)
                                          .set("online", site.online)
                                          .set("endpoint", site.endpoint)
                                          .set("requests", site.requests)
                                          .set("files", site.files)
                                          .set("url", "internet://" + site.name + "/"));
                    }
                }
                return failJson("404", "Site not found");
            }
            if (method == "DELETE") {
                std::string problem;
                if (!deleteSite(name, problem)) return failJson("500", problem);
                log("Deleted site " + name + " through the API");
                return okJson(Json::object().set("deleted", name));
            }
            return failJson("405", "Use GET or DELETE");
        }
        const std::string& action = parts[3];
        fs::path root = sitePath(name);
        if (action == "scan" && parts.size() == 4) {
            if (method != "POST") return failJson("405", "Use POST");
            ScanProgress progress;
            security_.scanTree({root}, "api", progress);
            Json records = Json::array();
            for (const ScanRecord& record : progress.records) {
                const Finding* strongest = strongestFinding(record.result);
                records.push(Json::object()
                                 .set("path", record.path)
                                 .set("verdict", verdictName(record.result.verdict))
                                 .set("rule", strongest ? strongest->rule : "")
                                 .set("action", record.action));
            }
            return okJson(Json::object()
                              .set("files", static_cast<std::uint64_t>(progress.files))
                              .set("malicious", static_cast<std::uint64_t>(progress.malicious))
                              .set("suspicious", static_cast<std::uint64_t>(progress.suspicious))
                              .set("records", std::move(records)));
        }
        if (action == "files") {
            if (parts.size() == 4) {
                if (method != "GET") return failJson("405", "Use GET");
                Json list = Json::array();
                for (const SiteFile& file : listSiteFiles(root)) {
                    list.push(Json::object()
                                  .set("path", file.path)
                                  .set("directory", file.directory)
                                  .set("size", static_cast<std::uint64_t>(file.size)));
                }
                return okJson(Json::object().set("files", std::move(list)));
            }
            std::string file = joinFrom(parts, 4);
            if (!isSafeSitePath(file)) return failJson("400", "Invalid file path");
            std::string problem;
            if (method == "GET") {
                std::string content;
                if (!readSiteFile(root, file, content, problem)) {
                    if (problem == "Binary file") return okJson(Json::object().set("path", file).set("binary", true));
                    return failJson("404", problem);
                }
                return okJson(Json::object()
                                  .set("path", file)
                                  .set("size", static_cast<std::uint64_t>(content.size()))
                                  .set("binary", false)
                                  .set("content", content));
            }
            if (method == "PUT") {
                ScanResult scan = security_.scanBuffer(file, body, "upload");
                if (scan.verdict == Verdict::Malicious) {
                    security_.noteBlocked("upload", name + "/" + file, "rejected by the security scan");
                    log("[security] Rejected upload of " + name + "/" + file);
                    Json rejected = scanJson(scan);
                    rejected.set("error", "Rejected by the security scan");
                    return errorMessage("422", rejected.dump());
                }
                if (!writeSiteFile(root, file, body, problem)) return failJson("422", problem);
                Json warnings = Json::array();
                for (const Finding& finding : scan.findings) warnings.push(finding.rule);
                return okJson(Json::object()
                                  .set("path", file)
                                  .set("size", static_cast<std::uint64_t>(body.size()))
                                  .set("sha256", scan.sha256)
                                  .set("verdict", verdictName(scan.verdict))
                                  .set("warnings", std::move(warnings)));
            }
            if (method == "DELETE") {
                if (!deleteSitePath(root, file, problem)) return failJson("404", problem);
                return okJson(Json::object().set("deleted", file));
            }
            return failJson("405", "Use GET, PUT or DELETE");
        }
        return failJson("404", "Unknown endpoint");
    }

    if (area == "scan" && parts.size() >= 3) {
        if (method != "POST") return failJson("405", "Use POST");
        return okJson(scanJson(security_.scanBuffer(joinFrom(parts, 2), body, "api")));
    }

    if (area == "security") {
        std::string action = parts.size() > 2 ? parts[2] : "status";
        if (action == "status") {
            SecuritySettings settings = security_.settings();
            SecurityCounters counters = security_.counters();
            return okJson(Json::object()
                              .set("definitions", security_.definitionsVersion())
                              .set("rules", static_cast<std::uint64_t>(security_.ruleCount()))
                              .set("scanned", counters.scanned)
                              .set("threats", counters.threats)
                              .set("blocked", counters.blocked)
                              .set("quarantined", static_cast<std::uint64_t>(security_.quarantineItems().size()))
                              .set("guardHosting", settings.guardHosting)
                              .set("autoQuarantine", settings.autoQuarantine));
        }
        if (action == "threats") {
            Json list = Json::array();
            for (const ThreatEvent& event : security_.events(100)) list.push(eventJson(event));
            return okJson(Json::object().set("threats", std::move(list)));
        }
        if (action == "quarantine") {
            if (parts.size() == 3 && method == "GET") {
                Json list = Json::array();
                for (const QuarantineItem& item : security_.quarantineItems()) {
                    list.push(Json::object()
                                  .set("id", item.id)
                                  .set("name", item.name)
                                  .set("path", item.originalPath)
                                  .set("sha256", item.sha256)
                                  .set("verdict", item.verdict)
                                  .set("rule", item.rule)
                                  .set("score", item.score)
                                  .set("time", item.time)
                                  .set("size", static_cast<std::uint64_t>(item.size)));
                }
                return okJson(Json::object().set("items", std::move(list)));
            }
            if (parts.size() == 4 && method == "DELETE") {
                std::string problem;
                if (!security_.deleteQuarantined(parts[3], problem)) return failJson("404", problem);
                return okJson(Json::object().set("deleted", parts[3]));
            }
            return failJson("405", "Use GET or DELETE");
        }
        if (action == "firewall") {
            if (parts.size() == 3 && method == "GET") {
                FirewallStats stats = firewall_.stats();
                FirewallConfig config = firewall_.config();
                Json bans = Json::array();
                for (const BanInfo& ban : firewall_.bans()) {
                    bans.push(Json::object().set("host", ban.host).set("reason", ban.reason).set("remaining", ban.remainingSeconds));
                }
                return okJson(Json::object()
                                  .set("enabled", config.enabled)
                                  .set("ratePerSecond", config.ratePerSecond)
                                  .set("burst", config.burst)
                                  .set("maxConnectionsPerHost", config.maxConnectionsPerHost)
                                  .set("allowed", stats.allowed)
                                  .set("rateLimited", stats.rateLimited)
                                  .set("refused", stats.refused)
                                  .set("bans", stats.bans)
                                  .set("banned", std::move(bans)));
            }
            if (parts.size() == 5 && parts[3] == "bans" && method == "DELETE") {
                if (!firewall_.unban(parts[4])) return failJson("404", "That host is not banned");
                return okJson(Json::object().set("unbanned", parts[4]));
            }
            return failJson("405", "Use GET or DELETE");
        }
        if (action == "definitions") {
            if (method != "POST") return failJson("405", "Use POST");
            std::string problem;
            if (!security_.updateDefinitions(body, problem)) return failJson("422", problem);
            return okJson(Json::object()
                              .set("definitions", security_.definitionsVersion())
                              .set("rules", static_cast<std::uint64_t>(security_.ruleCount())));
        }
    }
    return failJson("404", "Unknown endpoint");
}

Json scanResultJson(const ScanResult& result) { return scanJson(result); }

ApiResponse apiCall(const Endpoint& registry, const std::string& method, const std::string& path, const std::string& token,
                    const std::string& body) {
    ApiResponse response;
    try {
        Endpoint api = resolveNode(registry, "api");
        Message reply =
            exchange(api, Message{{"API", method, percentEncode(path, "/"), token.empty() ? "-" : token}, body});
        response.reachable = true;
        response.ok = !reply.fields.empty() && reply.fields[0] == "OK";
        response.code = response.ok ? "200" : (reply.fields.size() > 1 ? reply.fields[1] : "500");
        response.body = reply.body;
    } catch (const FetchError& problem) {
        response.code = problem.code().empty() ? "0" : problem.code();
        response.body = Json::object().set("error", problem.what()).dump();
    } catch (const std::exception& problem) {
        response.code = "0";
        response.body = Json::object().set("error", problem.what()).dump();
    }
    return response;
}

}
