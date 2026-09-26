#include "gateway.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <sstream>
#include <utility>

#include "client.hpp"
#include "json.hpp"

namespace internet {

namespace {

constexpr std::size_t kMaxHeaderLines = 100;
constexpr const char* kSuffix = ".localhost";
const std::string kScheme = "internet://";

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string escapeHtml(const std::string& text) {
    std::string out;
    for (char c : text) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 204: return "No Content";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 421: return "Misdirected Request";
        case 451: return "Unavailable For Legal Reasons";
        case 502: return "Bad Gateway";
        default: return "Error";
    }
}

int statusFor(const std::string& code) {
    if (code == "404") return 404;
    if (code == "451") return 451;
    if (code == "400") return 400;
    if (code == "403") return 403;
    if (code == "429") return 429;
    return 502;
}

std::string hostName(const std::string& host) {
    std::string name = lowered(host);
    if (!name.empty() && name.front() == '[') {
        std::size_t close = name.find(']');
        return close == std::string::npos ? name : name.substr(0, close + 1);
    }
    std::size_t colon = name.rfind(':');
    if (colon != std::string::npos) name.erase(colon);
    return name;
}

bool siteName(const std::string& host, std::string& name) {
    std::string base = hostName(host);
    std::string suffix = kSuffix;
    if (base.size() <= suffix.size() || base.compare(base.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
    name = base.substr(0, base.size() - suffix.size());
    return true;
}

std::string decodeForm(const std::string& text) {
    std::string spaced = text;
    std::replace(spaced.begin(), spaced.end(), '+', ' ');
    std::string decoded;
    if (!percentDecode(spaced, decoded)) return std::string();
    return decoded;
}

std::string queryValue(const std::string& query, const std::string& key) {
    std::stringstream stream(query);
    std::string pair;
    while (std::getline(stream, pair, '&')) {
        std::size_t equals = pair.find('=');
        if (equals == std::string::npos) continue;
        if (pair.substr(0, equals) == key) return decodeForm(pair.substr(equals + 1));
    }
    return std::string();
}

std::string trimmed(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return std::string();
    return text.substr(start, text.find_last_not_of(" \t\r\n") - start + 1);
}

std::string pageStyle() {
    return "<style>"
           ":root{color-scheme:dark}"
           "*{box-sizing:border-box}"
           "body{margin:0;min-height:100vh;font:16px/1.55 system-ui,'Segoe UI',Roboto,sans-serif;color:#e8ecf8;"
           "background:radial-gradient(1200px 600px at 10% -10%,#1d3a8a55,transparent),radial-gradient(900px 500px at 100% 0,#7c3aed44,transparent),#0b1020}"
           "main{max-width:760px;margin:0 auto;padding:48px 20px}"
           "h1{margin:0 0 6px;font-size:2rem;background:linear-gradient(90deg,#60a5fa,#c084fc);-webkit-background-clip:text;background-clip:text;color:transparent}"
           "h2{margin:32px 0 10px;font-size:1.05rem;color:#9fb0d8;font-weight:600;letter-spacing:.04em;text-transform:uppercase}"
           "p{color:#aab6d6}"
           "form{display:flex;gap:10px;margin:22px 0}"
           "input{flex:1;min-width:0;padding:12px 14px;border-radius:12px;border:1px solid #2b3a66;background:#111a35;color:#fff;font:inherit}"
           "input:focus{outline:2px solid #60a5fa;border-color:transparent}"
           "button{padding:12px 20px;border:0;border-radius:12px;background:linear-gradient(90deg,#3b82f6,#8b5cf6);color:#fff;font:inherit;font-weight:600;cursor:pointer}"
           "ul{list-style:none;padding:0;margin:0;display:grid;gap:10px}"
           "li a{display:flex;justify-content:space-between;gap:12px;padding:14px 16px;border-radius:12px;background:#111a35;border:1px solid #223055;color:#e8ecf8;text-decoration:none}"
           "li a:hover{border-color:#60a5fa;background:#15214a}"
           "li span{color:#7d8db8;font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
           ".card{padding:18px 20px;border-radius:14px;background:#111a35;border:1px solid #223055}"
           ".bad{border-color:#ef4444;background:#2a1020}.bad h1{background:linear-gradient(90deg,#f87171,#fb923c);-webkit-background-clip:text;background-clip:text}"
           ".pill{display:inline-block;padding:2px 10px;border-radius:999px;background:#1e2b55;color:#9fb0d8;font-size:.8rem;margin-right:6px}"
           "code{font-family:ui-monospace,Consolas,monospace;color:#c4b5fd}"
           "</style>";
}

std::string document(const std::string& title, const std::string& body) {
    return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>" +
           escapeHtml(title) + "</title>" + pageStyle() + "</head><body><main>" + body + "</main></body></html>";
}

std::string rewriteLinks(const std::string& html, std::uint16_t port) {
    std::string out;
    out.reserve(html.size());
    std::size_t index = 0;
    while (index < html.size()) {
        std::size_t found = html.find(kScheme, index);
        if (found == std::string::npos) {
            out.append(html, index, std::string::npos);
            break;
        }
        bool quoted = found > 0 && (html[found - 1] == '"' || html[found - 1] == '\'');
        std::size_t end = html.find_first_of("\"' >\r\n\t", found);
        if (end == std::string::npos) end = html.size();
        out.append(html, index, found - index);
        std::string target = html.substr(found, end - found);
        std::string name, path;
        if (quoted && parseInternetTarget(target, name, path)) {
            out += "http://" + name + kSuffix + ":" + std::to_string(port) + path;
        } else {
            out += target;
        }
        index = end;
    }
    return out;
}

std::string securityBanner(const std::string& rule, int score) {
    return "<div style=\"position:sticky;top:0;z-index:2147483647;padding:8px 14px;background:#7a4a00;color:#fff;font:14px system-ui,sans-serif\">"
           "Internet Security marked this page as suspicious (" +
           escapeHtml(rule.empty() ? "heuristics" : rule) + ", score " + std::to_string(score) + "). Be careful with it.</div>";
}

std::string injectBanner(const std::string& html, const std::string& banner) {
    std::string lower = lowered(html.substr(0, std::min<std::size_t>(html.size(), 65536)));
    std::size_t body = lower.find("<body");
    if (body != std::string::npos) {
        std::size_t close = lower.find('>', body);
        if (close != std::string::npos) return html.substr(0, close + 1) + banner + html.substr(close + 1);
    }
    return banner + html;
}

bool isMarkup(const std::string& type) {
    return type.rfind("text/html", 0) == 0 || type.rfind("application/xhtml", 0) == 0 || type.rfind("image/svg", 0) == 0;
}

}

struct Gateway::Request {
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::string host;
};

struct Gateway::Response {
    int status = 200;
    std::string type = "text/html; charset=utf-8";
    std::string body;
    std::map<std::string, std::string> headers;
    bool head = false;
};

std::string gatewayUrl(std::uint16_t port, const std::string& internetUrl) {
    std::string name, path;
    if (!parseInternetTarget(internetUrl, name, path)) return "http://localhost:" + std::to_string(port) + "/";
    return "http://" + name + kSuffix + ":" + std::to_string(port) + path;
}

bool parseInternetTarget(const std::string& text, std::string& name, std::string& path) {
    std::string rest = trimmed(text);
    if (rest.compare(0, kScheme.size(), kScheme) == 0) rest.erase(0, kScheme.size());
    std::size_t cut = rest.find('#');
    if (cut != std::string::npos) rest.erase(cut);
    std::size_t slash = rest.find('/');
    std::string candidate = lowered(rest.substr(0, slash));
    if (!validName(candidate)) return false;
    name = candidate;
    path = slash == std::string::npos ? "/" : rest.substr(slash);
    return true;
}

Gateway::~Gateway() { stop(); }

void Gateway::setRegistry(const Endpoint& registry) {
    std::lock_guard<std::mutex> lock(mutex_);
    registry_ = registry;
}

void Gateway::setSecurity(Security* security) {
    std::lock_guard<std::mutex> lock(mutex_);
    security_ = security;
}

void Gateway::setFirewall(Firewall* firewall) { server_.setFirewall(firewall); }

void Gateway::setAllowScripts(bool allow) {
    std::lock_guard<std::mutex> lock(mutex_);
    allowScripts_ = allow;
}

void Gateway::setLoopbackOnly(bool loopbackOnly) {
    std::lock_guard<std::mutex> lock(mutex_);
    loopbackOnly_ = loopbackOnly;
    server_.setLoopbackOnly(loopbackOnly);
}

void Gateway::setLog(std::function<void(const std::string&)> log) {
    std::lock_guard<std::mutex> lock(mutex_);
    log_ = std::move(log);
}

void Gateway::start(std::uint16_t port) {
    server_.start(port, [this](Socket& socket, const std::string& peer) { handle(socket, peer); });
    note("Gateway listening on http://localhost:" + std::to_string(server_.port()) + "/");
}

void Gateway::stop() { server_.stop(); }

bool Gateway::running() const { return server_.running(); }

std::uint16_t Gateway::port() const { return server_.port(); }

std::uint64_t Gateway::requests() const { return requests_; }

std::string Gateway::indexUrl() const { return "http://localhost:" + std::to_string(port()) + "/"; }

std::string Gateway::urlFor(const std::string& internetUrl) const { return gatewayUrl(port(), internetUrl); }

Endpoint Gateway::registry() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return registry_;
}

void Gateway::note(const std::string& text) {
    std::function<void(const std::string&)> log;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        log = log_;
    }
    if (log) log(text);
}

bool Gateway::hostAllowed(const std::string& host) const {
    bool restricted;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        restricted = loopbackOnly_;
    }
    if (!restricted) return true;
    std::string name = hostName(host);
    if (name == "localhost" || name == "127.0.0.1" || name == "[::1]") return true;
    std::string site;
    return siteName(host, site);
}

void Gateway::handle(Socket& socket, const std::string& peer) {
    Request request;
    std::string line;
    if (!socket.recvLine(line)) return;
    std::stringstream first(line);
    std::string version;
    first >> request.method >> request.target >> version;
    bool valid = !request.method.empty() && !request.target.empty() && version.rfind("HTTP/", 0) == 0;
    for (std::size_t count = 0; valid; ++count) {
        if (count > kMaxHeaderLines || !socket.recvLine(line)) {
            valid = false;
            break;
        }
        if (line.empty()) break;
        std::size_t colon = line.find(':');
        if (colon != std::string::npos && lowered(line.substr(0, colon)) == "host") request.host = trimmed(line.substr(colon + 1));
    }

    Response response;
    if (!valid) {
        response.status = 400;
        response.body = document("Bad request", "<div class=\"card bad\"><h1>Bad request</h1><p>This is an Internet gateway. Send it an HTTP GET.</p></div>");
    } else {
        std::size_t cut = request.target.find('?');
        request.path = request.target.substr(0, cut);
        if (cut != std::string::npos) request.query = request.target.substr(cut + 1);
        if (request.path.empty() || request.path[0] != '/') request.path = "/" + request.path;
        response = route(request, peer);
    }
    ++requests_;

    response.head = request.method == "HEAD";
    std::string out = "HTTP/1.1 " + std::to_string(response.status) + " " + reason(response.status) + "\r\n";
    out += "Content-Type: " + response.type + "\r\n";
    out += "Content-Length: " + std::to_string(response.body.size()) + "\r\n";
    out += "Connection: close\r\nCache-Control: no-cache\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n";
    for (const auto& header : response.headers) out += header.first + ": " + header.second + "\r\n";
    out += "\r\n";
    if (!response.head) out += response.body;
    socket.sendAll(out);
}

Gateway::Response Gateway::route(const Request& request, const std::string& peer) {
    (void)peer;
    Response response;
    if (request.method != "GET" && request.method != "HEAD") {
        response.status = 405;
        response.headers["Allow"] = "GET, HEAD";
        response.body = document("Method not allowed", "<div class=\"card bad\"><h1>Method not allowed</h1><p>The gateway only reads pages.</p></div>");
        return response;
    }
    if (!hostAllowed(request.host)) {
        response.status = 421;
        response.body = document("Wrong host", "<div class=\"card bad\"><h1>Wrong host</h1><p>Open the gateway as <code>http://localhost</code>.</p></div>");
        return response;
    }
    std::string name;
    if (siteName(request.host, name)) {
        if (!validName(name)) {
            response.status = 400;
            response.body = document("Invalid site", "<div class=\"card bad\"><h1>Invalid site name</h1><p>Site names use lowercase letters, digits, dashes and dots.</p></div>");
            return response;
        }
        return serveSite(request, name);
    }
    if (request.path == "/_nodes") return nodeList();
    if (request.path == "/go") return redirectTo(request);
    if (request.path == "/favicon.ico") {
        response.status = 204;
        return response;
    }
    return serveIndex(request);
}

Gateway::Response Gateway::nodeList() {
    Response response;
    response.type = "application/json";
    Json list = Json::array();
    try {
        for (const NodeInfo& node : listNodes(registry())) {
            list.push(Json::object().set("name", node.name).set("url", gatewayUrl(port(), kScheme + node.name + "/")));
        }
    } catch (const std::exception&) {
    }
    response.body = Json::object().set("port", static_cast<std::uint64_t>(port())).set("requests", requests_.load()).set("nodes", std::move(list)).dump();
    return response;
}

Gateway::Response Gateway::redirectTo(const Request& request) {
    std::string name, path;
    std::string text = queryValue(request.query, "url");
    if (!parseInternetTarget(text, name, path)) {
        Request again = request;
        again.query = "error=" + percentEncode(text, "");
        Response response = serveIndex(again);
        response.status = 400;
        return response;
    }
    Response response;
    response.status = 302;
    response.headers["Location"] = gatewayUrl(port(), kScheme + name + path);
    response.body = document("Redirect", "<p><a href=\"" + escapeHtml(response.headers["Location"]) + "\">Continue</a></p>");
    return response;
}

Gateway::Response Gateway::serveIndex(const Request& request) {
    Response response;
    std::string body;
    body += "<h1>Internet gateway</h1><p>Browse <code>internet://</code> sites from this browser. Every page passes through Internet Security first.</p>";
    std::string error = queryValue(request.query, "error");
    if (!error.empty()) body += "<div class=\"card bad\"><p>“" + escapeHtml(error) + "” is not a site address. Try <code>internet://home/</code>.</p></div>";
    body += "<form action=\"/go\" method=\"get\"><input name=\"url\" placeholder=\"internet://home/\" autofocus autocomplete=\"off\"><button type=\"submit\">Open</button></form>";

    Endpoint endpoint = registry();
    bool guarded;
    bool scripts;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        guarded = security_ != nullptr && security_->settings().realtime;
        scripts = allowScripts_;
    }
    body += "<p><span class=\"pill\">Registry " + escapeHtml(formatEndpoint(endpoint)) + "</span>";
    body += std::string("<span class=\"pill\">") + (guarded ? "Protection on" : "Protection off") + "</span>";
    body += std::string("<span class=\"pill\">") + (scripts ? "Scripts allowed" : "Scripts blocked") + "</span></p>";

    body += "<h2>Sites online</h2>";
    try {
        std::vector<NodeInfo> nodes = listNodes(endpoint);
        if (nodes.empty()) {
            body += "<div class=\"card\"><p>No site is registered yet.</p></div>";
        } else {
            body += "<ul>";
            for (const NodeInfo& node : nodes) {
                body += "<li><a href=\"" + escapeHtml(gatewayUrl(port(), kScheme + node.name + "/")) + "\"><strong>" + escapeHtml(node.name) +
                        "</strong><span>internet://" + escapeHtml(node.name) + "/</span></a></li>";
            }
            body += "</ul>";
        }
    } catch (const std::exception& failure) {
        body += "<div class=\"card bad\"><p>Cannot reach the registry: " + escapeHtml(failure.what()) + "</p></div>";
    }
    response.body = document("Internet gateway", body);
    return response;
}

Gateway::Response Gateway::serveSite(const Request& request, const std::string& name) {
    Response response;
    std::string url = kScheme + name + request.path;
    Endpoint endpoint = registry();
    Page page;
    try {
        page = fetch(endpoint, url);
    } catch (const FetchError& failure) {
        response.status = statusFor(failure.code());
        std::string title = response.status == 404 ? "Page not found" : "Cannot open this page";
        response.body = document(title, "<div class=\"card bad\"><h1>" + escapeHtml(title) + "</h1><p>" + escapeHtml(failure.what()) +
                                            "</p><p><code>" + escapeHtml(url) + "</code></p></div>");
        return response;
    } catch (const std::exception& failure) {
        response.status = 502;
        response.body = document("Cannot open this page", "<div class=\"card bad\"><h1>Cannot open this page</h1><p>" + escapeHtml(failure.what()) + "</p></div>");
        return response;
    }

    Security* security;
    bool scripts;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        security = security_;
        scripts = allowScripts_;
    }
    std::string verdict = "unchecked";
    std::string banner;
    if (security != nullptr && security->settings().realtime) {
        std::size_t slash = request.path.rfind('/');
        std::string file = slash == std::string::npos ? request.path : request.path.substr(slash + 1);
        if (file.empty()) file = page.contentType.rfind("text/html", 0) == 0 ? "index.html" : "listing";
        ScanResult result = security->scanBuffer(file, page.body, "gateway");
        const Finding* strongest = strongestFinding(result);
        std::string rule = strongest ? strongest->rule : std::string();
        verdict = verdictName(result.verdict);
        if (result.verdict == Verdict::Malicious) {
            security->noteBlocked("gateway", url, rule);
            note("Blocked " + url + " (" + rule + ")");
            response.status = 451;
            std::string detail = strongest ? strongest->description : std::string();
            response.body = document("Page blocked",
                                     "<div class=\"card bad\"><h1>Dangerous page blocked</h1><p>Internet Security stopped this page before it reached the browser.</p><p><code>" +
                                         escapeHtml(url) + "</code></p><p><span class=\"pill\">" + escapeHtml(rule) + "</span><span class=\"pill\">score " +
                                         std::to_string(result.score) + "</span></p><p>" + escapeHtml(detail) + "</p></div>");
            response.headers["X-Internet-Security"] = "malicious";
            return response;
        }
        if (result.verdict == Verdict::Suspicious) banner = securityBanner(rule, result.score);
    }

    std::string type = page.contentType.empty() ? "application/octet-stream" : page.contentType;
    bool markup = isMarkup(type);
    if (type.rfind("text/", 0) == 0 && type.find("charset") == std::string::npos) type += "; charset=utf-8";
    response.type = type;
    response.body = std::move(page.body);
    if (type.rfind("text/html", 0) == 0 || type.rfind("application/xhtml", 0) == 0) {
        response.body = rewriteLinks(response.body, port());
        if (!banner.empty()) response.body = injectBanner(response.body, banner);
    }
    if (markup && !scripts) {
        response.headers["Content-Security-Policy"] = "script-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'";
    }
    response.headers["X-Internet-Security"] = verdict;
    return response;
}

}
