#include "gateway.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <sstream>
#include <utility>

#include "accounts.hpp"
#include "client.hpp"
#include "googleauth.hpp"
#include "json.hpp"
#include "sha256.hpp"

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
        case 503: return "Service Unavailable";
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
           ".google{display:inline-flex;align-items:center;gap:10px;padding:11px 18px;border-radius:10px;background:#fff;color:#1f1f1f;font-weight:600;text-decoration:none}"
           ".button{display:inline-block;padding:10px 18px;border-radius:10px;background:#1e2b55;color:#e8ecf8;font-weight:600;text-decoration:none}"
           ".button:hover{background:#28397a}"
           "</style>";
}

const char kCookieName[] = "internet_session";

const char kGoogleLogo[] =
    "<svg width=\"18\" height=\"18\" viewBox=\"0 0 48 48\" aria-hidden=\"true\">"
    "<path fill=\"#EA4335\" d=\"M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z\"/>"
    "<path fill=\"#4285F4\" d=\"M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z\"/>"
    "<path fill=\"#FBBC05\" d=\"M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z\"/>"
    "<path fill=\"#34A853\" d=\"M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z\"/>"
    "</svg>";

std::string cookieValue(const std::string& header, const std::string& name) {
    std::size_t position = 0;
    while (position < header.size()) {
        std::size_t end = header.find(';', position);
        if (end == std::string::npos) end = header.size();
        std::string pair = trimmed(header.substr(position, end - position));
        position = end + 1;
        std::size_t equals = pair.find('=');
        if (equals != std::string::npos && pair.substr(0, equals) == name) return pair.substr(equals + 1);
    }
    return std::string();
}

std::string sessionCookie(const std::string& token, bool secure) {
    return std::string(kCookieName) + "=" + token + "; Path=/; Max-Age=" + std::to_string(kSessionSeconds) + "; HttpOnly; SameSite=Lax" +
           (secure ? "; Secure" : "");
}

std::string clearedCookie(bool secure) {
    return std::string(kCookieName) + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" + (secure ? "; Secure" : "");
}

std::string logoutToken(const std::string& session) { return sha256Hex(session + ":logout").substr(0, 16); }

std::string document(const std::string& title, const std::string& body) {
    return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>" +
           escapeHtml(title) + "</title>" + pageStyle() + "</head><body><main>" + body + "</main></body></html>";
}

std::string rewriteLinks(const std::string& html, const std::string& scheme, const std::string& suffix, const std::string& portText) {
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
            out += scheme + "://" + name + suffix + portText + path;
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

struct Gateway::Origin {
    std::string scheme;
    std::string suffix;
    std::string index;
    std::string port;
};

struct Gateway::Request {
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::string host;
    std::string cookie;
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

std::string normalizeWebBase(const std::string& text) {
    std::string value = trimmed(text);
    std::string scheme = "https";
    std::size_t marker = value.find("://");
    if (marker != std::string::npos) {
        scheme = lowered(value.substr(0, marker));
        value.erase(0, marker + 3);
    }
    if (scheme != "http" && scheme != "https") return std::string();
    std::size_t end = value.find_first_of("/?#");
    if (end != std::string::npos) value.erase(end);
    value = lowered(value);

    std::string host = value;
    std::string port;
    std::size_t colon = value.rfind(':');
    if (colon != std::string::npos) {
        host = value.substr(0, colon);
        port = value.substr(colon + 1);
        if (port.empty() || port.size() > 5 || port.find_first_not_of("0123456789") != std::string::npos) return std::string();
        int number = std::stoi(port);
        if (number < 1 || number > 65535) return std::string();
    }
    if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.' || host.find("..") != std::string::npos)
        return std::string();
    bool numeric = true;
    for (unsigned char c : host) {
        if (!(std::isalnum(c) || c == '-' || c == '.')) return std::string();
        if (!(std::isdigit(c) || c == '.')) numeric = false;
    }
    if (numeric) return std::string();
    return scheme + "://" + host + (port.empty() ? std::string() : ":" + port);
}

std::string webUrlFor(const std::string& base, const std::string& internetUrl) {
    std::string normal = normalizeWebBase(base);
    std::string name, path;
    if (normal.empty() || !parseInternetTarget(internetUrl, name, path)) return std::string();
    std::string trimmedUrl = trimmed(internetUrl);
    std::size_t hash = trimmedUrl.find('#');
    std::string fragment = hash == std::string::npos ? std::string() : trimmedUrl.substr(hash);
    std::size_t marker = normal.find("://");
    return normal.substr(0, marker) + "://" + name + "." + normal.substr(marker + 3) + path + fragment;
}

std::string internetUrlFor(const std::string& base, const std::string& webUrl) {
    std::string normal = normalizeWebBase(base);
    if (normal.empty()) return std::string();
    std::string rest = trimmed(webUrl);
    std::string head = lowered(rest.substr(0, 8));
    std::size_t skip = head.rfind("https://", 0) == 0 ? 8 : (head.rfind("http://", 0) == 0 ? 7 : 0);
    if (skip == 0) return std::string();
    rest.erase(0, skip);
    std::size_t end = rest.find_first_of("/?#");
    std::string authority = lowered(end == std::string::npos ? rest : rest.substr(0, end));
    std::string tail = end == std::string::npos ? std::string("/") : rest.substr(end);
    if (tail[0] != '/') tail = "/" + tail;
    std::string suffix = "." + normal.substr(normal.find("://") + 3);
    if (authority.size() <= suffix.size() || authority.compare(authority.size() - suffix.size(), suffix.size(), suffix) != 0)
        return std::string();
    std::string name = authority.substr(0, authority.size() - suffix.size());
    if (!validName(name)) return std::string();
    return kScheme + name + tail;
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

void Gateway::setDomain(const std::string& domain, bool https, std::uint16_t publicPort) {
    std::lock_guard<std::mutex> lock(mutex_);
    domain_ = lowered(domain);
    https_ = https;
    publicPort_ = publicPort;
}

void Gateway::setDisplayRegistry(const Endpoint& registry) {
    std::lock_guard<std::mutex> lock(mutex_);
    displayRegistry_ = registry;
}

void Gateway::setAccounts(Accounts* accounts) {
    std::lock_guard<std::mutex> lock(mutex_);
    accounts_ = accounts;
}

void Gateway::setGoogle(GoogleAuth* google) {
    std::lock_guard<std::mutex> lock(mutex_);
    google_ = google;
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

Gateway::Origin Gateway::origin() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (domain_.empty()) return Origin{"http", kSuffix, "localhost", ":" + std::to_string(server_.port())};
    return Origin{https_ ? "https" : "http", "." + domain_, domain_, publicPort_ == 0 ? std::string() : ":" + std::to_string(publicPort_)};
}

std::string Gateway::indexUrl() const {
    Origin where = origin();
    return where.scheme + "://" + where.index + where.port + "/";
}

std::string Gateway::urlFor(const std::string& internetUrl) const {
    Origin where = origin();
    std::string name, path;
    if (!parseInternetTarget(internetUrl, name, path)) return where.scheme + "://" + where.index + where.port + "/";
    return where.scheme + "://" + name + where.suffix + where.port + path;
}

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

bool Gateway::siteFor(const std::string& host, std::string& name) const {
    if (siteName(host, name)) return true;
    std::string domain;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        domain = domain_;
    }
    if (domain.empty()) return false;
    std::string base = hostName(host);
    std::string suffix = "." + domain;
    if (base.size() <= suffix.size() || base.compare(base.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
    name = base.substr(0, base.size() - suffix.size());
    return name != "www";
}

bool Gateway::hostAllowed(const std::string& host) const {
    bool restricted;
    std::string domain;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        restricted = loopbackOnly_;
        domain = domain_;
    }
    std::string name = hostName(host);
    if (name == "localhost" || name == "127.0.0.1" || name == "[::1]") return true;
    if (!domain.empty()) {
        std::string suffix = "." + domain;
        bool inside = name == domain || (name.size() > suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0);
        std::string site;
        return inside || siteName(host, site);
    }
    if (!restricted) return true;
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
        if (colon == std::string::npos) continue;
        std::string header = lowered(line.substr(0, colon));
        if (header == "host") request.host = trimmed(line.substr(colon + 1));
        if (header == "cookie") request.cookie = trimmed(line.substr(colon + 1));
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
    Response response;
    if (request.method != "GET" && request.method != "HEAD") {
        response.status = 405;
        response.headers["Allow"] = "GET, HEAD";
        response.body = document("Method not allowed", "<div class=\"card bad\"><h1>Method not allowed</h1><p>The gateway only reads pages.</p></div>");
        return response;
    }
    std::string requested = hostName(request.host);
    bool localHost = requested == "localhost" || requested == "127.0.0.1" || requested == "[::1]";
    if (request.path == "/_ask" && localHost && (peer == "127.0.0.1" || peer == "::1")) return askCertificate(request);
    if (!hostAllowed(request.host)) {
        response.status = 421;
        response.body = document("Wrong host", "<div class=\"card bad\"><h1>Wrong host</h1><p>Open the gateway with its own address, for example <code>" + escapeHtml(indexUrl()) + "</code>.</p></div>");
        return response;
    }
    std::string name;
    if (siteFor(request.host, name)) {
        if (!validName(name)) {
            response.status = 400;
            response.body = document("Invalid site", "<div class=\"card bad\"><h1>Invalid site name</h1><p>Site names use lowercase letters, digits, dashes and dots.</p></div>");
            return response;
        }
        return serveSite(request, name);
    }
    if (request.path == "/login" || request.path == "/account" || request.path == "/logout" || request.path.rfind("/auth/google/", 0) == 0)
        return accountRoute(request);
    if (request.path == "/_nodes") return nodeList();
    if (request.path == "/go") return redirectTo(request);
    if (request.path == "/favicon.ico") {
        response.status = 204;
        return response;
    }
    return serveIndex(request);
}

Gateway::Response Gateway::askCertificate(const Request& request) {
    Response response;
    response.type = "text/plain; charset=utf-8";
    std::string domain;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        domain = domain_;
    }
    std::string asked = lowered(queryValue(request.query, "domain"));
    bool allowed = false;
    if (!domain.empty() && !asked.empty()) {
        std::string suffix = "." + domain;
        if (asked == domain || asked == "www" + suffix) {
            allowed = true;
        } else if (asked.size() > suffix.size() && asked.compare(asked.size() - suffix.size(), suffix.size(), suffix) == 0) {
            std::string name = asked.substr(0, asked.size() - suffix.size());
            if (validName(name)) {
                try {
                    resolveNode(registry(), name);
                    allowed = true;
                } catch (const std::exception&) {
                }
            }
        }
    }
    response.status = allowed ? 200 : 404;
    response.body = allowed ? "ok" : "unknown domain";
    return response;
}

Gateway::Response Gateway::accountRoute(const Request& request) {
    Accounts* accounts;
    GoogleAuth* google;
    bool secure;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        accounts = accounts_;
        google = google_;
        secure = https_;
    }
    auto page = [](int status, const std::string& title, const std::string& body) {
        Response response;
        response.status = status;
        response.body = document(title, body);
        return response;
    };
    auto redirect = [](const std::string& target) {
        Response response;
        response.status = 302;
        response.headers["Location"] = target;
        response.body = document("Redirect", "<p><a href=\"" + escapeHtml(target) + "\">Continue</a></p>");
        return response;
    };
    auto failed = [&](int status, const std::string& title, const std::string& message) {
        return page(status, title, "<div class=\"card bad\"><h1>" + escapeHtml(title) + "</h1><p>" + escapeHtml(message) +
                                       "</p><p><a class=\"button\" href=\"/login\">Try again</a></p></div>");
    };
    if (!accounts || !google) return failed(404, "Sign-in is not available", "This server does not have accounts turned on.");

    std::string session = cookieValue(request.cookie, kCookieName);
    std::optional<Account> who;
    if (!session.empty()) who = accounts->sessionAccount(session);

    if (request.path == "/login") {
        if (who) return redirect("/account");
        std::string body = "<h1>Sign in</h1><p>Use your Google account to publish sites and keep your bookmarks with you on every device.</p>";
        if (!google->enabled()) {
            body += "<div class=\"card bad\"><p>Signing in with Google is not set up on this server.</p></div>";
        } else {
            body += std::string("<p><a class=\"google\" href=\"/auth/google/start\">") + kGoogleLogo + "Sign in with Google</a></p>";
        }
        return page(200, "Sign in", body);
    }

    if (request.path == "/auth/google/start") {
        if (!google->enabled()) return failed(503, "Sign-in is not available", "Signing in with Google is not set up on this server.");
        std::string port = queryValue(request.query, "app_port");
        std::string challenge = queryValue(request.query, "challenge");
        int appPort = 0;
        if (!port.empty()) {
            bool digits = port.size() <= 5 && port.find_first_not_of("0123456789") == std::string::npos;
            appPort = digits ? std::stoi(port) : 0;
            bool goodChallenge = challenge.size() == 64 && challenge.find_first_not_of("0123456789abcdef") == std::string::npos;
            if (appPort < 1024 || appPort > 65535 || !goodChallenge) return failed(400, "Bad request", "The app sent an invalid sign-in request.");
        }
        return redirect(google->begin(appPort > 0 ? challenge : std::string(), appPort));
    }

    if (request.path == "/auth/google/callback") {
        if (!google->enabled()) return failed(503, "Sign-in is not available", "Signing in with Google is not set up on this server.");
        if (!queryValue(request.query, "error").empty()) return failed(200, "Sign-in cancelled", "You did not finish signing in with Google.");
        LoginRequest pending;
        GoogleIdentity identity;
        std::string problem;
        if (!google->finish(queryValue(request.query, "code"), queryValue(request.query, "state"), pending, identity, problem)) {
            note("Sign-in failed: " + problem);
            return failed(400, "Sign-in failed", problem);
        }
        Account account = accounts->signIn(identity.subject, identity.email, identity.name, identity.picture);
        note("Signed in " + account.email);
        if (pending.appPort > 0) {
            std::string handoff = accounts->createHandoff(account.id, pending.appChallenge);
            return redirect("http://127.0.0.1:" + std::to_string(pending.appPort) + "/?code=" + handoff);
        }
        Response response = redirect("/account");
        response.headers["Set-Cookie"] = sessionCookie(accounts->createSession(account.id), secure);
        return response;
    }

    if (request.path == "/logout") {
        if (!who) return redirect("/login");
        if (queryValue(request.query, "t") != logoutToken(session)) return redirect("/account");
        accounts->endSession(session);
        Response response = redirect("/login");
        response.headers["Set-Cookie"] = clearedCookie(secure);
        return response;
    }

    if (request.path != "/account") return failed(404, "Not found", "There is nothing at this address.");
    if (!who) return redirect("/login");
    std::string body = "<h1>Your account</h1><div class=\"card\"><p><strong>" + escapeHtml(who->name) + "</strong><br>" + escapeHtml(who->email) + "</p></div>";
    body += "<h2>Your sites</h2>";
    std::vector<std::string> names = accounts->sitesOf(who->id);
    if (names.empty()) {
        body += "<div class=\"card\"><p>You have no sites yet. Create one from the Internet app or with the API.</p></div>";
    } else {
        body += "<ul>";
        for (const std::string& name : names) {
            body += "<li><a href=\"" + escapeHtml(urlFor(kScheme + name + "/")) + "\"><strong>" + escapeHtml(name) + "</strong><span>internet://" +
                    escapeHtml(name) + "/</span></a></li>";
        }
        body += "</ul>";
    }
    body += "<p><a class=\"button\" href=\"/logout?t=" + logoutToken(session) + "\">Sign out</a></p>";
    return page(200, "Your account", body);
}

Gateway::Response Gateway::nodeList() {
    Response response;
    response.type = "application/json";
    Json list = Json::array();
    try {
        for (const NodeInfo& node : listNodes(registry())) {
            list.push(Json::object().set("name", node.name).set("url", urlFor(kScheme + node.name + "/")));
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
    response.headers["Location"] = urlFor(kScheme + name + path);
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
    Endpoint shown = endpoint;
    bool guarded;
    bool scripts;
    bool publicSite;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        guarded = security_ != nullptr && security_->settings().realtime;
        scripts = allowScripts_;
        publicSite = !domain_.empty();
        if (displayRegistry_.port != 0) shown = displayRegistry_;
    }
    body += "<p><span class=\"pill\">Registry " + escapeHtml(formatEndpoint(shown)) + "</span>";
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
                if (publicSite && node.name == "api") continue;
                body += "<li><a href=\"" + escapeHtml(urlFor(kScheme + node.name + "/")) + "\"><strong>" + escapeHtml(node.name) +
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
        Origin where = origin();
        response.body = rewriteLinks(response.body, where.scheme, where.suffix, where.port);
        if (!banner.empty()) response.body = injectBanner(response.body, banner);
    }
    if (markup && !scripts) {
        response.headers["Content-Security-Policy"] = "script-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'";
    }
    response.headers["X-Internet-Security"] = verdict;
    return response;
}

}
