#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <thread>

#include "browser.hpp"
#include "gateway.hpp"
#include "json.hpp"
#include "node.hpp"
#include "registry.hpp"
#include "security.hpp"
#include "socket.hpp"

namespace fs = std::filesystem;

namespace {

int failures = 0;

void check(bool condition, const std::string& label) {
    if (!condition) {
        ++failures;
        std::cerr << "FAILED: " << label << '\n';
    }
}

std::string marker() { return std::string("INTERNET-AV-TEST-") + "MARKER-7f3a9c"; }

void writeFile(const fs::path& path, const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary) << content;
}

struct HttpReply {
    bool ok = false;
    int status = 0;
    std::map<std::string, std::string> headers;
    std::string body;
};

HttpReply http(std::uint16_t port, const std::string& method, const std::string& host, const std::string& target) {
    HttpReply reply;
    internet::Socket socket = internet::Socket::connect("127.0.0.1", port);
    if (!socket.valid()) return reply;
    socket.setTimeout(5000);
    socket.sendAll(method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
    std::string line;
    if (!socket.recvLine(line) || line.size() < 12) return reply;
    reply.status = std::stoi(line.substr(9, 3));
    while (socket.recvLine(line) && !line.empty()) {
        std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::size_t start = line.find_first_not_of(' ', colon + 1);
        reply.headers[line.substr(0, colon)] = start == std::string::npos ? "" : line.substr(start);
    }
    std::size_t length = reply.headers.count("Content-Length") ? std::stoul(reply.headers["Content-Length"]) : 0;
    if (method != "HEAD" && length > 0) socket.recvExact(reply.body, length);
    reply.ok = true;
    return reply;
}

bool contains(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }

void testHelpers() {
    std::string name, path;
    check(internet::parseInternetTarget("internet://home/a/b.html", name, path) && name == "home" && path == "/a/b.html", "parse a full url");
    check(internet::parseInternetTarget("Home", name, path) && name == "home" && path == "/", "parse a bare name");
    check(internet::parseInternetTarget("  internet://a.b/x#frag ", name, path) && name == "a.b" && path == "/x", "parse dots and fragments");
    check(!internet::parseInternetTarget("internet://bad name/", name, path), "reject a bad name");
    check(!internet::parseInternetTarget("", name, path), "reject an empty target");
    check(internet::gatewayUrl(8080, "internet://home/x.html") == "http://home.localhost:8080/x.html", "gateway url");
    check(internet::gatewayUrl(9, "nonsense name") == "http://localhost:9/", "gateway url falls back to the index");
    check(!internet::executablePath().empty(), "the program knows where it is");
    std::string chrome = internet::findChrome();
    check(chrome.empty() || fs::exists(chrome), "a found Chrome exists");
    check(!internet::openInChrome("file:///etc/passwd") && !internet::openInDefaultBrowser("javascript:alert(1)"), "only web addresses are opened");
}

void testGateway() {
    fs::path root = fs::temp_directory_path() / "internet-gateway-test";
    fs::remove_all(root);
    writeFile(root / "home" / "index.html",
              "<html><head><title>Home</title></head><body><h1>Hello browser</h1><a href=\"internet://other/page.html\">go</a>"
              "<a href='internet://home/about.html'>about</a><a href=\"about.html\">relative</a></body></html>");
    writeFile(root / "home" / "about.html", "<html><body>About</body></html>");
    writeFile(root / "home" / "notes.txt", "plain notes");
    writeFile(root / "home" / "evil.html", "<html><body>" + marker() + "</body></html>");
    writeFile(root / "other" / "page.html", "<html><body>Other</body></html>");

    internet::Registry registry;
    registry.start(0);
    internet::Endpoint endpoint{"127.0.0.1", registry.port()};
    internet::Node home("home", root / "home", endpoint);
    internet::Node other("other", root / "other", endpoint);
    home.start(0);
    other.start(0);
    for (int i = 0; i < 100 && !(home.registered() && other.registered()); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));

    internet::Security security(root / "security");
    internet::Firewall firewall;
    internet::Gateway gateway;
    gateway.setRegistry(endpoint);
    gateway.setSecurity(&security);
    gateway.setFirewall(&firewall);
    gateway.start(0);
    std::uint16_t port = gateway.port();
    std::string suffix = ":" + std::to_string(port);

    HttpReply index = http(port, "GET", "localhost" + suffix, "/");
    check(index.ok && index.status == 200 && contains(index.body, "internet://home/") && contains(index.body, "home.localhost"), "the index lists the sites");
    check(contains(index.headers["Content-Type"], "text/html"), "the index is html");

    HttpReply page = http(port, "GET", "home.localhost" + suffix, "/");
    check(page.ok && page.status == 200 && contains(page.body, "Hello browser"), "a site page is served");
    check(page.headers["X-Internet-Security"] == "clean", "the page is marked clean");
    check(contains(page.headers["Content-Security-Policy"], "script-src 'none'"), "scripts are blocked by default");
    check(page.headers["X-Content-Type-Options"] == "nosniff", "sniffing is off");
    check(contains(page.body, "href=\"http://other.localhost" + suffix + "/page.html\""), "links to other sites become gateway links");
    check(contains(page.body, "href='http://home.localhost" + suffix + "/about.html'"), "single quoted links are rewritten too");
    check(contains(page.body, "href=\"about.html\""), "relative links are left alone");

    HttpReply about = http(port, "GET", "home.localhost" + suffix, "/about.html");
    check(about.status == 200 && contains(about.body, "About"), "a second page is served");
    HttpReply text = http(port, "GET", "home.localhost" + suffix, "/notes.txt?x=1");
    check(text.status == 200 && text.body == "plain notes" && contains(text.headers["Content-Type"], "text/plain"), "text files keep their type and ignore the query");
    HttpReply head = http(port, "HEAD", "home.localhost" + suffix, "/notes.txt");
    check(head.status == 200 && head.body.empty() && head.headers["Content-Length"] == "11", "HEAD returns only the headers");

    HttpReply evil = http(port, "GET", "home.localhost" + suffix, "/evil.html");
    check(evil.status == 451 && contains(evil.body, "blocked") && !contains(evil.body, "<body>" + marker()), "a malicious page is blocked");
    check(evil.headers["X-Internet-Security"] == "malicious", "the block is reported in a header");
    check(security.counters().blocked >= 1, "the block is counted");

    HttpReply missing = http(port, "GET", "home.localhost" + suffix, "/nothing.html");
    check(missing.status == 404 && contains(missing.body, "not found"), "a missing page is 404");
    HttpReply unknown = http(port, "GET", "ghost.localhost" + suffix, "/");
    check(unknown.status == 404, "an unknown site is 404");

    check(http(port, "GET", "evil.example" + suffix, "/").status == 421, "foreign host names are refused");
    check(http(port, "POST", "localhost" + suffix, "/").status == 405, "posts are refused");
    check(http(port, "GET", "localhost" + suffix, "/favicon.ico").status == 204, "favicon is quiet");

    HttpReply go = http(port, "GET", "localhost" + suffix, "/go?url=internet%3A%2F%2Fhome%2Fabout.html");
    check(go.status == 302 && go.headers["Location"] == "http://home.localhost" + suffix + "/about.html", "the address form redirects");
    HttpReply goBad = http(port, "GET", "localhost" + suffix, "/go?url=not+a+site");
    check(goBad.status == 400 && contains(goBad.body, "not a site address"), "a bad address is explained");

    HttpReply nodes = http(port, "GET", "127.0.0.1" + suffix, "/_nodes");
    internet::Json json;
    std::string error;
    check(nodes.status == 200 && internet::Json::parse(nodes.body, json, error) && json.find("nodes")->size() == 2, "the node list is json");

    gateway.setAllowScripts(true);
    check(http(port, "GET", "home.localhost" + suffix, "/about.html").headers.count("Content-Security-Policy") == 0, "scripts can be allowed");

    security.setSettings([&] {
        internet::SecuritySettings settings = security.settings();
        settings.realtime = false;
        return settings;
    }());
    check(http(port, "GET", "home.localhost" + suffix, "/evil.html").status == 200, "protection can be switched off");

    gateway.setRegistry(internet::Endpoint{"127.0.0.1", 1});
    check(http(port, "GET", "home.localhost" + suffix, "/").status == 502, "an unreachable registry is a bad gateway");

    gateway.stop();
    other.stop();
    home.stop();
    registry.stop();
    fs::remove_all(root);
}

}

int runGatewayTests() {
    testHelpers();
    testGateway();
    return failures;
}
