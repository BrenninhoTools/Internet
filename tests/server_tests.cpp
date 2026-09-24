#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "client.hpp"
#include "json.hpp"
#include "siteserver.hpp"

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

bool waitForNodes(const internet::Endpoint& registry, const std::vector<std::string>& names) {
    for (int i = 0; i < 100; ++i) {
        try {
            std::vector<internet::NodeInfo> nodes = internet::listNodes(registry);
            bool all = true;
            for (const std::string& name : names) {
                bool found = false;
                for (const internet::NodeInfo& node : nodes) found = found || node.name == name;
                all = all && found;
            }
            if (all) return true;
        } catch (const std::exception&) {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

std::string fetchCode(const internet::Endpoint& registry, const std::string& url) {
    try {
        internet::fetch(registry, url);
        return "200";
    } catch (const internet::FetchError& error) {
        return error.code();
    }
}

internet::Json parseJson(const std::string& text) {
    internet::Json json;
    std::string error;
    internet::Json::parse(text, json, error);
    return json;
}

void testJson() {
    internet::Json json;
    std::string error;
    check(internet::Json::parse("{\"a\":[1,2.5,true,null,\"x\\n\\u00e9\\ud83d\\ude00\"],\"b\":{\"c\":\"d\"}}", json, error),
          "parse JSON");
    check(json.find("b") && json.find("b")->stringOr("c", "") == "d", "read a nested value");
    const internet::Json* array = json.find("a");
    check(array && array->size() == 5 && array->items()[1].asNumber() == 2.5 && array->items()[2].asBool(), "read an array");
    check(array && array->items()[4].asString() == "x\n\xC3\xA9\xF0\x9F\x98\x80", "decode escapes and surrogate pairs");
    check(!internet::Json::parse("{\"a\":}", json, error) && !error.empty(), "reject invalid JSON");
    check(!internet::Json::parse("{\"a\":1} trailing", json, error), "reject trailing data");
    std::string deep(100, '[');
    check(!internet::Json::parse(deep, json, error), "reject deep nesting");
    internet::Json built =
        internet::Json::object().set("n", 3).set("s", "q\"\\").set("list", internet::Json::array().push(1).push("two"));
    check(built.dump() == "{\"n\":3,\"s\":\"q\\\"\\\\\",\"list\":[1,\"two\"]}", "dump JSON");
}

void testServer() {
    fs::path root = fs::temp_directory_path() / "internet-tests-server";
    fs::remove_all(root);
    writeFile(root / "sites" / "blog" / "index.html", "<html><body><h1>Blog</h1></body></html>");
    writeFile(root / "sites" / "blog" / "bad.txt", marker());

    internet::ServerConfig config;
    config.dataDir = root / "data";
    config.sitesDir = root / "sites";
    config.registryPort = 0;
    config.rescanSeconds = 0;
    internet::SiteServer server(config);
    server.start();
    internet::Endpoint registry = server.registryEndpoint();
    check(waitForNodes(registry, {"api", "blog"}), "api and site register");
    check(!fs::exists(root / "sites" / "blog" / "bad.txt"), "malicious file is quarantined at start");
    check(server.security().quarantineItems().size() == 1, "quarantine holds the file");
    check(fetchCode(registry, "internet://blog/") == "200", "site is served");

    internet::Json status = parseJson(internet::fetch(registry, "internet://api/v1/status").body);
    check(status.stringOr("service", "") == "Internet API", "public status endpoint");
    check(fetchCode(registry, "internet://api/v1/sites") == "401", "other GET requests need a token");
    check(fetchCode(registry, "internet://api/index.html") == "404", "the API node does not serve files");

    const std::string token = server.token();
    check(token.size() >= 16, "token is generated");
    internet::ApiResponse denied = internet::apiCall(registry, "GET", "/v1/sites", "wrong-token", "");
    check(denied.reachable && !denied.ok && denied.code == "401", "wrong token is rejected");
    check(internet::apiCall(registry, "GET", "/v1/sites", "", "").code == "401", "missing token is rejected");

    internet::ApiResponse sites = internet::apiCall(registry, "GET", "/v1/sites", token, "");
    internet::Json siteList = parseJson(sites.body);
    check(sites.ok && siteList.find("sites") && siteList.find("sites")->size() == 1, "list sites");

    internet::ApiResponse created = internet::apiCall(registry, "POST", "/v1/sites", token, "{\"name\":\"shop\"}");
    check(created.ok && waitForNodes(registry, {"shop"}), "create a site");
    check(fetchCode(registry, "internet://shop/") == "200", "new site is served");
    check(internet::apiCall(registry, "POST", "/v1/sites", token, "{\"name\":\"shop\"}").code == "422", "duplicate site is rejected");
    check(internet::apiCall(registry, "POST", "/v1/sites", token, "{\"name\":\"Bad Name\"}").code == "422",
          "invalid site name is rejected");
    check(internet::apiCall(registry, "POST", "/v1/sites", token, "not json").code == "400", "invalid JSON is rejected");

    std::string page = "<html><body><p>New page</p></body></html>";
    internet::ApiResponse put = internet::apiCall(registry, "PUT", "/v1/sites/shop/files/docs/page.html", token, page);
    check(put.ok && parseJson(put.body).stringOr("verdict", "") == "clean", "upload a file");
    check(internet::fetch(registry, "internet://shop/docs/page.html").body == page, "uploaded file is served");

    internet::ApiResponse rejected = internet::apiCall(registry, "PUT", "/v1/sites/shop/files/bad.txt", token, "x " + marker());
    check(!rejected.ok && rejected.code == "422" && parseJson(rejected.body).stringOr("verdict", "") == "malicious",
          "malicious upload is rejected");
    check(!fs::exists(root / "sites" / "shop" / "bad.txt"), "rejected upload is not stored");
    check(internet::apiCall(registry, "PUT", "/v1/sites/shop/files/../../x.txt", token, "x").code == "400",
          "path traversal is rejected");
    check(internet::apiCall(registry, "PUT", "/v1/sites/nosuch/files/a.txt", token, "x").code == "404", "unknown site");

    internet::ApiResponse read = internet::apiCall(registry, "GET", "/v1/sites/shop/files/docs/page.html", token, "");
    check(read.ok && parseJson(read.body).stringOr("content", "") == page, "read a file through the API");
    internet::ApiResponse listing = internet::apiCall(registry, "GET", "/v1/sites/shop/files", token, "");
    check(listing.ok && parseJson(listing.body).find("files")->size() == 3, "list files");
    check(internet::apiCall(registry, "DELETE", "/v1/sites/shop/files/docs/page.html", token, "").ok &&
              fetchCode(registry, "internet://shop/docs/page.html") == "404",
          "delete a file");
    check(internet::apiCall(registry, "PATCH", "/v1/sites/shop/files/a.txt", token, "").code == "405", "unsupported method");

    internet::ApiResponse scanned = internet::apiCall(registry, "POST", "/v1/scan/test.txt", token, marker());
    check(scanned.ok && parseJson(scanned.body).stringOr("verdict", "") == "malicious", "scan endpoint");
    internet::ApiResponse securityStatus = internet::apiCall(registry, "GET", "/v1/security/status", token, "");
    check(securityStatus.ok && parseJson(securityStatus.body).find("rules")->asNumber() > 30, "security status");
    internet::ApiResponse quarantine = internet::apiCall(registry, "GET", "/v1/security/quarantine", token, "");
    internet::Json items = parseJson(quarantine.body);
    check(quarantine.ok && items.find("items")->size() == 1, "quarantine list");
    check(internet::apiCall(registry, "GET", "/v1/security/firewall", token, "").ok, "firewall status");
    check(internet::apiCall(registry, "GET", "/v1/security/threats", token, "").ok, "threat list");
    check(internet::apiCall(registry, "DELETE", "/v1/security/firewall/bans/10.1.1.1", token, "").code == "404",
          "unban an unknown host");
    check(internet::apiCall(registry, "POST", "/v1/security/definitions", token, "garbage").code == "422",
          "bad definitions are rejected");

    writeFile(root / "sites" / "blog" / "dropped.txt", "ordinary text");
    check(fetchCode(registry, "internet://blog/dropped.txt") == "200", "clean file is served");
    writeFile(root / "sites" / "blog" / "dropped.txt", "now infected " + marker());
    check(fetchCode(registry, "internet://blog/dropped.txt") == "451", "the guard blocks a file that turned malicious");
    server.scanNow();
    check(!fs::exists(root / "sites" / "blog" / "dropped.txt") && fetchCode(registry, "internet://blog/dropped.txt") == "404",
          "a scan quarantines it");
    check(server.security().quarantineItems().size() == 2, "quarantine grows");

    check(internet::apiCall(registry, "DELETE", "/v1/sites/shop", token, "").ok && !fs::exists(root / "sites" / "shop"),
          "delete a site");
    check(internet::apiCall(registry, "GET", "/v1/sites/shop", token, "").code == "404", "deleted site is gone");

    fs::create_directories(root / "sites" / "later");
    check(waitForNodes(registry, {"later"}), "new folders are hosted automatically");

    server.stop();
    fs::remove_all(root);
}

}

int runServerTests() {
    testJson();
    testServer();
    return failures;
}
