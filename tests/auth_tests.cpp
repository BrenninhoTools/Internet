#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "accounts.hpp"
#include "client.hpp"
#include "encoding.hpp"
#include "googleauth.hpp"
#include "http.hpp"
#include "json.hpp"
#include "server.hpp"
#include "sha256.hpp"
#include "siteserver.hpp"
#include "socket.hpp"
#include "storage.hpp"

namespace fs = std::filesystem;

namespace {

int failures = 0;

void check(bool condition, const std::string& label) {
    if (!condition) {
        ++failures;
        std::cerr << "FAILED: " << label << '\n';
    }
}

bool contains(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }

std::int64_t now() { return static_cast<std::int64_t>(std::time(nullptr)); }

class FakeGoogle {
public:
    int status = 200;
    std::string reply;
    std::string received;

    void start() {
        server_.start(0, [this](internet::Socket& socket, const std::string&) {
            std::string line;
            if (!socket.recvLine(line)) return;
            std::size_t length = 0;
            while (socket.recvLine(line) && !line.empty()) {
                std::size_t colon = line.find(':');
                if (colon == std::string::npos) continue;
                std::string name = line.substr(0, colon);
                std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (name == "content-length") length = std::stoul(line.substr(colon + 1));
            }
            std::string body;
            if (length > 0) socket.recvExact(body, length);
            received = body;
            auto chunk = [](const std::string& piece) {
                char size[24];
                std::snprintf(size, sizeof size, "%zx", piece.size());
                return std::string(size) + "\r\n" + piece + "\r\n";
            };
            std::size_t half = reply.size() / 2;
            socket.sendAll("HTTP/1.1 " + std::to_string(status) + " Reply\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
                           chunk(reply.substr(0, half)) + chunk(reply.substr(half)) + "0\r\n\r\n");
        });
    }

    void stop() { server_.stop(); }
    std::string url(const std::string& path) const { return "http://127.0.0.1:" + std::to_string(server_.port()) + path; }

private:
    internet::Server server_;
};

std::string makeToken(const internet::Json& claims) {
    return internet::base64UrlEncode("{\"alg\":\"none\"}") + "." + internet::base64UrlEncode(claims.dump()) + ".signature";
}

internet::Json validClaims(const std::string& audience) {
    return internet::Json::object()
        .set("iss", "https://accounts.google.com")
        .set("aud", audience)
        .set("sub", "1234567890")
        .set("email", "ana@example.com")
        .set("email_verified", true)
        .set("name", "Ana Lima")
        .set("picture", "https://example.com/ana.png")
        .set("exp", now() + 3600);
}

void testEncoding() {
    std::string decoded;
    check(internet::base64UrlEncode("foobar") == "Zm9vYmFy" && internet::base64UrlEncode("fo") == "Zm8" && internet::base64UrlEncode("f") == "Zg" &&
              internet::base64UrlEncode("").empty(),
          "base64url encodes the standard vectors without padding");
    check(internet::base64UrlDecode("Zm9vYmFy", decoded) && decoded == "foobar", "base64url decodes");
    check(internet::base64UrlDecode("Zm8=", decoded) && decoded == "fo", "base64url accepts padding");
    check(!internet::base64UrlDecode("Zm9v*", decoded) && !internet::base64UrlDecode("Z", decoded), "base64url refuses bad input");
    std::string binary;
    for (int i = 0; i < 256; ++i) binary += static_cast<char>(i);
    check(internet::base64UrlDecode(internet::base64UrlEncode(binary), decoded) && decoded == binary, "base64url keeps every byte");
    check(internet::base64UrlEncode("\xFB\xFF\xFE").find_first_of("+/=") == std::string::npos, "base64url uses the URL alphabet");

    check(internet::randomHex(16).size() == 32 && internet::randomHex(16) != internet::randomHex(16), "random values are long and different");

    std::vector<std::pair<std::string, std::string>> fields = {{"a b", "x&y=z"}, {"empty", ""}, {"utf", "caf\xC3\xA9"}};
    std::string form = internet::formEncode(fields);
    check(form.find(' ') == std::string::npos && form.find("x&y") == std::string::npos, "form values are escaped");
    check(internet::formDecode(form) == fields, "a form survives a round trip");
    check(internet::formDecode("k=a+b&&j=%41").size() == 2, "form decoding skips empty pairs and decodes plus and percent");
}

void testHttp() {
    internet::HttpResult parsed;
    check(internet::parseHttpResponse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello!!", parsed) && parsed.body == "hello" && parsed.status == 200,
          "a reply with a length is cut to that length");
    internet::HttpResult chunked;
    check(internet::parseHttpResponse("HTTP/1.1 400 Bad\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n", chunked) &&
              chunked.body == "abcde" && chunked.status == 400,
          "a chunked reply is joined");
    internet::HttpResult rest;
    check(internet::parseHttpResponse("HTTP/1.0 200 OK\r\n\r\nuntil close", rest) && rest.body == "until close", "a reply without a length reads to the end");
    internet::HttpResult broken;
    check(!internet::parseHttpResponse("garbage", broken) && !internet::parseHttpResponse("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort", broken) &&
              !internet::parseHttpResponse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", broken),
          "broken replies are refused");

    FakeGoogle fake;
    fake.reply = "{\"hello\":\"world\",\"padding\":\"0123456789\"}";
    fake.start();
    internet::HttpResult reply = internet::httpPost(fake.url("/token"), "application/x-www-form-urlencoded", "a=1&b=2");
    check(reply.ok && reply.status == 200 && reply.body == fake.reply, "a local POST returns the joined chunks");
    check(fake.received == "a=1&b=2", "the server received the body");
    fake.status = 400;
    check(internet::httpPost(fake.url("/token"), "text/plain", "x").status == 400, "error statuses are reported");
    fake.stop();

    check(!internet::httpPost("http://example.com/", "text/plain", "x").ok, "plain HTTP is refused for other hosts");
    check(!internet::httpPost("ftp://127.0.0.1/", "text/plain", "x").ok && !internet::httpPost("nonsense", "text/plain", "x").ok, "bad addresses are refused");
    check(!internet::httpPost("http://127.0.0.1:1/", "text/plain", "x", 1000).ok, "a closed port is an error");
}

void testAccounts() {
    fs::path root = fs::temp_directory_path() / "internet-auth-accounts";
    fs::remove_all(root);
    std::string session;
    std::string accountId;
    {
        internet::Accounts accounts(root);
        internet::Account ana = accounts.signIn("sub-1", "ana@example.com", "Ana", "");
        accountId = ana.id;
        check(ana.id.size() == 16 && ana.created > 0, "a new account gets an id");
        internet::Account again = accounts.signIn("sub-1", "ana@new.example.com", "Ana Lima", "https://p/1.png");
        check(again.id == ana.id && again.email == "ana@new.example.com" && again.name == "Ana Lima" && accounts.count() == 1, "the same Google subject is the same account");
        internet::Account bob = accounts.signIn("sub-2", "bob@example.com", "Bob", "");
        check(bob.id != ana.id && accounts.count() == 2, "another subject is another account");

        session = accounts.createSession(ana.id);
        check(session.size() == 64 && accounts.sessionAccount(session) && accounts.sessionAccount(session)->id == ana.id, "a session finds its account");
        check(!accounts.sessionAccount("nonsense") && !accounts.sessionAccount(std::string(64, 'a')), "unknown sessions are refused");
        std::string expired = accounts.createSession(ana.id, -5);
        check(!accounts.sessionAccount(expired), "an expired session is refused");
        std::string other = accounts.createSession(bob.id);
        accounts.endSession(other);
        check(!accounts.sessionAccount(other) && accounts.sessionAccount(session), "ending a session leaves the others");

        std::string problem;
        check(accounts.claimSite("blog", ana.id, 2, problem) && accounts.siteOwner("blog") == ana.id, "an account can claim a site name");
        check(!accounts.claimSite("blog", bob.id, 2, problem) && contains(problem, "taken"), "a claimed name is taken");
        check(accounts.claimSite("shop", ana.id, 2, problem) && !accounts.claimSite("third", ana.id, 2, problem) && contains(problem, "limit"), "the site limit is enforced");
        check(accounts.sitesOf(ana.id).size() == 2 && accounts.sitesOf(bob.id).empty(), "sites are listed per account");
        accounts.releaseSite("shop");
        check(accounts.siteOwner("shop").empty() && accounts.claimSite("third", ana.id, 2, problem), "a released name can be claimed again");
    }
    {
        internet::Accounts reopened(root);
        check(reopened.count() == 2 && reopened.sessionAccount(session) && reopened.sessionAccount(session)->id == accountId, "accounts and sessions survive a restart");
        check(reopened.siteOwner("blog") == accountId, "site owners survive a restart");
        check(std::ifstream(root / "accounts.json").good() && !fs::exists(root / "accounts.json.tmp"), "the store is written in one piece");
        check(reopened.find(accountId) && reopened.find(accountId)->email == "ana@new.example.com" && !reopened.find("missing"), "accounts can be looked up");
    }

    internet::Accounts accounts(root);
    std::string verifier = internet::base64UrlEncode(internet::randomBytes(32));
    std::string challenge = internet::sha256Hex(verifier);
    std::string code = accounts.createHandoff(accountId, challenge);
    check(!accounts.redeemHandoff(code, "wrong verifier") && !accounts.redeemHandoff(code, verifier), "a wrong verifier burns the code");
    code = accounts.createHandoff(accountId, challenge);
    check(accounts.redeemHandoff("nonsense", verifier) == std::nullopt, "an unknown code is refused");
    std::optional<std::string> redeemed = accounts.redeemHandoff(code, verifier);
    check(redeemed && *redeemed == accountId, "the right verifier redeems the code");
    check(!accounts.redeemHandoff(code, verifier), "a code works only once");

    internet::SyncBlob blob;
    std::int64_t updated = 0;
    std::string problem;
    check(!accounts.readSync(accountId, "bookmarks", blob), "there is no synced data at first");
    check(accounts.writeSync(accountId, "bookmarks", "internet://home/\tHome\n", updated, problem) && updated > 0, "data can be stored");
    check(accounts.readSync(accountId, "bookmarks", blob) && blob.content == "internet://home/\tHome\n" && blob.updated == updated, "stored data can be read");
    check(!accounts.writeSync(accountId, "passwords", "x", updated, problem) && !accounts.readSync(accountId, "../x", blob), "only known kinds are synced");
    check(!accounts.writeSync("../../x", "history", "x", updated, problem), "account ids cannot escape the folder");
    check(!accounts.writeSync(accountId, "history", std::string(internet::kMaxSyncBytes + 1, 'x'), updated, problem) && contains(problem, "more than"), "the size of synced data is limited");
    fs::remove_all(root);
}

void testSyncHelpers() {
    std::vector<internet::Entry> entries = {{"internet://home/", "Home\tpage"}, {"internet://blog/", ""}};
    std::string text = internet::formatEntries(entries);
    std::vector<internet::Entry> back = internet::parseEntries(text);
    check(back.size() == 2 && back[0].url == "internet://home/" && back[0].title == "Home page" && back[1].title.empty(), "entries survive a round trip and lose tabs in titles");
    check(internet::parseEntries("\n\r\ninternet://a/\tA\r\n").size() == 1 && internet::parseEntries("").empty(), "blank lines are skipped when reading entries");

    std::string merged = internet::mergeEntries("internet://a/\tA\ninternet://b/\tB\n", "internet://b/\tOther\ninternet://c/\tC\n", 0);
    std::vector<internet::Entry> mergedEntries = internet::parseEntries(merged);
    check(mergedEntries.size() == 3 && mergedEntries[0].url == "internet://a/" && mergedEntries[1].title == "B" && mergedEntries[2].url == "internet://c/",
          "merging keeps local entries first and adds the ones only the server has");
    check(internet::parseEntries(internet::mergeEntries("internet://a/\n", "internet://b/\ninternet://c/\n", 2)).size() == 2, "merging respects the limit");
    check(internet::mergeEntries("", "", 5).empty() && internet::mergeEntries("internet://a/\n", "", 5) == "internet://a/\t\n", "merging with nothing keeps what there is");

    internet::Settings settings;
    settings.palette = 3;
    settings.intro = false;
    settings.animations = false;
    settings.zoom = 1.25f;
    std::string synced = internet::formatSyncedSettings(settings);
    internet::Settings other;
    check(internet::applySyncedSettings(synced, other) && other.palette == 3 && !other.intro && !other.animations && other.zoom == 1.25f, "settings survive a round trip");
    check(!internet::applySyncedSettings("nonsense\nunknown=1\n", other) && other.palette == 3, "unknown lines change nothing");
    internet::Settings clamped;
    check(internet::applySyncedSettings("zoom=99\npalette=abc\n", clamped) && clamped.zoom == 2.5f && clamped.palette == 0, "extreme values are clamped and bad ones ignored");
    check(internet::formatSyncedSettings(other) == synced, "formatting is stable so unchanged settings never look changed");
}

void testGoogle() {
    std::string clientId = "client-1.apps.googleusercontent.com";
    internet::GoogleIdentity identity;
    std::string error;
    check(internet::GoogleAuth::parseIdToken(makeToken(validClaims(clientId)), clientId, now(), identity, error) && identity.subject == "1234567890" &&
              identity.email == "ana@example.com" && identity.name == "Ana Lima" && identity.picture == "https://example.com/ana.png",
          "a valid identity is read");
    check(internet::GoogleAuth::parseIdToken(makeToken(internet::Json::object().set("iss", "accounts.google.com").set("aud", internet::Json::array().push("x").push(clientId)).set("sub", "9").set("email", "a@b.c").set("email_verified", "true").set("exp", now() + 60)), clientId, now(), identity, error) &&
              identity.name == "a",
          "the older issuer, an audience list, a text flag and a missing name are accepted");

    check(!internet::GoogleAuth::parseIdToken(makeToken(validClaims("other")), clientId, now(), identity, error) && contains(error, "another application"), "an identity for another application is refused");
    internet::Json badIssuer = validClaims(clientId);
    badIssuer.set("iss", "https://evil.example");
    check(!internet::GoogleAuth::parseIdToken(makeToken(badIssuer), clientId, now(), identity, error) && contains(error, "not issued by Google"), "another issuer is refused");
    internet::Json old = validClaims(clientId);
    old.set("exp", now() - 3600);
    check(!internet::GoogleAuth::parseIdToken(makeToken(old), clientId, now(), identity, error) && contains(error, "expired"), "an expired identity is refused");
    internet::Json unverified = validClaims(clientId);
    unverified.set("email_verified", false);
    check(!internet::GoogleAuth::parseIdToken(makeToken(unverified), clientId, now(), identity, error) && contains(error, "verified"), "an unverified email is refused");
    internet::Json anonymous = validClaims(clientId);
    anonymous.set("sub", "");
    check(!internet::GoogleAuth::parseIdToken(makeToken(anonymous), clientId, now(), identity, error), "an identity without a subject is refused");
    check(!internet::GoogleAuth::parseIdToken("nonsense", clientId, now(), identity, error) && !internet::GoogleAuth::parseIdToken("a.!!!.c", clientId, now(), identity, error) &&
              !internet::GoogleAuth::parseIdToken("a.bm90IGpzb24.c", clientId, now(), identity, error),
          "a damaged token is refused");

    FakeGoogle fake;
    fake.reply = "{\"id_token\":\"" + makeToken(validClaims(clientId)) + "\",\"token_type\":\"Bearer\"}";
    fake.start();

    internet::GoogleAuth google;
    check(!google.enabled(), "sign in is off until it is configured");
    internet::GoogleConfig config;
    config.clientId = clientId;
    config.clientSecret = "secret-1";
    config.redirectUri = "https://example.com/auth/google/callback";
    config.authUrl = "https://accounts.example/o/oauth2/v2/auth";
    config.tokenUrl = fake.url("/token");
    google.configure(config);
    check(google.enabled(), "sign in turns on when it is configured");

    std::string url = google.begin("challenge-hex", 5123);
    check(url.rfind("https://accounts.example/o/oauth2/v2/auth?", 0) == 0, "the sign-in address starts at Google");
    std::vector<std::pair<std::string, std::string>> query = internet::formDecode(url.substr(url.find('?') + 1));
    auto value = [&](const std::string& key) {
        for (const auto& item : query) {
            if (item.first == key) return item.second;
        }
        return std::string();
    };
    check(value("client_id") == clientId && value("redirect_uri") == config.redirectUri && value("response_type") == "code" && value("scope") == "openid email profile" &&
              value("code_challenge_method") == "S256" && value("state").size() == 32 && !value("code_challenge").empty(),
          "the sign-in address carries the OAuth fields");
    check(!contains(url, "secret-1"), "the client secret never appears in the address");

    internet::LoginRequest request;
    check(!google.finish("code", "unknown-state", request, identity, error) && contains(error, "expired"), "an unknown state is refused");
    check(google.finish("google-code-1", value("state"), request, identity, error) && identity.email == "ana@example.com", "the code is exchanged for an identity");
    check(request.appPort == 5123 && request.appChallenge == "challenge-hex", "the app hand-off details come back");
    std::vector<std::pair<std::string, std::string>> sent = internet::formDecode(fake.received);
    auto field = [&](const std::string& key) {
        for (const auto& item : sent) {
            if (item.first == key) return item.second;
        }
        return std::string();
    };
    check(field("grant_type") == "authorization_code" && field("code") == "google-code-1" && field("client_id") == clientId && field("client_secret") == "secret-1" &&
              field("redirect_uri") == config.redirectUri,
          "the token request carries the code and the client secret");
    std::string digest;
    internet::fromHex(internet::sha256Hex(field("code_verifier")), digest);
    check(internet::base64UrlEncode(digest) == value("code_challenge"), "the verifier matches the challenge that was sent to Google");
    check(!google.finish("google-code-1", value("state"), request, identity, error), "a state can be used only once");

    fake.status = 400;
    fake.reply = "{\"error\":\"invalid_grant\",\"error_description\":\"Bad code\"}";
    std::string retryUrl = google.begin("", 0);
    std::string retryState;
    for (const auto& item : internet::formDecode(retryUrl.substr(retryUrl.find('?') + 1))) {
        if (item.first == "state") retryState = item.second;
    }
    check(!google.finish("bad", retryState, request, identity, error) && contains(error, "Bad code"), "a refusal from Google is explained");
    fake.stop();

    google.configure(config);
    std::string offlineUrl = google.begin("", 0);
    std::string offlineState;
    for (const auto& item : internet::formDecode(offlineUrl.substr(offlineUrl.find('?') + 1))) {
        if (item.first == "state") offlineState = item.second;
    }
    check(!google.finish("code", offlineState, request, identity, error) && contains(error, "Could not reach Google"), "an unreachable Google is reported");
}

struct WebReply {
    bool ok = false;
    int status = 0;
    std::map<std::string, std::string> headers;
    std::string body;
};

WebReply web(std::uint16_t port, const std::string& target, const std::string& cookie = std::string()) {
    WebReply reply;
    internet::Socket socket = internet::Socket::connect("127.0.0.1", port);
    if (!socket.valid()) return reply;
    socket.setTimeout(5000);
    socket.sendAll("GET " + target + " HTTP/1.1\r\nHost: localhost:" + std::to_string(port) + "\r\n" + (cookie.empty() ? std::string() : "Cookie: " + cookie + "\r\n") +
                   "Connection: close\r\n\r\n");
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
    if (length > 0) socket.recvExact(reply.body, length);
    reply.ok = true;
    return reply;
}

std::string queryField(const std::string& url, const std::string& key) {
    std::size_t question = url.find('?');
    if (question == std::string::npos) return std::string();
    for (const auto& item : internet::formDecode(url.substr(question + 1))) {
        if (item.first == key) return item.second;
    }
    return std::string();
}

internet::Json parseBody(const std::string& text) {
    internet::Json json;
    std::string error;
    internet::Json::parse(text, json, error);
    return json;
}

void testAccountService() {
    fs::path root = fs::temp_directory_path() / "internet-auth-service";
    fs::remove_all(root);
    fs::create_directories(root / "sites" / "shared");

    std::string clientId = "client-1";
    FakeGoogle fake;
    fake.start();
    auto identityFor = [&](const std::string& subject, const std::string& email, const std::string& name) {
        internet::Json claims = validClaims(clientId);
        claims.set("sub", subject).set("email", email).set("name", name);
        fake.reply = "{\"id_token\":\"" + makeToken(claims) + "\"}";
    };

    internet::ServerConfig config;
    config.dataDir = root / "data";
    config.sitesDir = root / "sites";
    config.registryPort = 0;
    config.rescanSeconds = 0;
    config.scanOnStart = false;
    config.gatewayPort = 46310;
    config.googleClientId = clientId;
    config.googleClientSecret = "secret";
    config.googleAuthUrl = "https://accounts.example/auth";
    config.googleTokenUrl = fake.url("/token");
    config.maxSitesPerAccount = 2;
    internet::SiteServer server(config);
    server.start();
    internet::Endpoint registry = server.registryEndpoint();
    std::uint16_t port = server.gatewayPort();
    check(port != 0, "the gateway starts for the sign-in pages");
    for (int i = 0; i < 100; ++i) {
        try {
            bool found = false;
            for (const internet::NodeInfo& node : internet::listNodes(registry)) found = found || node.name == "api";
            if (found) break;
        } catch (const std::exception&) {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    const std::string admin = server.token();
    auto api = [&](const std::string& method, const std::string& path, const std::string& token, const std::string& body = std::string()) {
        return internet::apiCall(registry, method, path, token, body);
    };

    internet::Json publicStatus = parseBody(internet::fetch(registry, "internet://api/v1/status").body);
    check(publicStatus.find("login") && publicStatus.find("login")->asBool(), "the public status says that sign-in is on");

    WebReply login = web(port, "/login");
    check(login.status == 200 && contains(login.body, "/auth/google/start") && contains(login.body, "Sign in with Google"), "the login page offers Google");
    WebReply start = web(port, "/auth/google/start");
    check(start.status == 302 && start.headers["Location"].rfind("https://accounts.example/auth?", 0) == 0, "starting sends the browser to Google");
    check(queryField(start.headers["Location"], "redirect_uri") == "http://localhost:" + std::to_string(port) + "/auth/google/callback",
          "the redirect address points back at the gateway");
    std::string state = queryField(start.headers["Location"], "state");

    identityFor("sub-ana", "ana@example.com", "Ana <b>Lima</b>");
    WebReply callback = web(port, "/auth/google/callback?code=abc&state=" + state);
    check(callback.status == 302 && callback.headers["Location"] == "/account", "a good callback lands on the account page");
    std::string setCookie = callback.headers["Set-Cookie"];
    check(setCookie.rfind("internet_session=", 0) == 0 && contains(setCookie, "HttpOnly") && contains(setCookie, "SameSite=Lax") && !contains(setCookie, "Secure"),
          "the session cookie is HttpOnly and lax");
    std::string cookie = setCookie.substr(0, setCookie.find(';'));
    check(cookie.size() == std::string("internet_session=").size() + 64, "the session cookie holds a long random token");

    WebReply account = web(port, "/account", cookie);
    check(account.status == 200 && contains(account.body, "ana@example.com") && contains(account.body, "Sign out") && !contains(account.body, "<b>Lima</b>") &&
              contains(account.body, "&lt;b&gt;Lima"),
          "the account page shows the signed in person and escapes the name");
    check(web(port, "/account").status == 302 && web(port, "/account").headers["Location"] == "/login", "the account page needs a session");
    check(web(port, "/account", "internet_session=" + std::string(64, 'a')).status == 302, "a made up session is refused");
    check(web(port, "/auth/google/callback?code=abc&state=" + state).status == 400, "a state cannot be reused");
    WebReply unknown = web(port, "/auth/google/callback?code=abc&state=nope");
    check(unknown.status == 400 && contains(unknown.body, "invalid or has expired"), "an unknown state is explained");
    check(web(port, "/auth/google/callback?error=access_denied").status == 200 && contains(web(port, "/auth/google/callback?error=access_denied").body, "cancelled"),
          "cancelling is not an error page");
    check(web(port, "/auth/google/other").status == 404, "unknown sign-in addresses are 404");

    std::size_t at = account.body.find("/logout?t=");
    std::string logoutLink = at == std::string::npos ? std::string() : account.body.substr(at, account.body.find('"', at) - at);
    check(!logoutLink.empty(), "the account page has a sign out link");
    WebReply wrongLogout = web(port, "/logout?t=0000", cookie);
    check(wrongLogout.status == 302 && wrongLogout.headers["Location"] == "/account" && web(port, "/account", cookie).status == 200, "a sign out without the right token does nothing");
    WebReply logout = web(port, logoutLink, cookie);
    check(logout.status == 302 && logout.headers["Location"] == "/login" && contains(logout.headers["Set-Cookie"], "Max-Age=0"), "signing out clears the cookie");
    check(web(port, "/account", cookie).status == 302, "a signed out session no longer works");

    check(web(port, "/auth/google/start?app_port=80&challenge=" + std::string(64, 'a')).status == 400, "the app port must not be a system port");
    check(web(port, "/auth/google/start?app_port=5555").status == 400 && web(port, "/auth/google/start?app_port=5555&challenge=xyz").status == 400, "the app needs a challenge");
    check(web(port, "/auth/google/start?app_port=abc&challenge=" + std::string(64, 'a')).status == 400, "the app port must be a number");

    std::string verifier = internet::base64UrlEncode(internet::randomBytes(32));
    std::string challenge = internet::sha256Hex(verifier);
    WebReply appStart = web(port, "/auth/google/start?app_port=5555&challenge=" + challenge);
    check(appStart.status == 302, "the app can start a sign in");
    identityFor("sub-ana", "ana@example.com", "Ana Lima");
    WebReply appCallback = web(port, "/auth/google/callback?code=abc&state=" + queryField(appStart.headers["Location"], "state"));
    std::string handoffUrl = appCallback.headers["Location"];
    check(appCallback.status == 302 && handoffUrl.rfind("http://127.0.0.1:5555/?code=", 0) == 0 && appCallback.headers.count("Set-Cookie") == 0,
          "an app sign in goes back to the app without a cookie");
    std::string code = queryField(handoffUrl, "code");

    internet::ApiResponse wrongVerifier = api("POST", "/v1/session/exchange", "", "{\"code\":\"" + code + "\",\"verifier\":\"nope\"}");
    check(!wrongVerifier.ok && wrongVerifier.code == "401", "a wrong verifier is refused");
    check(!api("POST", "/v1/session/exchange", "", "{\"code\":\"" + code + "\",\"verifier\":\"" + verifier + "\"}").ok, "and it burns the code");

    appStart = web(port, "/auth/google/start?app_port=5555&challenge=" + challenge);
    appCallback = web(port, "/auth/google/callback?code=abc&state=" + queryField(appStart.headers["Location"], "state"));
    code = queryField(appCallback.headers["Location"], "code");
    internet::ApiResponse exchanged = api("POST", "/v1/session/exchange", "", "{\"code\":\"" + code + "\",\"verifier\":\"" + verifier + "\"}");
    internet::Json exchangedJson = parseBody(exchanged.body);
    check(exchanged.ok && exchangedJson.stringOr("token", "").size() == 64, "the app exchanges the code for a session");
    std::string ana = exchangedJson.stringOr("token", "");
    check(exchangedJson.find("account") && exchangedJson.find("account")->stringOr("email", "") == "ana@example.com", "the exchange returns the profile");
    check(!api("POST", "/v1/session/exchange", "", "{\"code\":\"" + code + "\",\"verifier\":\"" + verifier + "\"}").ok, "a code works once");
    check(api("GET", "/v1/account", "").code == "401" && api("GET", "/v1/sites", "garbage").code == "401", "the API needs a token or a session");

    internet::Json profile = parseBody(api("GET", "/v1/account", ana).body);
    check(profile.stringOr("email", "") == "ana@example.com" && profile.stringOr("name", "") == "Ana Lima", "the profile is read with a session");
    check(api("GET", "/v1/account", admin).code == "403", "the administrator token is not an account");

    check(api("POST", "/v1/sites", ana, "{\"name\":\"myblog\"}").ok && fs::exists(root / "sites" / "myblog" / "index.html"), "an account creates a site");
    check(api("POST", "/v1/sites", ana, "{\"name\":\"admin\"}").code == "422" && api("POST", "/v1/sites", ana, "{\"name\":\"api\"}").code == "422" &&
              api("POST", "/v1/sites", ana, "{\"name\":\"Bad Name\"}").code == "422",
          "reserved and invalid names are refused");
    check(api("POST", "/v1/sites", ana, "{\"name\":\"shared\"}").code == "422", "an existing site cannot be claimed");
    check(api("POST", "/v1/sites", ana, "{\"name\":\"second\"}").ok && api("POST", "/v1/sites", ana, "{\"name\":\"third\"}").code == "422", "the number of sites is limited");
    internet::Json own = parseBody(api("GET", "/v1/sites", ana).body);
    check(own.find("sites") && own.find("sites")->size() == 2, "an account lists only its own sites");
    internet::Json all = parseBody(api("GET", "/v1/sites", admin).body);
    check(all.find("sites") && all.find("sites")->size() == 3, "the administrator lists every site");
    check(api("GET", "/v1/sites/shared", ana).code == "404" && api("DELETE", "/v1/sites/shared", ana).code == "404" &&
              api("PUT", "/v1/sites/shared/files/x.txt", ana, "x").code == "404",
          "an account cannot touch a site it does not own");
    check(api("PUT", "/v1/sites/myblog/files/hello.txt", ana, "hi").ok && fs::exists(root / "sites" / "myblog" / "hello.txt"), "an account uploads to its own site");
    check(api("GET", "/v1/security/status", ana).code == "403" && api("GET", "/v1/security/firewall", ana).code == "403", "security settings need the administrator");
    check(api("GET", "/v1/security/status", admin).ok, "the administrator still reaches the security settings");

    identityFor("sub-bob", "bob@example.com", "Bob");
    appStart = web(port, "/auth/google/start?app_port=5556&challenge=" + challenge);
    appCallback = web(port, "/auth/google/callback?code=abc&state=" + queryField(appStart.headers["Location"], "state"));
    internet::ApiResponse bobExchange = api("POST", "/v1/session/exchange", "", "{\"code\":\"" + queryField(appCallback.headers["Location"], "code") + "\",\"verifier\":\"" + verifier + "\"}");
    std::string bob = parseBody(bobExchange.body).stringOr("token", "");
    check(bob.size() == 64 && bob != ana, "another person gets another session");
    check(api("POST", "/v1/sites", bob, "{\"name\":\"myblog\"}").code == "422", "a name owned by someone else is taken");
    check(api("GET", "/v1/sites/myblog", bob).code == "404" && parseBody(api("GET", "/v1/sites", bob).body).find("sites")->size() == 0, "one account cannot see another's sites");

    check(api("PUT", "/v1/account/sync/bookmarks", ana, "internet://home/\tHome\n").ok, "an account stores synced data");
    internet::Json synced = parseBody(api("GET", "/v1/account/sync/bookmarks", ana).body);
    check(synced.stringOr("content", "") == "internet://home/\tHome\n" && synced.find("updated")->asNumber() > 0, "synced data is read back");
    check(parseBody(api("GET", "/v1/account/sync/bookmarks", bob).body).stringOr("content", "x").empty(), "synced data is private to the account");
    check(api("GET", "/v1/account/sync/passwords", ana).code == "404" && api("PUT", "/v1/account/sync/history", admin, "x").code == "403", "sync is limited to known kinds and to accounts");
    check(api("PUT", "/v1/account/sync/history", ana, std::string(internet::kMaxSyncBytes + 1, 'x')).code == "413", "synced data has a size limit");

    check(api("DELETE", "/v1/sites/second", ana).ok && api("POST", "/v1/sites", ana, "{\"name\":\"third\"}").ok, "deleting a site frees a place for a new one");
    check(api("DELETE", "/v1/sites/myblog", ana).ok && api("POST", "/v1/sites", bob, "{\"name\":\"myblog\"}").ok, "a deleted site name can be claimed again");

    check(api("DELETE", "/v1/account/session", ana).ok && api("GET", "/v1/account", ana).code == "401", "signing out ends the session");
    check(api("GET", "/v1/account", bob).ok, "signing out one person leaves the others");

    server.stop();
    fake.stop();
    fs::remove_all(root);
}

}

int runAuthTests() {
    testEncoding();
    testHttp();
    testAccounts();
    testSyncHelpers();
    testGoogle();
    testAccountService();
    return failures;
}
