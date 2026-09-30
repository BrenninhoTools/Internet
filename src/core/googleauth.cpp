#include "googleauth.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <iterator>
#include <utility>

#include "encoding.hpp"
#include "http.hpp"
#include "json.hpp"
#include "rsa.hpp"
#include "sha256.hpp"

namespace internet {

namespace {

constexpr std::size_t kMaxPending = 500;
constexpr std::int64_t kClockSkewSeconds = 60;
constexpr std::int64_t kMaxTokenAgeSeconds = 600;
constexpr std::int64_t kKeyLifetimeSeconds = 3600;
constexpr std::int64_t kKeyRetrySeconds = 30;

std::int64_t nowSeconds() { return static_cast<std::int64_t>(std::time(nullptr)); }

std::string shortText(const std::string& text, std::size_t limit) { return text.size() <= limit ? text : text.substr(0, limit); }

std::string lowerText(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool claimTrue(const Json& json, const std::string& key) {
    const Json* value = json.find(key);
    if (!value) return false;
    if (value->type() == Json::Type::Bool) return value->asBool();
    return value->isString() && value->asString() == "true";
}

bool contains(const std::vector<std::string>& list, const std::string& value) { return std::find(list.begin(), list.end(), value) != list.end(); }

}

std::vector<std::string> GoogleAuth::splitList(const std::string& text) {
    std::vector<std::string> items;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find_first_of(",; \t\r\n", start);
        if (end == std::string::npos) end = text.size();
        std::string item = lowerText(text.substr(start, end - start));
        if (!item.empty()) items.push_back(item);
        start = end + 1;
    }
    return items;
}

void GoogleAuth::configure(GoogleConfig config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = std::move(config);
    keys_.clear();
    keysFetched_ = 0;
}

bool GoogleAuth::enabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !config_.clientId.empty() && !config_.clientSecret.empty() && !config_.redirectUri.empty();
}

std::string GoogleAuth::begin(const std::string& appChallenge, int appPort) {
    GoogleConfig config;
    std::string state = randomHex(16);
    std::string nonce = randomHex(16);
    std::string verifier = base64UrlEncode(randomBytes(32));
    std::string challenge;
    {
        std::string digest = sha256Hex(verifier);
        std::string raw;
        fromHex(digest, raw);
        challenge = base64UrlEncode(raw);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        config = config_;
        std::int64_t now = nowSeconds();
        for (auto it = pending_.begin(); it != pending_.end();) {
            it = it->second.expires <= now ? pending_.erase(it) : std::next(it);
        }
        if (pending_.size() >= kMaxPending) pending_.erase(pending_.begin());
        pending_[state] = LoginRequest{verifier, nonce, appChallenge, appPort, now + kLoginSeconds};
    }
    std::string query = formEncode({{"client_id", config.clientId},
                                    {"redirect_uri", config.redirectUri},
                                    {"response_type", "code"},
                                    {"scope", "openid email profile"},
                                    {"state", state},
                                    {"nonce", nonce},
                                    {"code_challenge", challenge},
                                    {"code_challenge_method", "S256"},
                                    {"prompt", "select_account"}});
    return config.authUrl + (config.authUrl.find('?') == std::string::npos ? "?" : "&") + query;
}

bool GoogleAuth::refreshKeys(const GoogleConfig& config, std::string& error) {
    HttpResult reply = httpGet(config.keysUrl);
    if (!reply.ok) {
        error = "Could not fetch Google's signing keys: " + reply.error;
        return false;
    }
    if (reply.status != 200) {
        error = "Google's signing keys are unavailable (status " + std::to_string(reply.status) + ").";
        return false;
    }
    Json json;
    std::string problem;
    const Json* list = Json::parse(reply.body, json, problem) ? json.find("keys") : nullptr;
    if (!list || !list->isArray()) {
        error = "Google's signing keys could not be read.";
        return false;
    }
    std::vector<Key> keys;
    for (const Json& item : list->items()) {
        if (item.stringOr("kty", "") != "RSA") continue;
        std::string algorithm = item.stringOr("alg", "RS256");
        std::string use = item.stringOr("use", "sig");
        if (algorithm != "RS256" || use != "sig") continue;
        Key key;
        key.id = item.stringOr("kid", "");
        if (key.id.empty() || !base64UrlDecode(item.stringOr("n", ""), key.modulus) || !base64UrlDecode(item.stringOr("e", ""), key.exponent)) continue;
        keys.push_back(std::move(key));
    }
    if (keys.empty()) {
        error = "Google sent no usable signing keys.";
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    keys_ = std::move(keys);
    keysFetched_ = nowSeconds();
    return true;
}

bool GoogleAuth::verifySignature(const std::string& idToken, const GoogleConfig& config, std::string& error) {
    std::size_t first = idToken.find('.');
    std::size_t second = first == std::string::npos ? std::string::npos : idToken.find('.', first + 1);
    if (first == std::string::npos || second == std::string::npos) {
        error = "Google did not send an identity.";
        return false;
    }
    std::string headerText;
    Json header;
    std::string problem;
    if (!base64UrlDecode(idToken.substr(0, first), headerText) || !Json::parse(headerText, header, problem) || !header.isObject()) {
        error = "The identity from Google is damaged.";
        return false;
    }
    if (header.stringOr("alg", "") != "RS256") {
        error = "The identity is not signed with a supported algorithm.";
        return false;
    }
    std::string keyId = header.stringOr("kid", "");
    std::string signature;
    if (keyId.empty() || !base64UrlDecode(idToken.substr(second + 1), signature)) {
        error = "The identity from Google is damaged.";
        return false;
    }
    Key key;
    bool have = false;
    bool stale = false;
    std::int64_t age = 0;
    auto lookup = [&] {
        std::lock_guard<std::mutex> lock(mutex_);
        have = false;
        for (const Key& candidate : keys_) {
            if (candidate.id == keyId) {
                key = candidate;
                have = true;
            }
        }
        age = nowSeconds() - keysFetched_;
        stale = keys_.empty() || age > kKeyLifetimeSeconds;
    };
    lookup();
    if (!have || stale) {
        if (stale || age >= kKeyRetrySeconds) {
            if (!refreshKeys(config, error)) return false;
            lookup();
        }
    }
    if (!have) {
        error = "The identity is signed with a key that Google does not publish.";
        return false;
    }
    if (!rsaVerifySha256(key.modulus, key.exponent, signature, idToken.substr(0, second), config.minimumKeyBits)) {
        error = "The identity from Google has a bad signature.";
        return false;
    }
    return true;
}

bool GoogleAuth::finish(const std::string& code, const std::string& state, LoginRequest& request, GoogleIdentity& identity,
                        std::string& error) {
    GoogleConfig config;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto found = pending_.find(state);
        if (found == pending_.end() || found->second.expires <= nowSeconds()) {
            if (found != pending_.end()) pending_.erase(found);
            error = "This sign-in link is invalid or has expired. Start again.";
            return false;
        }
        request = found->second;
        pending_.erase(found);
        config = config_;
    }
    if (code.empty()) {
        error = "Google did not send a sign-in code.";
        return false;
    }

    HttpResult reply = httpPost(config.tokenUrl, "application/x-www-form-urlencoded",
                                formEncode({{"code", code},
                                            {"client_id", config.clientId},
                                            {"client_secret", config.clientSecret},
                                            {"redirect_uri", config.redirectUri},
                                            {"grant_type", "authorization_code"},
                                            {"code_verifier", request.verifier}}));
    if (!reply.ok) {
        error = "Could not reach Google: " + reply.error;
        return false;
    }
    Json json;
    std::string problem;
    if (!Json::parse(reply.body, json, problem)) {
        error = "Google sent a reply that could not be read.";
        return false;
    }
    if (reply.status != 200) {
        std::string detail = json.stringOr("error_description", json.stringOr("error", "unknown error"));
        error = "Google refused the sign-in: " + shortText(detail, 200);
        return false;
    }
    std::string idToken = json.stringOr("id_token", "");
    if (config.verifySignature && !verifySignature(idToken, config, error)) return false;

    TokenExpectations expectations;
    expectations.clientId = config.clientId;
    expectations.nonce = request.nonce;
    expectations.domains = config.allowedDomains;
    expectations.emails = config.allowedEmails;
    expectations.now = nowSeconds();
    return parseIdToken(idToken, expectations, identity, error);
}

bool GoogleAuth::parseIdToken(const std::string& idToken, const std::string& clientId, std::int64_t now, GoogleIdentity& identity,
                              std::string& error) {
    TokenExpectations expectations;
    expectations.clientId = clientId;
    expectations.now = now;
    return parseIdToken(idToken, expectations, identity, error);
}

bool GoogleAuth::parseIdToken(const std::string& idToken, const TokenExpectations& expectations, GoogleIdentity& identity,
                              std::string& error) {
    std::size_t first = idToken.find('.');
    std::size_t second = first == std::string::npos ? std::string::npos : idToken.find('.', first + 1);
    if (first == std::string::npos || second == std::string::npos) {
        error = "Google did not send an identity.";
        return false;
    }
    std::string payload;
    if (!base64UrlDecode(idToken.substr(first + 1, second - first - 1), payload)) {
        error = "The identity from Google is damaged.";
        return false;
    }
    Json claims;
    std::string problem;
    if (!Json::parse(payload, claims, problem) || !claims.isObject()) {
        error = "The identity from Google is damaged.";
        return false;
    }

    std::string issuer = claims.stringOr("iss", "");
    if (issuer != "https://accounts.google.com" && issuer != "accounts.google.com") {
        error = "The identity was not issued by Google.";
        return false;
    }
    bool audience = false;
    bool several = false;
    if (const Json* aud = claims.find("aud")) {
        if (aud->isString()) {
            audience = aud->asString() == expectations.clientId;
        } else if (aud->isArray()) {
            several = aud->size() > 1;
            for (const Json& item : aud->items()) audience = audience || (item.isString() && item.asString() == expectations.clientId);
        }
    }
    if (!audience) {
        error = "The identity was issued for another application.";
        return false;
    }
    std::string authorized = claims.stringOr("azp", "");
    if ((several && authorized != expectations.clientId) || (!authorized.empty() && authorized != expectations.clientId)) {
        error = "The identity was requested by another application.";
        return false;
    }
    const Json* expires = claims.find("exp");
    if (!expires || static_cast<std::int64_t>(expires->asNumber()) + kClockSkewSeconds < expectations.now) {
        error = "The identity from Google has expired.";
        return false;
    }
    const Json* issued = claims.find("iat");
    if (!issued) {
        error = "The identity from Google has no issue time.";
        return false;
    }
    std::int64_t issuedAt = static_cast<std::int64_t>(issued->asNumber());
    if (issuedAt > expectations.now + kClockSkewSeconds) {
        error = "The identity from Google claims to be from the future.";
        return false;
    }
    if (!expectations.nonce.empty() && expectations.now - issuedAt > kMaxTokenAgeSeconds + kClockSkewSeconds) {
        error = "The identity from Google is too old for this sign-in.";
        return false;
    }
    if (!expectations.nonce.empty() && !constantTimeEquals(claims.stringOr("nonce", ""), expectations.nonce)) {
        error = "The identity does not belong to this sign-in.";
        return false;
    }
    std::string subject = claims.stringOr("sub", "");
    std::string email = claims.stringOr("email", "");
    if (subject.empty() || email.empty() || !claimTrue(claims, "email_verified")) {
        error = "The Google account needs a verified email address.";
        return false;
    }

    if (!expectations.domains.empty() || !expectations.emails.empty()) {
        std::string lowerEmail = lowerText(email);
        std::size_t at = lowerEmail.rfind('@');
        std::string domain = at == std::string::npos ? std::string() : lowerEmail.substr(at + 1);
        bool listed = contains(expectations.emails, lowerEmail);
        bool managed = contains(expectations.domains, domain) && lowerText(claims.stringOr("hd", "")) == domain;
        if (!listed && !managed) {
            error = "This server only accepts sign-ins from approved accounts.";
            return false;
        }
    }

    identity.subject = shortText(subject, 64);
    identity.email = shortText(email, 254);
    std::string name = claims.stringOr("name", "");
    identity.name = shortText(name.empty() ? email.substr(0, email.find('@')) : name, 100);
    identity.picture = shortText(claims.stringOr("picture", ""), 500);
    return true;
}

}
