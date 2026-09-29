#include "googleauth.hpp"

#include <ctime>
#include <iterator>
#include <utility>

#include "encoding.hpp"
#include "http.hpp"
#include "json.hpp"
#include "sha256.hpp"

namespace internet {

namespace {

constexpr std::size_t kMaxPending = 500;
constexpr std::int64_t kClockSkewSeconds = 60;

std::int64_t nowSeconds() { return static_cast<std::int64_t>(std::time(nullptr)); }

std::string shortText(const std::string& text, std::size_t limit) { return text.size() <= limit ? text : text.substr(0, limit); }

bool claimTrue(const Json& json, const std::string& key) {
    const Json* value = json.find(key);
    if (!value) return false;
    if (value->type() == Json::Type::Bool) return value->asBool();
    return value->isString() && value->asString() == "true";
}

}

void GoogleAuth::configure(GoogleConfig config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = std::move(config);
}

bool GoogleAuth::enabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !config_.clientId.empty() && !config_.clientSecret.empty() && !config_.redirectUri.empty();
}

std::string GoogleAuth::begin(const std::string& appChallenge, int appPort) {
    GoogleConfig config;
    std::string state = randomHex(16);
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
        pending_[state] = LoginRequest{verifier, appChallenge, appPort, now + kLoginSeconds};
    }
    std::string query = formEncode({{"client_id", config.clientId},
                                    {"redirect_uri", config.redirectUri},
                                    {"response_type", "code"},
                                    {"scope", "openid email profile"},
                                    {"state", state},
                                    {"code_challenge", challenge},
                                    {"code_challenge_method", "S256"},
                                    {"prompt", "select_account"}});
    return config.authUrl + (config.authUrl.find('?') == std::string::npos ? "?" : "&") + query;
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
    return parseIdToken(json.stringOr("id_token", ""), config.clientId, nowSeconds(), identity, error);
}

bool GoogleAuth::parseIdToken(const std::string& idToken, const std::string& clientId, std::int64_t now, GoogleIdentity& identity,
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
    if (const Json* aud = claims.find("aud")) {
        if (aud->isString()) {
            audience = aud->asString() == clientId;
        } else if (aud->isArray()) {
            for (const Json& item : aud->items()) audience = audience || (item.isString() && item.asString() == clientId);
        }
    }
    if (!audience) {
        error = "The identity was issued for another application.";
        return false;
    }
    const Json* expires = claims.find("exp");
    if (!expires || static_cast<std::int64_t>(expires->asNumber()) + kClockSkewSeconds < now) {
        error = "The identity from Google has expired.";
        return false;
    }
    std::string subject = claims.stringOr("sub", "");
    std::string email = claims.stringOr("email", "");
    if (subject.empty() || email.empty() || !claimTrue(claims, "email_verified")) {
        error = "The Google account needs a verified email address.";
        return false;
    }
    identity.subject = shortText(subject, 64);
    identity.email = shortText(email, 254);
    std::string name = claims.stringOr("name", "");
    identity.name = shortText(name.empty() ? email.substr(0, email.find('@')) : name, 100);
    identity.picture = shortText(claims.stringOr("picture", ""), 500);
    return true;
}

}
