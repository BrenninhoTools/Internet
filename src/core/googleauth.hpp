#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace internet {

constexpr int kLoginSeconds = 600;

struct GoogleConfig {
    std::string clientId;
    std::string clientSecret;
    std::string redirectUri;
    std::string authUrl = "https://accounts.google.com/o/oauth2/v2/auth";
    std::string tokenUrl = "https://oauth2.googleapis.com/token";
    std::string keysUrl = "https://www.googleapis.com/oauth2/v3/certs";
    bool verifySignature = true;
    std::size_t minimumKeyBits = 2048;
    std::vector<std::string> allowedDomains;
    std::vector<std::string> allowedEmails;
};

struct GoogleIdentity {
    std::string subject;
    std::string email;
    std::string name;
    std::string picture;
};

struct LoginRequest {
    std::string verifier;
    std::string nonce;
    std::string appChallenge;
    int appPort = 0;
    std::int64_t expires = 0;
};

struct TokenExpectations {
    std::string clientId;
    std::string nonce;
    std::vector<std::string> domains;
    std::vector<std::string> emails;
    std::int64_t now = 0;
};

class GoogleAuth {
public:
    void configure(GoogleConfig config);
    bool enabled() const;
    std::string begin(const std::string& appChallenge, int appPort);
    bool finish(const std::string& code, const std::string& state, LoginRequest& request, GoogleIdentity& identity, std::string& error);

    static bool parseIdToken(const std::string& idToken, const TokenExpectations& expectations, GoogleIdentity& identity, std::string& error);
    static bool parseIdToken(const std::string& idToken, const std::string& clientId, std::int64_t now, GoogleIdentity& identity, std::string& error);
    static std::vector<std::string> splitList(const std::string& text);

private:
    struct Key {
        std::string id;
        std::string modulus;
        std::string exponent;
    };

    bool verifySignature(const std::string& idToken, const GoogleConfig& config, std::string& error);
    bool refreshKeys(const GoogleConfig& config, std::string& error);

    mutable std::mutex mutex_;
    GoogleConfig config_;
    std::map<std::string, LoginRequest> pending_;
    std::vector<Key> keys_;
    std::int64_t keysFetched_ = 0;
};

}
