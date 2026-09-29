#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>

namespace internet {

constexpr int kLoginSeconds = 600;

struct GoogleConfig {
    std::string clientId;
    std::string clientSecret;
    std::string redirectUri;
    std::string authUrl = "https://accounts.google.com/o/oauth2/v2/auth";
    std::string tokenUrl = "https://oauth2.googleapis.com/token";
};

struct GoogleIdentity {
    std::string subject;
    std::string email;
    std::string name;
    std::string picture;
};

struct LoginRequest {
    std::string verifier;
    std::string appChallenge;
    int appPort = 0;
    std::int64_t expires = 0;
};

class GoogleAuth {
public:
    void configure(GoogleConfig config);
    bool enabled() const;
    std::string begin(const std::string& appChallenge, int appPort);
    bool finish(const std::string& code, const std::string& state, LoginRequest& request, GoogleIdentity& identity, std::string& error);

    static bool parseIdToken(const std::string& idToken, const std::string& clientId, std::int64_t now, GoogleIdentity& identity,
                             std::string& error);

private:
    mutable std::mutex mutex_;
    GoogleConfig config_;
    std::map<std::string, LoginRequest> pending_;
};

}
