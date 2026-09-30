#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace internet {

constexpr int kSessionSeconds = 30 * 24 * 3600;
constexpr int kHandoffSeconds = 120;
constexpr int kIdleSeconds = 14 * 24 * 3600;
constexpr std::size_t kMaxSyncBytes = 512 * 1024;

struct Account {
    std::string id;
    std::string subject;
    std::string email;
    std::string name;
    std::string picture;
    std::int64_t created = 0;
    std::int64_t lastLogin = 0;
};

struct SessionInfo {
    std::string id;
    std::int64_t created = 0;
    std::int64_t lastUsed = 0;
    std::int64_t expires = 0;
};

struct SyncBlob {
    std::string content;
    std::int64_t updated = 0;
};

class Accounts {
public:
    explicit Accounts(std::filesystem::path directory);

    Account signIn(const std::string& subject, const std::string& email, const std::string& name, const std::string& picture);
    std::optional<Account> find(const std::string& id) const;
    std::size_t count() const;

    std::string createSession(const std::string& accountId, int lifetimeSeconds = kSessionSeconds);
    std::optional<Account> sessionAccount(const std::string& token);
    void endSession(const std::string& token);
    std::string sessionId(const std::string& token) const;
    std::vector<SessionInfo> sessionsOf(const std::string& accountId) const;
    std::size_t endAllSessions(const std::string& accountId);
    bool endSessionById(const std::string& accountId, const std::string& id);
    std::vector<std::string> deleteAccount(const std::string& accountId);

    std::string createHandoff(const std::string& accountId, const std::string& challenge);
    std::optional<std::string> redeemHandoff(const std::string& code, const std::string& verifier);

    bool claimSite(const std::string& name, const std::string& accountId, int limit, std::string& error);
    void releaseSite(const std::string& name);
    std::string siteOwner(const std::string& name) const;
    std::vector<std::string> sitesOf(const std::string& accountId) const;

    static bool validSyncKind(const std::string& kind);
    bool readSync(const std::string& accountId, const std::string& kind, SyncBlob& blob) const;
    bool writeSync(const std::string& accountId, const std::string& kind, const std::string& content, std::int64_t& updated,
                   std::string& error);

private:
    struct SessionRecord {
        std::string account;
        std::int64_t expires = 0;
        std::int64_t created = 0;
        std::int64_t lastUsed = 0;
    };

    struct HandoffRecord {
        std::string account;
        std::string challenge;
        std::int64_t expires = 0;
    };

    void load();
    void save() const;
    void purgeExpired(std::int64_t now);
    std::filesystem::path syncPath(const std::string& accountId, const std::string& kind) const;

    std::filesystem::path directory_;
    mutable std::mutex mutex_;
    std::vector<Account> accounts_;
    std::map<std::string, std::string> owners_;
    std::map<std::string, SessionRecord> sessions_;
    std::map<std::string, HandoffRecord> handoffs_;
};

}
