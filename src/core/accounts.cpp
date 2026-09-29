#include "accounts.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iterator>
#include <system_error>

#include "encoding.hpp"
#include "json.hpp"
#include "sha256.hpp"

namespace fs = std::filesystem;

namespace internet {

namespace {

constexpr std::size_t kMaxHandoffs = 1000;

std::int64_t nowSeconds() { return static_cast<std::int64_t>(std::time(nullptr)); }

bool readWhole(const fs::path& path, std::string& text) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    text.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    return true;
}

bool writeAtomically(const fs::path& path, const std::string& text) {
    std::error_code error;
    fs::create_directories(path.parent_path(), error);
    fs::path temporary = path;
    temporary += ".tmp";
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream) return false;
        stream << text;
        if (!stream) return false;
    }
    fs::rename(temporary, path, error);
    return !error;
}

std::string hashOf(const std::string& secret) { return sha256Hex(secret); }

Json accountJson(const Account& account) {
    return Json::object()
        .set("id", account.id)
        .set("subject", account.subject)
        .set("email", account.email)
        .set("name", account.name)
        .set("picture", account.picture)
        .set("created", account.created)
        .set("lastLogin", account.lastLogin);
}

}

Accounts::Accounts(fs::path directory) : directory_(std::move(directory)) { load(); }

void Accounts::load() {
    std::string text;
    if (!readWhole(directory_ / "accounts.json", text)) return;
    Json json;
    std::string problem;
    if (!Json::parse(text, json, problem)) {
        std::error_code error;
        fs::rename(directory_ / "accounts.json", directory_ / "accounts.json.corrupt", error);
        return;
    }
    if (const Json* list = json.find("accounts")) {
        for (const Json& item : list->items()) {
            Account account;
            account.id = item.stringOr("id", "");
            account.subject = item.stringOr("subject", "");
            account.email = item.stringOr("email", "");
            account.name = item.stringOr("name", "");
            account.picture = item.stringOr("picture", "");
            if (const Json* created = item.find("created")) account.created = static_cast<std::int64_t>(created->asNumber());
            if (const Json* seen = item.find("lastLogin")) account.lastLogin = static_cast<std::int64_t>(seen->asNumber());
            if (!account.id.empty() && !account.subject.empty()) accounts_.push_back(std::move(account));
        }
    }
    if (const Json* list = json.find("sites")) {
        for (const Json& item : list->items()) {
            std::string name = item.stringOr("name", "");
            std::string owner = item.stringOr("account", "");
            if (!name.empty() && !owner.empty()) owners_[name] = owner;
        }
    }
    if (const Json* list = json.find("sessions")) {
        std::int64_t now = nowSeconds();
        for (const Json& item : list->items()) {
            SessionRecord record;
            record.account = item.stringOr("account", "");
            if (const Json* expires = item.find("expires")) record.expires = static_cast<std::int64_t>(expires->asNumber());
            std::string hash = item.stringOr("hash", "");
            if (!hash.empty() && !record.account.empty() && record.expires > now) sessions_[hash] = std::move(record);
        }
    }
}

void Accounts::save() const {
    Json accounts = Json::array();
    for (const Account& account : accounts_) accounts.push(accountJson(account));
    Json sites = Json::array();
    for (const auto& owner : owners_) sites.push(Json::object().set("name", owner.first).set("account", owner.second));
    Json sessions = Json::array();
    for (const auto& session : sessions_) {
        sessions.push(Json::object().set("hash", session.first).set("account", session.second.account).set("expires", session.second.expires));
    }
    Json root = Json::object().set("accounts", std::move(accounts)).set("sites", std::move(sites)).set("sessions", std::move(sessions));
    writeAtomically(directory_ / "accounts.json", root.dump());
}

void Accounts::purgeExpired(std::int64_t now) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        it = it->second.expires <= now ? sessions_.erase(it) : std::next(it);
    }
    for (auto it = handoffs_.begin(); it != handoffs_.end();) {
        it = it->second.expires <= now ? handoffs_.erase(it) : std::next(it);
    }
}

Account Accounts::signIn(const std::string& subject, const std::string& email, const std::string& name, const std::string& picture) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::int64_t now = nowSeconds();
    for (Account& account : accounts_) {
        if (account.subject != subject) continue;
        account.email = email;
        account.name = name;
        account.picture = picture;
        account.lastLogin = now;
        save();
        return account;
    }
    Account account;
    account.id = randomHex(8);
    account.subject = subject;
    account.email = email;
    account.name = name;
    account.picture = picture;
    account.created = now;
    account.lastLogin = now;
    accounts_.push_back(account);
    save();
    return account;
}

std::optional<Account> Accounts::find(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const Account& account : accounts_) {
        if (account.id == id) return account;
    }
    return std::nullopt;
}

std::size_t Accounts::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return accounts_.size();
}

std::string Accounts::createSession(const std::string& accountId, int lifetimeSeconds) {
    std::string token = randomHex(32);
    std::lock_guard<std::mutex> lock(mutex_);
    std::int64_t now = nowSeconds();
    purgeExpired(now);
    sessions_[hashOf(token)] = SessionRecord{accountId, now + lifetimeSeconds};
    save();
    return token;
}

std::optional<Account> Accounts::sessionAccount(const std::string& token) {
    if (token.size() < 32) return std::nullopt;
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = sessions_.find(hashOf(token));
    if (found == sessions_.end()) return std::nullopt;
    if (found->second.expires <= nowSeconds()) {
        sessions_.erase(found);
        save();
        return std::nullopt;
    }
    for (const Account& account : accounts_) {
        if (account.id == found->second.account) return account;
    }
    return std::nullopt;
}

void Accounts::endSession(const std::string& token) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (sessions_.erase(hashOf(token)) != 0) save();
}

std::string Accounts::createHandoff(const std::string& accountId, const std::string& challenge) {
    std::string code = randomHex(24);
    std::lock_guard<std::mutex> lock(mutex_);
    purgeExpired(nowSeconds());
    if (handoffs_.size() >= kMaxHandoffs) handoffs_.erase(handoffs_.begin());
    handoffs_[hashOf(code)] = HandoffRecord{accountId, challenge, nowSeconds() + kHandoffSeconds};
    return code;
}

std::optional<std::string> Accounts::redeemHandoff(const std::string& code, const std::string& verifier) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = handoffs_.find(hashOf(code));
    if (found == handoffs_.end()) return std::nullopt;
    HandoffRecord record = found->second;
    handoffs_.erase(found);
    if (record.expires <= nowSeconds()) return std::nullopt;
    if (!constantTimeEquals(record.challenge, sha256Hex(verifier))) return std::nullopt;
    return record.account;
}

bool Accounts::claimSite(const std::string& name, const std::string& accountId, int limit, std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (owners_.count(name) != 0) {
        error = "That site name is already taken";
        return false;
    }
    int owned = static_cast<int>(std::count_if(owners_.begin(), owners_.end(), [&](const auto& item) { return item.second == accountId; }));
    if (limit > 0 && owned >= limit) {
        error = "You already have " + std::to_string(owned) + " sites, which is the limit";
        return false;
    }
    owners_[name] = accountId;
    save();
    return true;
}

void Accounts::releaseSite(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (owners_.erase(name) != 0) save();
}

std::string Accounts::siteOwner(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = owners_.find(name);
    return found == owners_.end() ? std::string() : found->second;
}

std::vector<std::string> Accounts::sitesOf(const std::string& accountId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    for (const auto& owner : owners_) {
        if (owner.second == accountId) names.push_back(owner.first);
    }
    return names;
}

bool Accounts::validSyncKind(const std::string& kind) { return kind == "bookmarks" || kind == "history" || kind == "settings"; }

fs::path Accounts::syncPath(const std::string& accountId, const std::string& kind) const {
    return directory_ / "sync" / accountId / (kind + ".json");
}

bool Accounts::readSync(const std::string& accountId, const std::string& kind, SyncBlob& blob) const {
    if (!validSyncKind(kind) || accountId.find_first_not_of("0123456789abcdef") != std::string::npos) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    std::string text;
    if (!readWhole(syncPath(accountId, kind), text)) return false;
    Json json;
    std::string problem;
    if (!Json::parse(text, json, problem)) return false;
    blob.content = json.stringOr("content", "");
    blob.updated = 0;
    if (const Json* updated = json.find("updated")) blob.updated = static_cast<std::int64_t>(updated->asNumber());
    return true;
}

bool Accounts::writeSync(const std::string& accountId, const std::string& kind, const std::string& content, std::int64_t& updated,
                         std::string& error) {
    if (!validSyncKind(kind) || accountId.find_first_not_of("0123456789abcdef") != std::string::npos) {
        error = "Unknown kind of data";
        return false;
    }
    if (content.size() > kMaxSyncBytes) {
        error = "That is more than the server keeps for one account";
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    updated = nowSeconds();
    Json json = Json::object().set("updated", updated).set("content", content);
    if (!writeAtomically(syncPath(accountId, kind), json.dump())) {
        error = "The server cannot store this data";
        return false;
    }
    return true;
}

}
