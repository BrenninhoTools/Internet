#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <ctime>
#include <fstream>
#include <iterator>
#include <sstream>
#include <thread>

#include "app.hpp"
#include "encoding.hpp"
#include "json.hpp"
#include "sha256.hpp"
#include "ui.hpp"

namespace fs = std::filesystem;

namespace internet {

namespace {

const ImVec4 kMuted(0.62f, 0.64f, 0.72f, 1.0f);
const ImVec4 kGood(0.28f, 0.84f, 0.52f, 1.0f);
const ImVec4 kAlert(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kSnow(1.0f, 1.0f, 1.0f, 1.0f);

constexpr double kSignInSeconds = 300.0;
constexpr double kSyncPollSeconds = 60.0;
constexpr std::size_t kMaxUploadFiles = 500;
constexpr std::uintmax_t kMaxUploadBytes = 16u * 1024u * 1024u;
const char* const kSyncKinds[] = {"bookmarks", "history", "settings"};

std::string trimText(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return std::string();
    return text.substr(start, text.find_last_not_of(" \t\r\n") - start + 1);
}

std::string apiErrorText(const ApiResponse& response) {
    Json json;
    std::string problem;
    if (Json::parse(response.body, json, problem)) {
        std::string message = json.stringOr("error", "");
        if (!message.empty()) return message;
    }
    return response.reachable ? "Error " + response.code : std::string("Cannot reach the server");
}

AccountProfile profileFrom(const Json& json) {
    AccountProfile profile;
    profile.id = json.stringOr("id", "");
    profile.email = json.stringOr("email", "");
    profile.name = json.stringOr("name", "");
    if (const Json* sites = json.find("sites")) {
        for (const Json& item : sites->items()) {
            if (item.isString()) profile.sites.push_back(item.asString());
        }
    }
    if (const Json* limit = json.find("maxSites")) profile.maxSites = static_cast<int>(limit->asNumber());
    return profile;
}

std::string clockText(long long seconds) {
    std::time_t stamp = static_cast<std::time_t>(seconds);
    std::tm parts{};
#ifdef _WIN32
    localtime_s(&parts, &stamp);
#else
    localtime_r(&stamp, &parts);
#endif
    char text[16] = {};
    std::strftime(text, sizeof text, "%H:%M", &parts);
    return text;
}

std::string mergeKind(const std::string& kind, const std::string& local, const std::string& remote, bool firstSync) {
    if (kind == "bookmarks") return mergeEntries(local, remote, 0);
    if (kind == "history") return mergeEntries(local, remote, 24);
    return firstSync ? remote : local;
}

bool drawGoogleButton(const char* id, float width, bool enabled, float unit) {
    float height = ImGui::GetFrameHeight() * 1.25f;
    ImVec2 position = ImGui::GetCursorScreenPos();
    ImGui::PushID(id);
    ImGui::BeginDisabled(!enabled);
    bool pressed = ImGui::InvisibleButton("##google", ImVec2(width, height));
    bool hovered = ImGui::IsItemHovered();
    ImGui::EndDisabled();
    ImGui::PopID();

    ImDrawList* list = ImGui::GetWindowDrawList();
    float alpha = enabled ? 1.0f : 0.45f;
    ImVec4 fill = hovered && enabled ? ImVec4(0.9f, 0.93f, 1.0f, 1.0f) : ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    list->AddRectFilled(position, ImVec2(position.x + width, position.y + height), packColor(withAlpha(fill, alpha)), height * 0.3f);

    ImVec2 center(position.x + height * 0.68f, position.y + height * 0.5f);
    float radius = height * 0.25f;
    float thickness = height * 0.13f;
    struct Arc {
        float from;
        float to;
        ImVec4 color;
    };
    const float pi = 3.14159265f;
    const Arc arcs[] = {{200.0f, 320.0f, ImVec4(0.92f, 0.26f, 0.21f, 1.0f)},
                        {320.0f, 380.0f, ImVec4(0.26f, 0.52f, 0.96f, 1.0f)},
                        {20.0f, 140.0f, ImVec4(0.20f, 0.66f, 0.33f, 1.0f)},
                        {140.0f, 200.0f, ImVec4(0.98f, 0.74f, 0.02f, 1.0f)}};
    for (const Arc& arc : arcs) {
        list->PathClear();
        list->PathArcTo(center, radius, arc.from * pi / 180.0f, arc.to * pi / 180.0f, 16);
        list->PathStroke(packColor(withAlpha(arc.color, alpha)), ImDrawFlags_None, thickness);
    }
    list->AddRectFilled(ImVec2(center.x, center.y - thickness * 0.5f), ImVec2(center.x + radius + thickness * 0.5f, center.y + thickness * 0.5f),
                        packColor(withAlpha(ImVec4(0.26f, 0.52f, 0.96f, 1.0f), alpha)));

    float textX = position.x + height * 1.2f;
    std::string label = fitText("Sign in with Google", unit, width - height * 1.4f);
    drawText(list, unit, ImVec2(textX, position.y + (height - unit) * 0.5f), packColor(withAlpha(ImVec4(0.13f, 0.13f, 0.16f, 1.0f), alpha)), label.c_str());
    return pressed && enabled;
}

}

bool App::signedIn() const { return !accountToken_.empty() && accountRegistry_ == registryBuffer_; }

void App::loadAccount() {
    std::ifstream stream(dataDir_ / "account.txt");
    std::string line;
    while (std::getline(stream, line)) {
        std::size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        std::string key = line.substr(0, equals);
        std::string value = line.substr(equals + 1);
        if (!value.empty() && value.back() == '\r') value.pop_back();
        if (key == "registry") accountRegistry_ = value;
        if (key == "token") accountToken_ = value;
        if (key == "id") account_.id = value;
        if (key == "email") account_.email = value;
        if (key == "name") account_.name = value;
    }
}

void App::saveAccount() const {
    fs::path file = dataDir_ / "account.txt";
    std::error_code error;
    {
        std::ofstream stream(file, std::ios::trunc);
        if (!accountToken_.empty()) {
            stream << "registry=" << accountRegistry_ << '\n';
            stream << "token=" << accountToken_ << '\n';
            stream << "id=" << account_.id << '\n';
            stream << "email=" << account_.email << '\n';
            stream << "name=" << account_.name << '\n';
        }
    }
    fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, error);
}

void App::startSignIn() {
    if (signInPhase_ != 0) return;
    std::string base = webBase();
    if (base.empty() || !discoveredLogin_) {
        toast("This server does not offer sign-in", ToastKind::Warning);
        return;
    }
    loginCatch_ = std::make_shared<LoginCatch>();
    loginListener_ = std::make_unique<Server>();
    loginListener_->setLoopbackOnly(true);
    std::shared_ptr<LoginCatch> shared = loginCatch_;
    try {
        loginListener_->start(0, [shared](Socket& socket, const std::string&) {
            std::string line;
            if (!socket.recvLine(line)) return;
            std::string header;
            while (socket.recvLine(header) && !header.empty()) {
            }
            std::stringstream first(line);
            std::string method;
            std::string target;
            first >> method >> target;
            std::string code;
            std::size_t question = target.find('?');
            if (question != std::string::npos) {
                for (const auto& item : formDecode(target.substr(question + 1))) {
                    if (item.first == "code") code = item.second;
                }
            }
            if (code.empty() || code.size() > 128) {
                socket.sendAll("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
                return;
            }
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                shared->code = code;
                shared->got = true;
            }
            std::string body =
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>Internet</title>"
                "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#e8ecf8;font:16px system-ui,sans-serif}"
                "main{text-align:center;padding:24px}h1{background:linear-gradient(90deg,#60a5fa,#c084fc);-webkit-background-clip:text;background-clip:text;color:transparent}"
                "p{color:#aab6d6}</style></head><body><main><h1>You are signed in</h1><p>You can close this tab and go back to the Internet app.</p></main></body></html>";
            socket.sendAll("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + std::to_string(body.size()) +
                           "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n" + body);
        });
    } catch (const std::exception& error) {
        loginListener_.reset();
        loginCatch_.reset();
        toast(std::string("Cannot wait for the sign-in: ") + error.what(), ToastKind::Error);
        return;
    }
    signInVerifier_ = base64UrlEncode(randomBytes(32));
    std::string url = base + "/auth/google/start?app_port=" + std::to_string(loginListener_->port()) + "&challenge=" + sha256Hex(signInVerifier_);
    signInPhase_ = 1;
    signInStarted_ = time_;
    if (!(browserSupported() && openInDefaultBrowser(url))) {
        ImGui::SetClipboardText(url.c_str());
        toast("Open the address that was copied in a browser to sign in", ToastKind::Warning);
    }
}

void App::cancelSignIn() {
    loginListener_.reset();
    loginCatch_.reset();
    exchangeJob_.reset();
    signInVerifier_.clear();
    signInPhase_ = 0;
}

void App::saveSyncState() const {
    fs::path file = dataDir_ / "sync-state.json";
    Json root = Json::object();
    for (const auto& item : synced_) {
        root.set(item.first, Json::object().set("updated", static_cast<std::int64_t>(item.second.updated)).set("content", item.second.content));
    }
    std::ofstream stream(file, std::ios::binary | std::ios::trunc);
    stream << root.dump();
    stream.close();
    std::error_code error;
    fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, error);
}

void App::loadSyncState() {
    synced_.clear();
    std::ifstream stream(dataDir_ / "sync-state.json", std::ios::binary);
    if (!stream) return;
    std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    Json root;
    std::string problem;
    if (!Json::parse(text, root, problem)) return;
    for (const char* kind : kSyncKinds) {
        const Json* item = root.find(kind);
        if (!item || !item->isObject()) continue;
        RemoteBlob blob;
        blob.content = item->stringOr("content", "");
        if (const Json* updated = item->find("updated")) blob.updated = static_cast<long long>(updated->asNumber());
        synced_[kind] = std::move(blob);
    }
}

void App::forgetSyncState() {
    synced_.clear();
    std::error_code error;
    fs::remove(dataDir_ / "sync-state.json", error);
}

void App::sessionExpired() {
    accountToken_.clear();
    account_ = AccountProfile{};
    profileLoaded_ = false;
    forgetSyncState();
    saveAccount();
    toast("Your session ended. Sign in again.", ToastKind::Warning);
}

void App::signOut() {
    if (!accountToken_.empty()) {
        try {
            Endpoint endpoint = registryEndpoint();
            std::string token = accountToken_;
            std::thread([endpoint, token] { apiCall(endpoint, "DELETE", "/v1/account/session", token, ""); }).detach();
        } catch (const std::exception&) {
        }
    }
    accountToken_.clear();
    account_ = AccountProfile{};
    profileLoaded_ = false;
    forgetSyncState();
    syncMessage_.clear();
    syncedClock_ = 0;
    saveAccount();
    toast("Signed out");
}

void App::signOutEverywhere() {
    bool started = accountCall("DELETE", "/v1/account/sessions", "", [this](const ApiResponse& response) {
        if (!response.ok) {
            toast(apiErrorText(response), ToastKind::Error);
            return;
        }
        accountToken_.clear();
        account_ = AccountProfile{};
        profileLoaded_ = false;
        forgetSyncState();
        syncMessage_.clear();
        syncedClock_ = 0;
        saveAccount();
        toast("Signed out of every device");
    });
    if (!started) toast("Wait for the last request to finish");
}

bool App::accountCall(const std::string& method, const std::string& path, const std::string& body,
                      std::function<void(const ApiResponse&)> done) {
    if (callJob_) return false;
    Endpoint endpoint;
    try {
        endpoint = registryEndpoint();
    } catch (const std::exception& error) {
        toast(error.what(), ToastKind::Error);
        return false;
    }
    callJob_ = std::make_shared<Job<ApiResponse>>();
    callDone_ = std::move(done);
    std::shared_ptr<Job<ApiResponse>> job = callJob_;
    std::string token = accountToken_;
    std::thread([job, endpoint, token, method, path, body] {
        job->result = apiCall(endpoint, method, path, token, body);
        job->done = true;
    }).detach();
    return true;
}

void App::refreshAccount() {
    accountCall("GET", "/v1/account", "", [this](const ApiResponse& response) {
        Json json;
        std::string problem;
        if (response.ok && Json::parse(response.body, json, problem)) {
            account_ = profileFrom(json);
            profileLoaded_ = true;
            saveAccount();
        }
    });
}

void App::createOwnedSite() {
    std::string name = trimText(siteNameBuffer_);
    if (name.empty()) return;
    bool started = accountCall("POST", "/v1/sites", Json::object().set("name", name).dump(), [this, name](const ApiResponse& response) {
        if (response.ok) {
            toast("Created internet://" + name + "/", ToastKind::Success);
            siteNameBuffer_[0] = '\0';
            refreshAccount();
        } else {
            toast(apiErrorText(response), ToastKind::Error);
        }
    });
    if (!started) toast("Wait for the last request to finish");
}

void App::publishSite(const std::string& name) {
    if (publish_ && !publish_->finished) return;
    fs::path root(nodeFolder_);
    std::error_code error;
    if (!fs::is_directory(root, error)) {
        toast("The site folder does not exist: " + root.string(), ToastKind::Error);
        return;
    }
    Endpoint endpoint;
    try {
        endpoint = registryEndpoint();
    } catch (const std::exception& problem) {
        toast(problem.what(), ToastKind::Error);
        return;
    }
    auto state = std::make_shared<PublishState>();
    state->site = name;
    publish_ = state;
    std::string token = accountToken_;
    std::thread([state, endpoint, token, root, name] {
        std::vector<SiteFile> files;
        for (const SiteFile& file : listSiteFiles(root)) {
            if (!file.directory) files.push_back(file);
        }
        if (files.size() > kMaxUploadFiles) {
            state->message = "That folder has more than " + std::to_string(kMaxUploadFiles) + " files";
            state->finished = true;
            return;
        }
        state->total = static_cast<int>(files.size());
        for (const SiteFile& file : files) {
            if (file.size > kMaxUploadBytes) {
                state->message = file.path + " is larger than 16 MB";
                state->finished = true;
                return;
            }
            std::ifstream stream(root / fs::u8path(file.path), std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
            ApiResponse response;
            for (int attempt = 0; attempt < 4; ++attempt) {
                response = apiCall(endpoint, "PUT", "/v1/sites/" + name + "/files/" + file.path, token, content);
                if (response.code != "429") break;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (!response.ok) {
                state->message = "Could not upload " + file.path + ": " + apiErrorText(response);
                state->finished = true;
                return;
            }
            ++state->done;
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
        }
        state->message = "Uploaded " + std::to_string(files.size()) + (files.size() == 1 ? " file to internet://" : " files to internet://") + name + "/";
        state->finished = true;
    }).detach();
}

std::string App::localSyncData(const std::string& kind) const {
    if (kind == "bookmarks") return formatEntries(bookmarks_);
    if (kind == "history") return formatEntries(recent_);
    return formatSyncedSettings(settings_);
}

void App::applyLocalSync(const std::string& kind, const std::string& content) {
    if (kind == "bookmarks") {
        bookmarks_ = parseEntries(content);
    } else if (kind == "history") {
        recent_ = parseEntries(content);
        if (recent_.size() > 24) recent_.resize(24);
    } else {
        Settings updated = settings_;
        if (applySyncedSettings(content, updated)) {
            settings_.palette = std::clamp(updated.palette, 0, paletteCount() - 1);
            settings_.zoom = updated.zoom;
            settings_.animations = updated.animations;
            settings_.intro = updated.intro;
            applyTheme(settings_.palette);
        }
    }
    settingsDirty_ = true;
}

void App::requestSync(double delay) {
    if (syncDue_ < 0.0) syncDue_ = time_ + delay;
}

void App::startSync() {
    syncDue_ = -1.0;
    if (!signedIn() || syncJob_) return;
    Endpoint endpoint;
    try {
        endpoint = registryEndpoint();
    } catch (const std::exception&) {
        return;
    }
    std::map<std::string, std::string> local;
    for (const char* kind : kSyncKinds) local[kind] = localSyncData(kind);
    std::map<std::string, RemoteBlob> base = synced_;
    std::string token = accountToken_;
    syncJob_ = std::make_shared<Job<SyncResult>>();
    std::shared_ptr<Job<SyncResult>> job = syncJob_;
    std::thread([job, endpoint, token, local, base] {
        SyncResult result;
        result.captured = local;
        auto finish = [&](const std::string& message) {
            result.message = message;
            job->result = std::move(result);
            job->done = true;
        };
        for (const char* name : kSyncKinds) {
            std::string kind = name;
            ApiResponse got = apiCall(endpoint, "GET", "/v1/account/sync/" + kind, token, "");
            if (!got.ok) {
                finish(got.code == "401" ? std::string("401") : apiErrorText(got));
                return;
            }
            Json json;
            std::string problem;
            if (!Json::parse(got.body, json, problem)) {
                finish("The server sent unreadable data");
                return;
            }
            RemoteBlob remote;
            remote.content = json.stringOr("content", "");
            if (const Json* updated = json.find("updated")) remote.updated = static_cast<long long>(updated->asNumber());
            auto known = base.find(kind);
            RemoteBlob before = known == base.end() ? RemoteBlob{} : known->second;
            const std::string& mine = local.at(kind);

            SyncOutcome outcome;
            outcome.content = mine;
            outcome.updated = before.updated;
            std::string toPush;
            bool push = false;
            if (remote.updated == before.updated) {
                if (mine != before.content) {
                    toPush = mine;
                    push = true;
                }
            } else if (mine == before.content) {
                outcome.content = remote.content;
                outcome.updated = remote.updated;
                outcome.adopt = remote.content != mine;
            } else {
                std::string merged = mergeKind(kind, mine, remote.content, before.updated == 0);
                outcome.content = merged;
                outcome.updated = remote.updated;
                outcome.adopt = merged != mine;
                if (merged != remote.content) {
                    toPush = merged;
                    push = true;
                }
            }
            if (push) {
                ApiResponse put = apiCall(endpoint, "PUT", "/v1/account/sync/" + kind, token, toPush);
                Json putJson;
                if (!put.ok || !Json::parse(put.body, putJson, problem)) {
                    finish(put.code == "401" ? std::string("401") : apiErrorText(put));
                    return;
                }
                outcome.content = toPush;
                if (const Json* updated = putJson.find("updated")) outcome.updated = static_cast<long long>(updated->asNumber());
            }
            result.outcomes[kind] = outcome;
        }
        result.ok = true;
        job->result = std::move(result);
        job->done = true;
    }).detach();
}

void App::applySync(SyncResult& result) {
    if (!result.ok) {
        if (result.message == "401") {
            sessionExpired();
        } else {
            syncMessage_ = "Sync failed: " + result.message;
        }
        return;
    }
    for (auto& item : result.outcomes) {
        const std::string& kind = item.first;
        const SyncOutcome& outcome = item.second;
        if (outcome.adopt) {
            if (localSyncData(kind) != result.captured[kind]) continue;
            applyLocalSync(kind, outcome.content);
            synced_[kind] = RemoteBlob{localSyncData(kind), outcome.updated};
        } else {
            synced_[kind] = RemoteBlob{outcome.content, outcome.updated};
        }
    }
    syncedClock_ = static_cast<long long>(std::time(nullptr));
    syncMessage_.clear();
    saveSyncState();
}

void App::pollAccount() {
    if (signInPhase_ == 1) {
        std::string code;
        if (loginCatch_ && loginCatch_->got) {
            std::lock_guard<std::mutex> lock(loginCatch_->mutex);
            code = loginCatch_->code;
        }
        if (!code.empty()) {
            loginListener_.reset();
            loginCatch_.reset();
            Endpoint endpoint;
            try {
                endpoint = registryEndpoint();
            } catch (const std::exception& error) {
                cancelSignIn();
                toast(error.what(), ToastKind::Error);
                return;
            }
            exchangeJob_ = std::make_shared<Job<ApiResponse>>();
            std::shared_ptr<Job<ApiResponse>> job = exchangeJob_;
            std::string verifier = signInVerifier_;
            std::thread([job, endpoint, code, verifier] {
                job->result = apiCall(endpoint, "POST", "/v1/session/exchange", "", Json::object().set("code", code).set("verifier", verifier).dump());
                job->done = true;
            }).detach();
            signInPhase_ = 2;
        } else if (time_ - signInStarted_ > kSignInSeconds) {
            cancelSignIn();
            toast("Signing in took too long", ToastKind::Warning);
        }
    } else if (signInPhase_ == 2 && exchangeJob_ && exchangeJob_->done) {
        ApiResponse response = exchangeJob_->result;
        exchangeJob_.reset();
        signInVerifier_.clear();
        signInPhase_ = 0;
        Json json;
        std::string problem;
        if (response.ok && Json::parse(response.body, json, problem) && !json.stringOr("token", "").empty()) {
            accountToken_ = json.stringOr("token", "");
            accountRegistry_ = registryBuffer_;
            if (const Json* profile = json.find("account")) account_ = profileFrom(*profile);
            profileLoaded_ = true;
            forgetSyncState();
            saveAccount();
            toast("Signed in as " + (account_.name.empty() ? account_.email : account_.name), ToastKind::Success);
            requestSync(0.2);
        } else {
            toast("Could not sign in: " + apiErrorText(response), ToastKind::Error);
        }
    }

    if (callJob_ && callJob_->done) {
        ApiResponse response = callJob_->result;
        std::function<void(const ApiResponse&)> done = std::move(callDone_);
        callJob_.reset();
        if (response.code == "401") {
            sessionExpired();
        } else if (done) {
            done(response);
        }
    }
    if (syncJob_ && syncJob_->done) {
        SyncResult result = std::move(syncJob_->result);
        syncJob_.reset();
        applySync(result);
    }
    if (signedIn()) {
        if (!callJob_ && !profileLoaded_ && time_ - profileTried_ > 30.0) {
            profileTried_ = time_;
            refreshAccount();
        }
        if (!syncJob_ && syncDue_ >= 0.0 && time_ >= syncDue_) {
            syncPolled_ = time_;
            startSync();
        } else if (!syncJob_ && time_ - syncPolled_ > kSyncPollSeconds) {
            syncPolled_ = time_;
            startSync();
        }
    }
    if (publish_ && publish_->finished) {
        toast(publish_->message, publish_->message.rfind("Uploaded", 0) == 0 ? ToastKind::Success : ToastKind::Error);
        publish_.reset();
    }
}

void App::drawAccount(float width) {
    float unit = ImGui::GetFontSize();
    ImDrawList* list = ImGui::GetWindowDrawList();
    const Palette& colors = palette();

    if (!signedIn()) {
        if (signInPhase_ != 0) {
            ImVec2 position = ImGui::GetCursorScreenPos();
            drawSpinner(list, ImVec2(position.x + unit * 0.9f, position.y + unit * 0.95f), unit * 0.7f, packColor(colors.secondary), static_cast<float>(time_));
            ImGui::Indent(unit * 2.2f);
            ImGui::TextColored(kMuted, "%s", signInPhase_ == 1 ? "Waiting for Google in your browser" : "Finishing the sign in");
            ImGui::Unindent(unit * 2.2f);
            ImGui::Spacing();
            if (ImGui::Button("Cancel", ImVec2(width, 0))) cancelSignIn();
            return;
        }
        bool available = !webBase().empty() && discoveredLogin_;
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(kMuted, "Sign in to publish your own sites and keep your bookmarks with you.");
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        if (drawGoogleButton("acct-google", width, available, unit)) startSignIn();
        if (!available) {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextColored(kMuted, "%s", webBase().empty() ? "Connect to a public server to sign in." : "This server does not offer sign-in.");
            ImGui::PopTextWrapPos();
        }
        return;
    }

    ImVec2 position = ImGui::GetCursorScreenPos();
    float radius = unit * 1.25f;
    ImVec2 center(position.x + radius, position.y + radius);
    std::string shown = account_.name.empty() ? account_.email : account_.name;
    list->AddCircleFilled(center, radius, packColor(avatarColor(account_.email.empty() ? shown : account_.email)), 28);
    std::string initial = shown.empty() ? "?" : std::string(1, static_cast<char>(std::toupper(static_cast<unsigned char>(shown.front()))));
    float initialSize = radius * 1.15f;
    drawText(list, initialSize, ImVec2(center.x - textWidth(initialSize, initial) * 0.5f, center.y - initialSize * 0.5f), packColor(kSnow), initial.c_str());
    float textLimit = width - radius * 2.0f - unit * 0.8f;
    drawText(list, unit, ImVec2(position.x + radius * 2.0f + unit * 0.7f, position.y + radius - unit * 1.05f), packColor(kSnow), fitText(shown, unit, textLimit).c_str());
    drawText(list, unit * 0.85f, ImVec2(position.x + radius * 2.0f + unit * 0.7f, position.y + radius + unit * 0.05f), packColor(kMuted),
             fitText(account_.email, unit * 0.85f, textLimit).c_str());
    ImGui::Dummy(ImVec2(width, radius * 2.0f + unit * 0.3f));

    float spacing = ImGui::GetStyle().ItemSpacing.x;
    float half = (width - spacing) * 0.5f;
    if (textButton("acct-sync", "Sync now", Icon::Reload, false, half)) {
        syncDue_ = -1.0;
        startSync();
    }
    ImGui::SameLine();
    if (textButton("acct-out", "Sign out", Icon::Close, false, half)) signOut();
    if (ImGui::SmallButton("Sign out everywhere")) signOutEverywhere();
    if (ImGui::IsItemHovered() && !touch_) ImGui::SetTooltip("End every session of this account, on every device");
    ImGui::PushTextWrapPos(0.0f);
    if (syncJob_) {
        ImGui::TextColored(kMuted, "Syncing...");
    } else if (!syncMessage_.empty()) {
        ImGui::TextColored(kAlert, "%s", syncMessage_.c_str());
    } else if (syncedClock_ != 0) {
        ImGui::TextColored(kMuted, "Bookmarks, history and settings synced at %s", clockText(syncedClock_).c_str());
    }
    ImGui::PopTextWrapPos();

    ImGui::Spacing();
    ImGui::TextColored(kMuted, "Your sites (%d of %d)", static_cast<int>(account_.sites.size()), account_.maxSites);
    bool uploading = publish_ && !publish_->finished;
    for (const std::string& name : account_.sites) {
        ImGui::PushID(name.c_str());
        if (ImGui::Selectable(name.c_str(), false, 0, ImVec2(width - unit * 6.0f, 0.0f))) clickedLink_ = "internet://" + name + "/";
        ImGui::SameLine();
        ImGui::BeginDisabled(uploading);
        if (ImGui::SmallButton("Upload")) publishSite(name);
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && !touch_) ImGui::SetTooltip("Send the files of the folder you host to internet://%s/", name.c_str());
        ImGui::PopID();
    }
    if (account_.sites.empty()) ImGui::TextColored(kMuted, "You have no sites yet.");
    if (uploading) {
        int total = std::max(1, publish_->total.load());
        ImGui::ProgressBar(static_cast<float>(publish_->done.load()) / static_cast<float>(total), ImVec2(width, unit * 0.6f), "");
        ImGui::TextColored(kMuted, "Uploading to internet://%s/", publish_->site.c_str());
    }
    ImGui::SetNextItemWidth(width - unit * 5.2f);
    ImGui::InputTextWithHint("##newsite", "name of a new site", siteNameBuffer_, sizeof siteNameBuffer_);
    ImGui::SameLine();
    ImGui::BeginDisabled(trimText(siteNameBuffer_).empty() || callJob_ != nullptr);
    if (ImGui::Button("Create")) createOwnedSite();
    ImGui::EndDisabled();
}

}
