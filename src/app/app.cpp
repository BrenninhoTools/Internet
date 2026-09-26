#include "app.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <thread>

#include "platform.hpp"

namespace fs = std::filesystem;

namespace internet {

namespace {

void copyText(char* target, std::size_t size, const std::string& text) {
    std::snprintf(target, size, "%s", text.c_str());
}

std::string trim(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

std::string lowerCase(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

void writeFile(const fs::path& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    file << content;
}

std::string downloadName(const std::string& url) {
    std::string name = url.substr(url.rfind('/') + 1);
    std::string clean;
    for (char c : name) {
        clean += (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_') ? c : '_';
    }
    if (clean.empty() || clean == "." || clean == "..") return "download";
    return clean;
}

}

void ensureSampleSite(const fs::path& root) {
    std::error_code error;
    fs::create_directories(root, error);
    if (!fs::exists(root / "index.html")) {
        writeFile(root / "index.html",
                  "<!DOCTYPE html>\n<html>\n<head><title>Welcome to Internet</title></head>\n<body>\n"
                  "<h1>Welcome to Internet</h1>\n"
                  "<p>This page travelled over the Internet protocol. It was looked up in the registry, "
                  "fetched from a node and rendered by the Internet app.</p>\n"
                  "<h2>Explore</h2>\n<ul>\n"
                  "<li><a href=\"about.html\">About this network</a></li>\n"
                  "<li><a href=\"files/\">Browse the file listing</a></li>\n</ul>\n"
                  "<hr>\n<p>Host your own site from the sidebar and share its name.</p>\n"
                  "</body>\n</html>\n");
    }
    if (!fs::exists(root / "about.html")) {
        writeFile(root / "about.html",
                  "<!DOCTYPE html>\n<html>\n<head><title>About</title></head>\n<body>\n"
                  "<h1>About</h1>\n"
                  "<p>Internet is a small network made of three parts: a <b>registry</b> that maps names to "
                  "addresses, <b>nodes</b> that serve files, and <b>clients</b> that browse them.</p>\n"
                  "<p><a href=\"/\">Back to the start page</a></p>\n</body>\n</html>\n");
    }
    fs::create_directories(root / "files", error);
    if (!fs::exists(root / "files" / "hello.txt")) {
        writeFile(root / "files" / "hello.txt", "Hello from the Internet.\n");
    }
}

App::App(fs::path dataDirectory) : dataDir_(std::move(dataDirectory)) {
    copyText(registryBuffer_, sizeof registryBuffer_, "127.0.0.1:" + std::to_string(kDefaultRegistryPort));
    copyText(nodeName_, sizeof nodeName_, "home");
    copyText(nodeFolder_, sizeof nodeFolder_, defaultSiteFolder());
    copyText(address_, sizeof address_, "");
    search_[0] = '\0';
    find_[0] = '\0';
    paletteQuery_[0] = '\0';

    settings_ = loadSettings(dataDir_ / "settings.txt");
    settings_.palette = std::clamp(settings_.palette, 0, paletteCount() - 1);
    bookmarks_ = loadEntries(dataDir_ / "bookmarks.txt");
    recent_ = loadEntries(dataDir_ / "history.txt");
    applyTheme(settings_.palette);
    splash_ = settings_.intro;
    tabs_.emplace_back();

    security_ = std::make_shared<Security>(dataDir_ / "security");
    copyText(scanPath_, sizeof scanPath_, defaultSiteFolder());
    copyText(definitionsSource_, sizeof definitionsSource_, "internet://defs/definitions.txt");
    applyFirewallSettings();
    firewall_.setListener([this](const std::string& text) {
        std::lock_guard<std::mutex> lock(firewallMutex_);
        pendingFirewallNotice_ = text;
    });
}

App::~App() {
    if (scan_) scan_->cancel = true;
    if (scanThread_.joinable()) scanThread_.join();
    saveState();
    gateway_.reset();
    node_.reset();
    registry_.reset();
}

const Palette& App::palette() const { return paletteAt(settings_.palette); }

std::string App::defaultSiteFolder() const { return (dataDir_ / "sites" / "home").lexically_normal().generic_string(); }

void App::saveState() {
    std::error_code error;
    fs::create_directories(dataDir_, error);
    saveSettings(dataDir_ / "settings.txt", settings_);
    saveEntries(dataDir_ / "bookmarks.txt", bookmarks_);
    saveEntries(dataDir_ / "history.txt", recent_);
    settingsDirty_ = false;
}

void App::setInsets(float left, float top, float right, float bottom) {
    insets_[0] = left;
    insets_[1] = top;
    insets_[2] = right;
    insets_[3] = bottom;
}

void App::setTouchMode(bool enabled) { touch_ = enabled; }

bool App::back() {
    if (paletteOpen_) {
        paletteOpen_ = false;
        return true;
    }
    if (securityView_) {
        closeSecurity();
        return true;
    }
    if (menuOpen_) {
        menuOpen_ = false;
        return true;
    }
    if (editor_) {
        closeEditor();
        return true;
    }
    if (findOpen_) {
        findOpen_ = false;
        return true;
    }
    if (!home_ && position_ > 0) {
        goBack();
        return true;
    }
    if (!home_ && position_ == 0) {
        goHome();
        return true;
    }
    return false;
}

void App::showSecurity(int tab) { openSecurity(tab); }

void App::scanFolder(const std::string& path) {
    if (path.empty()) return;
    copyText(scanPath_, sizeof scanPath_, path);
    startScan({fs::path(path)}, path);
    openSecurity(1);
}

void App::setRegistry(const std::string& endpoint) {
    if (!endpoint.empty()) copyText(registryBuffer_, sizeof registryBuffer_, endpoint);
    lastRefresh_ = -100.0;
}

void App::openLink(const std::string& url) {
    if (url.empty()) return;
    editor_ = false;
    securityView_ = false;
    if (!home_ || !currentUrl_.empty()) newTab();
    navigate(url);
}

void App::touchScroll() {
    if (!touch_ || !ImGui::IsWindowHovered()) return;
    ImGuiIO& io = ImGui::GetIO();
    if (ImGui::IsMouseDragging(ImGuiMouseButton_Left, io.MouseDragThreshold)) {
        ImGui::SetScrollY(ImGui::GetScrollY() - io.MouseDelta.y);
        ImGui::SetScrollX(ImGui::GetScrollX() - io.MouseDelta.x);
    }
}

Endpoint App::registryEndpoint() const {
    std::string text = trim(registryBuffer_);
    return parseEndpoint(text);
}

void App::toast(const std::string& text, ToastKind kind) {
    toasts_.push_back(Toast{text, ImGui::GetTime(), kind});
    if (touch_) platform::haptic(12);
}

void App::setPalette(int index) {
    settings_.palette = std::clamp(index, 0, paletteCount() - 1);
    applyTheme(settings_.palette);
    settingsDirty_ = true;
}

void App::setZoom(float zoom) {
    settings_.zoom = std::clamp(std::round(zoom * 20.0f) / 20.0f, 0.6f, 2.5f);
    settingsDirty_ = true;
}

bool App::isBookmarked(const std::string& url) const {
    return std::any_of(bookmarks_.begin(), bookmarks_.end(), [&](const Entry& entry) { return entry.url == url; });
}

void App::toggleBookmark() {
    if (currentUrl_.empty() || home_) return;
    auto found = std::find_if(bookmarks_.begin(), bookmarks_.end(),
                              [&](const Entry& entry) { return entry.url == currentUrl_; });
    if (found != bookmarks_.end()) {
        bookmarks_.erase(found);
        toast("Bookmark removed");
    } else {
        bookmarks_.push_back(Entry{currentUrl_, pageTitle_.empty() ? currentUrl_ : pageTitle_});
        toast("Bookmark added");
    }
    settingsDirty_ = true;
}

void App::shareCurrent() {
    std::string url;
    if (!home_ && !currentUrl_.empty()) {
        url = currentUrl_;
    } else if (node_) {
        url = "internet://" + node_->name() + "/";
    }
    if (url.empty()) {
        toast("Open a page or host a site to share it");
        return;
    }
    if (!platform::shareText(url)) {
        ImGui::SetClipboardText(url.c_str());
        toast("Link copied");
    }
}

void App::recordVisit(const std::string& url, const std::string& title) {
    recent_.erase(std::remove_if(recent_.begin(), recent_.end(), [&](const Entry& entry) { return entry.url == url; }),
                  recent_.end());
    recent_.insert(recent_.begin(), Entry{url, title.empty() ? url : title});
    if (recent_.size() > 24) recent_.resize(24);
    settingsDirty_ = true;
}

TabState App::captureTab() {
    TabState state;
    state.history = std::move(history_);
    state.position = position_;
    state.currentUrl = std::move(currentUrl_);
    state.message = std::move(message_);
    state.contentType = std::move(contentType_);
    state.body = std::move(body_);
    state.title = std::move(pageTitle_);
    state.address = address_;
    state.loading = loading_;
    state.failed = failed_;
    state.binary = binary_;
    state.preformatted = preformatted_;
    state.home = home_;
    state.document = std::move(document_);
    state.job = std::move(pageJob_);
    state.blocked = blocked_;
    state.allowed = blockOverride_;
    state.threat = std::move(threat_);
    return state;
}

void App::restoreTab(TabState&& state) {
    history_ = std::move(state.history);
    position_ = state.position;
    currentUrl_ = std::move(state.currentUrl);
    message_ = std::move(state.message);
    contentType_ = std::move(state.contentType);
    body_ = std::move(state.body);
    pageTitle_ = std::move(state.title);
    copyText(address_, sizeof address_, state.address);
    loading_ = state.loading;
    failed_ = state.failed;
    binary_ = state.binary;
    preformatted_ = state.preformatted;
    home_ = state.home;
    document_ = std::move(state.document);
    pageJob_ = std::move(state.job);
    blocked_ = state.blocked;
    blockOverride_ = state.allowed;
    threat_ = std::move(state.threat);
    pageFade_ = 0.0f;
    homeSince_ = -1.0;
    matchesShown_ = 0;
}

void App::newTab() {
    tabs_[static_cast<std::size_t>(activeTab_)] = captureTab();
    tabs_.emplace_back();
    activeTab_ = static_cast<int>(tabs_.size()) - 1;
    restoreTab(TabState{});
    editor_ = false;
    securityView_ = false;
    menuOpen_ = false;
}

void App::switchTab(int index) {
    if (index < 0 || index >= static_cast<int>(tabs_.size()) || index == activeTab_) return;
    tabs_[static_cast<std::size_t>(activeTab_)] = captureTab();
    activeTab_ = index;
    restoreTab(std::move(tabs_[static_cast<std::size_t>(index)]));
    editor_ = false;
    securityView_ = false;
}

void App::closeTab(int index) {
    if (index < 0 || index >= static_cast<int>(tabs_.size())) return;
    if (tabs_.size() == 1) {
        captureTab();
        restoreTab(TabState{});
        return;
    }
    if (index != activeTab_) {
        tabs_.erase(tabs_.begin() + index);
        if (index < activeTab_) --activeTab_;
        return;
    }
    captureTab();
    tabs_.erase(tabs_.begin() + index);
    activeTab_ = std::min(index, static_cast<int>(tabs_.size()) - 1);
    restoreTab(std::move(tabs_[static_cast<std::size_t>(activeTab_)]));
}

std::string App::tabTitle(int index) {
    bool active = index == activeTab_;
    const TabState& state = tabs_[static_cast<std::size_t>(index)];
    bool onHome = active ? home_ : state.home;
    const std::string& url = active ? currentUrl_ : state.currentUrl;
    const std::string& title = active ? pageTitle_ : state.title;
    if (active && editor_) return "Editor - " + ed_.siteName + (editorDirty() ? " *" : "");
    if (onHome || url.empty()) return "New tab";
    return title.empty() ? url : title;
}

void App::handleShortcuts() {
    ImGuiIO& io = ImGui::GetIO();
    bool ctrl = io.KeyCtrl;
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_K, false)) {
        paletteOpen_ = !paletteOpen_;
        paletteFocus_ = paletteOpen_;
        paletteQuery_[0] = '\0';
        paletteIndex_ = 0;
    }
    if (paletteOpen_) return;

    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_L, false)) focusAddress_ = true;
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_F, false) && !home_ && !editor_) {
        findOpen_ = true;
        focusFind_ = true;
    }
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_D, false)) toggleBookmark();
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_H, false)) goHome();
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_J, false)) {
        if (securityView_) {
            closeSecurity();
        } else {
            openSecurity();
        }
    }
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_T, false)) newTab();
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_W, false)) closeTab(activeTab_);
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_B, false)) sidebarOpen_ = !sidebarOpen_;
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_E, false)) {
        if (editor_) {
            closeEditor();
        } else {
            openEditor();
        }
    }
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_S, false) && editor_) editorSave();
    if (ctrl && ImGui::IsKeyPressed(ImGuiKey_Tab, false) && tabs_.size() > 1) {
        int step = io.KeyShift ? -1 : 1;
        int count = static_cast<int>(tabs_.size());
        switchTab((activeTab_ + step + count) % count);
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F5, false) || (ctrl && ImGui::IsKeyPressed(ImGuiKey_R, false))) reload();
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false)) goBack();
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow, false)) goForward();
    if (ctrl && (ImGui::IsKeyPressed(ImGuiKey_Equal) || ImGui::IsKeyPressed(ImGuiKey_KeypadAdd)))
        setZoom(settings_.zoom + 0.1f);
    if (ctrl && (ImGui::IsKeyPressed(ImGuiKey_Minus) || ImGui::IsKeyPressed(ImGuiKey_KeypadSubtract)))
        setZoom(settings_.zoom - 0.1f);
    if (ctrl && (ImGui::IsKeyPressed(ImGuiKey_0, false) || ImGui::IsKeyPressed(ImGuiKey_Keypad0, false))) setZoom(1.0f);
    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && findOpen_) findOpen_ = false;
    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && securityView_ && !ImGui::IsAnyItemActive()) closeSecurity();
}

void App::draw() {
    ImGuiIO& io = ImGui::GetIO();
    dt_ = io.DeltaTime;
    time_ = ImGui::GetTime();
    if (settings_.animations || splash_) particles_.update(dt_);
    pollJobs();
    pollSecurity();
    pollBrowser();
    hoveredLink_.clear();
    clickedLink_.clear();
    if (!splash_) handleShortcuts();
    pageFade_ = std::min(1.0f, pageFade_ + dt_ * 3.5f);
    approach(sidebarAnim_, sidebarOpen_ ? 1.0f : 0.0f, 14.0f, dt_);
    approach(paletteAnim_, paletteOpen_ ? 1.0f : 0.0f, 18.0f, dt_);
    int viewKey = (securityView_ ? 3 : (editor_ ? 2 : (home_ ? 0 : 1))) * 100 + activeTab_;
    if (viewKey != viewKey_) {
        viewKey_ = viewKey;
        pageFade_ = 0.0f;
    }

    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + insets_[0], viewport->WorkPos.y + insets_[1]));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x - insets_[0] - insets_[2],
                                    viewport->WorkSize.y - insets_[1] - insets_[3]));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("Internet", nullptr, flags);

    float unit = ImGui::GetFontSize();
    float footer = ImGui::GetFrameHeightWithSpacing() + 2.0f;
    compact_ = ImGui::GetContentRegionAvail().x < unit * 42.0f;
    bool wideContent = (showSource_ || preformatted_) && !home_ && !editor_;
    ImGuiWindowFlags pageFlags = wideContent ? ImGuiWindowFlags_HorizontalScrollbar : ImGuiWindowFlags_None;
    if (editor_) pageFlags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

    if (compact_) {
        drawToolbar(true);
        if (menuOpen_) {
            ImGui::BeginChild("sidebar", ImVec2(0, -footer), ImGuiChildFlags_Borders);
            drawSidebar();
            ImGui::EndChild();
        } else {
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(unit * 0.8f, unit * 0.8f));
            ImGui::BeginChild("page", ImVec2(0, -footer), ImGuiChildFlags_Borders, pageFlags);
            drawPage();
            ImGui::EndChild();
            ImGui::PopStyleVar();
        }
    } else {
        float sidebarWidth = unit * 20.0f * easeOutCubic(sidebarAnim_);
        if (sidebarWidth > unit * 2.0f) {
            ImGuiWindowFlags sidebarFlags = sidebarAnim_ < 0.98f ? ImGuiWindowFlags_NoScrollbar : ImGuiWindowFlags_None;
            ImGui::BeginChild("sidebar", ImVec2(sidebarWidth, -footer), ImGuiChildFlags_Borders, sidebarFlags);
            drawSidebar();
            ImGui::EndChild();
            ImGui::SameLine();
        }
        ImGui::BeginGroup();
        drawTabBar();
        drawToolbar(false);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(unit * 1.1f, unit * 1.0f));
        ImGui::BeginChild("page", ImVec2(0, -footer), ImGuiChildFlags_Borders, pageFlags);
        drawPage();
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::EndGroup();
    }

    drawStatusBar();
    ImGui::End();
    ImGui::PopStyleVar();

    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) && hoveredLink_.empty()) pressedLink_.clear();
    if (ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
        ImVec2 drag = ImGui::GetMouseDragDelta(ImGuiMouseButton_Left, io.MouseDragThreshold);
        if (!pressedLink_.empty() && drag.x == 0.0f && drag.y == 0.0f && clickedLink_.empty())
            clickedLink_ = pressedLink_;
        pressedLink_.clear();
    }
    if (!clickedLink_.empty()) {
        editor_ = false;
        securityView_ = false;
        navigate(clickedLink_);
    }

    drawPalette();
    drawToasts();
    drawSplash();

    if (settingsDirty_ && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) saveState();
}

void App::pollJobs() {
    if (pageJob_ && pageJob_->done) {
        PageResult& result = pageJob_->result;
        loading_ = false;
        if (result.ok) {
            failed_ = false;
            threat_ = std::move(result.threat);
            blocked_ = threat_.verdict == Verdict::Malicious;
            blockOverride_ = false;
            if (blocked_) {
                security_->noteBlocked("page", result.url, threat_.findings.empty() ? "malicious content" : threat_.findings[0].rule);
                toast("Blocked a dangerous page", ToastKind::Error);
            } else if (threat_.verdict == Verdict::Suspicious) {
                toast("This page looks suspicious", ToastKind::Warning);
            }
            contentType_ = result.contentType;
            body_ = std::move(result.body);
            binary_ = !isTextType(contentType_);
            document_ = binary_ ? Document{} : parseContent(contentType_, body_);
            preformatted_ = std::any_of(document_.blocks.begin(), document_.blocks.end(),
                                        [](const Block& block) { return block.kind == BlockKind::Preformatted; });
            pageTitle_ = document_.title;
            pageFade_ = 0.0f;
            recordVisit(result.url, pageTitle_);
            status_ = "Loaded " + result.url + " (" + contentType_ + ", " + std::to_string(body_.size()) + " bytes)";
        } else {
            failed_ = true;
            message_ = result.message;
            pageTitle_.clear();
            pageFade_ = 0.0f;
            status_ = "Failed to load " + result.url;
        }
        pageJob_.reset();
    }
    if (nodesJob_ && nodesJob_->done) {
        NodeListResult& result = nodesJob_->result;
        if (result.ok) {
            nodes_ = std::move(result.nodes);
            nodesMessage_.clear();
        } else {
            nodes_.clear();
            nodesMessage_ = result.message;
        }
        nodesJob_.reset();
    }
    if (!nodesJob_ && ImGui::GetTime() - lastRefresh_ > 5.0) refreshNodes();

    if (!pendingNavigation_.empty()) {
        if (!node_) {
            pendingNavigation_.clear();
        } else if (node_->registered()) {
            std::string target = pendingNavigation_;
            pendingNavigation_.clear();
            editor_ = false;
            securityView_ = false;
            navigate(target);
        }
    }
}

void App::refreshNodes() {
    lastRefresh_ = ImGui::GetTime();
    Endpoint endpoint;
    try {
        endpoint = registryEndpoint();
    } catch (const std::exception& error) {
        nodes_.clear();
        nodesMessage_ = error.what();
        return;
    }
    nodesJob_ = std::make_shared<Job<NodeListResult>>();
    auto job = nodesJob_;
    std::thread([job, endpoint] {
        NodeListResult result;
        try {
            result.nodes = listNodes(endpoint);
            result.ok = true;
        } catch (const std::exception& error) {
            result.message = error.what();
        }
        job->result = std::move(result);
        job->done = true;
    }).detach();
}

void App::navigate(const std::string& url, bool record) {
    std::string target = trim(url);
    if (target.empty()) return;
    if (target.find("://") == std::string::npos) target = "internet://" + target;

    Endpoint endpoint;
    try {
        endpoint = registryEndpoint();
    } catch (const std::exception& error) {
        failed_ = true;
        loading_ = false;
        home_ = false;
        message_ = std::string("Invalid registry address: ") + error.what();
        return;
    }

    if (record) {
        history_.resize(static_cast<std::size_t>(position_ + 1));
        history_.push_back(target);
        position_ = static_cast<int>(history_.size()) - 1;
    }
    currentUrl_ = target;
    home_ = false;
    menuOpen_ = false;
    copyText(address_, sizeof address_, target);
    loading_ = true;
    failed_ = false;
    status_ = "Loading " + target;

    blocked_ = false;
    blockOverride_ = false;
    threat_ = ThreatInfo{};

    bool scanPages = security_->settings().realtime;
    std::shared_ptr<Security> security = security_;
    pageJob_ = std::make_shared<Job<PageResult>>();
    auto job = pageJob_;
    std::thread([job, endpoint, target, scanPages, security] {
        PageResult result;
        result.url = target;
        try {
            Page page = fetch(endpoint, target);
            result.ok = true;
            result.contentType = page.contentType;
            result.body = std::move(page.body);
            if (scanPages) {
                std::string name = target.substr(target.rfind('/') + 1);
                if (name.empty()) name = "index.html";
                if (result.contentType == "text/html" && name.find('.') == std::string::npos) name += ".html";
                ScanResult scan = security->scanBuffer(name, result.body, "page");
                result.threat.verdict = scan.verdict;
                result.threat.score = scan.score;
                result.threat.sha256 = scan.sha256;
                result.threat.note = scan.note;
                result.threat.findings = std::move(scan.findings);
            }
        } catch (const std::exception& error) {
            result.message = error.what();
        }
        job->result = std::move(result);
        job->done = true;
    }).detach();
}

void App::submitSearch() {
    std::string text = trim(search_);
    if (text.empty()) return;
    if (text.find("://") != std::string::npos || text.find('/') != std::string::npos) {
        navigate(text);
        return;
    }
    std::string wanted = lowerCase(text);
    std::vector<const NodeInfo*> matches;
    for (const NodeInfo& info : nodes_) {
        if (info.name == wanted) {
            navigate("internet://" + info.name + "/");
            return;
        }
        if (info.name.find(wanted) != std::string::npos) matches.push_back(&info);
    }
    if (matches.size() == 1) {
        navigate("internet://" + matches.front()->name + "/");
    } else if (matches.empty()) {
        navigate("internet://" + wanted + "/");
    }
}

void App::goBack() {
    if (position_ > 0) navigate(history_[static_cast<std::size_t>(--position_)], false);
}

void App::goForward() {
    if (position_ + 1 < static_cast<int>(history_.size()))
        navigate(history_[static_cast<std::size_t>(++position_)], false);
}

void App::reload() {
    if (!currentUrl_.empty() && !home_) navigate(currentUrl_, false);
}

void App::goHome() {
    home_ = true;
    editor_ = false;
    securityView_ = false;
    menuOpen_ = false;
    homeSince_ = -1.0;
}

void App::startRegistry() {
    try {
        auto created = std::make_unique<Registry>();
        created->setFirewall(&firewall_);
        created->start(static_cast<std::uint16_t>(registryPort_));
        registry_ = std::move(created);
        copyText(registryBuffer_, sizeof registryBuffer_, "127.0.0.1:" + std::to_string(registryPort_));
        status_ = "Registry listening on port " + std::to_string(registryPort_);
        toast("Registry started on port " + std::to_string(registryPort_));
        lastRefresh_ = -100.0;
    } catch (const std::exception& error) {
        status_ = error.what();
        toast(std::string("Cannot start registry: ") + error.what());
    }
}

void App::stopRegistry() {
    registry_.reset();
    status_ = "Registry stopped";
    toast("Registry stopped");
    lastRefresh_ = -100.0;
}

void App::startNode() {
    try {
        fs::path folder(trim(nodeFolder_));
        if (!fs::exists(folder) && folder.lexically_normal().generic_string() == defaultSiteFolder())
            ensureSampleSite(folder);
        auto created = std::make_unique<Node>(trim(nodeName_), folder, registryEndpoint());
        created->setFirewall(&firewall_);
        created->setGuard([security = security_](const fs::path& path) { return security->guard(path); });
        created->start(static_cast<std::uint16_t>(nodePort_));
        node_ = std::move(created);
        status_ = "Hosting internet://" + node_->name() + "/";
        toast("Hosting internet://" + node_->name() + "/");
        platform::setHosting(true, node_->name());
        lastRefresh_ = -100.0;
    } catch (const std::exception& error) {
        status_ = error.what();
        toast(std::string("Cannot host site: ") + error.what());
    }
}

void App::stopNode() {
    node_.reset();
    platform::setHosting(false, "");
    status_ = "Site stopped";
    toast("Site stopped");
    lastRefresh_ = -100.0;
}

void App::hostSite() {
    if (node_) {
        stopNode();
        return;
    }
    bool reachable = nodesMessage_.empty();
    if (!registry_ && !reachable) startRegistry();
    startNode();
}

void App::quickStart() {
    if (!registry_) startRegistry();
    if (!registry_) return;
    if (!node_) {
        copyText(nodeName_, sizeof nodeName_, "home");
        copyText(nodeFolder_, sizeof nodeFolder_, defaultSiteFolder());
        ensureSampleSite(fs::path(nodeFolder_));
        startNode();
    }
    if (node_) pendingNavigation_ = "internet://" + node_->name() + "/";
}

void App::saveDownload() {
    if (threat_.verdict == Verdict::Malicious && security_->settings().blockDownloads) {
        security_->noteBlocked("download", currentUrl_, threat_.findings.empty() ? "malicious file" : threat_.findings[0].rule);
        toast("Download blocked: the file is dangerous", ToastKind::Error);
        return;
    }
    std::error_code error;
    fs::path directory = fs::absolute(dataDir_ / "downloads", error);
    fs::create_directories(directory, error);
    fs::path target = directory / downloadName(currentUrl_);
    std::ofstream file(target, std::ios::binary);
    if (!file) {
        status_ = "Cannot write " + target.string();
        toast("Cannot save the file");
        return;
    }
    file.write(body_.data(), static_cast<std::streamsize>(body_.size()));
    status_ = "Saved to " + target.string();
    toast("Saved " + target.filename().string());
}

}
