#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "av.hpp"
#include "client.hpp"
#include "firewall.hpp"
#include "imgui.h"
#include "markup.hpp"
#include "node.hpp"
#include "protocol.hpp"
#include "registry.hpp"
#include "security.hpp"
#include "sitefiles.hpp"
#include "storage.hpp"
#include "theme.hpp"
#include "widgets.hpp"

namespace internet {

template <typename T>
struct Job {
    std::atomic<bool> done{false};
    T result;
};

struct ThreatInfo {
    Verdict verdict = Verdict::Clean;
    int score = 0;
    std::string sha256;
    std::string note;
    std::vector<Finding> findings;
};

struct PageResult {
    bool ok = false;
    std::string url;
    std::string contentType;
    std::string body;
    std::string message;
    ThreatInfo threat;
};

struct NodeListResult {
    bool ok = false;
    std::vector<NodeInfo> nodes;
    std::string message;
};

struct TabState {
    std::vector<std::string> history;
    int position = -1;
    std::string currentUrl;
    std::string message;
    std::string contentType;
    std::string body;
    std::string title;
    std::string address;
    bool loading = false;
    bool failed = false;
    bool binary = false;
    bool preformatted = false;
    bool home = true;
    bool blocked = false;
    bool allowed = false;
    ThreatInfo threat;
    Document document;
    std::shared_ptr<Job<PageResult>> job;
};

struct EditorState {
    std::filesystem::path root;
    std::string siteName;
    std::vector<SiteFile> files;
    bool rescan = true;
    double scanned = -100.0;
    std::string current;
    std::string text;
    std::string saved;
    bool binary = false;
    std::string notice;
    Document preview;
    std::string previewSource;
    bool previewValid = false;
    int mode = 0;
    int cursor = 0;
    int pendingCursor = -1;
    bool focusEditor = false;
    char nameBuffer[160] = {0};
    int templateIndex = 0;
    std::string target;
    std::string afterDiscard;
    std::string error;
    bool openNew = false;
    bool openRename = false;
    bool openDelete = false;
    bool openDiscard = false;
    bool openLinks = false;
    int securityLevel = 0;
    std::string securityNote;
};

struct PaletteItem {
    std::string label;
    std::string hint;
    Icon icon;
    ImVec4 tint;
    std::function<void()> run;
    int score = 0;
};

enum class ToastKind { Info, Success, Warning, Error };

enum class SecurityState { Protected, Attention, Danger, Scanning };

void ensureSampleSite(const std::filesystem::path& root);

class App {
public:
    explicit App(std::filesystem::path dataDirectory = ".");
    ~App();

    void draw();
    void setInsets(float left, float top, float right, float bottom);
    void setTouchMode(bool enabled);
    bool back();
    void openLink(const std::string& url);
    void setRegistry(const std::string& endpoint);
    void showSecurity(int tab);
    void scanFolder(const std::string& path);

private:
    struct CardState {
        bool clicked;
        ImVec2 min;
        ImVec2 max;
        float hover;
    };

    struct Toast {
        std::string text;
        double born;
        ToastKind kind;
    };

    void drawSidebar();
    void drawBrand();
    void drawAppearance();
    void drawToolbar(bool compact);
    void drawTabBar();
    void drawFindBar();
    void drawStatusBar();
    void drawPalette();
    std::vector<PaletteItem> buildPaletteItems();

    void drawPage();
    void drawPageContent();
    void drawDocument(const Document& document, bool interactive, const std::string& base);
    void drawWords(const Block& block, float scale, const ImVec4* tint, bool interactive, const std::string& base);
    void drawBinary();
    void drawError();
    void drawLoading();
    void drawBlocked();
    void drawThreatBanner();

    void drawHome();
    void drawHero(float width, bool compact);
    void drawActions(float width);
    void drawNodeCards(float width);
    void drawBookmarkCards(float width);
    void drawRecentChips(float width);
    void drawSplash();
    void drawToasts();
    void sectionTitle(const char* text, const ImVec4& color);
    CardState card(const std::string& id, ImVec2 size, const ImVec4& tint, bool selected);
    bool iconButton(const char* id, Icon icon, const char* tooltip, bool enabled = true, bool active = false,
                    ImVec4 tint = ImVec4(0, 0, 0, 0));
    bool textButton(const char* id, const char* label, Icon icon, bool primary, float width = 0.0f);

    void drawEditor();
    void drawEditorHeader(bool compact);
    void drawFileTree(float width, float height);
    void drawEditorPane(float width, float height);
    void drawPreviewPane(float width, float height);
    void drawEditorPopups();
    void openEditor();
    void closeEditor();
    void scanSiteFiles();
    void editorOpenFile(const std::string& path, bool force);
    void editorSave();
    void editorInsert(const std::string& snippet);
    void editorPublish();
    std::string editorLiveUrl(const std::string& path) const;
    bool editorDirty() const;

    void drawSecurity();
    void drawSecurityOverview(float width);
    void drawSecurityScan(float width);
    void drawSecurityQuarantine(float width);
    void drawSecurityFirewall(float width);
    void drawSecuritySettings(float width);
    bool toggleSwitch(const char* id, bool* value);
    void drawStatCard(const char* id, const char* label, const std::string& value, Icon icon, const ImVec4& tint, ImVec2 size);
    void openSecurity(int tab = 0);
    void closeSecurity();
    SecurityState securityState() const;
    ImVec4 stateColor(SecurityState state) const;
    const char* stateText(SecurityState state) const;
    void startScan(const std::vector<std::filesystem::path>& roots, const std::string& label);
    void finishScan();
    void updateDefinitions(const std::string& source);
    void applyFirewallSettings();
    ThreatInfo makeThreat(const ScanResult& result) const;

    void handleShortcuts();
    void touchScroll();
    void toast(const std::string& text, ToastKind kind = ToastKind::Info);
    void submitSearch();
    void navigate(const std::string& url, bool record = true);
    void goBack();
    void goForward();
    void reload();
    void goHome();
    void pollJobs();
    void pollSecurity();
    void refreshNodes();
    void quickStart();
    void hostSite();
    void startRegistry();
    void stopRegistry();
    void startNode();
    void stopNode();
    void saveDownload();
    void toggleBookmark();
    void shareCurrent();
    bool isBookmarked(const std::string& url) const;
    void recordVisit(const std::string& url, const std::string& title);
    void setPalette(int index);
    void setZoom(float zoom);
    void saveState();

    TabState captureTab();
    void restoreTab(TabState&& state);
    void newTab();
    void closeTab(int index);
    void switchTab(int index);
    std::string tabTitle(int index);

    std::string defaultSiteFolder() const;
    const Palette& palette() const;
    Endpoint registryEndpoint() const;

    char registryBuffer_[128];
    int registryPort_ = kDefaultRegistryPort;
    char nodeName_[64];
    char nodeFolder_[256];
    int nodePort_ = 0;
    char address_[512];
    char search_[256];
    char find_[128];
    char paletteQuery_[128];
    char scanPath_[512];
    char definitionsSource_[512];
    bool showSource_ = false;
    bool compact_ = false;
    bool menuOpen_ = false;
    bool touch_ = false;
    bool home_ = true;
    bool editor_ = false;
    bool securityView_ = false;
    bool splash_ = false;
    bool findOpen_ = false;
    bool focusFind_ = false;
    bool focusAddress_ = false;
    bool focusSearch_ = false;
    bool paletteOpen_ = false;
    bool paletteFocus_ = false;
    bool settingsDirty_ = false;
    bool sidebarOpen_ = true;
    float sidebarAnim_ = 1.0f;
    float paletteAnim_ = 0.0f;
    int paletteIndex_ = 0;
    int securityTab_ = 0;
    float insets_[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    std::filesystem::path dataDir_;

    Settings settings_;
    std::vector<Entry> bookmarks_;
    std::vector<Entry> recent_;
    ParticleField particles_;
    std::map<std::string, float> hover_;
    std::vector<Toast> toasts_;
    float dt_ = 0.016f;
    double time_ = 0.0;
    double splashStart_ = -1.0;
    double homeSince_ = -1.0;
    float pageFade_ = 1.0f;
    int matches_ = 0;
    int matchesShown_ = 0;
    int viewKey_ = -1;
    std::string pageTitle_;

    std::vector<TabState> tabs_;
    int activeTab_ = 0;

    EditorState ed_;

    std::shared_ptr<Security> security_;
    Firewall firewall_;
    ThreatInfo threat_;
    bool blocked_ = false;
    bool blockOverride_ = false;
    std::unique_ptr<ScanProgress> scan_;
    std::thread scanThread_;
    std::string scanLabel_;
    int unresolved_ = 0;
    std::vector<QuarantineItem> quarantineCache_;
    double quarantineRefreshed_ = -100.0;
    std::vector<ThreatEvent> eventsCache_;
    double eventsRefreshed_ = -100.0;
    std::shared_ptr<Job<std::string>> definitionsJob_;
    std::string definitionsMessage_;
    std::vector<ScanRecord> scanRecords_;
    std::string pendingFirewallNotice_;
    bool bannerExpanded_ = false;
    std::mutex firewallMutex_;

    std::unique_ptr<Registry> registry_;
    std::unique_ptr<Node> node_;

    std::vector<std::string> history_;
    int position_ = -1;
    std::string currentUrl_;
    bool loading_ = false;
    bool failed_ = false;
    std::string message_;
    std::string contentType_;
    std::string body_;
    Document document_;
    bool binary_ = false;
    bool preformatted_ = false;

    std::shared_ptr<Job<PageResult>> pageJob_;
    std::shared_ptr<Job<NodeListResult>> nodesJob_;
    std::vector<NodeInfo> nodes_;
    std::string nodesMessage_;
    double lastRefresh_ = -100.0;

    std::string hoveredLink_;
    std::string clickedLink_;
    std::string pressedLink_;
    std::string status_;
    std::string pendingNavigation_;
};

}
