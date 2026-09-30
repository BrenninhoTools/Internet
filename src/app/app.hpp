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
#include "browser.hpp"
#include "client.hpp"
#include "firewall.hpp"
#include "gateway.hpp"
#include "imgui.h"
#include "markup.hpp"
#include "node.hpp"
#include "protocol.hpp"
#include "registry.hpp"
#include "security.hpp"
#include "server.hpp"
#include "sitefiles.hpp"
#include "siteserver.hpp"
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

struct OutlineItem {
    int level = 1;
    std::string text;
    float y = 0.0f;
};

struct ServerInfo {
    std::string web;
    bool login = false;
};

struct AccountProfile {
    std::string id;
    std::string email;
    std::string name;
    std::vector<std::string> sites;
    int maxSites = 0;
};

struct LoginCatch {
    std::mutex mutex;
    std::string code;
    std::atomic<bool> got{false};
};

struct RemoteBlob {
    std::string content;
    long long updated = 0;
};

struct SyncOutcome {
    std::string content;
    long long updated = 0;
    bool adopt = false;
};

struct SyncResult {
    bool ok = false;
    std::string message;
    std::map<std::string, SyncOutcome> outcomes;
    std::map<std::string, std::string> captured;
};

struct PublishState {
    std::atomic<int> done{0};
    std::atomic<int> total{0};
    std::atomic<bool> finished{false};
    std::string message;
    std::string site;
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
    void drawAddressChip(ImVec2 min, ImVec2 max, bool typing);
    void drawTabIdentity(ImDrawList* list, int index, ImVec2 center, float radius);
    void drawStatusBar();
    void drawPalette();
    std::vector<PaletteItem> buildPaletteItems();

    void drawPage();
    void drawPageContent();
    void drawDocument(const Document& document, bool interactive, const std::string& base);
    void drawWords(const std::vector<Span>& spans, float scale, const ImVec4* tint, bool interactive,
                   const std::string& base);
    void drawTable(const Document& document, std::size_t begin, std::size_t end, bool interactive,
                   const std::string& base);
    void drawImage(const Block& block, bool interactive, const std::string& base);
    void drawListMarker(const Block& block, ImVec2 origin, float gutter, float unit);
    void drawQuoteBars(int depth, float left, float top, float bottom, float unit);
    void drawOutline(float width);
    void drawScrollTools();
    void applyScrollTarget();
    void followAnchor(const std::string& anchor);
    void drawBinary();
    void drawError();
    void drawLoading();
    void drawBlocked();
    void drawThreatBanner();

    void drawBrowserPanel(float width);
    void drawBrowserSidebar(float width);
    bool ensureGateway();
    void openInBrowser(const std::string& internetUrl);
    std::string browserTarget() const;
    void toggleLinkRegistration();
    void pollBrowser();
    void copyGatewayAddress();
    std::string shareTarget() const;
    std::string webBase() const;
    std::string webLink(const std::string& internetUrl) const;
    std::string fromWebLink(const std::string& address);
    void copyWebLink();
    void copyInternetLink();
    void discoverWeb();
    void drawWebLink(float width);

    bool signedIn() const;
    void loadAccount();
    void saveAccount() const;
    void saveSyncState() const;
    void loadSyncState();
    void forgetSyncState();
    void startSignIn();
    void cancelSignIn();
    void pollAccount();
    void signOut();
    void signOutEverywhere();
    void sessionExpired();
    bool accountCall(const std::string& method, const std::string& path, const std::string& body,
                     std::function<void(const ApiResponse&)> done);
    void refreshAccount();
    void createOwnedSite();
    void publishSite(const std::string& name);
    void requestSync(double delay);
    void startSync();
    void applySync(SyncResult& result);
    std::string localSyncData(const std::string& kind) const;
    void applyLocalSync(const std::string& kind, const std::string& content);
    void drawAccount(float width);

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
    std::vector<OutlineItem> outline_;
    std::vector<OutlineItem> outlineNext_;
    std::map<std::string, float> anchors_;
    std::map<std::string, float> anchorsNext_;
    std::string outlineUrl_;
    float rightInset_ = 0.0f;
    float scrollTarget_ = -1.0f;
    float pageScroll_ = 0.0f;
    float pageScrollMax_ = 0.0f;
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
    std::unique_ptr<Gateway> gateway_;
    std::string chromePath_;
    bool chromeChecked_ = false;
    bool linksRegistered_ = false;
    double browserPolled_ = -100.0;
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
    std::shared_ptr<Job<ServerInfo>> webJob_;
    std::string discoveredWeb_;
    bool discoveredLogin_ = false;
    std::string webRegistry_;
    double webChecked_ = -1000.0;
    char webBuffer_[256];

    AccountProfile account_;
    std::string accountToken_;
    std::string accountRegistry_;
    int signInPhase_ = 0;
    double signInStarted_ = 0.0;
    std::string signInVerifier_;
    std::unique_ptr<Server> loginListener_;
    std::shared_ptr<LoginCatch> loginCatch_;
    std::shared_ptr<Job<ApiResponse>> exchangeJob_;
    std::shared_ptr<Job<ApiResponse>> callJob_;
    std::function<void(const ApiResponse&)> callDone_;
    std::shared_ptr<Job<SyncResult>> syncJob_;
    std::map<std::string, RemoteBlob> synced_;
    double syncDue_ = -1.0;
    double syncPolled_ = -1000.0;
    double profileTried_ = -1000.0;
    bool profileLoaded_ = false;
    std::string syncMessage_;
    long long syncedClock_ = 0;
    std::shared_ptr<PublishState> publish_;
    char siteNameBuffer_[64];
    std::string nodesMessage_;
    double lastRefresh_ = -100.0;

    std::string hoveredLink_;
    std::string clickedLink_;
    std::string pressedLink_;
    std::string status_;
    std::string pendingNavigation_;
};

}
