#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "client.hpp"
#include "markup.hpp"
#include "node.hpp"
#include "protocol.hpp"
#include "registry.hpp"

namespace internet {

template <typename T>
struct Job {
    std::atomic<bool> done{false};
    T result;
};

struct PageResult {
    bool ok = false;
    std::string url;
    std::string contentType;
    std::string body;
    std::string message;
};

struct NodeListResult {
    bool ok = false;
    std::vector<NodeInfo> nodes;
    std::string message;
};

class App {
public:
    explicit App(std::filesystem::path dataDirectory = ".");
    ~App();

    void draw();
    void setInsets(float left, float top, float right, float bottom);
    void setTouchMode(bool enabled);
    bool back();

private:
    void drawSidebar();
    void drawToolbar(bool compact);
    void touchScroll();
    std::string defaultSiteFolder() const;
    void drawPage();
    void drawStatusBar();
    void drawDocument();
    void drawWords(const Block& block, float scale);
    void drawBinary();

    void navigate(const std::string& url, bool record = true);
    void goBack();
    void goForward();
    void reload();
    void pollJobs();
    void refreshNodes();
    void quickStart();
    void startRegistry();
    void stopRegistry();
    void startNode();
    void stopNode();
    void saveDownload();
    Endpoint registryEndpoint() const;

    char registryBuffer_[128];
    int registryPort_ = kDefaultRegistryPort;
    char nodeName_[64];
    char nodeFolder_[256];
    int nodePort_ = 0;
    char address_[512];
    bool showSource_ = false;
    bool compact_ = false;
    bool menuOpen_ = false;
    bool touch_ = false;
    float insets_[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    std::filesystem::path dataDir_;

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
