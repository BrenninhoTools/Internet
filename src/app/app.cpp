#include "app.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <thread>

#include "imgui.h"

namespace fs = std::filesystem;

namespace internet {

namespace {

const ImVec4 kLinkColor(0.36f, 0.62f, 1.0f, 1.0f);
const ImVec4 kErrorColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kGoodColor(0.45f, 0.85f, 0.5f, 1.0f);
const ImVec4 kDimColor(0.62f, 0.62f, 0.66f, 1.0f);

void copyText(char* target, std::size_t size, const std::string& text) {
    std::snprintf(target, size, "%s", text.c_str());
}

std::string trim(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

void writeFile(const fs::path& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    file << content;
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

App::App() {
    copyText(registryBuffer_, sizeof registryBuffer_, "127.0.0.1:" + std::to_string(kDefaultRegistryPort));
    copyText(nodeName_, sizeof nodeName_, "home");
    copyText(nodeFolder_, sizeof nodeFolder_, "sites/home");
    copyText(address_, sizeof address_, "internet://home/");
}

App::~App() {
    node_.reset();
    registry_.reset();
}

Endpoint App::registryEndpoint() const { return parseEndpoint(trim(registryBuffer_)); }

void App::draw() {
    pollJobs();
    hoveredLink_.clear();
    clickedLink_.clear();

    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("Internet", nullptr, flags);

    float unit = ImGui::GetFontSize();
    float footer = ImGui::GetFrameHeightWithSpacing() + 2.0f;
    ImGui::BeginChild("sidebar", ImVec2(unit * 20.0f, -footer), ImGuiChildFlags_Borders);
    drawSidebar();
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginGroup();
    drawToolbar();
    ImGui::BeginChild("page", ImVec2(0, -footer), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    drawPage();
    ImGui::EndChild();
    ImGui::EndGroup();

    drawStatusBar();
    ImGui::End();
    ImGui::PopStyleVar();

    if (!clickedLink_.empty()) navigate(clickedLink_);
}

void App::pollJobs() {
    if (pageJob_ && pageJob_->done) {
        PageResult& result = pageJob_->result;
        loading_ = false;
        if (result.ok) {
            failed_ = false;
            contentType_ = result.contentType;
            body_ = std::move(result.body);
            binary_ = !isTextType(contentType_);
            document_ = binary_ ? Document{} : parseContent(contentType_, body_);
            status_ = "Loaded " + result.url + " (" + contentType_ + ", " + std::to_string(body_.size()) + " bytes)";
        } else {
            failed_ = true;
            message_ = result.message;
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
        message_ = std::string("Invalid registry address: ") + error.what();
        return;
    }

    if (record) {
        history_.resize(static_cast<std::size_t>(position_ + 1));
        history_.push_back(target);
        position_ = static_cast<int>(history_.size()) - 1;
    }
    currentUrl_ = target;
    copyText(address_, sizeof address_, target);
    loading_ = true;
    failed_ = false;
    status_ = "Loading " + target;

    pageJob_ = std::make_shared<Job<PageResult>>();
    auto job = pageJob_;
    std::thread([job, endpoint, target] {
        PageResult result;
        result.url = target;
        try {
            Page page = fetch(endpoint, target);
            result.ok = true;
            result.contentType = page.contentType;
            result.body = std::move(page.body);
        } catch (const std::exception& error) {
            result.message = error.what();
        }
        job->result = std::move(result);
        job->done = true;
    }).detach();
}

void App::goBack() {
    if (position_ > 0) navigate(history_[static_cast<std::size_t>(--position_)], false);
}

void App::goForward() {
    if (position_ + 1 < static_cast<int>(history_.size())) navigate(history_[static_cast<std::size_t>(++position_)], false);
}

void App::reload() {
    if (!currentUrl_.empty()) navigate(currentUrl_, false);
}

void App::startRegistry() {
    try {
        auto created = std::make_unique<Registry>();
        created->start(static_cast<std::uint16_t>(registryPort_));
        registry_ = std::move(created);
        copyText(registryBuffer_, sizeof registryBuffer_, "127.0.0.1:" + std::to_string(registryPort_));
        status_ = "Registry listening on port " + std::to_string(registryPort_);
        lastRefresh_ = -100.0;
    } catch (const std::exception& error) {
        status_ = error.what();
    }
}

void App::stopRegistry() {
    registry_.reset();
    status_ = "Registry stopped";
}

void App::startNode() {
    try {
        auto created = std::make_unique<Node>(trim(nodeName_), fs::path(trim(nodeFolder_)), registryEndpoint());
        created->start(static_cast<std::uint16_t>(nodePort_));
        node_ = std::move(created);
        status_ = "Hosting internet://" + node_->name() + "/";
    } catch (const std::exception& error) {
        status_ = error.what();
    }
}

void App::stopNode() {
    node_.reset();
    status_ = "Site stopped";
}

void App::quickStart() {
    if (!registry_) startRegistry();
    if (!registry_) return;
    if (!node_) {
        copyText(nodeName_, sizeof nodeName_, "home");
        copyText(nodeFolder_, sizeof nodeFolder_, "sites/home");
        ensureSampleSite(fs::path(nodeFolder_));
        startNode();
    }
    if (node_) pendingNavigation_ = "internet://" + node_->name() + "/";
}

void App::saveDownload() {
    std::error_code error;
    fs::path directory = fs::absolute("downloads", error);
    fs::create_directories(directory, error);
    fs::path target = directory / downloadName(currentUrl_);
    std::ofstream file(target, std::ios::binary);
    if (!file) {
        status_ = "Cannot write " + target.string();
        return;
    }
    file.write(body_.data(), static_cast<std::streamsize>(body_.size()));
    status_ = "Saved to " + target.string();
}

void App::drawSidebar() {
    float width = ImGui::GetContentRegionAvail().x;
    if (ImGui::Button("Quick start", ImVec2(width, 0))) quickStart();
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Start a local registry, host a sample site and open it");
    }
    ImGui::Spacing();

    if (ImGui::CollapsingHeader("Registry", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextColored(kDimColor, "Address used by this app");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##registry", registryBuffer_, sizeof registryBuffer_);
        ImGui::Spacing();
        ImGui::TextColored(kDimColor, "Run a registry on this computer");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputInt("##registryPort", &registryPort_, 0, 0);
        registryPort_ = std::clamp(registryPort_, 1, 65535);
        if (registry_) {
            if (ImGui::Button("Stop registry", ImVec2(width, 0))) stopRegistry();
            ImGui::TextColored(kGoodColor, "Running on port %d", static_cast<int>(registry_->port()));
        } else {
            if (ImGui::Button("Start registry", ImVec2(width, 0))) startRegistry();
            ImGui::TextColored(kDimColor, "Not running");
        }
    }

    if (ImGui::CollapsingHeader("Host a site", ImGuiTreeNodeFlags_DefaultOpen)) {
        bool running = node_ != nullptr;
        ImGui::BeginDisabled(running);
        ImGui::TextColored(kDimColor, "Name");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##nodeName", nodeName_, sizeof nodeName_);
        ImGui::TextColored(kDimColor, "Folder");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##nodeFolder", nodeFolder_, sizeof nodeFolder_);
        ImGui::TextColored(kDimColor, "Port (0 = automatic)");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputInt("##nodePort", &nodePort_, 0, 0);
        nodePort_ = std::clamp(nodePort_, 0, 65535);
        ImGui::EndDisabled();
        if (running) {
            if (ImGui::Button("Stop hosting", ImVec2(width, 0))) stopNode();
        } else if (ImGui::Button("Start hosting", ImVec2(width, 0))) {
            startNode();
        }
        if (node_) {
            ImGui::TextColored(kGoodColor, "internet://%s/", node_->name().c_str());
            ImGui::TextColored(node_->registered() ? kGoodColor : kErrorColor, node_->registered()
                                                                                   ? "Registered"
                                                                                   : "Waiting for registry");
            ImGui::TextColored(kDimColor, "Port %d, %llu requests", static_cast<int>(node_->port()),
                               static_cast<unsigned long long>(node_->requests()));
        }
    }

    if (ImGui::CollapsingHeader("Directory", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::Button("Refresh", ImVec2(width, 0))) lastRefresh_ = -100.0;
        if (!nodesMessage_.empty()) {
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextColored(kErrorColor, "%s", nodesMessage_.c_str());
            ImGui::PopTextWrapPos();
        } else if (nodes_.empty()) {
            ImGui::TextColored(kDimColor, "No nodes online");
        }
        for (const NodeInfo& info : nodes_) {
            std::string label = info.name + "##" + formatEndpoint(info.endpoint);
            if (ImGui::Selectable(label.c_str())) clickedLink_ = "internet://" + info.name + "/";
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", formatEndpoint(info.endpoint).c_str());
        }
    }
}

void App::drawToolbar() {
    float unit = ImGui::GetFontSize();
    ImGui::BeginDisabled(position_ <= 0);
    if (ImGui::Button("Back")) goBack();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(position_ + 1 >= static_cast<int>(history_.size()));
    if (ImGui::Button("Forward")) goForward();
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Reload")) reload();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - unit * 9.5f);
    bool submitted = ImGui::InputText("##address", address_, sizeof address_, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Go")) submitted = true;
    ImGui::SameLine();
    ImGui::Checkbox("Source", &showSource_);
    if (submitted) navigate(address_);
}

void App::drawPage() {
    if (loading_) {
        ImGui::TextColored(kDimColor, "Loading %s ...", currentUrl_.c_str());
        return;
    }
    if (failed_) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::SetWindowFontScale(1.4f);
        ImGui::TextColored(kErrorColor, "Cannot open this page");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::TextUnformatted(message_.c_str());
        ImGui::Spacing();
        ImGui::TextColored(kDimColor, "Check that the registry address is right and that the site is running.");
        ImGui::PopTextWrapPos();
        return;
    }
    if (currentUrl_.empty()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::SetWindowFontScale(1.6f);
        ImGui::TextUnformatted("Welcome to Internet");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::TextUnformatted("Press Quick start to run a registry and a sample site on this computer, or type an "
                               "address such as internet://home/ in the bar above.");
        ImGui::PopTextWrapPos();
        return;
    }
    if (binary_) {
        drawBinary();
    } else if (showSource_) {
        ImGui::TextUnformatted(body_.c_str(), body_.c_str() + body_.size());
    } else {
        drawDocument();
    }
}

void App::drawBinary() {
    ImGui::SetWindowFontScale(1.3f);
    ImGui::TextUnformatted("Binary content");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::TextColored(kDimColor, "%s, %zu bytes", contentType_.c_str(), body_.size());
    ImGui::Spacing();
    if (ImGui::Button("Save to downloads folder")) saveDownload();
}

void App::drawDocument() {
    static const float scales[] = {2.0f, 1.6f, 1.35f, 1.15f, 1.05f, 1.0f};
    float unit = ImGui::GetFontSize();
    for (const Block& block : document_.blocks) {
        switch (block.kind) {
            case BlockKind::Rule:
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();
                break;
            case BlockKind::Heading: {
                int index = std::clamp(block.level, 1, 6) - 1;
                ImGui::Spacing();
                drawWords(block, scales[index]);
                ImGui::Spacing();
                break;
            }
            case BlockKind::ListItem: {
                ImVec2 origin = ImGui::GetCursorScreenPos();
                float height = ImGui::GetTextLineHeight();
                ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(origin.x + unit * 0.55f, origin.y + height * 0.5f),
                                                            unit * 0.14f, ImGui::GetColorU32(ImGuiCol_Text));
                ImGui::Indent(unit * 1.4f);
                drawWords(block, 1.0f);
                ImGui::Unindent(unit * 1.4f);
                break;
            }
            case BlockKind::Preformatted: {
                std::string text;
                for (const Span& span : block.spans) text += span.text;
                ImGui::TextUnformatted(text.c_str(), text.c_str() + text.size());
                ImGui::Spacing();
                break;
            }
            case BlockKind::Paragraph:
                drawWords(block, 1.0f);
                ImGui::Dummy(ImVec2(0, unit * 0.4f));
                break;
        }
    }
}

void App::drawWords(const Block& block, float scale) {
    ImGui::SetWindowFontScale(scale);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 2.0f));
    float rightEdge = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
    float space = ImGui::CalcTextSize(" ").x;
    bool first = true;
    bool previousEndedWithSpace = true;

    for (const Span& span : block.spans) {
        bool link = !span.href.empty();
        std::string target = link ? resolveUrl(currentUrl_, span.href) : std::string();
        bool glue = !first && !previousEndedWithSpace && !span.text.empty() && span.text.front() != ' ';
        std::size_t start = 0;
        while (start < span.text.size()) {
            std::size_t end = span.text.find(' ', start);
            if (end == std::string::npos) end = span.text.size();
            if (end == start) {
                ++start;
                continue;
            }
            const char* begin = span.text.c_str() + start;
            const char* finish = span.text.c_str() + end;
            ImVec2 size = ImGui::CalcTextSize(begin, finish);
            if (!first) {
                if (glue) {
                    ImGui::SameLine(0.0f, 0.0f);
                } else if (ImGui::GetItemRectMax().x + space + size.x <= rightEdge) {
                    ImGui::SameLine(0.0f, space);
                }
            }
            glue = false;
            if (link) ImGui::PushStyleColor(ImGuiCol_Text, kLinkColor);
            ImGui::TextUnformatted(begin, finish);
            if (link) {
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered()) {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                    hoveredLink_ = target;
                    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) clickedLink_ = target;
                    ImVec2 min = ImGui::GetItemRectMin();
                    ImVec2 max = ImGui::GetItemRectMax();
                    ImGui::GetWindowDrawList()->AddLine(ImVec2(min.x, max.y), max, ImGui::GetColorU32(kLinkColor));
                }
            }
            first = false;
            start = end + 1;
        }
        previousEndedWithSpace = !span.text.empty() && span.text.back() == ' ';
    }
    ImGui::PopStyleVar();
    ImGui::SetWindowFontScale(1.0f);
}

void App::drawStatusBar() {
    ImGui::Separator();
    if (!hoveredLink_.empty()) {
        ImGui::TextUnformatted(hoveredLink_.c_str());
    } else {
        ImGui::TextColored(kDimColor, "%s", status_.c_str());
    }
}

}
