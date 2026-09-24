#include <algorithm>
#include <cctype>
#include <cmath>

#include "app.hpp"
#include "platform.hpp"
#include "ui.hpp"

namespace internet {

namespace {

const ImVec4 kErrorColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kGoodColor(0.45f, 0.85f, 0.5f, 1.0f);
const ImVec4 kDimColor(0.62f, 0.62f, 0.68f, 1.0f);
const ImVec4 kGold(1.0f, 0.78f, 0.2f, 1.0f);
const ImVec4 kSafe(0.28f, 0.84f, 0.52f, 1.0f);
const ImVec4 kWarn(1.0f, 0.74f, 0.20f, 1.0f);
const ImVec4 kWhite(1.0f, 1.0f, 1.0f, 1.0f);

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

int fuzzyScore(const std::string& query, const std::string& text) {
    if (query.empty()) return 1;
    std::string haystack = lowered(text);
    std::size_t matched = 0;
    int score = 0;
    int streak = 0;
    for (std::size_t i = 0; i < haystack.size() && matched < query.size(); ++i) {
        if (haystack[i] == query[matched]) {
            bool boundary = i == 0 || haystack[i - 1] == ' ' || haystack[i - 1] == '/' || haystack[i - 1] == ':';
            score += 1 + streak * 2 + (boundary ? 5 : 0);
            ++streak;
            ++matched;
        } else {
            streak = 0;
        }
    }
    return matched == query.size() ? score : -1;
}

}

bool App::iconButton(const char* id, Icon icon, const char* tooltip, bool enabled, bool active, ImVec4 tint) {
    float size = ImGui::GetFrameHeight();
    ImVec2 position = ImGui::GetCursorScreenPos();
    ImGui::PushID(id);
    ImGui::BeginDisabled(!enabled);
    bool pressed = ImGui::InvisibleButton("##icon", ImVec2(size, size));
    bool hovered = ImGui::IsItemHovered();
    ImGui::EndDisabled();
    bool tipHovered = ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled);
    ImGui::PopID();

    float& hover = hover_[std::string("icon:") + id];
    approach(hover, (hovered && enabled) ? 1.0f : 0.0f, 14.0f, dt_);

    ImVec4 frame = ImGui::GetStyleColorVec4(ImGuiCol_FrameBg);
    ImVec4 background = mixColor(frame, palette().primary, 0.12f + 0.6f * hover);
    if (active) background = mixColor(background, palette().secondary, 0.55f);
    ImDrawList* list = ImGui::GetWindowDrawList();
    list->AddRectFilled(position, ImVec2(position.x + size, position.y + size), ImGui::GetColorU32(background),
                        size * 0.3f);

    ImVec4 color = tint.w > 0.0f ? tint : kWhite;
    if (!enabled) color = withAlpha(color, 0.3f);
    drawIcon(list, icon, ImVec2(position.x + size * 0.5f, position.y + size * 0.5f), size * 0.55f,
             ImGui::GetColorU32(color));
    if (tipHovered && tooltip && !touch_) ImGui::SetTooltip("%s", tooltip);
    return pressed && enabled;
}

bool App::textButton(const char* id, const char* label, Icon icon, bool primary, float width) {
    float height = ImGui::GetFrameHeight();
    float size = ImGui::GetFontSize();
    float content = textWidth(size, label) + height * 0.9f + size * 0.6f;
    float w = width > 0.0f ? width : content + size * 0.8f;
    ImVec2 position = ImGui::GetCursorScreenPos();
    ImGui::PushID(id);
    bool pressed = ImGui::InvisibleButton("##text", ImVec2(w, height));
    bool hovered = ImGui::IsItemHovered();
    bool held = ImGui::IsItemActive();
    ImGui::PopID();

    float& hover = hover_[std::string("text:") + id];
    approach(hover, hovered ? 1.0f : 0.0f, 14.0f, dt_);
    ImVec4 frame = ImGui::GetStyleColorVec4(ImGuiCol_FrameBg);
    ImVec4 base = primary ? palette().primary : mixColor(frame, palette().primary, 0.22f);
    ImVec4 fill = mixColor(base, primary ? palette().secondary : palette().primary, 0.55f * hover);
    if (held) fill = mixColor(fill, kWhite, 0.12f);
    ImDrawList* list = ImGui::GetWindowDrawList();
    list->AddRectFilled(position, ImVec2(position.x + w, position.y + height), ImGui::GetColorU32(fill), height * 0.3f);

    float startX = position.x + (w - content) * 0.5f;
    drawIcon(list, icon, ImVec2(startX + height * 0.35f, position.y + height * 0.5f), height * 0.5f,
             ImGui::GetColorU32(kWhite));
    drawText(list, size, ImVec2(startX + height * 0.9f, position.y + (height - size) * 0.5f),
             ImGui::GetColorU32(kWhite), label);
    return pressed;
}

void App::drawBrand() {
    float unit = ImGui::GetFontSize();
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 position = ImGui::GetCursorScreenPos();
    float radius = unit * 1.15f;
    ImVec2 center(position.x + radius + unit * 0.3f, position.y + radius + unit * 0.2f);
    float animTime = settings_.animations ? static_cast<float>(time_) : 0.0f;
    const Palette& colors = palette();
    drawGlobe(list, center, radius, animTime, packColor(ImVec4(0.96f, 0.97f, 1.0f, 0.95f)),
              packColor(withAlpha(colors.primary, 0.35f)), packColor(colors.secondary), 0.0f);
    float textX = center.x + radius + unit * 0.7f;
    drawText(list, unit * 1.5f, ImVec2(textX, position.y + unit * 0.15f), packColor(ImVec4(0.96f, 0.97f, 1.0f, 1.0f)),
             "Internet");
    drawText(list, unit * 0.82f, ImVec2(textX, position.y + unit * 1.85f),
             packColor(mixColor(colors.primary, kWhite, 0.4f)), "your own network");
    ImGui::Dummy(ImVec2(ImGui::GetContentRegionAvail().x, radius * 2.0f + unit * 0.6f));
}

void App::drawAppearance() {
    float unit = ImGui::GetFontSize();
    float width = ImGui::GetContentRegionAvail().x;
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImGui::TextColored(kDimColor, "Accent colors");
    for (int i = 0; i < paletteCount(); ++i) {
        ImGui::PushID(i);
        float size = unit * 1.8f;
        ImVec2 position = ImGui::GetCursorScreenPos();
        if (ImGui::InvisibleButton("swatch", ImVec2(size, size))) setPalette(i);
        bool hovered = ImGui::IsItemHovered();
        const Palette& swatch = paletteAt(i);
        ImVec2 center(position.x + size * 0.5f, position.y + size * 0.5f);
        list->AddCircleFilled(center, size * (hovered ? 0.44f : 0.4f), packColor(swatch.primary), 24);
        list->AddCircleFilled(center, size * 0.2f, packColor(swatch.secondary), 16);
        if (settings_.palette == i) list->AddCircle(center, size * 0.5f, packColor(kWhite), 24, 2.0f);
        if (hovered && !touch_) ImGui::SetTooltip("%s", swatch.name);
        ImGui::PopID();
        ImGui::SameLine();
    }
    ImGui::NewLine();
    if (ImGui::Checkbox("Show intro on start", &settings_.intro)) settingsDirty_ = true;
    if (ImGui::Checkbox("Animated backgrounds", &settings_.animations)) settingsDirty_ = true;
    float percent = settings_.zoom * 100.0f;
    ImGui::SetNextItemWidth(-1);
    if (ImGui::SliderFloat("##zoom", &percent, 60.0f, 250.0f, "Page zoom %.0f%%")) setZoom(percent / 100.0f);
    if (ImGui::Button("Replay intro", ImVec2(width, 0))) {
        splash_ = true;
        splashStart_ = -1.0;
    }
    if (ImGui::Button("Clear history", ImVec2(width, 0))) {
        recent_.clear();
        settingsDirty_ = true;
        toast("History cleared");
    }
    if (ImGui::Button("Clear bookmarks", ImVec2(width, 0))) {
        bookmarks_.clear();
        settingsDirty_ = true;
        toast("Bookmarks cleared");
    }
}

void App::drawSidebar() {
    touchScroll();
    float width = ImGui::GetContentRegionAvail().x;
    const Palette& colors = palette();
    drawBrand();

    ImGui::PushStyleColor(ImGuiCol_Button, colors.primary);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, mixColor(colors.primary, colors.secondary, 0.6f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, colors.secondary);
    if (ImGui::Button("Quick start", ImVec2(width, ImGui::GetFrameHeight() * 1.2f))) quickStart();
    ImGui::PopStyleColor(3);
    if (ImGui::IsItemHovered() && !touch_) {
        ImGui::SetTooltip("Start a local registry, host a sample site and open it");
    }

    float spacing = ImGui::GetStyle().ItemSpacing.x;
    float third = (width - spacing * 2.0f) / 3.0f;
    if (textButton("side-edit", editor_ ? "Close" : "Edit", Icon::Pencil, false, third)) {
        if (editor_) {
            closeEditor();
        } else {
            openEditor();
        }
        menuOpen_ = false;
    }
    ImGui::SameLine();
    if (textButton("side-share", "Share", Icon::Share, false, third)) shareCurrent();
    ImGui::SameLine();
    if (textButton("side-palette", "Search", Icon::Command, false, third)) {
        paletteOpen_ = true;
        paletteFocus_ = true;
        paletteQuery_[0] = '\0';
        paletteIndex_ = 0;
        menuOpen_ = false;
    }
    {
        SecurityState securityStateNow = securityState();
        ImVec4 tint = stateColor(securityStateNow);
        std::string label = std::string("Security: ") + (securityStateNow == SecurityState::Protected ? "protected"
                                                          : securityStateNow == SecurityState::Scanning ? "scanning"
                                                          : securityStateNow == SecurityState::Danger   ? "threats found"
                                                                                                       : "needs attention");
        ImVec4 frameColor = ImGui::GetStyleColorVec4(ImGuiCol_FrameBg);
        ImGui::PushStyleColor(ImGuiCol_Button, mixColor(frameColor, tint, 0.45f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, mixColor(frameColor, tint, 0.7f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, tint);
        if (ImGui::Button(label.c_str(), ImVec2(width, 0))) openSecurity();
        ImGui::PopStyleColor(3);
    }
    if (compact_) ImGui::Checkbox("Show page source", &showSource_);
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
            if (ImGui::Button("Copy link", ImVec2(width, 0))) {
                ImGui::SetClipboardText(("internet://" + node_->name() + "/").c_str());
                toast("Link copied");
            }
            ImGui::TextColored(node_->registered() ? kGoodColor : kErrorColor,
                               node_->registered() ? "Registered" : "Waiting for registry");
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
        ImDrawList* list = ImGui::GetWindowDrawList();
        for (const NodeInfo& info : nodes_) {
            ImVec2 position = ImGui::GetCursorScreenPos();
            float line = ImGui::GetTextLineHeight();
            list->AddCircleFilled(ImVec2(position.x + line * 0.55f, position.y + line * 0.5f), line * 0.34f,
                                  packColor(avatarColor(info.name)), 16);
            ImGui::Indent(line * 1.5f);
            std::string label = info.name + "##" + formatEndpoint(info.endpoint);
            if (ImGui::Selectable(label.c_str())) clickedLink_ = "internet://" + info.name + "/";
            if (ImGui::IsItemHovered() && !touch_) ImGui::SetTooltip("%s", formatEndpoint(info.endpoint).c_str());
            ImGui::Unindent(line * 1.5f);
        }
    }

    std::string bookmarkLabel = "Bookmarks (" + std::to_string(bookmarks_.size()) + ")###bookmarks";
    if (ImGui::CollapsingHeader(bookmarkLabel.c_str())) {
        if (bookmarks_.empty()) ImGui::TextColored(kDimColor, "Press the star to save a page");
        for (const Entry& entry : bookmarks_) {
            std::string label = fitText(entry.title.empty() ? entry.url : entry.title, ImGui::GetFontSize(),
                                        width - ImGui::GetFontSize() * 1.5f) +
                                "##" + entry.url;
            if (ImGui::Selectable(label.c_str())) clickedLink_ = entry.url;
        }
    }

    if (ImGui::CollapsingHeader("Appearance")) drawAppearance();

    if (ImGui::CollapsingHeader("Shortcuts")) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(kDimColor,
                           "Ctrl+K  command palette\nCtrl+T  new tab\nCtrl+W  close tab\nCtrl+E  site editor\n"
                           "Ctrl+S  save file\nCtrl+B  sidebar\nCtrl+L  address bar\nCtrl+F  find in page\n"
                           "Ctrl+D  bookmark\nCtrl+H  home\nF5  reload\nAlt+Left/Right  back and forward\n"
                           "Ctrl +/-/0  zoom");
        ImGui::PopTextWrapPos();
    }
}

void App::drawTabBar() {
    float unit = ImGui::GetFontSize();
    float height = ImGui::GetFrameHeight();
    float spacing = ImGui::GetStyle().ItemSpacing.x;
    float available = ImGui::GetContentRegionAvail().x - height - spacing;
    int count = static_cast<int>(tabs_.size());
    float tabWidth = std::clamp((available - spacing * static_cast<float>(count - 1)) / static_cast<float>(count),
                                unit * 5.0f, unit * 13.0f);
    const Palette& colors = palette();
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 mouse = ImGui::GetIO().MousePos;
    int closeRequest = -1;
    int switchRequest = -1;

    for (int i = 0; i < count; ++i) {
        if (i > 0) ImGui::SameLine();
        ImGui::PushID(i);
        ImVec2 position = ImGui::GetCursorScreenPos();
        bool pressed = ImGui::InvisibleButton("##tab", ImVec2(tabWidth, height));
        bool hovered = ImGui::IsItemHovered();
        bool middle = hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Middle);
        ImGui::PopID();

        bool active = i == activeTab_;
        float& hover = hover_["tab:" + std::to_string(i)];
        approach(hover, (hovered || active) ? 1.0f : 0.0f, 14.0f, dt_);
        ImVec2 max(position.x + tabWidth, position.y + height);
        ImVec4 frame = ImGui::GetStyleColorVec4(ImGuiCol_ChildBg);
        ImVec4 fill = mixColor(frame, colors.primary, active ? 0.4f : 0.12f * hover);
        list->AddRectFilled(position, max, packColor(fill), height * 0.3f, ImDrawFlags_RoundCornersTop);
        if (active) {
            list->AddRectFilled(ImVec2(position.x + unit * 0.5f, position.y), ImVec2(max.x - unit * 0.5f, position.y + 3.0f),
                                packColor(colors.secondary), 2.0f);
        }

        std::string title = tabTitle(i);
        bool showClose = count > 1 && (hovered || active);
        float textLimit = tabWidth - unit * (showClose ? 3.2f : 1.6f);
        drawText(list, unit, ImVec2(position.x + unit * 0.8f, position.y + (height - unit) * 0.5f),
                 packColor(active ? kWhite : ImVec4(0.75f, 0.77f, 0.85f, 1.0f)), fitText(title, unit, textLimit).c_str());

        ImVec2 closeMin(max.x - unit * 2.0f, position.y);
        bool overClose = showClose && mouse.x >= closeMin.x && mouse.x <= max.x && mouse.y >= position.y && mouse.y <= max.y;
        if (showClose) {
            drawIcon(list, Icon::Close, ImVec2(max.x - unit * 1.1f, position.y + height * 0.5f), unit * 0.9f,
                     overClose ? IM_COL32(255, 120, 120, 255) : packColor(withAlpha(kWhite, 0.6f)));
        }
        if (middle) {
            closeRequest = i;
        } else if (pressed) {
            if (overClose) {
                closeRequest = i;
            } else {
                switchRequest = i;
            }
        }
    }

    ImGui::SameLine();
    if (iconButton("newtab", Icon::Plus, "New tab (Ctrl+T)")) newTab();
    if (closeRequest >= 0) {
        closeTab(closeRequest);
    } else if (switchRequest >= 0) {
        switchTab(switchRequest);
    }
}

void App::drawToolbar(bool compact) {
    float unit = ImGui::GetFontSize();
    float frame = ImGui::GetFrameHeight();
    float spacing = ImGui::GetStyle().ItemSpacing.x;
    bool page = !home_ && !editor_ && !currentUrl_.empty();
    bool bookmarked = page && isBookmarked(currentUrl_);

    if (compact) {
        if (iconButton("menu", Icon::Menu, "Menu", true, menuOpen_)) menuOpen_ = !menuOpen_;
        ImGui::SameLine();
    } else {
        if (iconButton("panel", Icon::Panel, "Toggle sidebar (Ctrl+B)", true, sidebarOpen_)) sidebarOpen_ = !sidebarOpen_;
        ImGui::SameLine();
    }
    if (iconButton("back", Icon::Back, "Back (Alt+Left)", position_ > 0 && !home_)) goBack();
    ImGui::SameLine();
    if (iconButton("forward", Icon::Forward, "Forward (Alt+Right)", position_ + 1 < static_cast<int>(history_.size())))
        goForward();
    ImGui::SameLine();
    if (iconButton("reload", Icon::Reload, "Reload (F5)", page)) reload();
    ImGui::SameLine();
    if (iconButton("home", Icon::Home, "Home (Ctrl+H)", true, home_ && !editor_)) goHome();

    if (compact) {
        ImGui::SameLine();
        if (iconButton("star", bookmarked ? Icon::StarFilled : Icon::Star, "Bookmark this page", page, bookmarked,
                       bookmarked ? kGold : ImVec4(0, 0, 0, 0)))
            toggleBookmark();
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - unit * 3.6f);
    } else {
        ImGui::SameLine();
        float reserve = 6.0f * (frame + spacing) + unit * 6.4f;
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - reserve);
    }

    if (focusAddress_) {
        ImGui::SetKeyboardFocusHere();
        focusAddress_ = false;
    }
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, frame * 0.5f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(frame * 0.45f, ImGui::GetStyle().FramePadding.y));
    bool submitted = ImGui::InputTextWithHint("##address", "Type an address, e.g. internet://home/", address_,
                                              sizeof address_,
                                              ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
    ImGui::PopStyleVar(2);

    if (compact) {
        ImGui::SameLine();
        if (ImGui::Button("Go")) submitted = true;
    } else {
        ImGui::SameLine();
        SecurityState securityStateNow = securityState();
        if (iconButton("shield", Icon::Shield, "Security Center (Ctrl+J)", true, securityView_, stateColor(securityStateNow))) {
            if (securityView_) {
                closeSecurity();
            } else {
                openSecurity();
            }
        }
        ImGui::SameLine();
        if (iconButton("star", bookmarked ? Icon::StarFilled : Icon::Star, "Bookmark this page (Ctrl+D)", page,
                       bookmarked, bookmarked ? kGold : ImVec4(0, 0, 0, 0)))
            toggleBookmark();
        ImGui::SameLine();
        if (iconButton("share", Icon::Share, "Share or copy the link")) shareCurrent();
        ImGui::SameLine();
        if (iconButton("find", Icon::Search, "Find in page (Ctrl+F)", page && !binary_, findOpen_)) {
            findOpen_ = !findOpen_;
            focusFind_ = findOpen_;
        }
        ImGui::SameLine();
        if (iconButton("edit", Icon::Pencil, "Edit your site (Ctrl+E)", true, editor_)) {
            if (editor_) {
                closeEditor();
            } else {
                openEditor();
            }
        }
        ImGui::SameLine();
        if (iconButton("palette", Icon::Command, "Command palette (Ctrl+K)", true, paletteOpen_)) {
            paletteOpen_ = true;
            paletteFocus_ = true;
            paletteQuery_[0] = '\0';
            paletteIndex_ = 0;
        }
        ImGui::SameLine();
        ImGui::Checkbox("Source", &showSource_);
    }
    if (submitted) {
        editor_ = false;
        securityView_ = false;
        navigate(address_);
    }

    ImVec2 position = ImGui::GetCursorScreenPos();
    float width = ImGui::GetContentRegionAvail().x;
    float thickness = std::max(2.0f, unit * 0.16f);
    ImDrawList* list = ImGui::GetWindowDrawList();
    list->AddRectFilled(position, ImVec2(position.x + width, position.y + thickness),
                        packColor(withAlpha(palette().primary, 0.14f)), thickness * 0.5f);
    if (loading_) {
        float segment = width * 0.32f;
        float phase = std::fmod(static_cast<float>(time_) * 0.9f, 1.0f);
        float start = position.x - segment + (width + segment) * phase;
        float left = std::max(start, position.x);
        float right = std::min(start + segment, position.x + width);
        if (right > left) {
            list->AddRectFilled(ImVec2(left, position.y), ImVec2(right, position.y + thickness),
                                packColor(palette().secondary), thickness * 0.5f);
        }
    }
    ImGui::Dummy(ImVec2(width, thickness + 2.0f));

    if (findOpen_ && page && !binary_) drawFindBar();
}

void App::drawFindBar() {
    float unit = ImGui::GetFontSize();
    ImGui::SetNextItemWidth(unit * 14.0f);
    if (focusFind_) {
        ImGui::SetKeyboardFocusHere();
        focusFind_ = false;
    }
    ImGui::InputTextWithHint("##find", "Find in page", find_, sizeof find_);
    ImGui::SameLine();
    if (find_[0] != '\0') {
        ImGui::TextColored(matchesShown_ > 0 ? kGoodColor : kErrorColor, "%d match%s", matchesShown_,
                           matchesShown_ == 1 ? "" : "es");
    } else {
        ImGui::TextColored(kDimColor, "Type to highlight words");
    }
    ImGui::SameLine();
    if (iconButton("findclose", Icon::Close, "Close (Esc)")) findOpen_ = false;
}

void App::drawStatusBar() {
    ImGui::Separator();
    ImVec2 start = ImGui::GetCursorScreenPos();
    float right = start.x + ImGui::GetContentRegionAvail().x;
    float size = ImGui::GetFontSize();
    bool online = nodesMessage_.empty();
    std::string pill = online ? "Registry online - " + std::to_string(nodes_.size()) +
                                    (nodes_.size() == 1 ? " site" : " sites")
                              : std::string("Registry offline");
    if (std::fabs(settings_.zoom - 1.0f) > 0.01f)
        pill += "  |  " + std::to_string(static_cast<int>(std::round(settings_.zoom * 100.0f))) + "%";
    if (tabs_.size() > 1) pill += "  |  " + std::to_string(tabs_.size()) + " tabs";
    float pillWidth = textWidth(size, pill) + size * 1.5f;

    std::string left = !hoveredLink_.empty() ? hoveredLink_ : status_;
    float available = std::max(0.0f, right - start.x - pillWidth - size);
    std::string fitted = fitText(left, size, available);
    if (!hoveredLink_.empty()) {
        ImGui::TextUnformatted(fitted.c_str());
    } else {
        ImGui::TextColored(kDimColor, "%s", fitted.c_str());
    }

    ImDrawList* list = ImGui::GetWindowDrawList();
    float pulse = online ? 0.5f + 0.5f * std::sin(static_cast<float>(time_) * 3.0f) : 0.0f;
    ImVec4 dot = online ? kGoodColor : kErrorColor;
    ImVec2 center(right - pillWidth + size * 0.45f, start.y + size * 0.55f);
    if (online && settings_.animations)
        list->AddCircleFilled(center, size * (0.3f + 0.25f * pulse), packColor(withAlpha(dot, 0.25f * (1.0f - pulse))), 16);
    list->AddCircleFilled(center, size * 0.26f, packColor(dot), 16);
    drawText(list, size, ImVec2(right - pillWidth + size * 1.0f, start.y), packColor(ImVec4(0.7f, 0.72f, 0.8f, 1.0f)),
             pill.c_str());
}

std::vector<PaletteItem> App::buildPaletteItems() {
    const Palette& colors = palette();
    std::vector<PaletteItem> items;
    auto add = [&](const std::string& label, const std::string& hint, Icon icon, const ImVec4& tint,
                   std::function<void()> run) { items.push_back(PaletteItem{label, hint, icon, tint, std::move(run), 0}); };

    add("New tab", "Ctrl+T", Icon::Plus, colors.primary, [this] { newTab(); });
    add("Go home", "Ctrl+H", Icon::Home, colors.secondary, [this] { goHome(); });
    add("Quick start", "Registry and sample site", Icon::Play, colors.primary, [this] { quickStart(); });
    add(editor_ ? "Close the site editor" : "Edit your site", "Ctrl+E", Icon::Pencil, colors.secondary, [this] {
        if (editor_) {
            closeEditor();
        } else {
            openEditor();
        }
    });
    add(node_ ? "Stop hosting" : "Host a site", "Serve your folder", Icon::Server, colors.primary, [this] { hostSite(); });
    add(registry_ ? "Stop the local registry" : "Start a local registry", "Port " + std::to_string(registryPort_),
        Icon::Globe, colors.secondary, [this] {
            if (registry_) {
                stopRegistry();
            } else {
                startRegistry();
            }
        });
    add("Share the current link", "Send it to someone", Icon::Share, colors.primary, [this] { shareCurrent(); });
    add("Open the Security Center", "Ctrl+J", Icon::Shield, kSafe, [this] { openSecurity(); });
    add("Quick scan", "Site folder and downloads", Icon::Search, kSafe, [this] {
        std::vector<std::filesystem::path> roots = {std::filesystem::path(nodeFolder_)};
        std::error_code error;
        if (std::filesystem::exists(dataDir_ / "downloads", error)) roots.push_back(dataDir_ / "downloads");
        startScan(roots, "site folder and downloads");
        openSecurity(1);
    });
    add(security_->settings().realtime ? "Turn real-time protection off" : "Turn real-time protection on", "Security", Icon::Shield, kWarn,
        [this] {
            SecuritySettings settings = security_->settings();
            settings.realtime = !settings.realtime;
            security_->setSettings(settings);
            toast(settings.realtime ? "Real-time protection is on" : "Real-time protection is off",
                  settings.realtime ? ToastKind::Success : ToastKind::Warning);
        });
    if (!home_ && !editor_ && !currentUrl_.empty()) {
        add(isBookmarked(currentUrl_) ? "Remove bookmark" : "Bookmark this page", "Ctrl+D", Icon::Star, kGold,
            [this] { toggleBookmark(); });
        add("Reload the page", "F5", Icon::Reload, colors.secondary, [this] { reload(); });
        add("Find in page", "Ctrl+F", Icon::Search, colors.primary, [this] {
            findOpen_ = true;
            focusFind_ = true;
        });
    }
    add(sidebarOpen_ ? "Hide the sidebar" : "Show the sidebar", "Ctrl+B", Icon::Panel, colors.secondary,
        [this] { sidebarOpen_ = !sidebarOpen_; });
    add("Zoom in", "Ctrl +", Icon::Search, colors.primary, [this] { setZoom(settings_.zoom + 0.1f); });
    add("Zoom out", "Ctrl -", Icon::Search, colors.primary, [this] { setZoom(settings_.zoom - 0.1f); });
    add("Reset zoom", "Ctrl 0", Icon::Search, colors.primary, [this] { setZoom(1.0f); });
    add("Replay the intro", "", Icon::Play, colors.secondary, [this] {
        splash_ = true;
        splashStart_ = -1.0;
    });
    for (int i = 0; i < paletteCount(); ++i) {
        add(std::string("Theme: ") + paletteAt(i).name, "Accent colors", Icon::Sliders, paletteAt(i).primary,
            [this, i] { setPalette(i); });
    }
    add("Clear history", "", Icon::Trash, colors.secondary, [this] {
        recent_.clear();
        settingsDirty_ = true;
        toast("History cleared");
    });

    for (const NodeInfo& info : nodes_) {
        std::string url = "internet://" + info.name + "/";
        add("Open " + url, formatEndpoint(info.endpoint), Icon::Globe, avatarColor(info.name),
            [this, url] { clickedLink_ = url; });
    }
    for (const Entry& entry : bookmarks_) {
        std::string url = entry.url;
        add("Bookmark: " + (entry.title.empty() ? entry.url : entry.title), entry.url, Icon::StarFilled, kGold,
            [this, url] { clickedLink_ = url; });
    }
    for (std::size_t i = 0; i < std::min<std::size_t>(recent_.size(), 8); ++i) {
        std::string url = recent_[i].url;
        add("Recent: " + (recent_[i].title.empty() ? url : recent_[i].title), url, Icon::Clock, avatarColor(url),
            [this, url] { clickedLink_ = url; });
    }
    if (editor_) {
        for (const SiteFile& file : ed_.files) {
            if (file.directory || !isTextPath(file.path)) continue;
            std::string path = file.path;
            add("Edit file: " + path, ed_.siteName, Icon::File, colors.secondary,
                [this, path] { editorOpenFile(path, false); });
        }
    }

    return items;
}

void App::drawPalette() {
    if (paletteAnim_ < 0.01f && !paletteOpen_) return;

    ImGuiIO& io = ImGui::GetIO();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImDrawList* overlay = ImGui::GetForegroundDrawList();
    float unit = ImGui::GetFontSize();
    float anim = easeOutCubic(paletteAnim_);
    ImVec2 min = viewport->WorkPos;
    ImVec2 max(min.x + viewport->WorkSize.x, min.y + viewport->WorkSize.y);
    overlay->AddRectFilled(min, max, IM_COL32(4, 6, 14, static_cast<int>(170.0f * anim)));

    float width = std::min(unit * 38.0f, viewport->WorkSize.x - unit * 2.0f);
    float height = std::min(unit * 28.0f, viewport->WorkSize.y * 0.75f);
    ImVec2 position(min.x + (viewport->WorkSize.x - width) * 0.5f, min.y + viewport->WorkSize.y * 0.1f - (1.0f - anim) * unit);
    ImGui::SetNextWindowPos(position);
    ImGui::SetNextWindowSize(ImVec2(width, height));
    ImGui::SetNextWindowFocus();
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, anim);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, unit * 0.9f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(unit * 0.8f, unit * 0.8f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.5f);
    ImGui::PushStyleColor(ImGuiCol_Border, palette().primary);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.07f, 0.08f, 0.13f, 0.98f));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                             ImGuiWindowFlags_NoNav;
    bool run = false;
    std::function<void()> action;
    if (ImGui::Begin("##palette", nullptr, flags)) {
        if (paletteFocus_) {
            ImGui::SetKeyboardFocusHere();
            paletteFocus_ = false;
        }
        ImGui::SetNextItemWidth(-1);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, unit * 0.6f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(unit * 0.8f, unit * 0.55f));
        bool entered = ImGui::InputTextWithHint("##paletteQuery", "Type a command, a site, a bookmark or an address",
                                                paletteQuery_, sizeof paletteQuery_, ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopStyleVar(2);

        std::string query = lowered(paletteQuery_);
        std::vector<PaletteItem> items = buildPaletteItems();
        std::string typed(paletteQuery_);
        if (typed.find("://") != std::string::npos) {
            items.insert(items.begin(), PaletteItem{"Go to " + typed, "Open this address", Icon::Globe, palette().secondary,
                                                    [this, typed] { clickedLink_ = typed; }, 0});
        }
        for (PaletteItem& item : items) item.score = fuzzyScore(query, item.label + " " + item.hint);
        items.erase(std::remove_if(items.begin(), items.end(), [](const PaletteItem& item) { return item.score < 0; }),
                    items.end());
        if (!query.empty()) {
            std::stable_sort(items.begin(), items.end(),
                             [](const PaletteItem& a, const PaletteItem& b) { return a.score > b.score; });
        }
        if (items.size() > 40) items.resize(40);

        int count = static_cast<int>(items.size());
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) paletteIndex_ = std::min(paletteIndex_ + 1, count - 1);
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) paletteIndex_ = std::max(paletteIndex_ - 1, 0);
        paletteIndex_ = std::clamp(paletteIndex_, 0, std::max(0, count - 1));
        if (entered && count > 0) {
            run = true;
            action = items[static_cast<std::size_t>(paletteIndex_)].run;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) paletteOpen_ = false;

        ImGui::Spacing();
        ImGui::BeginChild("##paletteList", ImVec2(0, 0), ImGuiChildFlags_None);
        touchScroll();
        ImDrawList* list = ImGui::GetWindowDrawList();
        float rowHeight = unit * 2.7f;
        for (int i = 0; i < count; ++i) {
            const PaletteItem& item = items[static_cast<std::size_t>(i)];
            ImGui::PushID(i);
            ImVec2 rowMin = ImGui::GetCursorScreenPos();
            float rowWidth = ImGui::GetContentRegionAvail().x;
            bool pressed = ImGui::InvisibleButton("##row", ImVec2(rowWidth, rowHeight));
            bool hovered = ImGui::IsItemHovered();
            ImGui::PopID();
            if (hovered && ImGui::GetIO().MouseDelta.x != 0.0f) paletteIndex_ = i;
            bool selected = i == paletteIndex_;
            if (selected) {
                list->AddRectFilled(rowMin, ImVec2(rowMin.x + rowWidth, rowMin.y + rowHeight),
                                    packColor(withAlpha(palette().primary, 0.35f)), unit * 0.5f);
                ImGui::SetScrollHereY(0.5f);
            }
            ImVec2 badge(rowMin.x + unit * 1.5f, rowMin.y + rowHeight * 0.5f);
            list->AddCircleFilled(badge, unit * 0.95f, packColor(item.tint), 20);
            drawIcon(list, item.icon, badge, unit * 1.1f, IM_COL32(255, 255, 255, 255));
            float hintWidth = item.hint.empty() ? 0.0f : std::min(textWidth(unit * 0.85f, item.hint), rowWidth * 0.4f);
            float labelLimit = rowWidth - unit * 3.6f - hintWidth - unit;
            drawText(list, unit, ImVec2(rowMin.x + unit * 3.0f, rowMin.y + (rowHeight - unit) * 0.5f),
                     IM_COL32(255, 255, 255, 255), fitText(item.label, unit, labelLimit).c_str());
            if (!item.hint.empty()) {
                std::string hint = fitText(item.hint, unit * 0.85f, hintWidth);
                drawText(list, unit * 0.85f, ImVec2(rowMin.x + rowWidth - hintWidth - unit * 0.6f, rowMin.y + (rowHeight - unit * 0.85f) * 0.5f),
                         packColor(kDimColor), hint.c_str());
            }
            if (pressed) {
                run = true;
                action = item.run;
            }
        }
        if (count == 0) ImGui::TextColored(kDimColor, "Nothing matches. Type an internet:// address to open it.");
        (void)io;
        ImGui::EndChild();
    }
    ImGui::End();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(4);

    if (run && action) {
        paletteOpen_ = false;
        action();
    }
}

}
