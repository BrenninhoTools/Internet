#include <algorithm>
#include <cctype>
#include <cmath>
#include <ctime>

#include "app.hpp"

namespace internet {

namespace {

const ImVec4 kWhite(1.0f, 1.0f, 1.0f, 1.0f);
const ImVec4 kDim(0.62f, 0.64f, 0.72f, 1.0f);
const ImVec4 kGold(1.0f, 0.78f, 0.2f, 1.0f);
const ImVec4 kAmber(0.98f, 0.70f, 0.15f, 1.0f);
const ImVec4 kRose(0.93f, 0.30f, 0.55f, 1.0f);
const ImVec4 kNavy(0.03f, 0.04f, 0.09f, 1.0f);

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string greeting() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    if (local.tm_hour < 5) return "Good night";
    if (local.tm_hour < 12) return "Good morning";
    if (local.tm_hour < 18) return "Good afternoon";
    return "Good evening";
}

ImU32 color(const ImVec4& value, float alpha) { return packColor(withAlpha(value, value.w * clamp01(alpha))); }

}

App::CardState App::card(const std::string& id, ImVec2 size, const ImVec4& tint, bool selected) {
    float unit = ImGui::GetFontSize();
    ImVec2 position = ImGui::GetCursorScreenPos();
    ImGui::PushID(id.c_str());
    bool clicked = ImGui::InvisibleButton("##card", size);
    bool hovered = ImGui::IsItemHovered();
    bool held = ImGui::IsItemActive();
    ImGui::PopID();

    float& hover = hover_["card:" + id];
    approach(hover, (hovered || selected) ? 1.0f : 0.0f, 12.0f, dt_);
    float lift = unit * 0.22f * hover - (held ? unit * 0.1f : 0.0f);
    ImVec2 min(position.x, position.y - lift);
    ImVec2 max(position.x + size.x, position.y + size.y - lift);
    float rounding = unit * 0.7f;

    ImDrawList* list = ImGui::GetWindowDrawList();
    list->AddRectFilled(ImVec2(min.x + 3.0f, min.y + unit * 0.3f), ImVec2(max.x - 3.0f, max.y + unit * 0.3f),
                        IM_COL32(0, 0, 0, static_cast<int>(45 + 70 * hover)), rounding);
    ImVec4 panel = ImGui::GetStyleColorVec4(ImGuiCol_ChildBg);
    ImVec4 fill = mixColor(mixColor(panel, kWhite, 0.05f), tint, 0.14f + 0.22f * hover);
    list->AddRectFilled(min, max, packColor(fill), rounding);
    list->AddRect(min, max, packColor(withAlpha(tint, 0.3f + 0.7f * hover)), rounding, ImDrawFlags_None, 1.5f);
    return CardState{clicked, min, max, hover};
}

void App::sectionTitle(const char* text, const ImVec4& tint) {
    float unit = ImGui::GetFontSize();
    ImVec2 position = ImGui::GetCursorScreenPos();
    ImDrawList* list = ImGui::GetWindowDrawList();
    list->AddRectFilled(ImVec2(position.x, position.y + unit * 0.1f), ImVec2(position.x + unit * 0.28f, position.y + unit * 1.5f),
                        packColor(tint), 3.0f);
    ImGui::SetCursorScreenPos(ImVec2(position.x + unit * 0.75f, position.y));
    pushTextScale(1.25f);
    ImGui::TextUnformatted(text);
    popTextScale(1.0f);
    ImGui::Spacing();
}

void App::drawHome() {
    if (homeSince_ < 0.0) homeSince_ = time_;
    float unit = ImGui::GetFontSize();
    float width = ImGui::GetContentRegionAvail().x;
    float age = static_cast<float>(time_ - homeSince_);

    drawHero(width, compact_);
    ImGui::Dummy(ImVec2(0, unit * 0.3f));

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, smoothStep((age - 0.2f) / 0.5f));
    float frame = ImGui::GetFrameHeight();
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, frame * 0.5f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(frame * 0.5f, ImGui::GetStyle().FramePadding.y));
    ImGui::SetNextItemWidth(width - unit * 6.4f);
    if (focusSearch_) {
        ImGui::SetKeyboardFocusHere();
        focusSearch_ = false;
    }
    bool submitted = ImGui::InputTextWithHint("##search", "Search sites or type internet://name/path", search_,
                                              sizeof search_, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, palette().primary);
    if (ImGui::Button("Search", ImVec2(unit * 5.6f, 0))) submitted = true;
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
    if (submitted) submitSearch();
    ImGui::PopStyleVar();
    ImGui::Dummy(ImVec2(0, unit * 0.5f));

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, smoothStep((age - 0.35f) / 0.5f));
    drawActions(width);
    ImGui::PopStyleVar();

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, smoothStep((age - 0.5f) / 0.5f));
    drawNodeCards(width);
    ImGui::PopStyleVar();

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, smoothStep((age - 0.65f) / 0.5f));
    drawBookmarkCards(width);
    drawRecentChips(width);
    ImGui::PopStyleVar();
    ImGui::Dummy(ImVec2(0, unit * 2.0f));
}

void App::drawHero(float width, bool compact) {
    float unit = ImGui::GetFontSize();
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 position = ImGui::GetCursorScreenPos();
    float height = unit * 9.4f;
    ImVec2 max(position.x + width, position.y + height);
    const Palette& colors = palette();
    float age = static_cast<float>(time_ - homeSince_);
    float time = settings_.animations ? static_cast<float>(time_) : 0.0f;

    float shift = 0.5f + 0.5f * std::sin(time * 0.5f);
    ImVec4 left = mixColor(colors.primary, colors.secondary, shift * 0.5f);
    ImVec4 right = mixColor(colors.secondary, colors.primary, shift * 0.5f);
    left = mixColor(kNavy, left, 0.62f);
    right = mixColor(kNavy, right, 0.55f);

    const int strips = 36;
    for (int i = 0; i < strips; ++i) {
        float t0 = static_cast<float>(i) / strips;
        float t1 = static_cast<float>(i + 1) / strips;
        ImDrawFlags flags = ImDrawFlags_RoundCornersNone;
        if (i == 0) flags = ImDrawFlags_RoundCornersLeft;
        if (i == strips - 1) flags = ImDrawFlags_RoundCornersRight;
        list->AddRectFilled(ImVec2(position.x + width * t0 - (i > 0 ? 0.6f : 0.0f), position.y),
                            ImVec2(position.x + width * t1 + (i < strips - 1 ? 0.6f : 0.0f), max.y),
                            packColor(mixColor(left, right, (t0 + t1) * 0.5f)), unit * 1.0f, flags);
    }

    list->PushClipRect(position, max, true);
    if (settings_.animations) {
        particles_.draw(list, position, ImVec2(width, height), IM_COL32(255, 255, 255, 255), unit * 7.0f, 0.45f);
    }
    if (!compact) {
        drawGlobe(list, ImVec2(max.x - unit * 6.6f, position.y + height * 0.5f), unit * 3.0f, time * 1.1f,
                  IM_COL32(255, 255, 255, 230), IM_COL32(255, 255, 255, 34), packColor(kAmber), 1.0f);
    }
    list->PopClipRect();

    float enter = easeOutCubic(age / 0.8f);
    float slide = (1.0f - enter) * unit * 1.2f;
    float textLimit = compact ? width - unit * 3.0f : width - unit * 15.0f;
    drawText(list, unit * 0.95f, ImVec2(position.x + unit * 1.7f, position.y + unit * 0.55f + slide),
             color(ImVec4(0.92f, 0.94f, 1.0f, 0.75f), enter), greeting().c_str());
    drawText(list, unit * 3.3f, ImVec2(position.x + unit * 1.6f, position.y + unit * 1.6f + slide),
                  color(kWhite, enter), "Internet");
    std::string tagline = fitText("Browse, host and share sites on your own network.", unit * 1.05f, textLimit);
    drawText(list, unit * 1.05f, ImVec2(position.x + unit * 1.6f, position.y + unit * 5.4f + slide),
                  color(ImVec4(0.92f, 0.94f, 1.0f, 0.9f), enter), tagline.c_str());

    int online = static_cast<int>(nodes_.size());
    bool reachable = nodesMessage_.empty();
    std::string pills[2] = {std::to_string(online) + (online == 1 ? " site online" : " sites online"),
                            reachable ? (registry_ ? "Local registry running" : "Registry connected")
                                      : "Registry offline"};
    float pillSize = unit * 0.88f;
    float x = position.x + unit * 1.6f;
    float y = position.y + height - unit * 2.5f;
    for (int i = 0; i < 2; ++i) {
        float w = textWidth(pillSize, pills[i]) + unit * 1.9f;
        if (x + w > max.x - unit) break;
        list->AddRectFilled(ImVec2(x, y), ImVec2(x + w, y + unit * 1.6f), color(ImVec4(0, 0, 0, 0.32f), enter), unit * 0.8f);
        ImVec4 dot = (i == 1 && !reachable) ? ImVec4(1.0f, 0.42f, 0.42f, 1.0f) : ImVec4(0.45f, 0.95f, 0.55f, 1.0f);
        list->AddCircleFilled(ImVec2(x + unit * 0.8f, y + unit * 0.8f), unit * 0.24f, color(dot, enter), 12);
        drawText(list, pillSize, ImVec2(x + unit * 1.4f, y + unit * 0.35f), color(kWhite, enter),
                      pills[i].c_str());
        x += w + unit * 0.6f;
    }
    ImGui::Dummy(ImVec2(width, height));
}

void App::drawActions(float width) {
    float unit = ImGui::GetFontSize();
    float gap = ImGui::GetStyle().ItemSpacing.x;
    const Palette& colors = palette();

    struct Action {
        std::string id;
        std::string title;
        std::string subtitle;
        Icon icon;
        ImVec4 tint;
    };
    std::vector<Action> actions = {
        {"quick", "Quick start", "Registry and sample site", Icon::Play, colors.primary},
        {"host", node_ ? "Stop hosting" : "Host a site", node_ ? "Take your site offline" : "Share a folder", Icon::Server,
         colors.secondary},
        {"registry", registry_ ? "Stop registry" : "Start registry", registry_ ? "Running locally" : "Run on this device",
         Icon::Globe, kAmber},
        {"edit", "Edit site", "Write pages and preview", Icon::Pencil, kGold},
        {"find", "Find a site", "Search the directory", Icon::Search, kRose},
    };

    int columns = compact_ ? 2 : 5;
    float cardWidth = (width - gap * static_cast<float>(columns - 1)) / static_cast<float>(columns);
    ImVec2 size(cardWidth, unit * 5.6f);
    for (std::size_t i = 0; i < actions.size(); ++i) {
        if (i % static_cast<std::size_t>(columns) != 0) ImGui::SameLine(0.0f, gap);
        const Action& action = actions[i];
        CardState state = card("action:" + action.id, size, action.tint, false);
        ImDrawList* list = ImGui::GetWindowDrawList();
        ImVec2 badge(state.min.x + unit * 1.7f, state.min.y + unit * 1.75f);
        list->AddCircleFilled(badge, unit * (1.05f + 0.1f * state.hover), packColor(action.tint), 24);
        drawIcon(list, action.icon, badge, unit * 1.25f, IM_COL32(255, 255, 255, 255));
        float textLimit = cardWidth - unit * 1.6f;
        std::string title = fitText(action.title, unit * 1.12f, textLimit);
        std::string subtitle = fitText(action.subtitle, unit * 0.82f, textLimit);
        drawText(list, unit * 1.12f, ImVec2(state.min.x + unit * 0.9f, state.min.y + unit * 3.2f),
                      IM_COL32(255, 255, 255, 255), title.c_str());
        drawText(list, unit * 0.82f, ImVec2(state.min.x + unit * 0.9f, state.min.y + unit * 4.4f),
                      packColor(kDim), subtitle.c_str());
        if (state.clicked) {
            if (action.id == "quick") quickStart();
            if (action.id == "host") hostSite();
            if (action.id == "registry") {
                if (registry_) {
                    stopRegistry();
                } else {
                    startRegistry();
                }
            }
            if (action.id == "edit") openEditor();
            if (action.id == "find") focusSearch_ = true;
        }
    }
    ImGui::Dummy(ImVec2(0, unit * 0.6f));
}

void App::drawNodeCards(float width) {
    float unit = ImGui::GetFontSize();
    float gap = ImGui::GetStyle().ItemSpacing.x;
    std::string filter = lowered(search_);
    std::vector<const NodeInfo*> shown;
    for (const NodeInfo& info : nodes_) {
        if (filter.empty() || info.name.find(filter) != std::string::npos) shown.push_back(&info);
    }

    std::string title = "Online now";
    sectionTitle(title.c_str(), palette().secondary);

    if (shown.empty()) {
        ImVec2 position = ImGui::GetCursorScreenPos();
        float height = unit * 5.0f;
        ImGui::Dummy(ImVec2(width, height));
        ImDrawList* list = ImGui::GetWindowDrawList();
        list->AddRect(position, ImVec2(position.x + width, position.y + height), packColor(withAlpha(palette().primary, 0.4f)),
                      unit * 0.7f, ImDrawFlags_None, 1.5f);
        std::string headline = !nodesMessage_.empty() ? "The registry is not reachable"
                               : (filter.empty() ? "No sites are online yet" : "No site matches your search");
        std::string hint = !nodesMessage_.empty() ? "Start a registry or check the address in the sidebar."
                                                  : "Press Quick start or host a folder to publish a site.";
        drawText(list, unit * 1.15f,
                      ImVec2(position.x + unit * 1.2f, position.y + unit * 1.1f), IM_COL32(255, 255, 255, 235),
                      fitText(headline, unit * 1.15f, width - unit * 2.4f).c_str());
        drawText(list, unit * 0.9f, ImVec2(position.x + unit * 1.2f, position.y + unit * 2.9f),
                      packColor(kDim), fitText(hint, unit * 0.9f, width - unit * 2.4f).c_str());
        ImGui::Dummy(ImVec2(0, unit * 0.6f));
        return;
    }

    int columns = std::max(1, static_cast<int>((width + gap) / (unit * 14.0f + gap)));
    float cardWidth = (width - gap * static_cast<float>(columns - 1)) / static_cast<float>(columns);
    ImVec2 size(cardWidth, unit * 4.4f);
    for (std::size_t i = 0; i < shown.size(); ++i) {
        if (i % static_cast<std::size_t>(columns) != 0) ImGui::SameLine(0.0f, gap);
        const NodeInfo& info = *shown[i];
        ImVec4 tint = avatarColor(info.name);
        CardState state = card("node:" + info.name, size, tint, false);
        ImDrawList* list = ImGui::GetWindowDrawList();
        ImVec2 center(state.min.x + unit * 2.0f, state.min.y + size.y * 0.5f);
        list->AddCircleFilled(center, unit * 1.35f, packColor(tint), 28);
        std::string letter(1, static_cast<char>(std::toupper(static_cast<unsigned char>(info.name.empty() ? '?' : info.name[0]))));
        float letterSize = unit * 1.6f;
        drawText(list, letterSize, ImVec2(center.x - textWidth(letterSize, letter) * 0.5f, center.y - letterSize * 0.5f),
                      IM_COL32(20, 22, 32, 255), letter.c_str());
        float textX = state.min.x + unit * 4.0f;
        float limit = cardWidth - unit * 4.6f;
        drawText(list, unit * 1.2f, ImVec2(textX, state.min.y + unit * 0.95f), IM_COL32(255, 255, 255, 255),
                      fitText(info.name, unit * 1.2f, limit).c_str());
        drawText(list, unit * 0.85f, ImVec2(textX, state.min.y + unit * 2.5f), packColor(kDim),
                      fitText(formatEndpoint(info.endpoint), unit * 0.85f, limit).c_str());
        bool mine = node_ && node_->name() == info.name;
        if (mine) {
            float badge = textWidth(unit * 0.75f, "you") + unit * 0.9f;
            ImVec2 badgeMin(state.max.x - badge - unit * 0.6f, state.min.y + unit * 0.6f);
            list->AddRectFilled(badgeMin, ImVec2(badgeMin.x + badge, badgeMin.y + unit * 1.2f), packColor(withAlpha(tint, 0.9f)),
                                unit * 0.6f);
            drawText(list, unit * 0.75f, ImVec2(badgeMin.x + unit * 0.45f, badgeMin.y + unit * 0.2f),
                          IM_COL32(20, 22, 32, 255), "you");
        }
        if (state.hover > 0.02f) {
            drawText(list, unit * 0.85f, ImVec2(state.max.x - unit * 3.4f, state.max.y - unit * 1.6f),
                          color(tint, state.hover), "Open >");
        }
        if (state.clicked) clickedLink_ = "internet://" + info.name + "/";
    }
    ImGui::Dummy(ImVec2(0, unit * 0.6f));
}

void App::drawBookmarkCards(float width) {
    if (bookmarks_.empty()) return;
    float unit = ImGui::GetFontSize();
    float gap = ImGui::GetStyle().ItemSpacing.x;
    sectionTitle("Bookmarks", kGold);

    int columns = std::max(1, static_cast<int>((width + gap) / (unit * 16.0f + gap)));
    float cardWidth = (width - gap * static_cast<float>(columns - 1)) / static_cast<float>(columns);
    ImVec2 size(cardWidth, unit * 3.4f);
    int removal = -1;
    ImVec2 mouse = ImGui::GetIO().MousePos;
    for (std::size_t i = 0; i < bookmarks_.size(); ++i) {
        if (i % static_cast<std::size_t>(columns) != 0) ImGui::SameLine(0.0f, gap);
        const Entry& entry = bookmarks_[i];
        CardState state = card("bookmark:" + entry.url, size, kGold, false);
        ImDrawList* list = ImGui::GetWindowDrawList();
        drawIcon(list, Icon::StarFilled, ImVec2(state.min.x + unit * 1.4f, state.min.y + size.y * 0.5f), unit * 1.4f, packColor(kGold));
        float textX = state.min.x + unit * 2.7f;
        float limit = cardWidth - unit * 4.6f;
        std::string title = entry.title.empty() ? entry.url : entry.title;
        drawText(list, unit * 1.05f, ImVec2(textX, state.min.y + unit * 0.55f), IM_COL32(255, 255, 255, 255),
                      fitText(title, unit * 1.05f, limit).c_str());
        drawText(list, unit * 0.8f, ImVec2(textX, state.min.y + unit * 1.95f), packColor(kDim),
                      fitText(entry.url, unit * 0.8f, limit).c_str());
        ImVec2 closeMin(state.max.x - unit * 1.9f, state.min.y + unit * 0.3f);
        ImVec2 closeMax(state.max.x - unit * 0.3f, state.min.y + unit * 1.9f);
        bool overClose = mouse.x >= closeMin.x && mouse.x <= closeMax.x && mouse.y >= closeMin.y && mouse.y <= closeMax.y;
        if (state.hover > 0.02f) {
            drawIcon(list, Icon::Close, ImVec2((closeMin.x + closeMax.x) * 0.5f, (closeMin.y + closeMax.y) * 0.5f), unit * 1.1f,
                     overClose ? IM_COL32(255, 120, 120, 255) : packColor(withAlpha(kWhite, 0.6f * state.hover)));
        }
        if (state.clicked) {
            if (overClose) {
                removal = static_cast<int>(i);
            } else {
                clickedLink_ = entry.url;
            }
        }
    }
    if (removal >= 0) {
        bookmarks_.erase(bookmarks_.begin() + removal);
        settingsDirty_ = true;
        toast("Bookmark removed");
    }
    ImGui::Dummy(ImVec2(0, unit * 0.6f));
}

void App::drawRecentChips(float width) {
    if (recent_.empty()) return;
    float unit = ImGui::GetFontSize();
    float gap = ImGui::GetStyle().ItemSpacing.x;
    sectionTitle("Recent", palette().primary);

    float left = ImGui::GetCursorScreenPos().x;
    float right = left + width;
    float chipHeight = unit * 2.1f;
    bool first = true;
    std::size_t count = std::min<std::size_t>(recent_.size(), 12);
    for (std::size_t i = 0; i < count; ++i) {
        const Entry& entry = recent_[i];
        std::string label = fitText(entry.title.empty() ? entry.url : entry.title, unit * 0.95f, unit * 15.0f);
        float w = textWidth(unit * 0.95f, label) + unit * 3.0f;
        if (!first) {
            float remaining = right - ImGui::GetItemRectMax().x - gap;
            if (remaining >= w) ImGui::SameLine(0.0f, gap);
        }
        first = false;
        ImVec4 tint = avatarColor(entry.url);
        CardState state = card("recent:" + entry.url, ImVec2(w, chipHeight), tint, false);
        ImDrawList* list = ImGui::GetWindowDrawList();
        list->AddCircleFilled(ImVec2(state.min.x + unit * 1.1f, state.min.y + chipHeight * 0.5f), unit * 0.32f, packColor(tint), 12);
        drawText(list, unit * 0.95f, ImVec2(state.min.x + unit * 1.9f, state.min.y + chipHeight * 0.5f - unit * 0.5f),
                      IM_COL32(255, 255, 255, 255), label.c_str());
        if (state.clicked) clickedLink_ = entry.url;
    }
    ImGui::Dummy(ImVec2(0, unit * 0.3f));
}

void App::drawSplash() {
    if (!splash_) return;
    if (splashStart_ < 0.0) splashStart_ = time_;
    const float total = 3.4f;
    const float fade = 0.5f;
    float t = static_cast<float>(time_ - splashStart_);

    bool skip = ImGui::IsMouseClicked(ImGuiMouseButton_Left) || ImGui::IsKeyPressed(ImGuiKey_Space, false) ||
                ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    if (skip && t < total - fade) {
        splashStart_ = time_ - (total - fade);
        t = total - fade;
    }
    if (t >= total) {
        splash_ = false;
        homeSince_ = -1.0;
        return;
    }

    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                             ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoScrollbar;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 1.0f);
    ImGui::Begin("##splash", nullptr, flags);
    ImGui::InvisibleButton("##skip", viewport->WorkSize);

    ImDrawList* list = ImGui::GetWindowDrawList();
    float unit = ImGui::GetFontSize();
    ImVec2 min = viewport->WorkPos;
    ImVec2 size = viewport->WorkSize;
    ImVec2 max(min.x + size.x, min.y + size.y);
    const Palette& colors = palette();
    float alpha = 1.0f - smoothStep((t - (total - fade)) / fade);

    list->AddRectFilledMultiColor(min, max, color(kNavy, alpha), color(mixColor(kNavy, colors.primary, 0.28f), alpha),
                                  color(mixColor(kNavy, colors.secondary, 0.38f), alpha), color(kNavy, alpha));
    particles_.draw(list, min, size, packColor(mixColor(colors.primary, kWhite, 0.5f)), unit * 9.0f, 0.4f * alpha);

    ImVec2 center(min.x + size.x * 0.5f, min.y + size.y * 0.4f);
    float radius = std::clamp(std::min(size.x, size.y) * 0.15f, unit * 2.5f, unit * 6.5f);
    float grow = easeOutBack(t / 1.0f);
    float orbit = smoothStep((t - 0.4f) / 0.9f);
    for (int k = 0; k < 5; ++k) {
        list->AddCircleFilled(center, radius * grow * (1.25f + 0.2f * static_cast<float>(k)), color(colors.primary, 0.05f * alpha), 48);
    }
    drawGlobe(list, center, radius * grow, t * 1.3f, color(ImVec4(0.96f, 0.97f, 1.0f, 1.0f), alpha),
              color(withAlpha(colors.primary, 0.35f), alpha), color(colors.secondary, alpha), orbit);

    float titleSize = std::max(unit * 2.6f, radius * 0.72f);
    const std::string title = "Internet";
    float titleWidth = textWidth(titleSize, title);
    float x = center.x - titleWidth * 0.5f;
    float y = center.y + radius * 1.85f;
    for (std::size_t i = 0; i < title.size(); ++i) {
        std::string letter(1, title[i]);
        float a = easeOutCubic((t - 1.1f - static_cast<float>(i) * 0.07f) / 0.4f);
        float mixAmount = static_cast<float>(i) / static_cast<float>(title.size() - 1);
        ImVec4 tone = mixColor(kWhite, mixColor(colors.primary, colors.secondary, mixAmount), 0.35f);
        drawText(list, titleSize, ImVec2(x, y + (1.0f - a) * unit * 1.4f), color(tone, a * alpha), letter.c_str());
        x += textWidth(titleSize, letter);
    }

    std::string tagline = "Your own network. Browse. Host. Share.";
    float taglineSize = unit * 1.15f;
    float taglineAlpha = smoothStep((t - 1.9f) / 0.6f) * alpha;
    drawText(list, taglineSize, ImVec2(center.x - textWidth(taglineSize, tagline) * 0.5f, y + titleSize * 1.3f),
                  color(ImVec4(0.85f, 0.88f, 1.0f, 1.0f), taglineAlpha), tagline.c_str());

    float barWidth = std::min(unit * 16.0f, size.x * 0.6f);
    float barHeight = std::max(3.0f, unit * 0.28f);
    ImVec2 barMin(center.x - barWidth * 0.5f, max.y - unit * 4.2f);
    list->AddRectFilled(barMin, ImVec2(barMin.x + barWidth, barMin.y + barHeight), color(kWhite, 0.14f * alpha), barHeight * 0.5f);
    float progress = clamp01(t / (total - fade));
    list->AddRectFilledMultiColor(barMin, ImVec2(barMin.x + barWidth * progress, barMin.y + barHeight), color(colors.primary, alpha),
                                  color(colors.secondary, alpha), color(colors.secondary, alpha), color(colors.primary, alpha));

    std::string hint = "Click or press any key to skip";
    float hintSize = unit * 0.85f;
    drawText(list, hintSize, ImVec2(center.x - textWidth(hintSize, hint) * 0.5f, barMin.y + unit * 1.1f),
                  color(kWhite, smoothStep((t - 1.0f) / 0.6f) * 0.5f * alpha), hint.c_str());

    ImGui::End();
    ImGui::PopStyleVar(3);
}

void App::drawToasts() {
    toasts_.erase(std::remove_if(toasts_.begin(), toasts_.end(), [&](const Toast& item) { return time_ - item.born > 2.8; }),
                  toasts_.end());
    if (toasts_.empty()) return;

    ImDrawList* list = ImGui::GetForegroundDrawList();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    float unit = ImGui::GetFontSize();
    float right = viewport->WorkPos.x + viewport->WorkSize.x - insets_[2] - unit;
    float y = viewport->WorkPos.y + viewport->WorkSize.y - insets_[3] - unit * 4.0f;
    for (std::size_t i = toasts_.size(); i-- > 0;) {
        const Toast& item = toasts_[i];
        float age = static_cast<float>(time_ - item.born);
        float in = easeOutCubic(age / 0.3f);
        float out = 1.0f - smoothStep((age - 2.3f) / 0.5f);
        float width = std::min(textWidth(unit, item.text) + unit * 3.0f, viewport->WorkSize.x - unit * 2.0f);
        float height = unit * 2.4f;
        float x = right - width + (1.0f - in) * (width + unit);
        ImVec2 min(x, y);
        ImVec2 max(x + width, y + height);
        list->AddRectFilled(ImVec2(min.x + 2.0f, min.y + 4.0f), ImVec2(max.x + 2.0f, max.y + 4.0f), IM_COL32(0, 0, 0, static_cast<int>(80 * out)),
                            unit * 0.6f);
        list->AddRectFilled(min, max, color(ImVec4(0.10f, 0.11f, 0.17f, 0.97f), out), unit * 0.6f);
        list->AddRect(min, max, color(palette().primary, out), unit * 0.6f, ImDrawFlags_None, 1.4f);
        list->AddRectFilled(ImVec2(min.x + unit * 0.5f, min.y + unit * 0.55f), ImVec2(min.x + unit * 0.75f, max.y - unit * 0.55f),
                            color(palette().secondary, out), 2.0f);
        drawText(list, unit, ImVec2(min.x + unit * 1.2f, min.y + unit * 0.7f), color(kWhite, out),
                      fitText(item.text, unit, width - unit * 1.8f).c_str());
        y -= height + unit * 0.5f;
    }
}

}
