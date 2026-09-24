#include <algorithm>
#include <cctype>
#include <cmath>

#include "app.hpp"
#include "ui.hpp"

namespace internet {

namespace {

const ImVec4 kErrorColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kDimColor(0.62f, 0.62f, 0.68f, 1.0f);
const ImVec4 kWhite(1.0f, 1.0f, 1.0f, 1.0f);

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

}

void App::drawPage() {
    if (editor_) {
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, easeOutCubic(pageFade_));
        drawEditor();
        ImGui::PopStyleVar();
        return;
    }
    touchScroll();
    if (home_) {
        drawHome();
        return;
    }
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, easeOutCubic(pageFade_));
    drawPageContent();
    ImGui::PopStyleVar();
}

void App::drawPageContent() {
    if (loading_) {
        drawLoading();
    } else if (failed_) {
        drawError();
    } else if (currentUrl_.empty()) {
        goHome();
    } else if (binary_) {
        drawBinary();
    } else if (showSource_) {
        ImGui::PushFont(monoFont());
        ImGui::SetWindowFontScale(settings_.zoom);
        ImGui::TextUnformatted(body_.c_str(), body_.c_str() + body_.size());
        ImGui::SetWindowFontScale(1.0f);
        ImGui::PopFont();
    } else {
        drawDocument(document_, true, currentUrl_);
    }
}

void App::drawLoading() {
    float unit = ImGui::GetFontSize();
    ImVec2 position = ImGui::GetCursorScreenPos();
    float radius = unit * 1.3f;
    drawSpinner(ImGui::GetWindowDrawList(), ImVec2(position.x + radius + unit * 0.4f, position.y + radius + unit * 0.4f),
                radius, packColor(palette().secondary), static_cast<float>(time_));
    ImGui::SetCursorScreenPos(ImVec2(position.x + radius * 2.0f + unit, position.y + radius - unit * 0.1f));
    ImGui::TextColored(kDimColor, "Loading %s ...", currentUrl_.c_str());
}

void App::drawError() {
    float unit = ImGui::GetFontSize();
    ImGui::PushTextWrapPos(0.0f);
    pushTextScale(1.5f);
    ImGui::TextColored(kErrorColor, "Cannot open this page");
    popTextScale(1.0f);
    ImGui::Spacing();
    ImGui::TextUnformatted(message_.c_str());
    ImGui::Spacing();
    ImGui::TextColored(kDimColor, "Check that the registry address is right and that the site is running.");
    ImGui::PopTextWrapPos();
    ImGui::Dummy(ImVec2(0, unit * 0.5f));
    if (textButton("error-retry", "Try again", Icon::Reload, true)) reload();
    ImGui::SameLine();
    if (textButton("error-home", "Go home", Icon::Home, false)) goHome();
}

void App::drawBinary() {
    pushTextScale(1.4f);
    ImGui::TextUnformatted("Binary content");
    popTextScale(1.0f);
    ImGui::TextColored(kDimColor, "%s, %zu bytes", contentType_.c_str(), body_.size());
    ImGui::Spacing();
    if (textButton("binary-save", "Save to downloads folder", Icon::Save, true)) saveDownload();
}

void App::drawDocument(const Document& document, bool interactive, const std::string& base) {
    static const float scales[] = {2.0f, 1.6f, 1.35f, 1.15f, 1.05f, 1.0f};
    const Palette& colors = palette();
    ImVec4 h1 = mixColor(colors.primary, kWhite, 0.3f);
    ImVec4 h2 = mixColor(colors.secondary, kWhite, 0.25f);
    float zoom = interactive ? settings_.zoom : 1.0f;
    if (interactive) matches_ = 0;
    ImGui::SetWindowFontScale(zoom);
    float unit = ImGui::GetFontSize();
    for (const Block& block : document.blocks) {
        switch (block.kind) {
            case BlockKind::Rule: {
                ImVec2 position = ImGui::GetCursorScreenPos();
                float width = ImGui::GetContentRegionAvail().x;
                ImGui::Dummy(ImVec2(width, unit * 0.9f));
                ImGui::GetWindowDrawList()->AddRectFilledMultiColor(
                    ImVec2(position.x, position.y + unit * 0.4f), ImVec2(position.x + width, position.y + unit * 0.5f),
                    packColor(colors.primary), packColor(colors.secondary), packColor(withAlpha(colors.secondary, 0.0f)),
                    packColor(withAlpha(colors.primary, 0.0f)));
                break;
            }
            case BlockKind::Heading: {
                int index = std::clamp(block.level, 1, 6) - 1;
                ImGui::Spacing();
                const ImVec4* tint = block.level == 1 ? &h1 : (block.level == 2 ? &h2 : nullptr);
                drawWords(block, scales[index], tint, interactive, base);
                ImGui::Spacing();
                break;
            }
            case BlockKind::ListItem: {
                ImVec2 origin = ImGui::GetCursorScreenPos();
                float height = ImGui::GetTextLineHeight();
                ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(origin.x + unit * 0.55f, origin.y + height * 0.5f),
                                                            unit * 0.16f, ImGui::GetColorU32(colors.secondary));
                ImGui::Indent(unit * 1.4f);
                drawWords(block, 1.0f, nullptr, interactive, base);
                ImGui::Unindent(unit * 1.4f);
                break;
            }
            case BlockKind::Preformatted: {
                std::string text;
                for (const Span& span : block.spans) text += span.text;
                while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
                ImVec2 origin = ImGui::GetCursorScreenPos();
                float padding = unit * 0.6f;
                float available = ImGui::GetContentRegionAvail().x;
                ImGui::PushFont(monoFont());
                ImVec2 size = ImGui::CalcTextSize(text.c_str(), text.c_str() + text.size());
                ImGui::GetWindowDrawList()->AddRectFilled(
                    origin, ImVec2(origin.x + std::max(size.x + padding * 2.0f, std::min(available, unit * 12.0f)), origin.y + size.y + padding * 2.0f),
                    packColor(ImVec4(0.04f, 0.05f, 0.09f, 1.0f)), unit * 0.4f);
                ImGui::SetCursorScreenPos(ImVec2(origin.x + padding, origin.y + padding));
                ImGui::TextUnformatted(text.c_str(), text.c_str() + text.size());
                ImGui::PopFont();
                ImGui::SetCursorScreenPos(ImVec2(origin.x, origin.y + size.y + padding * 2.0f));
                ImGui::Dummy(ImVec2(0, unit * 0.4f));
                break;
            }
            case BlockKind::Paragraph:
                drawWords(block, 1.0f, nullptr, interactive, base);
                ImGui::Dummy(ImVec2(0, unit * 0.4f));
                break;
        }
    }
    if (interactive) matchesShown_ = matches_;
    ImGui::SetWindowFontScale(1.0f);
}

void App::drawWords(const Block& block, float scale, const ImVec4* tint, bool interactive, const std::string& base) {
    float zoom = interactive ? settings_.zoom : 1.0f;
    pushTextScale(scale * zoom);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 2.0f));
    float rightEdge = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
    float space = ImGui::CalcTextSize(" ").x;
    bool first = true;
    bool previousEndedWithSpace = true;
    ImVec4 linkColor = mixColor(palette().primary, kWhite, 0.35f);
    std::string needle = (findOpen_ && interactive) ? lowered(find_) : std::string();

    for (const Span& span : block.spans) {
        bool link = !span.href.empty();
        std::string target = link ? resolveUrl(base, span.href) : std::string();
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

            if (!needle.empty() && lowered(std::string(begin, finish)).find(needle) != std::string::npos) {
                ++matches_;
                ImVec2 at = ImGui::GetCursorScreenPos();
                ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(at.x - 2.0f, at.y), ImVec2(at.x + size.x + 2.0f, at.y + size.y),
                                                          ImGui::GetColorU32(ImVec4(1.0f, 0.78f, 0.15f, 0.55f)), 3.0f);
            }

            if (link) {
                ImGui::PushStyleColor(ImGuiCol_Text, linkColor);
            } else if (tint) {
                ImGui::PushStyleColor(ImGuiCol_Text, *tint);
            }
            ImGui::TextUnformatted(begin, finish);
            if (link || tint) ImGui::PopStyleColor();
            if (link) {
                if (interactive && ImGui::IsItemHovered()) {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                    hoveredLink_ = target;
                    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) pressedLink_ = target;
                }
                ImVec2 min = ImGui::GetItemRectMin();
                ImVec2 max = ImGui::GetItemRectMax();
                ImGui::GetWindowDrawList()->AddLine(ImVec2(min.x, max.y), max, ImGui::GetColorU32(linkColor));
            }
            first = false;
            start = end + 1;
        }
        previousEndedWithSpace = !span.text.empty() && span.text.back() == ' ';
    }
    ImGui::PopStyleVar();
    popTextScale(zoom);
}

}
