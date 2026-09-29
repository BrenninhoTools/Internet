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
const ImVec4 kQuoteColor(0.74f, 0.76f, 0.84f, 1.0f);
const ImVec4 kMarkText(0.09f, 0.09f, 0.12f, 1.0f);
const float kColumnUnits = 62.0f;

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

void shear(ImDrawList* list, int from, float baseline, float slant) {
    for (int i = from; i < list->VtxBuffer.Size; ++i) {
        ImDrawVert& vertex = list->VtxBuffer[i];
        vertex.pos.x += (baseline - vertex.pos.y) * slant;
    }
}

std::string sourceName(const std::string& url) {
    std::string name = url.substr(url.rfind('/') + 1);
    return name.empty() ? url : name;
}

float listGutter(const Block& block, float unit) {
    float gutter = unit * 1.6f;
    if (block.number > 0) gutter = std::max(gutter, textWidth(unit, std::to_string(block.number) + ".") + unit * 0.9f);
    return gutter;
}

}

void App::drawPage() {
    pageScroll_ = 0.0f;
    pageScrollMax_ = 0.0f;
    if (securityView_) {
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, easeOutCubic(pageFade_));
        drawSecurity();
        ImGui::PopStyleVar();
        return;
    }
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
        return;
    }
    if (failed_) {
        drawError();
        return;
    }
    if (blocked_ && !blockOverride_) {
        drawBlocked();
        return;
    }
    if (currentUrl_.empty()) {
        goHome();
        return;
    }
    if (threat_.verdict != Verdict::Clean) drawThreatBanner();
    if (binary_) {
        drawBinary();
        return;
    }
    applyScrollTarget();
    if (showSource_) {
        ImGui::PushFont(monoFont());
        ImGui::SetWindowFontScale(settings_.zoom);
        ImGui::TextUnformatted(body_.c_str(), body_.c_str() + body_.size());
        ImGui::SetWindowFontScale(1.0f);
        ImGui::PopFont();
    } else {
        drawDocument(document_, true, currentUrl_);
    }
    pageScroll_ = ImGui::GetScrollY();
    pageScrollMax_ = ImGui::GetScrollMaxY();
    drawScrollTools();
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

void App::applyScrollTarget() {
    if (scrollTarget_ < 0.0f) return;
    if (ImGui::GetIO().MouseWheel != 0.0f) {
        scrollTarget_ = -1.0f;
        return;
    }
    float goal = std::min(scrollTarget_, ImGui::GetScrollMaxY());
    float current = ImGui::GetScrollY();
    float next = settings_.animations ? current + (goal - current) * std::min(1.0f, dt_ * 14.0f) : goal;
    if (std::fabs(goal - next) < 1.0f) {
        next = goal;
        scrollTarget_ = -1.0f;
    }
    ImGui::SetScrollY(next);
}

void App::followAnchor(const std::string& anchor) {
    std::string id = anchor.substr(1);
    if (id.empty() || id == "top") {
        scrollTarget_ = 0.0f;
        return;
    }
    auto found = anchors_.find(id);
    if (found != anchors_.end()) scrollTarget_ = std::max(0.0f, found->second - ImGui::GetFontSize() * 0.5f);
}

void App::drawScrollTools() {
    float unit = ImGui::GetFontSize();
    bool visible = pageScrollMax_ > 0.0f && pageScroll_ > ImGui::GetWindowHeight() * 0.5f;
    float& shown = hover_["scroll:top:shown"];
    approach(shown, visible ? 1.0f : 0.0f, 12.0f, dt_);
    if (shown < 0.02f) return;

    float radius = unit * 1.25f;
    ImVec2 windowPos = ImGui::GetWindowPos();
    ImVec2 windowSize = ImGui::GetWindowSize();
    float margin = unit * 1.1f;
    ImVec2 center(windowPos.x + windowSize.x - ImGui::GetStyle().ScrollbarSize - margin - radius,
                  windowPos.y + windowSize.y - margin - radius + (1.0f - shown) * unit * 1.5f);
    ImVec2 min(center.x - radius, center.y - radius);
    ImVec2 max(center.x + radius, center.y + radius);
    bool hovered = ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(min, max);
    float& hover = hover_["scroll:top"];
    approach(hover, hovered ? 1.0f : 0.0f, 14.0f, dt_);

    const Palette& colors = palette();
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec4 frame = ImGui::GetStyleColorVec4(ImGuiCol_FrameBg);
    list->AddCircleFilled(ImVec2(center.x, center.y + unit * 0.12f), radius + unit * 0.1f,
                          packColor(ImVec4(0.0f, 0.0f, 0.0f, 0.28f * shown)), 32);
    list->AddCircleFilled(center, radius, packColor(withAlpha(mixColor(frame, colors.primary, 0.55f + 0.4f * hover), shown)), 32);
    list->AddCircle(center, radius, packColor(withAlpha(colors.secondary, (0.35f + 0.5f * hover) * shown)), 32, 1.5f);
    drawIcon(list, Icon::ArrowUp, center, radius * 1.15f, packColor(withAlpha(kWhite, shown)));
    if (hovered) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        hoveredLink_.clear();
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) scrollTarget_ = 0.0f;
        if (!touch_) ImGui::SetTooltip("Back to top");
    }
}

void App::drawOutline(float width) {
    bool available = !home_ && !editor_ && !securityView_ && !loading_ && !failed_ && !binary_ && !showSource_ &&
                     !currentUrl_.empty() && outlineUrl_ == currentUrl_ && outline_.size() >= 2;
    if (!available) return;
    std::string label = "On this page (" + std::to_string(outline_.size()) + ")###outline";
    if (!ImGui::CollapsingHeader(label.c_str(), ImGuiTreeNodeFlags_DefaultOpen)) return;

    float unit = ImGui::GetFontSize();
    int shallowest = 6;
    for (const OutlineItem& item : outline_) shallowest = std::min(shallowest, item.level);
    int current = 0;
    for (std::size_t i = 0; i < outline_.size(); ++i) {
        if (outline_[i].y <= pageScroll_ + unit * 2.0f) current = static_cast<int>(i);
    }
    ImDrawList* list = ImGui::GetWindowDrawList();
    for (std::size_t i = 0; i < outline_.size(); ++i) {
        const OutlineItem& item = outline_[i];
        float indent = unit * 0.9f * static_cast<float>(std::min(item.level - shallowest, 3));
        bool selected = static_cast<int>(i) == current;
        ImVec2 position = ImGui::GetCursorScreenPos();
        float line = ImGui::GetTextLineHeight();
        if (selected) {
            list->AddRectFilled(ImVec2(position.x, position.y + line * 0.15f), ImVec2(position.x + unit * 0.2f, position.y + line * 0.85f),
                                packColor(palette().secondary), unit * 0.1f);
        }
        ImGui::Indent(unit * 0.6f + indent);
        std::string text = fitText(item.text.empty() ? "(untitled)" : item.text, unit, width - indent - unit * 1.8f);
        std::string id = text + "##outline" + std::to_string(i);
        if (selected) ImGui::PushStyleColor(ImGuiCol_Text, mixColor(palette().secondary, kWhite, 0.35f));
        bool pressed = ImGui::Selectable(id.c_str(), false);
        if (selected) ImGui::PopStyleColor();
        ImGui::Unindent(unit * 0.6f + indent);
        if (pressed) {
            scrollTarget_ = std::max(0.0f, item.y - unit * 0.5f);
            menuOpen_ = false;
        }
    }
    ImGui::Spacing();
}

void App::drawListMarker(const Block& block, ImVec2 origin, float gutter, float unit) {
    ImDrawList* list = ImGui::GetWindowDrawList();
    const Palette& colors = palette();
    float height = ImGui::GetTextLineHeight();
    if (block.number > 0) {
        std::string label = std::to_string(block.number) + ".";
        float x = origin.x + gutter - unit * 0.4f - textWidth(unit, label);
        drawText(list, unit, ImVec2(x, origin.y), ImGui::GetColorU32(mixColor(colors.secondary, kWhite, 0.2f)), label.c_str());
        return;
    }
    ImVec2 center(origin.x + unit * 0.55f, origin.y + height * 0.5f);
    ImU32 color = ImGui::GetColorU32(colors.secondary);
    switch (block.depth % 3) {
        case 0:
            list->AddCircleFilled(center, unit * 0.16f, color, 16);
            break;
        case 1:
            list->AddCircle(center, unit * 0.15f, color, 16, std::max(1.4f, unit * 0.09f));
            break;
        default:
            list->AddRectFilled(ImVec2(center.x - unit * 0.13f, center.y - unit * 0.13f),
                                ImVec2(center.x + unit * 0.13f, center.y + unit * 0.13f), color, unit * 0.03f);
            break;
    }
}

void App::drawQuoteBars(int depth, float left, float top, float bottom, float unit) {
    ImDrawList* list = ImGui::GetWindowDrawList();
    const Palette& colors = palette();
    for (int level = 0; level < depth; ++level) {
        float x = left + unit * (0.25f + 1.3f * static_cast<float>(level));
        ImVec4 color = mixColor(colors.primary, colors.secondary, level % 2 == 0 ? 0.6f : 0.0f);
        list->AddRectFilled(ImVec2(x, top), ImVec2(x + unit * 0.2f, bottom), ImGui::GetColorU32(withAlpha(color, 0.9f)),
                            unit * 0.1f);
    }
}

void App::drawImage(const Block& block, bool interactive, const std::string& base) {
    const Span& span = block.spans.front();
    std::string target;
    if (!span.href.empty()) target = span.href[0] == '#' ? span.href : resolveUrl(base, span.href);
    std::string name = span.text.empty() ? (span.href.empty() ? std::string("Image") : sourceName(span.href)) : span.text;
    float unit = ImGui::GetFontSize();
    const Palette& colors = palette();
    float width = std::min(ImGui::GetContentRegionAvail().x - rightInset_, unit * 28.0f);
    float height = unit * 3.4f;
    ImVec2 position = ImGui::GetCursorScreenPos();
    ImGui::PushID(&block);
    ImGui::InvisibleButton("##image", ImVec2(std::max(width, unit * 6.0f), height));
    ImGui::PopID();
    bool hovered = interactive && !target.empty() && ImGui::IsItemHovered();
    if (hovered) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        hoveredLink_ = target;
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) pressedLink_ = target;
    }

    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec4 frame = ImGui::GetStyleColorVec4(ImGuiCol_FrameBg);
    ImVec2 max(position.x + std::max(width, unit * 6.0f), position.y + height);
    list->AddRectFilled(position, max, ImGui::GetColorU32(mixColor(frame, colors.primary, hovered ? 0.3f : 0.14f)), unit * 0.6f);
    list->AddRect(position, max, ImGui::GetColorU32(withAlpha(colors.primary, hovered ? 0.8f : 0.4f)), unit * 0.6f,
                  ImDrawFlags_None, 1.5f);
    ImVec2 badge(position.x + height * 0.5f, position.y + height * 0.5f);
    list->AddCircleFilled(badge, height * 0.32f, ImGui::GetColorU32(withAlpha(colors.secondary, 0.85f)), 24);
    drawIcon(list, Icon::Image, badge, height * 0.42f, ImGui::GetColorU32(kWhite));
    float textX = position.x + height * 1.0f;
    float textWidthLimit = max.x - textX - unit * 0.8f;
    drawText(list, unit, ImVec2(textX, position.y + height * 0.5f - unit * 1.05f), ImGui::GetColorU32(kWhite),
             fitText(name, unit, textWidthLimit).c_str());
    drawText(list, unit * 0.85f, ImVec2(textX, position.y + height * 0.5f + unit * 0.1f), ImGui::GetColorU32(kDimColor),
             target.empty() ? "Image" : (hovered ? "Click to open the image" : "Image"));
    ImGui::Dummy(ImVec2(0, unit * 0.4f));
}

void App::drawTable(const Document& document, std::size_t begin, std::size_t end, bool interactive,
                    const std::string& base) {
    const Palette& colors = palette();
    float unit = ImGui::GetFontSize();
    std::size_t columns = 0;
    for (std::size_t i = begin; i < end; ++i) columns = std::max(columns, document.blocks[i].cells.size());
    columns = std::min<std::size_t>(columns, 24);
    if (columns == 0) return;

    ImVec4 frame = ImGui::GetStyleColorVec4(ImGuiCol_FrameBg);
    ImVec4 border = mixColor(frame, colors.primary, 0.35f);
    float width = std::max(ImGui::GetContentRegionAvail().x - rightInset_, unit * 6.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(unit * 0.7f, unit * 0.4f));
    ImGui::PushStyleColor(ImGuiCol_TableBorderStrong, border);
    ImGui::PushStyleColor(ImGuiCol_TableBorderLight, withAlpha(border, 0.6f));
    ImGui::PushStyleColor(ImGuiCol_TableRowBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt, ImVec4(1.0f, 1.0f, 1.0f, 0.035f));
    ImGui::PushID(static_cast<int>(begin));
    float savedInset = rightInset_;
    rightInset_ = 0.0f;
    ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp |
                            ImGuiTableFlags_NoSavedSettings;
    if (ImGui::BeginTable("##table", static_cast<int>(columns), flags, ImVec2(width, 0.0f))) {
        for (std::size_t row = begin; row < end; ++row) {
            const std::vector<Cell>& cells = document.blocks[row].cells;
            bool header = !cells.empty() && std::all_of(cells.begin(), cells.end(), [](const Cell& cell) { return cell.header; });
            ImGui::TableNextRow();
            if (header) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, packColor(withAlpha(colors.primary, 0.32f)));
            for (std::size_t column = 0; column < columns; ++column) {
                ImGui::TableSetColumnIndex(static_cast<int>(column));
                if (column < cells.size()) drawWords(cells[column].spans, 1.0f, nullptr, interactive, base);
            }
        }
        ImGui::EndTable();
    }
    rightInset_ = savedInset;
    ImGui::PopID();
    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar();
    ImGui::Dummy(ImVec2(0, unit * 0.4f));
}

void App::drawDocument(const Document& document, bool interactive, const std::string& base) {
    static const float scales[] = {2.0f, 1.6f, 1.35f, 1.15f, 1.05f, 1.0f};
    const Palette& colors = palette();
    const std::vector<Block>& blocks = document.blocks;
    ImVec4 h1 = mixColor(colors.primary, kWhite, 0.3f);
    ImVec4 h2 = mixColor(colors.secondary, kWhite, 0.25f);
    float zoom = interactive ? settings_.zoom : 1.0f;
    if (interactive) {
        matches_ = 0;
        outlineNext_.clear();
        anchorsNext_.clear();
    }
    ImGui::SetWindowFontScale(zoom);
    float unit = ImGui::GetFontSize();
    bool plain = blocks.size() == 1 && blocks[0].kind == BlockKind::Preformatted;
    float pad = (interactive && !plain) ? std::max(0.0f, (ImGui::GetContentRegionAvail().x - unit * kColumnUnits) * 0.5f) : 0.0f;
    if (pad > 0.0f) ImGui::Indent(pad);
    rightInset_ = pad;

    for (std::size_t position = 0; position < blocks.size(); ++position) {
        const Block& block = blocks[position];
        if (interactive) {
            float top = ImGui::GetCursorPosY();
            if (!block.anchor.empty()) anchorsNext_.emplace(block.anchor, top);
            if (block.kind == BlockKind::Heading) outlineNext_.push_back(OutlineItem{block.level, plainText(block), top});
        }
        ImVec2 origin = ImGui::GetCursorScreenPos();
        float quoteIndent = unit * 1.3f * static_cast<float>(block.quote);
        if (block.quote > 0) ImGui::Indent(quoteIndent);
        const ImVec4* bodyTint = block.quote > 0 ? &kQuoteColor : nullptr;

        switch (block.kind) {
            case BlockKind::Rule: {
                ImVec2 at = ImGui::GetCursorScreenPos();
                float width = ImGui::GetContentRegionAvail().x - rightInset_;
                ImGui::Dummy(ImVec2(width, unit * 0.9f));
                ImGui::GetWindowDrawList()->AddRectFilledMultiColor(
                    ImVec2(at.x, at.y + unit * 0.4f), ImVec2(at.x + width, at.y + unit * 0.5f),
                    packColor(colors.primary), packColor(colors.secondary), packColor(withAlpha(colors.secondary, 0.0f)),
                    packColor(withAlpha(colors.primary, 0.0f)));
                break;
            }
            case BlockKind::Heading: {
                int level = std::clamp(block.level, 1, 6) - 1;
                ImGui::Spacing();
                const ImVec4* tint = block.level == 1 ? &h1 : (block.level == 2 ? &h2 : nullptr);
                drawWords(block.spans, scales[level], tint, interactive, base);
                ImGui::Spacing();
                break;
            }
            case BlockKind::ListItem: {
                ImVec2 at = ImGui::GetCursorScreenPos();
                float levelOffset = unit * 1.6f * static_cast<float>(std::min(block.depth, 6));
                float gutter = listGutter(block, unit);
                drawListMarker(block, ImVec2(at.x + levelOffset, at.y), gutter, unit);
                ImGui::Indent(levelOffset + gutter);
                drawWords(block.spans, 1.0f, bodyTint, interactive, base);
                ImGui::Unindent(levelOffset + gutter);
                break;
            }
            case BlockKind::Preformatted: {
                std::string text;
                for (const Span& span : block.spans) text += span.text;
                while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
                ImVec2 at = ImGui::GetCursorScreenPos();
                float padding = unit * 0.7f;
                float available = ImGui::GetContentRegionAvail().x - rightInset_;
                ImGui::PushFont(monoFont());
                ImVec2 size = ImGui::CalcTextSize(text.c_str(), text.c_str() + text.size());
                float boxWidth = std::max(size.x + padding * 2.0f, available);
                ImDrawList* list = ImGui::GetWindowDrawList();
                ImVec2 boxMax(at.x + boxWidth, at.y + size.y + padding * 2.0f);
                list->AddRectFilled(at, boxMax, ImGui::GetColorU32(ImVec4(0.04f, 0.05f, 0.09f, 1.0f)), unit * 0.5f);
                list->AddRect(at, boxMax, ImGui::GetColorU32(withAlpha(colors.primary, 0.35f)), unit * 0.5f, ImDrawFlags_None, 1.2f);
                ImGui::SetCursorScreenPos(ImVec2(at.x + padding, at.y + padding));
                ImGui::TextUnformatted(text.c_str(), text.c_str() + text.size());
                ImGui::PopFont();
                ImGui::SetCursorScreenPos(ImVec2(at.x, at.y + size.y + padding * 2.0f));
                ImGui::Dummy(ImVec2(0, unit * 0.4f));
                break;
            }
            case BlockKind::Image:
                drawImage(block, interactive, base);
                break;
            case BlockKind::TableRow: {
                std::size_t end = position;
                while (end < blocks.size() && blocks[end].kind == BlockKind::TableRow && blocks[end].quote == block.quote) ++end;
                drawTable(document, position, end, interactive, base);
                position = end - 1;
                break;
            }
            case BlockKind::Paragraph:
                drawWords(block.spans, 1.0f, bodyTint, interactive, base);
                ImGui::Dummy(ImVec2(0, unit * 0.4f));
                break;
        }

        if (block.quote > 0) {
            ImGui::Unindent(quoteIndent);
            drawQuoteBars(block.quote, origin.x, origin.y, ImGui::GetCursorScreenPos().y, unit);
        }
    }

    if (interactive) {
        matchesShown_ = matches_;
        outline_.swap(outlineNext_);
        anchors_.swap(anchorsNext_);
        outlineUrl_ = currentUrl_;
    }
    rightInset_ = 0.0f;
    if (pad > 0.0f) ImGui::Unindent(pad);
    ImGui::SetWindowFontScale(1.0f);
}

void App::drawWords(const std::vector<Span>& spans, float scale, const ImVec4* tint, bool interactive,
                    const std::string& base) {
    float zoom = interactive ? settings_.zoom : 1.0f;
    pushTextScale(scale * zoom);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 2.0f));
    const Palette& colors = palette();
    ImDrawList* list = ImGui::GetWindowDrawList();
    float unit = ImGui::GetFontSize();
    float baseScale = unit / ImGui::GetFont()->FontSize;
    float rightEdge = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x - rightInset_;
    float space = ImGui::CalcTextSize(" ").x;
    float boldShift = std::max(0.6f, unit * 0.045f);
    bool first = true;
    bool previousEndedWithSpace = true;
    ImVec4 linkColor = mixColor(colors.primary, kWhite, 0.35f);
    ImVec4 codeColor = mixColor(colors.secondary, kWhite, 0.6f);
    ImVec4 textColor = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    std::string needle = (findOpen_ && interactive) ? lowered(find_) : std::string();

    for (std::size_t s = 0; s < spans.size(); ++s) {
        const Span& span = spans[s];
        bool link = !span.href.empty();
        bool bold = (span.style & kStyleBold) != 0;
        bool italic = (span.style & kStyleItalic) != 0;
        bool code = (span.style & kStyleCode) != 0;
        bool mark = (span.style & kStyleMark) != 0;
        bool strike = (span.style & kStyleStrike) != 0;
        bool underline = link || (span.style & kStyleUnderline) != 0;
        std::string target;
        if (link) target = span.href[0] == '#' ? span.href : resolveUrl(base, span.href);
        bool glue = !first && !previousEndedWithSpace && !span.text.empty() && span.text.front() != ' ';
        bool glueAfter = s + 1 < spans.size() && !span.text.empty() && span.text.back() != ' ' &&
                         !spans[s + 1].text.empty() && spans[s + 1].text.front() != ' ';
        ImVec4 color = tint ? *tint : textColor;
        if (code) color = codeColor;
        if (mark) color = kMarkText;
        if (link) color = linkColor;

        if (code) {
            ImFont* mono = monoFont();
            ImGui::PushFont(mono);
            ImGui::SetWindowFontScale(unit / mono->FontSize);
        }
        bool firstWord = true;
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
            bool gluedBefore = glue;
            glue = false;
            ImVec2 at = ImGui::GetCursorScreenPos();
            bool lastWord = span.text.find_first_not_of(' ', end) == std::string::npos;

            if (!needle.empty() && lowered(std::string(begin, finish)).find(needle) != std::string::npos) {
                ++matches_;
                list->AddRectFilled(ImVec2(at.x - 2.0f, at.y), ImVec2(at.x + size.x + 2.0f, at.y + size.y),
                                    ImGui::GetColorU32(ImVec4(1.0f, 0.78f, 0.15f, 0.55f)), 3.0f);
            }
            if (code || mark) {
                float outer = unit * 0.2f;
                float left = firstWord ? (gluedBefore ? 0.0f : outer) : space * 0.5f;
                float right = lastWord ? (glueAfter ? 0.0f : outer) : space * 0.5f;
                ImDrawFlags corners = ImDrawFlags_RoundCornersNone;
                if (firstWord && lastWord) {
                    corners = ImDrawFlags_RoundCornersAll;
                } else if (firstWord) {
                    corners = ImDrawFlags_RoundCornersLeft;
                } else if (lastWord) {
                    corners = ImDrawFlags_RoundCornersRight;
                }
                ImVec4 fill = mark ? ImVec4(1.0f, 0.84f, 0.28f, 0.95f) : ImVec4(0.04f, 0.05f, 0.09f, 1.0f);
                list->AddRectFilled(ImVec2(at.x - left, at.y - unit * 0.05f), ImVec2(at.x + size.x + right, at.y + size.y + unit * 0.05f),
                                    ImGui::GetColorU32(fill), unit * 0.22f, corners);
            }

            int vertexStart = list->VtxBuffer.Size;
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::TextUnformatted(begin, finish);
            ImGui::PopStyleColor();
            ImVec2 min = ImGui::GetItemRectMin();
            ImVec2 max = ImGui::GetItemRectMax();
            ImU32 packed = ImGui::GetColorU32(color);
            if (bold) list->AddText(ImGui::GetFont(), unit, ImVec2(min.x + boldShift, min.y), packed, begin, finish);
            if (italic) shear(list, vertexStart, min.y + size.y * 0.85f, 0.2f);
            if (underline) list->AddLine(ImVec2(min.x, max.y), max, packed);
            if (strike) list->AddLine(ImVec2(min.x, min.y + size.y * 0.55f), ImVec2(max.x, min.y + size.y * 0.55f), packed);
            if (link && interactive && ImGui::IsItemHovered()) {
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                hoveredLink_ = target;
                if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) pressedLink_ = target;
            }
            first = false;
            firstWord = false;
            start = end + 1;
        }
        if (code) {
            ImGui::PopFont();
            ImGui::SetWindowFontScale(baseScale);
        }
        previousEndedWithSpace = !span.text.empty() && span.text.back() == ' ';
    }
    ImGui::PopStyleVar();
    popTextScale(zoom);
}

}
