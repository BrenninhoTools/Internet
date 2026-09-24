#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cstdio>
#include <cstring>
#include <filesystem>

#include "app.hpp"
#include "ui.hpp"

namespace fs = std::filesystem;

namespace internet {

namespace {

const ImVec4 kErrorColor(1.0f, 0.42f, 0.42f, 1.0f);
const ImVec4 kGoodColor(0.45f, 0.85f, 0.5f, 1.0f);
const ImVec4 kDimColor(0.62f, 0.62f, 0.68f, 1.0f);
const ImVec4 kGold(1.0f, 0.78f, 0.2f, 1.0f);
const ImVec4 kWhite(1.0f, 1.0f, 1.0f, 1.0f);

struct EditorCallback {
    std::string* text;
    int* cursor;
    int* pendingCursor;
};

int editorCallback(ImGuiInputTextCallbackData* data) {
    EditorCallback* context = static_cast<EditorCallback*>(data->UserData);
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        context->text->resize(static_cast<std::size_t>(data->BufTextLen));
        data->Buf = context->text->data();
    } else if (data->EventFlag == ImGuiInputTextFlags_CallbackAlways) {
        if (*context->pendingCursor >= 0) {
            int position = std::min(*context->pendingCursor, data->BufTextLen);
            data->CursorPos = position;
            data->SelectionStart = position;
            data->SelectionEnd = position;
            *context->pendingCursor = -1;
        }
        *context->cursor = data->CursorPos;
    }
    return 0;
}

std::string trimmed(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool isHtmlPath(const std::string& path) {
    std::string lower = lowered(path);
    auto ends = [&](const char* suffix) {
        std::size_t length = std::strlen(suffix);
        return lower.size() >= length && lower.compare(lower.size() - length, length, suffix) == 0;
    };
    return ends(".html") || ends(".htm");
}

std::string baseName(const std::string& path) {
    std::size_t slash = path.rfind('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string stem(const std::string& path) {
    std::string name = baseName(path);
    std::size_t dot = name.rfind('.');
    return dot == std::string::npos || dot == 0 ? name : name.substr(0, dot);
}

std::string parentOf(const std::string& path) {
    std::size_t slash = path.rfind('/');
    return slash == std::string::npos ? std::string() : path.substr(0, slash + 1);
}

void copyBuffer(char* target, std::size_t size, const std::string& text) {
    std::snprintf(target, size, "%s", text.c_str());
}

}

bool App::editorDirty() const { return !ed_.current.empty() && !ed_.binary && ed_.text != ed_.saved; }

std::string App::editorLiveUrl(const std::string& path) const {
    return "internet://" + ed_.siteName + "/" + percentEncode(path, "/");
}

void App::scanSiteFiles() {
    ed_.files = listSiteFiles(ed_.root);
    ed_.rescan = false;
    ed_.scanned = time_;
}

void App::openEditor() {
    fs::path root(trimmed(nodeFolder_));
    if (root.empty()) {
        toast("Choose a site folder first");
        return;
    }
    std::error_code error;
    if (!fs::exists(root, error)) {
        if (root.lexically_normal().generic_string() == defaultSiteFolder()) {
            ensureSampleSite(root);
        } else {
            fs::create_directories(root, error);
        }
    }
    if (!fs::is_directory(root, error)) {
        toast("Cannot open the site folder");
        return;
    }
    if (ed_.root != root) {
        ed_ = EditorState{};
        ed_.root = root;
    }
    ed_.siteName = trimmed(nodeName_);
    ed_.rescan = true;
    editor_ = true;
    menuOpen_ = false;
    pageFade_ = 0.0f;
    scanSiteFiles();
    if (ed_.current.empty()) {
        std::string first = "index.html";
        bool hasIndex = std::any_of(ed_.files.begin(), ed_.files.end(),
                                    [&](const SiteFile& file) { return !file.directory && file.path == first; });
        if (hasIndex) {
            editorOpenFile(first, true);
        } else {
            auto page = std::find_if(ed_.files.begin(), ed_.files.end(),
                                     [](const SiteFile& file) { return !file.directory && isHtmlPath(file.path); });
            if (page != ed_.files.end()) editorOpenFile(page->path, true);
        }
    }
}

void App::closeEditor() { editor_ = false; }

void App::editorOpenFile(const std::string& path, bool force) {
    if (!force && editorDirty() && path != ed_.current) {
        ed_.afterDiscard = path;
        ed_.openDiscard = true;
        return;
    }
    ed_.target = path;
    ed_.current = path;
    ed_.previewValid = false;
    ed_.cursor = 0;
    ed_.pendingCursor = 0;
    ed_.notice.clear();
    if (!isTextPath(path)) {
        ed_.binary = true;
        ed_.text.clear();
        ed_.saved.clear();
        ed_.notice = "This kind of file cannot be edited as text.";
        return;
    }
    std::string content;
    std::string error;
    if (readSiteFile(ed_.root, path, content, error)) {
        ed_.binary = false;
        ed_.text = std::move(content);
        ed_.saved = ed_.text;
    } else {
        ed_.binary = true;
        ed_.text.clear();
        ed_.saved.clear();
        ed_.notice = error;
        toast(error);
    }
}

void App::editorSave() {
    if (ed_.current.empty() || ed_.binary) return;
    std::string error;
    if (!writeSiteFile(ed_.root, ed_.current, ed_.text, error)) {
        toast(error);
        return;
    }
    ed_.saved = ed_.text;
    ed_.rescan = true;
    ed_.securityLevel = 0;
    ed_.securityNote.clear();
    if (security_->settings().scanOnSave) {
        ScanResult scan = security_->scanBuffer(ed_.current, ed_.text, "editor");
        if (scan.verdict == Verdict::Clean) {
            ed_.securityLevel = 1;
            ed_.securityNote = "Security scan: clean";
            toast("Saved " + baseName(ed_.current), ToastKind::Success);
        } else {
            const Finding* strongest = strongestFinding(scan);
            ed_.securityLevel = scan.verdict == Verdict::Malicious ? 3 : 2;
            ed_.securityNote = std::string("Security scan: ") + (strongest ? strongest->rule + " - " + strongest->description : "suspicious content");
            toast("Saved, but the security scan found a problem: " + (strongest ? strongest->rule : std::string("suspicious")),
                  scan.verdict == Verdict::Malicious ? ToastKind::Error : ToastKind::Warning);
        }
    } else {
        toast("Saved " + baseName(ed_.current), ToastKind::Success);
    }
    std::string live = editorLiveUrl(ed_.current);
    std::string base = "internet://" + ed_.siteName + "/";
    bool showsThisFile = currentUrl_ == live || (ed_.current == "index.html" && currentUrl_ == base);
    if (!home_ && showsThisFile) reload();
}

void App::editorInsert(const std::string& snippet) {
    if (ed_.binary || ed_.current.empty()) return;
    int position = std::clamp(ed_.cursor, 0, static_cast<int>(ed_.text.size()));
    ed_.text.insert(static_cast<std::size_t>(position), snippet);
    ed_.pendingCursor = position + static_cast<int>(snippet.size());
    ed_.focusEditor = true;
}

void App::editorPublish() {
    if (editorDirty()) editorSave();
    if (!node_) {
        hostSite();
        if (!node_) return;
    }
    if (ed_.current.empty() || ed_.current == "index.html") {
        pendingNavigation_ = "internet://" + ed_.siteName + "/";
    } else {
        pendingNavigation_ = editorLiveUrl(ed_.current);
    }
    toast("Opening the live site");
}

void App::drawEditorHeader(bool compact) {
    float unit = ImGui::GetFontSize();
    float frame = ImGui::GetFrameHeight();
    float spacing = ImGui::GetStyle().ItemSpacing.x;
    bool dirty = editorDirty();
    bool html = !ed_.current.empty() && !ed_.binary && isHtmlPath(ed_.current);
    ImDrawList* list = ImGui::GetWindowDrawList();

    if (compact) {
        float third = (ImGui::GetContentRegionAvail().x - spacing * 2.0f) / 3.0f;
        if (ed_.mode == 0) ed_.mode = 1;
        if (textButton("mode-files", "Files", Icon::Folder, ed_.mode == 3, third)) ed_.mode = 3;
        ImGui::SameLine();
        if (textButton("mode-edit", "Edit", Icon::Pencil, ed_.mode == 1, third)) ed_.mode = 1;
        ImGui::SameLine();
        if (textButton("mode-preview", "Preview", Icon::Eye, ed_.mode == 2, third)) ed_.mode = 2;
    } else {
        ImVec2 position = ImGui::GetCursorScreenPos();
        list->AddCircleFilled(ImVec2(position.x + frame * 0.5f, position.y + frame * 0.5f), frame * 0.5f,
                              packColor(palette().primary), 20);
        drawIcon(list, Icon::Pencil, ImVec2(position.x + frame * 0.5f, position.y + frame * 0.5f), frame * 0.55f,
                 IM_COL32(255, 255, 255, 255));
        ImGui::Dummy(ImVec2(frame, frame));
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::Text("Editing");
        ImGui::SameLine();
        ImGui::TextColored(mixColor(palette().secondary, kWhite, 0.3f), "internet://%s/", ed_.siteName.c_str());
        ImGui::SameLine(0.0f, unit * 1.6f);
        if (textButton("mode-split", "Split", Icon::Panel, ed_.mode == 0)) ed_.mode = 0;
        ImGui::SameLine();
        if (textButton("mode-edit", "Edit", Icon::Pencil, ed_.mode == 1)) ed_.mode = 1;
        ImGui::SameLine();
        if (textButton("mode-preview", "Preview", Icon::Eye, ed_.mode == 2)) ed_.mode = 2;
    }

    ImGui::Dummy(ImVec2(0, 2.0f));
    ImGui::AlignTextToFramePadding();
    if (ed_.current.empty()) {
        ImGui::TextColored(kDimColor, "No file open");
    } else {
        ImGui::TextUnformatted(fitText(ed_.current, unit, unit * (compact ? 9.0f : 20.0f)).c_str());
        if (dirty) {
            ImGui::SameLine();
            ImGui::TextColored(kGold, "unsaved");
        }
        if (ed_.securityLevel > 0 && !dirty) {
            ImGui::SameLine();
            ImVec2 spot = ImGui::GetCursorScreenPos();
            float size = ImGui::GetFrameHeight();
            ImVec4 chip = ed_.securityLevel == 1 ? ImVec4(0.28f, 0.84f, 0.52f, 1.0f) : (ed_.securityLevel == 2 ? ImVec4(1.0f, 0.74f, 0.20f, 1.0f) : ImVec4(0.95f, 0.30f, 0.34f, 1.0f));
            ImGui::Dummy(ImVec2(size, size));
            drawIcon(ImGui::GetWindowDrawList(), ed_.securityLevel == 1 ? Icon::Shield : Icon::Warning, ImVec2(spot.x + size * 0.5f, spot.y + size * 0.5f), size * 0.6f, packColor(chip));
            if (ImGui::IsItemHovered() && !touch_) ImGui::SetTooltip("%s", ed_.securityNote.c_str());
        }
    }
    ImGui::SameLine();
    if (compact) {
        if (iconButton("save", Icon::Save, "Save", dirty, dirty)) editorSave();
        ImGui::SameLine();
        if (iconButton("live", Icon::Globe, "Open the live site")) editorPublish();
    } else {
        if (textButton("save", "Save", Icon::Save, dirty)) editorSave();
        ImGui::SameLine();
        if (textButton("live", node_ ? "Open live" : "Publish", Icon::Globe, false)) editorPublish();
        ImGui::SameLine();
        if (textButton("revert", "Revert", Icon::Reload, false) && dirty) {
            ed_.text = ed_.saved;
            ed_.previewValid = false;
        }
    }

    if (html && (!compact || ed_.mode == 1)) {
        struct Snippet {
            const char* label;
            const char* text;
        };
        static const Snippet snippets[] = {
            {"H1", "<h1>Heading</h1>\n"},
            {"H2", "<h2>Subheading</h2>\n"},
            {"Text", "<p>Write something here.</p>\n"},
            {"Link", "<a href=\"page.html\">link text</a>"},
            {"List", "<ul>\n<li>First item</li>\n<li>Second item</li>\n</ul>\n"},
            {"Rule", "<hr>\n"},
            {"Bold", "<b>bold text</b>"},
            {"Code", "<pre>code goes here</pre>\n"},
        };
        float right = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
        bool first = true;
        auto place = [&](float width) {
            if (!first) {
                float next = ImGui::GetItemRectMax().x + spacing + width;
                if (next <= right) ImGui::SameLine();
            }
            first = false;
        };
        for (const Snippet& snippet : snippets) {
            float width = textWidth(unit, snippet.label) + unit * 1.4f;
            place(width);
            ImGui::PushStyleColor(ImGuiCol_Button, mixColor(ImGui::GetStyleColorVec4(ImGuiCol_FrameBg), palette().primary, 0.3f));
            if (ImGui::Button(snippet.label, ImVec2(width, 0))) editorInsert(snippet.text);
            ImGui::PopStyleColor();
        }
        float linkWidth = textWidth(unit, "Page link") + unit * 1.4f;
        place(linkWidth);
        if (ImGui::Button("Page link", ImVec2(linkWidth, 0))) ed_.openLinks = true;
    }
    ImGui::Spacing();
}

void App::drawFileTree(float width, float height) {
    float unit = ImGui::GetFontSize();
    ImGui::BeginChild("##files", ImVec2(width, height), ImGuiChildFlags_Borders);
    touchScroll();
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImGui::TextColored(kDimColor, "FILES");
    ImGui::SameLine();
    float buttons = 3.0f * (ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.x);
    ImGui::SameLine(std::max(ImGui::GetCursorPosX(), ImGui::GetWindowContentRegionMax().x - buttons));
    if (iconButton("file-new", Icon::Plus, "New file or folder")) {
        std::string prefix = ed_.target;
        bool targetIsDirectory = std::any_of(ed_.files.begin(), ed_.files.end(), [&](const SiteFile& file) {
            return file.directory && file.path == ed_.target;
        });
        prefix = targetIsDirectory ? ed_.target + "/" : parentOf(ed_.target);
        copyBuffer(ed_.nameBuffer, sizeof ed_.nameBuffer, prefix + "new-page.html");
        ed_.templateIndex = 0;
        ed_.error.clear();
        ed_.openNew = true;
    }
    ImGui::SameLine();
    if (iconButton("file-rename", Icon::Pencil, "Rename", !ed_.target.empty())) {
        copyBuffer(ed_.nameBuffer, sizeof ed_.nameBuffer, ed_.target);
        ed_.error.clear();
        ed_.openRename = true;
    }
    ImGui::SameLine();
    if (iconButton("file-delete", Icon::Trash, "Delete", !ed_.target.empty())) {
        ed_.error.clear();
        ed_.openDelete = true;
    }
    ImGui::Separator();

    if (ed_.files.empty()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(kDimColor, "This folder is empty. Press + to create your first page.");
        ImGui::PopTextWrapPos();
    }

    float indentStep = unit * 1.1f;
    for (const SiteFile& file : ed_.files) {
        int depth = static_cast<int>(std::count(file.path.begin(), file.path.end(), '/'));
        ImVec2 position = ImGui::GetCursorScreenPos();
        float line = ImGui::GetTextLineHeight();
        float offset = depth * indentStep;
        drawIcon(list, file.directory ? Icon::Folder : Icon::File,
                 ImVec2(position.x + offset + line * 0.6f, position.y + line * 0.5f), line * 0.95f,
                 packColor(file.directory ? kGold : mixColor(palette().primary, kWhite, 0.4f)));
        ImGui::Indent(offset + line * 1.5f);
        std::string label = baseName(file.path) + "##" + file.path;
        bool selected = file.path == ed_.target;
        if (ImGui::Selectable(label.c_str(), selected)) {
            ed_.target = file.path;
            if (!file.directory) {
                editorOpenFile(file.path, false);
                if (compact_) ed_.mode = 1;
            }
        }
        if (ImGui::BeginPopupContextItem()) {
            if (ImGui::MenuItem("Rename")) {
                ed_.target = file.path;
                copyBuffer(ed_.nameBuffer, sizeof ed_.nameBuffer, file.path);
                ed_.error.clear();
                ed_.openRename = true;
            }
            if (ImGui::MenuItem("Delete")) {
                ed_.target = file.path;
                ed_.error.clear();
                ed_.openDelete = true;
            }
            ImGui::EndPopup();
        }
        if (!file.directory && ImGui::IsItemHovered() && !touch_) {
            ImGui::SetTooltip("%s (%llu bytes)", file.path.c_str(), static_cast<unsigned long long>(file.size));
        }
        if (file.path == ed_.current && editorDirty()) {
            ImVec2 max = ImGui::GetItemRectMax();
            list->AddCircleFilled(ImVec2(max.x - unit * 0.6f, position.y + line * 0.5f), unit * 0.22f, packColor(kGold), 12);
        }
        ImGui::Unindent(offset + line * 1.5f);
    }
    ImGui::EndChild();
}

void App::drawEditorPane(float width, float height) {
    float unit = ImGui::GetFontSize();
    ImGui::BeginChild("##editorPane", ImVec2(width, height), ImGuiChildFlags_Borders, ImGuiWindowFlags_NoScrollbar);
    if (ed_.current.empty()) {
        ImGui::Dummy(ImVec2(0, unit));
        pushTextScale(1.3f);
        ImGui::TextUnformatted("Pick a file to start editing");
        popTextScale(1.0f);
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(kDimColor, "Choose a page from the file list, or press + to create a new one from a template.");
        ImGui::PopTextWrapPos();
    } else if (ed_.binary) {
        ImGui::Dummy(ImVec2(0, unit));
        pushTextScale(1.3f);
        ImGui::TextUnformatted(baseName(ed_.current).c_str());
        popTextScale(1.0f);
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(kDimColor, "%s", ed_.notice.c_str());
        ImGui::PopTextWrapPos();
    } else {
        float statusHeight = ImGui::GetFrameHeightWithSpacing();
        ImGui::PushFont(monoFont());
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.04f, 0.05f, 0.09f, 1.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(unit * 0.6f, unit * 0.5f));
        EditorCallback context{&ed_.text, &ed_.cursor, &ed_.pendingCursor};
        if (ed_.focusEditor) {
            ImGui::SetKeyboardFocusHere();
            ed_.focusEditor = false;
        }
        ImGuiInputTextFlags flags = ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CallbackResize |
                                    ImGuiInputTextFlags_CallbackAlways;
        ImGui::InputTextMultiline("##editor", ed_.text.data(), ed_.text.capacity() + 1,
                                  ImVec2(-FLT_MIN, ImGui::GetContentRegionAvail().y - statusHeight), flags, editorCallback,
                                  &context);
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        ImGui::PopFont();

        int line = 1;
        int column = 1;
        int limit = std::min(ed_.cursor, static_cast<int>(ed_.text.size()));
        for (int i = 0; i < limit; ++i) {
            if (ed_.text[static_cast<std::size_t>(i)] == '\n') {
                ++line;
                column = 1;
            } else {
                ++column;
            }
        }
        ImGui::TextColored(kDimColor, "Line %d, column %d   %zu characters", line, column, ed_.text.size());
        if (editorDirty()) {
            ImGui::SameLine();
            ImGui::TextColored(kGold, "  Ctrl+S to save");
        }
    }
    ImGui::EndChild();
}

void App::drawPreviewPane(float width, float height) {
    float unit = ImGui::GetFontSize();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.06f, 0.07f, 0.11f, 1.0f));
    ImGui::BeginChild("##previewPane", ImVec2(width, height), ImGuiChildFlags_Borders);
    touchScroll();
    if (ed_.current.empty() || ed_.binary) {
        ImGui::TextColored(kDimColor, "The preview appears here.");
    } else {
        if (!ed_.previewValid || ed_.text != ed_.previewSource) {
            ed_.preview = isHtmlPath(ed_.current) ? parseMarkup(ed_.text) : parsePlain(ed_.text);
            ed_.previewSource = ed_.text;
            ed_.previewValid = true;
        }
        ImVec2 position = ImGui::GetCursorScreenPos();
        drawIcon(ImGui::GetWindowDrawList(), Icon::Eye, ImVec2(position.x + unit * 0.6f, position.y + unit * 0.6f), unit,
                 packColor(kDimColor));
        ImGui::SetCursorScreenPos(ImVec2(position.x + unit * 1.5f, position.y));
        ImGui::TextColored(kDimColor, "Live preview");
        ImGui::Spacing();
        drawDocument(ed_.preview, false, editorLiveUrl(ed_.current));
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void App::drawEditor() {
    float unit = ImGui::GetFontSize();
    float spacing = ImGui::GetStyle().ItemSpacing.x;
    if (ed_.rescan || time_ - ed_.scanned > 3.0) scanSiteFiles();
    drawEditorHeader(compact_);

    ImVec2 available = ImGui::GetContentRegionAvail();
    float height = std::max(unit * 6.0f, available.y);
    if (compact_) {
        if (ed_.mode == 3) {
            drawFileTree(available.x, height);
        } else if (ed_.mode == 2) {
            drawPreviewPane(available.x, height);
        } else {
            drawEditorPane(available.x, height);
        }
    } else {
        float filesWidth = unit * 13.0f;
        drawFileTree(filesWidth, height);
        ImGui::SameLine();
        float remaining = available.x - filesWidth - spacing;
        if (ed_.mode == 0) {
            float half = (remaining - spacing) * 0.5f;
            drawEditorPane(half, height);
            ImGui::SameLine();
            drawPreviewPane(half, height);
        } else if (ed_.mode == 1) {
            drawEditorPane(remaining, height);
        } else {
            drawPreviewPane(remaining, height);
        }
    }
    drawEditorPopups();
}

void App::drawEditorPopups() {
    float unit = ImGui::GetFontSize();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImVec2 center(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.4f);
    float popupWidth = std::min(unit * 28.0f, viewport->WorkSize.x - unit * 2.0f);

    if (ed_.openNew) {
        ImGui::OpenPopup("New file");
        ed_.openNew = false;
    }
    if (ed_.openRename) {
        ImGui::OpenPopup("Rename");
        ed_.openRename = false;
    }
    if (ed_.openDelete) {
        ImGui::OpenPopup("Delete");
        ed_.openDelete = false;
    }
    if (ed_.openDiscard) {
        ImGui::OpenPopup("Unsaved changes");
        ed_.openDiscard = false;
    }
    if (ed_.openLinks) {
        ImGui::OpenPopup("Insert page link");
        ed_.openLinks = false;
    }

    ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(popupWidth, 0.0f));
    if (ImGui::BeginPopupModal("New file", nullptr, ImGuiWindowFlags_NoResize)) {
        ImGui::TextColored(kDimColor, "Name (end with / to create a folder)");
        ImGui::SetNextItemWidth(-1);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        bool entered = ImGui::InputText("##newname", ed_.nameBuffer, sizeof ed_.nameBuffer, ImGuiInputTextFlags_EnterReturnsTrue);
        std::string name = trimmed(ed_.nameBuffer);
        bool folder = !name.empty() && name.back() == '/';
        bool html = name.empty() || folder ? false : (name.find('.') == std::string::npos || isHtmlPath(name));
        if (html) {
            ImGui::TextColored(kDimColor, "Template");
            std::vector<std::string> names = siteTemplateNames();
            ImGui::SetNextItemWidth(-1);
            if (ImGui::BeginCombo("##template", names[static_cast<std::size_t>(ed_.templateIndex)].c_str())) {
                for (int i = 0; i < static_cast<int>(names.size()); ++i) {
                    if (ImGui::Selectable(names[static_cast<std::size_t>(i)].c_str(), i == ed_.templateIndex))
                        ed_.templateIndex = i;
                }
                ImGui::EndCombo();
            }
        }
        if (!ed_.error.empty()) ImGui::TextColored(kErrorColor, "%s", ed_.error.c_str());
        ImGui::Spacing();
        bool create = entered;
        if (textButton("new-create", "Create", Icon::Plus, true)) create = true;
        ImGui::SameLine();
        if (textButton("new-cancel", "Cancel", Icon::Close, false)) ImGui::CloseCurrentPopup();
        if (create) {
            std::string path = name;
            std::size_t lastSlash = path.rfind('/');
            std::string lastName = lastSlash == std::string::npos ? path : path.substr(lastSlash + 1);
            if (!path.empty() && path.back() != '/' && lastName.find('.') == std::string::npos) path += ".html";
            std::string content;
            if (!path.empty() && isHtmlPath(path)) content = siteTemplate(ed_.templateIndex, ed_.siteName, stem(path));
            std::string error;
            if (createSitePath(ed_.root, path, content, error)) {
                ed_.rescan = true;
                ed_.target = path;
                if (path.back() != '/') editorOpenFile(path, false);
                toast("Created " + path);
                ImGui::CloseCurrentPopup();
            } else {
                ed_.error = error;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(popupWidth, 0.0f));
    if (ImGui::BeginPopupModal("Rename", nullptr, ImGuiWindowFlags_NoResize)) {
        ImGui::TextColored(kDimColor, "New name for %s", ed_.target.c_str());
        ImGui::SetNextItemWidth(-1);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        bool entered = ImGui::InputText("##rename", ed_.nameBuffer, sizeof ed_.nameBuffer, ImGuiInputTextFlags_EnterReturnsTrue);
        if (!ed_.error.empty()) ImGui::TextColored(kErrorColor, "%s", ed_.error.c_str());
        ImGui::Spacing();
        bool apply = entered;
        if (textButton("rename-apply", "Rename", Icon::Pencil, true)) apply = true;
        ImGui::SameLine();
        if (textButton("rename-cancel", "Cancel", Icon::Close, false)) ImGui::CloseCurrentPopup();
        if (apply) {
            std::string to = trimmed(ed_.nameBuffer);
            std::string error;
            if (renameSitePath(ed_.root, ed_.target, to, error)) {
                if (ed_.current == ed_.target) {
                    ed_.current = to;
                } else if (ed_.current.rfind(ed_.target + "/", 0) == 0) {
                    ed_.current = to + ed_.current.substr(ed_.target.size());
                }
                ed_.target = to;
                ed_.rescan = true;
                toast("Renamed to " + baseName(to));
                ImGui::CloseCurrentPopup();
            } else {
                ed_.error = error;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(popupWidth, 0.0f));
    if (ImGui::BeginPopupModal("Delete", nullptr, ImGuiWindowFlags_NoResize)) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::Text("Delete %s?", ed_.target.c_str());
        ImGui::TextColored(kDimColor, "This cannot be undone.");
        ImGui::PopTextWrapPos();
        if (!ed_.error.empty()) ImGui::TextColored(kErrorColor, "%s", ed_.error.c_str());
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Button, kErrorColor);
        bool confirmed = ImGui::Button("Delete", ImVec2(unit * 7.0f, 0));
        ImGui::PopStyleColor();
        ImGui::SameLine();
        if (textButton("delete-cancel", "Cancel", Icon::Close, false)) ImGui::CloseCurrentPopup();
        if (confirmed) {
            std::string error;
            if (deleteSitePath(ed_.root, ed_.target, error)) {
                if (ed_.current == ed_.target || ed_.current.rfind(ed_.target + "/", 0) == 0) {
                    ed_.current.clear();
                    ed_.text.clear();
                    ed_.saved.clear();
                    ed_.binary = false;
                    ed_.previewValid = false;
                }
                ed_.target.clear();
                ed_.rescan = true;
                toast("Deleted");
                ImGui::CloseCurrentPopup();
            } else {
                ed_.error = error;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(popupWidth, 0.0f));
    if (ImGui::BeginPopupModal("Unsaved changes", nullptr, ImGuiWindowFlags_NoResize)) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::Text("%s has changes that are not saved.", ed_.current.c_str());
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        if (textButton("discard-save", "Save", Icon::Save, true)) {
            editorSave();
            std::string next = ed_.afterDiscard;
            ImGui::CloseCurrentPopup();
            editorOpenFile(next, true);
        }
        ImGui::SameLine();
        if (textButton("discard-drop", "Discard", Icon::Trash, false)) {
            std::string next = ed_.afterDiscard;
            ImGui::CloseCurrentPopup();
            editorOpenFile(next, true);
        }
        ImGui::SameLine();
        if (textButton("discard-cancel", "Cancel", Icon::Close, false)) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(popupWidth, std::min(unit * 22.0f, viewport->WorkSize.y * 0.7f)));
    if (ImGui::BeginPopupModal("Insert page link", nullptr, ImGuiWindowFlags_NoResize)) {
        ImGui::TextColored(kDimColor, "Choose a page to link to");
        ImGui::BeginChild("##linklist", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
        touchScroll();
        bool any = false;
        for (const SiteFile& file : ed_.files) {
            if (file.directory || !isHtmlPath(file.path)) continue;
            any = true;
            std::string label = file.path + "##link" + file.path;
            if (ImGui::Selectable(label.c_str())) {
                editorInsert("<a href=\"" + file.path + "\">" + stem(file.path) + "</a>");
                ImGui::CloseCurrentPopup();
            }
        }
        if (!any) ImGui::TextColored(kDimColor, "There are no other pages yet.");
        ImGui::EndChild();
        if (textButton("links-cancel", "Cancel", Icon::Close, false)) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

}
