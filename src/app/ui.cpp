#include "ui.hpp"

namespace internet {

extern const unsigned char kFontData[];
extern const unsigned long kFontSize;
extern const unsigned char kMonoData[];
extern const unsigned long kMonoSize;

namespace {

constexpr int kFontCount = 3;
ImFont* gFonts[kFontCount] = {nullptr, nullptr, nullptr};
ImFont* gMono = nullptr;
float gSizes[kFontCount] = {17.0f, 34.0f, 76.0f};

}

void setupUi(float scale, bool touch) {
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.MouseDragThreshold = 8.0f * scale;

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 4.0f;
    style.FrameRounding = 4.0f;
    style.ChildRounding = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.FramePadding = touch ? ImVec2(12.0f, 10.0f) : ImVec2(8.0f, 5.0f);
    style.ItemSpacing = touch ? ImVec2(10.0f, 10.0f) : ImVec2(8.0f, 6.0f);
    style.ScrollbarSize = touch ? 16.0f : 14.0f;
    style.ScaleAllSizes(scale);

    static const ImWchar full[] = {0x0020, 0x00FF, 0x0100, 0x017F, 0x2010, 0x2027, 0x2030, 0x203A, 0x20AC, 0x20AC, 0};
    static const ImWchar latin[] = {0x0020, 0x00FF, 0};
    static const ImWchar ascii[] = {0x0020, 0x007E, 0};
    const ImWchar* ranges[kFontCount] = {full, latin, ascii};

    ImFontConfig config;
    config.FontDataOwnedByAtlas = false;
    for (int i = 0; i < kFontCount; ++i) {
        gFonts[i] = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(kFontData), static_cast<int>(kFontSize),
                                                   gSizes[i] * scale, &config, ranges[i]);
        gSizes[i] *= scale;
    }
    gMono = io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(kMonoData), static_cast<int>(kMonoSize),
                                           gSizes[0], &config, latin);
    io.FontDefault = gFonts[0];
}

ImFont* fontForSize(float pixelSize) {
    for (int i = 0; i < kFontCount; ++i) {
        if (gFonts[i] && gSizes[i] >= pixelSize * 0.98f) return gFonts[i];
    }
    return gFonts[kFontCount - 1] ? gFonts[kFontCount - 1] : ImGui::GetFont();
}

ImFont* monoFont() { return gMono ? gMono : ImGui::GetFont(); }

}
