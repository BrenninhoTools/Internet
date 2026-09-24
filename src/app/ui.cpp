#include "ui.hpp"

#include "imgui.h"

namespace internet {

extern const unsigned char kFontData[];
extern const unsigned long kFontSize;

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

    static const ImWchar ranges[] = {0x0020, 0x00FF, 0x0100, 0x017F, 0x2010, 0x2027, 0x2030, 0x203A, 0x20AC, 0x20AC, 0};
    ImFontConfig config;
    config.FontDataOwnedByAtlas = false;
    io.Fonts->AddFontFromMemoryTTF(const_cast<unsigned char*>(kFontData), static_cast<int>(kFontSize), 17.0f * scale,
                                   &config, ranges);
}

}
