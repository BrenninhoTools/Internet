#include "theme.hpp"

#include <algorithm>
#include <functional>

namespace internet {

namespace {

const Palette kPalettes[] = {
    {"Ocean", ImVec4(0.23f, 0.51f, 0.96f, 1.0f), ImVec4(0.02f, 0.71f, 0.83f, 1.0f)},
    {"Sunset", ImVec4(0.98f, 0.45f, 0.09f, 1.0f), ImVec4(0.93f, 0.28f, 0.60f, 1.0f)},
    {"Forest", ImVec4(0.13f, 0.77f, 0.37f, 1.0f), ImVec4(0.08f, 0.72f, 0.65f, 1.0f)},
    {"Violet", ImVec4(0.55f, 0.36f, 0.96f, 1.0f), ImVec4(0.85f, 0.27f, 0.94f, 1.0f)},
    {"Candy", ImVec4(0.96f, 0.25f, 0.37f, 1.0f), ImVec4(0.96f, 0.62f, 0.04f, 1.0f)},
};

}

int paletteCount() { return static_cast<int>(sizeof kPalettes / sizeof kPalettes[0]); }

const Palette& paletteAt(int index) { return kPalettes[std::clamp(index, 0, paletteCount() - 1)]; }

ImVec4 mixColor(const ImVec4& a, const ImVec4& b, float t) {
    return ImVec4(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t, a.w + (b.w - a.w) * t);
}

ImVec4 withAlpha(const ImVec4& color, float alpha) { return ImVec4(color.x, color.y, color.z, alpha); }

ImU32 packColor(const ImVec4& color) { return ImGui::ColorConvertFloat4ToU32(color); }

ImVec4 avatarColor(const std::string& text) {
    std::size_t hash = std::hash<std::string>{}(text);
    float hue = static_cast<float>(hash % 360) / 360.0f;
    float r = 0.0f;
    float g = 0.0f;
    float b = 0.0f;
    ImGui::ColorConvertHSVtoRGB(hue, 0.62f, 0.95f, r, g, b);
    return ImVec4(r, g, b, 1.0f);
}

void applyTheme(int index) {
    const Palette& palette = paletteAt(index);
    const ImVec4& primary = palette.primary;
    const ImVec4& secondary = palette.secondary;
    ImVec4* colors = ImGui::GetStyle().Colors;

    const ImVec4 background(0.050f, 0.058f, 0.092f, 1.0f);
    const ImVec4 panel(0.082f, 0.094f, 0.140f, 1.0f);
    const ImVec4 frame(0.125f, 0.140f, 0.204f, 1.0f);

    colors[ImGuiCol_Text] = ImVec4(0.93f, 0.94f, 0.98f, 1.0f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.52f, 0.56f, 0.68f, 1.0f);
    colors[ImGuiCol_WindowBg] = background;
    colors[ImGuiCol_ChildBg] = panel;
    colors[ImGuiCol_PopupBg] = ImVec4(0.09f, 0.10f, 0.15f, 0.98f);
    colors[ImGuiCol_Border] = mixColor(frame, primary, 0.28f);
    colors[ImGuiCol_FrameBg] = frame;
    colors[ImGuiCol_FrameBgHovered] = mixColor(frame, primary, 0.28f);
    colors[ImGuiCol_FrameBgActive] = mixColor(frame, primary, 0.42f);
    colors[ImGuiCol_Button] = mixColor(frame, primary, 0.55f);
    colors[ImGuiCol_ButtonHovered] = primary;
    colors[ImGuiCol_ButtonActive] = secondary;
    colors[ImGuiCol_Header] = mixColor(frame, primary, 0.38f);
    colors[ImGuiCol_HeaderHovered] = mixColor(frame, primary, 0.62f);
    colors[ImGuiCol_HeaderActive] = primary;
    colors[ImGuiCol_CheckMark] = secondary;
    colors[ImGuiCol_SliderGrab] = primary;
    colors[ImGuiCol_SliderGrabActive] = secondary;
    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.18f);
    colors[ImGuiCol_ScrollbarGrab] = mixColor(frame, primary, 0.5f);
    colors[ImGuiCol_ScrollbarGrabHovered] = primary;
    colors[ImGuiCol_ScrollbarGrabActive] = secondary;
    colors[ImGuiCol_Separator] = mixColor(frame, primary, 0.3f);
    colors[ImGuiCol_TextSelectedBg] = withAlpha(primary, 0.4f);
    colors[ImGuiCol_NavHighlight] = secondary;
}

}
