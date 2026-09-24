#pragma once

#include <string>

#include "imgui.h"

namespace internet {

struct Palette {
    const char* name;
    ImVec4 primary;
    ImVec4 secondary;
};

int paletteCount();
const Palette& paletteAt(int index);
void applyTheme(int index);

ImVec4 mixColor(const ImVec4& a, const ImVec4& b, float t);
ImVec4 withAlpha(const ImVec4& color, float alpha);
ImVec4 avatarColor(const std::string& text);
ImU32 packColor(const ImVec4& color);

}
