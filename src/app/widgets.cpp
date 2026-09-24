#include "widgets.hpp"

#include "ui.hpp"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <random>

namespace internet {

namespace {

constexpr float kPi = 3.14159265358979f;
constexpr int kParticleCount = 46;

ImVec2 offset(ImVec2 center, float x, float y) { return ImVec2(center.x + x, center.y + y); }

}

float clamp01(float value) { return std::clamp(value, 0.0f, 1.0f); }

float easeOutCubic(float t) {
    float inverse = 1.0f - clamp01(t);
    return 1.0f - inverse * inverse * inverse;
}

float easeOutBack(float t) {
    t = clamp01(t);
    const float c1 = 1.70158f;
    const float c3 = c1 + 1.0f;
    float shifted = t - 1.0f;
    return 1.0f + c3 * shifted * shifted * shifted + c1 * shifted * shifted;
}

float smoothStep(float t) {
    t = clamp01(t);
    return t * t * (3.0f - 2.0f * t);
}

void approach(float& value, float target, float rate, float dt) {
    value += (target - value) * std::min(1.0f, rate * dt);
}

ImU32 scaleAlpha(ImU32 color, float alpha) {
    ImU32 current = (color >> IM_COL32_A_SHIFT) & 0xFF;
    ImU32 scaled = static_cast<ImU32>(static_cast<float>(current) * clamp01(alpha));
    return (color & ~IM_COL32_A_MASK) | (scaled << IM_COL32_A_SHIFT);
}

void drawEllipse(ImDrawList* list, ImVec2 center, float radiusX, float radiusY, ImU32 color, float thickness) {
    constexpr int segments = 48;
    ImVec2 points[segments];
    for (int i = 0; i < segments; ++i) {
        float angle = 2.0f * kPi * static_cast<float>(i) / segments;
        points[i] = offset(center, std::cos(angle) * radiusX, std::sin(angle) * radiusY);
    }
    list->AddPolyline(points, segments, color, ImDrawFlags_Closed, thickness);
}

void drawSpinner(ImDrawList* list, ImVec2 center, float radius, ImU32 color, float time) {
    float start = time * 6.0f;
    float sweep = 1.6f + 1.2f * std::sin(time * 3.0f);
    list->PathClear();
    list->PathArcTo(center, radius, start, start + sweep, 24);
    list->PathStroke(color, ImDrawFlags_None, std::max(2.0f, radius * 0.28f));
}

void drawShield(ImDrawList* list, ImVec2 center, float size, ImU32 color, float pulse, int mark, float time) {
    ImVec4 base = ImGui::ColorConvertU32ToFloat4(color);
    ImU32 glow = ImGui::ColorConvertFloat4ToU32(ImVec4(base.x, base.y, base.z, 0.10f + 0.08f * pulse));
    for (int ring = 0; ring < 4; ++ring) list->AddCircleFilled(center, size * (0.62f + 0.16f * static_cast<float>(ring) + 0.05f * pulse), glow, 40);

    const int steps = 10;
    std::vector<ImVec2> outline;
    outline.push_back(offset(center, 0.0f, -size * 0.5f));
    for (int i = 1; i <= steps; ++i) {
        float t = static_cast<float>(i) / steps;
        outline.push_back(offset(center, size * 0.42f * t, -size * 0.5f + size * 0.10f * std::sin(t * kPi * 0.5f) - size * 0.02f * t));
    }
    for (int i = 1; i <= steps; ++i) {
        float t = static_cast<float>(i) / steps;
        float x = size * 0.42f * (1.0f - std::pow(t, 1.8f));
        float y = -size * 0.4f + size * 0.9f * std::pow(t, 0.9f);
        outline.push_back(offset(center, x, y));
    }
    std::vector<ImVec2> left;
    for (auto it = outline.rbegin(); it != outline.rend(); ++it) left.push_back(offset(center, -(it->x - center.x), it->y - center.y));
    std::vector<ImVec2> full = outline;
    for (std::size_t i = 1; i + 1 < left.size(); ++i) full.push_back(left[i]);

    ImU32 top = ImGui::ColorConvertFloat4ToU32(ImVec4(std::min(1.0f, base.x + 0.18f), std::min(1.0f, base.y + 0.18f), std::min(1.0f, base.z + 0.18f), 1.0f));
    for (std::size_t i = 1; i + 1 < full.size(); ++i) list->AddTriangleFilled(full[0], full[i], full[i + 1], i % 2 == 0 ? color : top);
    list->AddPolyline(full.data(), static_cast<int>(full.size()), IM_COL32(255, 255, 255, 235), ImDrawFlags_Closed, std::max(2.0f, size * 0.04f));

    ImU32 white = IM_COL32(255, 255, 255, 255);
    float thickness = std::max(2.5f, size * 0.07f);
    if (mark == 0) {
        list->AddLine(offset(center, -size * 0.18f, size * 0.02f), offset(center, -size * 0.04f, size * 0.16f), white, thickness);
        list->AddLine(offset(center, -size * 0.04f, size * 0.16f), offset(center, size * 0.2f, -size * 0.14f), white, thickness);
    } else if (mark == 1) {
        list->AddLine(offset(center, 0, -size * 0.2f), offset(center, 0, size * 0.06f), white, thickness);
        list->AddCircleFilled(offset(center, 0, size * 0.2f), thickness * 0.75f, white);
    } else if (mark == 2) {
        list->AddLine(offset(center, -size * 0.14f, -size * 0.12f), offset(center, size * 0.14f, size * 0.16f), white, thickness);
        list->AddLine(offset(center, -size * 0.14f, size * 0.16f), offset(center, size * 0.14f, -size * 0.12f), white, thickness);
    } else {
        float start = time * 4.0f;
        list->PathClear();
        list->PathArcTo(offset(center, 0, size * 0.02f), size * 0.2f, start, start + 4.2f, 24);
        list->PathStroke(white, ImDrawFlags_None, thickness);
    }
}

void drawGlobe(ImDrawList* list, ImVec2 center, float radius, float time, ImU32 line, ImU32 fill, ImU32 node,
               float orbit) {
    float thickness = std::max(1.5f, radius * 0.07f);
    list->AddCircleFilled(center, radius, fill, 48);
    list->AddCircle(center, radius, line, 48, thickness);

    for (float latitude : {-0.5f, 0.0f, 0.5f}) {
        float y = radius * latitude;
        float half = std::sqrt(std::max(0.0f, radius * radius - y * y));
        list->AddLine(offset(center, -half, y), offset(center, half, y), line, thickness * 0.8f);
    }
    for (int k = 0; k < 3; ++k) {
        float phase = time * 0.8f + static_cast<float>(k) * kPi / 3.0f;
        float rx = radius * std::fabs(std::cos(phase));
        if (rx < radius * 0.04f) {
            list->AddLine(offset(center, 0, -radius), offset(center, 0, radius), line, thickness * 0.8f);
        } else {
            drawEllipse(list, center, rx, radius, line, thickness * 0.8f);
        }
    }

    if (orbit <= 0.0f) return;
    for (int i = 0; i < 3; ++i) {
        float angle = time * 0.7f + static_cast<float>(i) * 2.0f * kPi / 3.0f - 0.7f;
        float distance = radius * (1.0f + 0.55f * orbit);
        float nodeRadius = radius * 0.13f * orbit;
        ImVec2 direction(std::cos(angle), std::sin(angle));
        ImVec2 from = offset(center, direction.x * radius, direction.y * radius);
        ImVec2 target = offset(center, direction.x * (distance - nodeRadius), direction.y * (distance - nodeRadius));
        list->AddLine(from, target, scaleAlpha(node, 0.85f), thickness * 0.9f);
        ImVec2 position = offset(center, direction.x * distance, direction.y * distance);
        list->AddCircleFilled(position, nodeRadius, node, 20);
        list->AddCircleFilled(position, nodeRadius * 0.42f, IM_COL32(255, 255, 255, 240), 12);
    }
}

void drawIcon(ImDrawList* list, Icon icon, ImVec2 c, float s, ImU32 color) {
    float thickness = std::max(1.6f, s * 0.11f);
    switch (icon) {
        case Icon::Play:
            list->AddTriangleFilled(offset(c, -s * 0.28f, -s * 0.42f), offset(c, -s * 0.28f, s * 0.42f),
                                    offset(c, s * 0.46f, 0), color);
            break;
        case Icon::Server:
            for (float row : {-0.30f, 0.30f}) {
                list->AddRect(offset(c, -s * 0.44f, s * (row - 0.24f)), offset(c, s * 0.44f, s * (row + 0.24f)), color,
                              s * 0.08f, ImDrawFlags_None, thickness);
                list->AddCircleFilled(offset(c, s * 0.26f, s * row), s * 0.06f, color);
                list->AddCircleFilled(offset(c, s * 0.10f, s * row), s * 0.06f, color);
            }
            break;
        case Icon::Globe:
            list->AddCircle(c, s * 0.44f, color, 32, thickness);
            drawEllipse(list, c, s * 0.19f, s * 0.44f, color, thickness);
            list->AddLine(offset(c, -s * 0.44f, 0), offset(c, s * 0.44f, 0), color, thickness);
            break;
        case Icon::Star:
        case Icon::StarFilled: {
            ImVec2 points[10];
            for (int i = 0; i < 10; ++i) {
                float angle = -kPi / 2.0f + static_cast<float>(i) * kPi / 5.0f;
                float radius = (i % 2 == 0) ? s * 0.48f : s * 0.21f;
                points[i] = offset(c, std::cos(angle) * radius, std::sin(angle) * radius);
            }
            if (icon == Icon::StarFilled) {
                for (int i = 0; i < 10; ++i) list->AddTriangleFilled(c, points[i], points[(i + 1) % 10], color);
            }
            list->AddPolyline(points, 10, color, ImDrawFlags_Closed, thickness * 0.8f);
            break;
        }
        case Icon::Clock:
            list->AddCircle(c, s * 0.44f, color, 32, thickness);
            list->AddLine(c, offset(c, 0, -s * 0.28f), color, thickness);
            list->AddLine(c, offset(c, s * 0.2f, s * 0.1f), color, thickness);
            break;
        case Icon::Sliders:
            for (int i = 0; i < 3; ++i) {
                float y = s * (-0.32f + 0.32f * static_cast<float>(i));
                float knob = s * (i == 0 ? 0.18f : (i == 1 ? -0.2f : 0.1f));
                list->AddLine(offset(c, -s * 0.44f, y), offset(c, s * 0.44f, y), color, thickness);
                list->AddCircleFilled(offset(c, knob, y), s * 0.11f, color);
            }
            break;
        case Icon::Home:
            list->AddLine(offset(c, -s * 0.46f, -s * 0.02f), offset(c, 0, -s * 0.44f), color, thickness);
            list->AddLine(offset(c, 0, -s * 0.44f), offset(c, s * 0.46f, -s * 0.02f), color, thickness);
            list->AddRect(offset(c, -s * 0.3f, -s * 0.05f), offset(c, s * 0.3f, s * 0.42f), color, 0.0f,
                          ImDrawFlags_None, thickness);
            break;
        case Icon::Search:
            list->AddCircle(offset(c, -s * 0.08f, -s * 0.08f), s * 0.28f, color, 24, thickness);
            list->AddLine(offset(c, s * 0.14f, s * 0.14f), offset(c, s * 0.44f, s * 0.44f), color, thickness);
            break;
        case Icon::Copy:
            list->AddRect(offset(c, -s * 0.36f, -s * 0.16f), offset(c, s * 0.14f, s * 0.42f), color, s * 0.06f,
                          ImDrawFlags_None, thickness);
            list->AddRect(offset(c, -s * 0.14f, -s * 0.42f), offset(c, s * 0.36f, s * 0.16f), color, s * 0.06f,
                          ImDrawFlags_None, thickness);
            break;
        case Icon::Close:
            list->AddLine(offset(c, -s * 0.3f, -s * 0.3f), offset(c, s * 0.3f, s * 0.3f), color, thickness);
            list->AddLine(offset(c, -s * 0.3f, s * 0.3f), offset(c, s * 0.3f, -s * 0.3f), color, thickness);
            break;
        case Icon::Back:
            list->AddLine(offset(c, s * 0.22f, -s * 0.36f), offset(c, -s * 0.16f, 0), color, thickness * 1.2f);
            list->AddLine(offset(c, -s * 0.16f, 0), offset(c, s * 0.22f, s * 0.36f), color, thickness * 1.2f);
            break;
        case Icon::Forward:
            list->AddLine(offset(c, -s * 0.22f, -s * 0.36f), offset(c, s * 0.16f, 0), color, thickness * 1.2f);
            list->AddLine(offset(c, s * 0.16f, 0), offset(c, -s * 0.22f, s * 0.36f), color, thickness * 1.2f);
            break;
        case Icon::Reload: {
            float start = 0.9f;
            float end = start + 4.7f;
            list->PathClear();
            list->PathArcTo(c, s * 0.34f, start, end, 24);
            list->PathStroke(color, ImDrawFlags_None, thickness);
            ImVec2 tip = offset(c, std::cos(end) * s * 0.34f, std::sin(end) * s * 0.34f);
            list->AddTriangleFilled(offset(tip, s * 0.2f, -s * 0.02f), offset(tip, -s * 0.12f, -s * 0.16f),
                                    offset(tip, -s * 0.02f, s * 0.2f), color);
            break;
        }
        case Icon::Menu:
            for (float row : {-0.3f, 0.0f, 0.3f}) {
                list->AddLine(offset(c, -s * 0.4f, s * row), offset(c, s * 0.4f, s * row), color, thickness * 1.1f);
            }
            break;
        case Icon::Pencil:
            list->AddLine(offset(c, s * 0.30f, -s * 0.30f), offset(c, -s * 0.20f, s * 0.20f), color, thickness * 1.8f);
            list->AddTriangleFilled(offset(c, -s * 0.44f, s * 0.44f), offset(c, -s * 0.32f, s * 0.14f),
                                    offset(c, -s * 0.14f, s * 0.32f), color);
            break;
        case Icon::Save:
            list->AddRect(offset(c, -s * 0.4f, -s * 0.4f), offset(c, s * 0.4f, s * 0.4f), color, s * 0.08f,
                          ImDrawFlags_None, thickness);
            list->AddRect(offset(c, -s * 0.2f, -s * 0.4f), offset(c, s * 0.16f, -s * 0.1f), color, 0.0f,
                          ImDrawFlags_None, thickness);
            list->AddRect(offset(c, -s * 0.24f, s * 0.06f), offset(c, s * 0.24f, s * 0.4f), color, 0.0f,
                          ImDrawFlags_None, thickness);
            break;
        case Icon::Trash: {
            list->AddLine(offset(c, -s * 0.42f, -s * 0.26f), offset(c, s * 0.42f, -s * 0.26f), color, thickness);
            ImVec2 handle[4] = {offset(c, -s * 0.14f, -s * 0.26f), offset(c, -s * 0.14f, -s * 0.42f),
                                offset(c, s * 0.14f, -s * 0.42f), offset(c, s * 0.14f, -s * 0.26f)};
            list->AddPolyline(handle, 4, color, ImDrawFlags_None, thickness);
            ImVec2 body[4] = {offset(c, -s * 0.3f, -s * 0.2f), offset(c, -s * 0.24f, s * 0.42f),
                              offset(c, s * 0.24f, s * 0.42f), offset(c, s * 0.3f, -s * 0.2f)};
            list->AddPolyline(body, 4, color, ImDrawFlags_None, thickness);
            list->AddLine(offset(c, -s * 0.08f, -s * 0.06f), offset(c, -s * 0.08f, s * 0.3f), color, thickness * 0.8f);
            list->AddLine(offset(c, s * 0.08f, -s * 0.06f), offset(c, s * 0.08f, s * 0.3f), color, thickness * 0.8f);
            break;
        }
        case Icon::Plus:
            list->AddLine(offset(c, -s * 0.36f, 0), offset(c, s * 0.36f, 0), color, thickness * 1.2f);
            list->AddLine(offset(c, 0, -s * 0.36f), offset(c, 0, s * 0.36f), color, thickness * 1.2f);
            break;
        case Icon::File: {
            ImVec2 outline[5] = {offset(c, -s * 0.3f, -s * 0.44f), offset(c, s * 0.1f, -s * 0.44f),
                                 offset(c, s * 0.3f, -s * 0.24f), offset(c, s * 0.3f, s * 0.44f),
                                 offset(c, -s * 0.3f, s * 0.44f)};
            list->AddPolyline(outline, 5, color, ImDrawFlags_Closed, thickness);
            list->AddLine(offset(c, s * 0.1f, -s * 0.44f), offset(c, s * 0.1f, -s * 0.24f), color, thickness * 0.8f);
            list->AddLine(offset(c, s * 0.1f, -s * 0.24f), offset(c, s * 0.3f, -s * 0.24f), color, thickness * 0.8f);
            break;
        }
        case Icon::Folder: {
            ImVec2 outline[7] = {offset(c, -s * 0.46f, -s * 0.3f), offset(c, -s * 0.46f, s * 0.36f),
                                 offset(c, s * 0.46f, s * 0.36f), offset(c, s * 0.46f, -s * 0.18f),
                                 offset(c, s * 0.06f, -s * 0.18f), offset(c, -s * 0.06f, -s * 0.32f),
                                 offset(c, -s * 0.3f, -s * 0.32f)};
            list->AddPolyline(outline, 7, color, ImDrawFlags_Closed, thickness);
            break;
        }
        case Icon::Share:
            list->AddLine(offset(c, s * 0.3f, -s * 0.28f), offset(c, -s * 0.3f, 0), color, thickness);
            list->AddLine(offset(c, -s * 0.3f, 0), offset(c, s * 0.3f, s * 0.28f), color, thickness);
            list->AddCircleFilled(offset(c, s * 0.3f, -s * 0.28f), s * 0.14f, color);
            list->AddCircleFilled(offset(c, -s * 0.3f, 0), s * 0.14f, color);
            list->AddCircleFilled(offset(c, s * 0.3f, s * 0.28f), s * 0.14f, color);
            break;
        case Icon::Eye:
            drawEllipse(list, c, s * 0.46f, s * 0.26f, color, thickness);
            list->AddCircleFilled(c, s * 0.13f, color);
            break;
        case Icon::Panel:
            list->AddRect(offset(c, -s * 0.44f, -s * 0.36f), offset(c, s * 0.44f, s * 0.36f), color, s * 0.08f,
                          ImDrawFlags_None, thickness);
            list->AddLine(offset(c, -s * 0.14f, -s * 0.36f), offset(c, -s * 0.14f, s * 0.36f), color, thickness);
            break;
        case Icon::Command:
            list->AddRect(offset(c, -s * 0.28f, -s * 0.28f), offset(c, s * 0.28f, s * 0.28f), color, s * 0.05f,
                          ImDrawFlags_None, thickness);
            for (float x : {-0.28f, 0.28f}) {
                for (float y : {-0.28f, 0.28f}) list->AddCircle(offset(c, s * x * 1.35f, s * y * 1.35f), s * 0.1f, color, 12, thickness);
            }
            break;
        case Icon::Shield: {
            ImVec2 outline[7] = {offset(c, 0, -s * 0.46f),        offset(c, s * 0.38f, -s * 0.3f), offset(c, s * 0.38f, s * 0.06f),
                                 offset(c, s * 0.2f, s * 0.32f), offset(c, 0, s * 0.46f),          offset(c, -s * 0.2f, s * 0.32f),
                                 offset(c, -s * 0.38f, s * 0.06f)};
            list->AddPolyline(outline, 7, color, ImDrawFlags_Closed, thickness);
            list->AddLine(offset(c, -s * 0.38f, -s * 0.3f), offset(c, -s * 0.38f, s * 0.06f), color, thickness);
            list->AddLine(offset(c, 0, -s * 0.46f), offset(c, -s * 0.38f, -s * 0.3f), color, thickness);
            break;
        }
        case Icon::Warning: {
            ImVec2 triangle[3] = {offset(c, 0, -s * 0.44f), offset(c, s * 0.46f, s * 0.36f), offset(c, -s * 0.46f, s * 0.36f)};
            list->AddPolyline(triangle, 3, color, ImDrawFlags_Closed, thickness);
            list->AddLine(offset(c, 0, -s * 0.12f), offset(c, 0, s * 0.12f), color, thickness);
            list->AddCircleFilled(offset(c, 0, s * 0.25f), thickness * 0.7f, color);
            break;
        }
        case Icon::Check:
            list->AddLine(offset(c, -s * 0.38f, s * 0.02f), offset(c, -s * 0.1f, s * 0.3f), color, thickness * 1.3f);
            list->AddLine(offset(c, -s * 0.1f, s * 0.3f), offset(c, s * 0.4f, -s * 0.3f), color, thickness * 1.3f);
            break;
        case Icon::Bug:
            list->AddCircle(offset(c, 0, s * 0.06f), s * 0.24f, color, 20, thickness);
            list->AddCircleFilled(offset(c, 0, -s * 0.28f), s * 0.11f, color);
            for (float side : {-1.0f, 1.0f}) {
                list->AddLine(offset(c, side * s * 0.24f, -s * 0.02f), offset(c, side * s * 0.46f, -s * 0.12f), color, thickness);
                list->AddLine(offset(c, side * s * 0.24f, s * 0.1f), offset(c, side * s * 0.46f, s * 0.1f), color, thickness);
                list->AddLine(offset(c, side * s * 0.2f, s * 0.22f), offset(c, side * s * 0.42f, s * 0.36f), color, thickness);
            }
            break;
    }
}

void drawText(ImDrawList* list, float size, ImVec2 position, ImU32 color, const char* text) {
    list->AddText(fontForSize(size), size, position, color, text);
}

void pushTextScale(float scale) {
    float base = fontForSize(1.0f)->FontSize;
    float target = base * scale;
    ImFont* font = fontForSize(target);
    ImGui::PushFont(font);
    ImGui::SetWindowFontScale(target / font->FontSize);
}

void popTextScale(float restore) {
    ImGui::PopFont();
    ImGui::SetWindowFontScale(restore);
}

float textWidth(float size, const std::string& text) {
    return fontForSize(size)->CalcTextSizeA(size, FLT_MAX, 0.0f, text.c_str(), text.c_str() + text.size()).x;
}

std::string fitText(const std::string& text, float size, float maxWidth) {
    if (textWidth(size, text) <= maxWidth) return text;
    std::string result = text;
    while (!result.empty()) {
        result.pop_back();
        while (!result.empty() && (static_cast<unsigned char>(result.back()) & 0xC0) == 0x80) result.pop_back();
        if (textWidth(size, result + "...") <= maxWidth) return result + "...";
    }
    return "";
}

ParticleField::ParticleField() {
    std::mt19937 random(7);
    std::uniform_real_distribution<float> position(0.0f, 1.0f);
    std::uniform_real_distribution<float> speed(-0.035f, 0.035f);
    for (int i = 0; i < kParticleCount; ++i) {
        particles_.push_back(Particle{position(random), position(random), speed(random), speed(random)});
    }
}

void ParticleField::update(float dt) {
    for (Particle& p : particles_) {
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        if (p.x < 0.0f) p.x += 1.0f;
        if (p.x > 1.0f) p.x -= 1.0f;
        if (p.y < 0.0f) p.y += 1.0f;
        if (p.y > 1.0f) p.y -= 1.0f;
    }
}

void ParticleField::draw(ImDrawList* list, ImVec2 origin, ImVec2 size, ImU32 color, float linkDistance,
                         float alpha) const {
    for (std::size_t i = 0; i < particles_.size(); ++i) {
        ImVec2 a(origin.x + particles_[i].x * size.x, origin.y + particles_[i].y * size.y);
        for (std::size_t j = i + 1; j < particles_.size(); ++j) {
            ImVec2 b(origin.x + particles_[j].x * size.x, origin.y + particles_[j].y * size.y);
            float dx = a.x - b.x;
            float dy = a.y - b.y;
            float distance = std::sqrt(dx * dx + dy * dy);
            if (distance < linkDistance) {
                float strength = 1.0f - distance / linkDistance;
                list->AddLine(a, b, scaleAlpha(color, alpha * strength * 0.9f), 1.2f);
            }
        }
        list->AddCircleFilled(a, 2.4f, scaleAlpha(color, alpha), 8);
    }
}

}
