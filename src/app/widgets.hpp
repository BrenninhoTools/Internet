#pragma once

#include <string>
#include <vector>

#include "imgui.h"

namespace internet {

enum class Icon {
    Play,
    Server,
    Globe,
    Star,
    StarFilled,
    Clock,
    Sliders,
    Home,
    Search,
    Copy,
    Close,
    Back,
    Forward,
    Reload,
    Menu,
    Pencil,
    Save,
    Trash,
    Plus,
    File,
    Folder,
    Share,
    Eye,
    Panel,
    Command,
    Shield,
    Warning,
    Check,
    Bug
};

float clamp01(float value);
float easeOutCubic(float t);
float easeOutBack(float t);
float smoothStep(float t);
void approach(float& value, float target, float rate, float dt);
ImU32 scaleAlpha(ImU32 color, float alpha);

void drawIcon(ImDrawList* list, Icon icon, ImVec2 center, float size, ImU32 color);
void drawEllipse(ImDrawList* list, ImVec2 center, float radiusX, float radiusY, ImU32 color, float thickness);
void drawSpinner(ImDrawList* list, ImVec2 center, float radius, ImU32 color, float time);
void drawShield(ImDrawList* list, ImVec2 center, float size, ImU32 color, float pulse, int mark, float time);
void drawGlobe(ImDrawList* list, ImVec2 center, float radius, float time, ImU32 line, ImU32 fill, ImU32 node,
               float orbit);

void drawText(ImDrawList* list, float size, ImVec2 position, ImU32 color, const char* text);
void pushTextScale(float scale);
void popTextScale(float restore);
float textWidth(float size, const std::string& text);
std::string fitText(const std::string& text, float size, float maxWidth);

class ParticleField {
public:
    ParticleField();
    void update(float dt);
    void draw(ImDrawList* list, ImVec2 origin, ImVec2 size, ImU32 color, float linkDistance, float alpha) const;

private:
    struct Particle {
        float x;
        float y;
        float vx;
        float vy;
    };
    std::vector<Particle> particles_;
};

}
