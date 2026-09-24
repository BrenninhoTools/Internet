#include "icon.hpp"

#include <algorithm>
#include <cmath>

namespace internet {

namespace {

struct Color {
    float r, g, b;
};

struct Point {
    float x, y;
};

constexpr float kPi = 3.14159265358979f;
constexpr int kSamples = 4;

const Color kTop{0.145f, 0.388f, 0.922f};
const Color kBottom{0.263f, 0.220f, 0.792f};
const Color kWhite{0.96f, 0.97f, 1.0f};
const Color kNode{0.40f, 0.91f, 0.98f};

constexpr float kGlobeRadius = 0.27f;
constexpr float kStroke = 0.030f;
constexpr float kOrbit = 0.385f;
constexpr float kNodeRadius = 0.052f;
constexpr float kLinkWidth = 0.018f;
constexpr float kNodeAngles[3] = {-38.0f, 142.0f, 258.0f};

Color mix(const Color& a, const Color& b, float t) {
    return Color{a.r + (b.r - a.r) * t, a.g + (b.g - a.g) * t, a.b + (b.b - a.b) * t};
}

float length(float x, float y) { return std::sqrt(x * x + y * y); }

float segmentDistance(Point p, Point a, Point b) {
    float dx = b.x - a.x;
    float dy = b.y - a.y;
    float t = ((p.x - a.x) * dx + (p.y - a.y) * dy) / (dx * dx + dy * dy);
    t = std::clamp(t, 0.0f, 1.0f);
    return length(p.x - (a.x + dx * t), p.y - (a.y + dy * t));
}

bool insideSquare(Point p, float radius) {
    float qx = std::fabs(p.x) - (0.5f - radius);
    float qy = std::fabs(p.y) - (0.5f - radius);
    float outside = length(std::max(qx, 0.0f), std::max(qy, 0.0f));
    float inside = std::min(std::max(qx, qy), 0.0f);
    return outside + inside - radius <= 0.0f;
}

float globeStrokeDistance(Point p) {
    float radial = length(p.x, p.y);
    float best = std::fabs(radial - kGlobeRadius);
    if (radial <= kGlobeRadius) {
        best = std::min(best, std::fabs(p.x));
        best = std::min(best, std::fabs(p.y));
        best = std::min(best, std::fabs(p.y - kGlobeRadius * 0.5f));
        best = std::min(best, std::fabs(p.y + kGlobeRadius * 0.5f));
    }
    float a = kGlobeRadius * 0.46f;
    float f = (p.x * p.x) / (a * a) + (p.y * p.y) / (kGlobeRadius * kGlobeRadius) - 1.0f;
    float gx = 2.0f * p.x / (a * a);
    float gy = 2.0f * p.y / (kGlobeRadius * kGlobeRadius);
    float gradient = length(gx, gy);
    if (gradient > 1e-6f) best = std::min(best, std::fabs(f) / gradient);
    return best;
}

struct Sample {
    Color color;
    float alpha;
};

Sample shade(Point p, bool rounded) {
    if (!insideSquare(p, rounded ? 0.22f : 0.0f)) return Sample{{0, 0, 0}, 0.0f};

    Color color = mix(kTop, kBottom, std::clamp(p.y + 0.5f, 0.0f, 1.0f));
    float radial = length(p.x, p.y);
    if (radial <= kGlobeRadius) color = mix(color, kWhite, 0.14f);

    for (float degrees : kNodeAngles) {
        float angle = degrees * kPi / 180.0f;
        Point node{std::cos(angle) * kOrbit, std::sin(angle) * kOrbit};
        Point ring{std::cos(angle) * kGlobeRadius, std::sin(angle) * kGlobeRadius};
        if (segmentDistance(p, ring, node) <= kLinkWidth * 0.5f) color = mix(color, kNode, 0.9f);
    }

    if (globeStrokeDistance(p) <= kStroke * 0.5f) color = mix(color, kWhite, 0.96f);

    for (float degrees : kNodeAngles) {
        float angle = degrees * kPi / 180.0f;
        float d = length(p.x - std::cos(angle) * kOrbit, p.y - std::sin(angle) * kOrbit);
        if (d <= kNodeRadius) color = kNode;
        if (d <= kNodeRadius * 0.42f) color = kWhite;
    }
    return Sample{color, 1.0f};
}

}

std::vector<std::uint8_t> renderIcon(int size, bool rounded) {
    std::vector<std::uint8_t> pixels(static_cast<std::size_t>(size) * size * 4);
    const float step = 1.0f / (static_cast<float>(size) * kSamples);
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            float r = 0, g = 0, b = 0, a = 0;
            for (int sy = 0; sy < kSamples; ++sy) {
                for (int sx = 0; sx < kSamples; ++sx) {
                    Point p{(static_cast<float>(x) / size) + (sx + 0.5f) * step - 0.5f,
                            (static_cast<float>(y) / size) + (sy + 0.5f) * step - 0.5f};
                    Sample s = shade(p, rounded);
                    r += s.color.r * s.alpha;
                    g += s.color.g * s.alpha;
                    b += s.color.b * s.alpha;
                    a += s.alpha;
                }
            }
            const float total = static_cast<float>(kSamples * kSamples);
            std::uint8_t* out = &pixels[(static_cast<std::size_t>(y) * size + x) * 4];
            if (a > 0.0f) {
                out[0] = static_cast<std::uint8_t>(std::clamp(r / a, 0.0f, 1.0f) * 255.0f + 0.5f);
                out[1] = static_cast<std::uint8_t>(std::clamp(g / a, 0.0f, 1.0f) * 255.0f + 0.5f);
                out[2] = static_cast<std::uint8_t>(std::clamp(b / a, 0.0f, 1.0f) * 255.0f + 0.5f);
            }
            out[3] = static_cast<std::uint8_t>(a / total * 255.0f + 0.5f);
        }
    }
    return pixels;
}

}
