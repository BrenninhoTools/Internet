#pragma once

#include "imgui.h"

namespace internet {

void setupUi(float scale, bool touch);
ImFont* fontForSize(float pixelSize);
ImFont* monoFont();

}
