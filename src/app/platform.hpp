#pragma once

#include <string>

namespace internet {
namespace platform {

bool shareText(const std::string& text);
void haptic(int milliseconds);
std::string takeLaunchLink();
void setHosting(bool active, const std::string& name);

}
}
