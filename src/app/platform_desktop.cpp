#include "platform.hpp"

namespace internet {
namespace platform {

bool shareText(const std::string&) { return false; }

void haptic(int) {}

std::string takeLaunchLink() { return std::string(); }

void setHosting(bool, const std::string&) {}

}
}
