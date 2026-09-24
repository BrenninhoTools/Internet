#pragma once

#include <filesystem>
#include <functional>
#include <string>

namespace internet {

struct GuardDecision {
    bool allowed = true;
    std::string reason;
};

using GuardFunction = std::function<GuardDecision(const std::filesystem::path&)>;

}
