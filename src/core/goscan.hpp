#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace internet {

struct GoBuildInfo {
    bool found = false;
    bool tables = false;
    std::string version;
    std::string path;
    std::string module;
    std::vector<std::string> deps;
    std::vector<std::string> replacements;
    std::vector<std::string> flags;
};

struct GoIssue {
    std::string rule;
    std::string category;
    std::string description;
    int severity = 0;
};

bool detectGoBinary(const std::uint8_t* data, std::size_t size, GoBuildInfo& info);
bool looksLikeGoSource(const std::string& head);
bool isGoModuleFile(const std::string& baseName);

std::vector<GoIssue> reviewGoBinary(const GoBuildInfo& info);
std::vector<GoIssue> reviewGoModule(const std::string& text);
std::vector<GoIssue> reviewGoSource(const std::string& text);
std::vector<GoIssue> reviewModulePaths(const std::vector<std::string>& paths);

int editDistance(const std::string& a, const std::string& b);

}
