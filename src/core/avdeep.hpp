#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace internet {

struct DeepIssue {
    std::string rule;
    std::string category;
    std::string description;
    int severity = 0;
};

struct DecodedLayer {
    std::string label;
    std::string extension;
    std::string bytes;
};

struct VbaModule {
    std::string name;
    std::string source;
};

struct OleReport {
    bool valid = false;
    bool hasVba = false;
    bool hasEmbedded = false;
    bool equationEditor = false;
    std::vector<VbaModule> modules;
    std::vector<std::string> embeddedPayloads;
};

std::vector<DecodedLayer> decodeLayers(const std::string& text, std::size_t budget);

bool ovbaDecompress(const std::uint8_t* data, std::size_t size, std::string& out);
OleReport readOle(const std::uint8_t* data, std::size_t size);
std::vector<DeepIssue> reviewVba(const std::string& source);
std::vector<DeepIssue> reviewOleReport(const OleReport& report);
std::vector<DeepIssue> reviewOfficePart(const std::string& partName, const std::string& content);

std::string foldToAscii(const std::uint8_t* data, std::size_t size);
bool looksLikeLnk(const std::uint8_t* data, std::size_t size);
std::vector<DeepIssue> reviewLnk(const std::uint8_t* data, std::size_t size);

std::vector<DeepIssue> reviewPeImports(const std::uint8_t* data, std::size_t size);

}
