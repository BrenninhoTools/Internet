#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "definitions.hpp"

namespace internet {

enum class Verdict { Clean, Suspicious, Malicious, Unscannable };

const char* verdictName(Verdict verdict);

struct Finding {
    std::string rule;
    std::string category;
    std::string description;
    std::string location;
    int severity = 0;
};

struct ScanResult {
    std::string name;
    std::string sha256;
    std::string type;
    std::string note;
    std::uint64_t size = 0;
    Verdict verdict = Verdict::Clean;
    int score = 0;
    double entropy = 0.0;
    bool truncated = false;
    std::vector<Finding> findings;
};

struct ScanOptions {
    std::size_t maxBytes = 64u * 1024u * 1024u;
    int archiveDepth = 3;
    std::size_t entryLimit = 16u * 1024u * 1024u;
    std::size_t archiveLimit = 128u * 1024u * 1024u;
    std::size_t maxEntries = 500;
};

std::string detectFileType(const std::string& name, const std::uint8_t* data, std::size_t size);
double shannonEntropy(const std::uint8_t* data, std::size_t size);
const Finding* strongestFinding(const ScanResult& result);

class Scanner {
public:
    explicit Scanner(Definitions definitions);

    ScanResult scan(const std::string& name, const std::uint8_t* data, std::size_t size,
                    const ScanOptions& options = ScanOptions()) const;
    ScanResult scan(const std::string& name, const std::string& data, const ScanOptions& options = ScanOptions()) const;

    const Definitions& definitions() const;
    std::size_t ruleCount() const;

private:
    struct Impl;
    std::shared_ptr<const Impl> impl_;
};

std::shared_ptr<const Scanner> makeScanner(const std::string& updateText, std::string& error);

}
