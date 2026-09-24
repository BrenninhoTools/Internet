#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "av.hpp"

namespace internet {

struct QuarantineItem {
    std::string id;
    std::string name;
    std::string originalPath;
    std::string sha256;
    std::string verdict;
    std::string rule;
    int score = 0;
    std::int64_t time = 0;
    std::uint64_t size = 0;
};

class Quarantine {
public:
    explicit Quarantine(std::filesystem::path directory);

    bool add(const std::string& originalPath, const std::string& data, const ScanResult& result, QuarantineItem& item,
             std::string& error);
    std::vector<QuarantineItem> list() const;
    bool restore(const std::string& id, const std::filesystem::path& destination, std::string& error) const;
    bool remove(const std::string& id, std::string& error) const;
    const std::filesystem::path& directory() const;

private:
    std::filesystem::path directory_;
};

}
