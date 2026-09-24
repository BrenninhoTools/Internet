#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace internet {

struct Entry {
    std::string url;
    std::string title;
};

struct Settings {
    int palette = 0;
    bool intro = true;
    bool animations = true;
    float zoom = 1.0f;
};

std::filesystem::path userDataDirectory();
std::vector<Entry> loadEntries(const std::filesystem::path& file);
void saveEntries(const std::filesystem::path& file, const std::vector<Entry>& entries);
Settings loadSettings(const std::filesystem::path& file);
void saveSettings(const std::filesystem::path& file, const Settings& settings);

}
