#include "storage.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <system_error>

namespace fs = std::filesystem;

namespace internet {

namespace {

std::string environment(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) return "";
    std::string result(value);
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
#endif
}

std::string clean(std::string text) {
    std::replace_if(text.begin(), text.end(), [](char c) { return c == '\t' || c == '\n' || c == '\r'; }, ' ');
    return text;
}

}

fs::path userDataDirectory() {
    fs::path base;
#ifdef _WIN32
    base = environment("APPDATA");
#elif defined(__APPLE__)
    std::string home = environment("HOME");
    if (!home.empty()) base = fs::path(home) / "Library" / "Application Support";
#else
    std::string data = environment("XDG_DATA_HOME");
    std::string home = environment("HOME");
    if (!data.empty()) {
        base = data;
    } else if (!home.empty()) {
        base = fs::path(home) / ".local" / "share";
    }
#endif
    if (base.empty()) return fs::path(".");
    fs::path directory = base / "Internet";
    std::error_code error;
    fs::create_directories(directory, error);
    if (error) return fs::path(".");
    return directory;
}

std::vector<Entry> parseEntries(const std::string& text) {
    std::vector<Entry> entries;
    std::stringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        std::size_t tab = line.find('\t');
        Entry entry;
        entry.url = line.substr(0, tab);
        if (tab != std::string::npos) entry.title = line.substr(tab + 1);
        if (!entry.url.empty()) entries.push_back(std::move(entry));
    }
    return entries;
}

std::string formatEntries(const std::vector<Entry>& entries) {
    std::string text;
    for (const Entry& entry : entries) text += clean(entry.url) + '\t' + clean(entry.title) + '\n';
    return text;
}

std::string mergeEntries(const std::string& local, const std::string& remote, std::size_t limit) {
    std::vector<Entry> merged = parseEntries(local);
    for (Entry& item : parseEntries(remote)) {
        bool present = std::any_of(merged.begin(), merged.end(), [&](const Entry& entry) { return entry.url == item.url; });
        if (!present) merged.push_back(std::move(item));
    }
    if (limit > 0 && merged.size() > limit) merged.resize(limit);
    return formatEntries(merged);
}

std::string formatSyncedSettings(const Settings& settings) {
    std::ostringstream out;
    out << "palette=" << settings.palette << '\n';
    out << "intro=" << (settings.intro ? 1 : 0) << '\n';
    out << "animations=" << (settings.animations ? 1 : 0) << '\n';
    out << "zoom=" << settings.zoom << '\n';
    return out.str();
}

bool applySyncedSettings(const std::string& text, Settings& settings) {
    bool any = false;
    std::stringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        std::size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        std::string key = line.substr(0, equals);
        std::string value = line.substr(equals + 1);
        try {
            if (key == "palette") {
                settings.palette = std::stoi(value);
                any = true;
            } else if (key == "intro") {
                settings.intro = value == "1";
                any = true;
            } else if (key == "animations") {
                settings.animations = value == "1";
                any = true;
            } else if (key == "zoom") {
                settings.zoom = std::clamp(std::stof(value), 0.6f, 2.5f);
                any = true;
            }
        } catch (const std::exception&) {
        }
    }
    return any;
}

std::vector<Entry> loadEntries(const fs::path& file) {
    std::ifstream stream(file);
    std::stringstream text;
    text << stream.rdbuf();
    return parseEntries(text.str());
}

void saveEntries(const fs::path& file, const std::vector<Entry>& entries) {
    std::ofstream stream(file, std::ios::trunc);
    stream << formatEntries(entries);
}

Settings loadSettings(const fs::path& file) {
    Settings settings;
    std::ifstream stream(file);
    std::string line;
    while (std::getline(stream, line)) {
        std::size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        std::string key = line.substr(0, equals);
        std::string value = line.substr(equals + 1);
        try {
            if (key == "palette") settings.palette = std::stoi(value);
            if (key == "intro") settings.intro = value == "1";
            if (key == "animations") settings.animations = value == "1";
            if (key == "browserscripts") settings.browserScripts = value == "1";
            if (key == "web") settings.webBase = value;
            if (key == "zoom") settings.zoom = std::clamp(std::stof(value), 0.6f, 2.5f);
        } catch (const std::exception&) {
        }
    }
    return settings;
}

void saveSettings(const fs::path& file, const Settings& settings) {
    std::ofstream stream(file, std::ios::trunc);
    stream << "palette=" << settings.palette << '\n';
    stream << "intro=" << (settings.intro ? 1 : 0) << '\n';
    stream << "animations=" << (settings.animations ? 1 : 0) << '\n';
    stream << "zoom=" << settings.zoom << '\n';
    stream << "browserscripts=" << (settings.browserScripts ? 1 : 0) << '\n';
    stream << "web=" << clean(settings.webBase) << '\n';
}

}
