#include "quarantine.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iterator>
#include <sstream>
#include <system_error>

namespace fs = std::filesystem;

namespace internet {

namespace {

const char kMagic[] = "IQ1\n";

std::string encode(const std::string& data) {
    std::string out = kMagic;
    out.reserve(data.size() + sizeof kMagic);
    for (std::size_t i = 0; i < data.size(); ++i) {
        out += static_cast<char>(static_cast<unsigned char>(data[i]) ^ static_cast<unsigned char>(0x5A + (i % 251)));
    }
    return out;
}

bool decode(const std::string& stored, std::string& data) {
    std::size_t header = sizeof kMagic - 1;
    if (stored.size() < header || stored.compare(0, header, kMagic) != 0) return false;
    data.clear();
    data.reserve(stored.size() - header);
    for (std::size_t i = header; i < stored.size(); ++i) {
        std::size_t index = i - header;
        data += static_cast<char>(static_cast<unsigned char>(stored[i]) ^ static_cast<unsigned char>(0x5A + (index % 251)));
    }
    return true;
}

std::string sanitized(const std::string& text) {
    std::string clean = text;
    std::replace_if(clean.begin(), clean.end(), [](char c) { return c == '\n' || c == '\r'; }, ' ');
    return clean;
}

bool readMeta(const fs::path& path, QuarantineItem& item) {
    std::ifstream stream(path);
    if (!stream) return false;
    std::string line;
    while (std::getline(stream, line)) {
        std::size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        std::string key = line.substr(0, equals);
        std::string value = line.substr(equals + 1);
        try {
            if (key == "name") item.name = value;
            if (key == "path") item.originalPath = value;
            if (key == "sha256") item.sha256 = value;
            if (key == "verdict") item.verdict = value;
            if (key == "rule") item.rule = value;
            if (key == "score") item.score = std::stoi(value);
            if (key == "time") item.time = std::stoll(value);
            if (key == "size") item.size = std::stoull(value);
        } catch (const std::exception&) {
        }
    }
    return true;
}

bool validId(const std::string& id) {
    if (id.empty() || id.size() > 64) return false;
    return std::all_of(id.begin(), id.end(), [](unsigned char c) { return std::isalnum(c) || c == '-'; });
}

}

Quarantine::Quarantine(fs::path directory) : directory_(std::move(directory)) {
    std::error_code error;
    fs::create_directories(directory_, error);
}

const fs::path& Quarantine::directory() const { return directory_; }

bool Quarantine::add(const std::string& originalPath, const std::string& data, const ScanResult& result, QuarantineItem& item,
                     std::string& error) {
    std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::string tag = result.sha256.substr(0, 10);
    std::string id = std::to_string(now) + "-" + tag;
    for (int i = 2; fs::exists(directory_ / (id + ".qz")); ++i) id = std::to_string(now) + "-" + tag + "-" + std::to_string(i);

    std::ofstream payload(directory_ / (id + ".qz"), std::ios::binary | std::ios::trunc);
    std::string encoded = encode(data);
    payload.write(encoded.data(), static_cast<std::streamsize>(encoded.size()));
    if (!payload) {
        error = "Cannot write the quarantine file";
        return false;
    }
    payload.close();

    const Finding* strongest = strongestFinding(result);
    item.id = id;
    item.name = result.name;
    item.originalPath = originalPath;
    item.sha256 = result.sha256;
    item.verdict = verdictName(result.verdict);
    item.rule = strongest ? strongest->rule : "";
    item.score = result.score;
    item.time = now;
    item.size = data.size();

    std::ofstream meta(directory_ / (id + ".meta"), std::ios::trunc);
    meta << "name=" << sanitized(item.name) << '\n'
         << "path=" << sanitized(item.originalPath) << '\n'
         << "sha256=" << item.sha256 << '\n'
         << "verdict=" << item.verdict << '\n'
         << "rule=" << sanitized(item.rule) << '\n'
         << "score=" << item.score << '\n'
         << "time=" << item.time << '\n'
         << "size=" << item.size << '\n';
    if (!meta) {
        error = "Cannot write the quarantine record";
        return false;
    }
    return true;
}

std::vector<QuarantineItem> Quarantine::list() const {
    std::vector<QuarantineItem> items;
    std::error_code error;
    for (fs::directory_iterator it(directory_, error), end; !error && it != end; it.increment(error)) {
        if (it->path().extension() != ".meta") continue;
        QuarantineItem item;
        item.id = it->path().stem().string();
        if (readMeta(it->path(), item)) items.push_back(std::move(item));
    }
    std::sort(items.begin(), items.end(), [](const QuarantineItem& a, const QuarantineItem& b) { return a.time > b.time; });
    return items;
}

bool Quarantine::restore(const std::string& id, const fs::path& destination, std::string& error) const {
    if (!validId(id)) {
        error = "Invalid item";
        return false;
    }
    std::ifstream stream(directory_ / (id + ".qz"), std::ios::binary);
    if (!stream) {
        error = "The quarantined file is missing";
        return false;
    }
    std::string stored((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    std::string data;
    if (!decode(stored, data)) {
        error = "The quarantined file is damaged";
        return false;
    }
    std::error_code code;
    if (!destination.parent_path().empty()) fs::create_directories(destination.parent_path(), code);
    if (fs::exists(destination, code)) {
        error = "A file already exists at the destination";
        return false;
    }
    std::ofstream out(destination, std::ios::binary | std::ios::trunc);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out) {
        error = "Cannot write the restored file";
        return false;
    }
    return true;
}

bool Quarantine::remove(const std::string& id, std::string& error) const {
    if (!validId(id)) {
        error = "Invalid item";
        return false;
    }
    std::error_code code;
    bool removed = fs::remove(directory_ / (id + ".qz"), code);
    removed = fs::remove(directory_ / (id + ".meta"), code) || removed;
    if (!removed) {
        error = "Item not found";
        return false;
    }
    return true;
}

}
