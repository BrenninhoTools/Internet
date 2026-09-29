#include "encoding.hpp"

#include <algorithm>
#include <cstdint>
#include <random>

#include "protocol.hpp"
#include "sha256.hpp"

namespace internet {

namespace {

const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int alphabetValue(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

}

std::string base64UrlEncode(const std::string& data) {
    std::string out;
    std::size_t i = 0;
    while (i + 2 < data.size()) {
        std::uint32_t value = (static_cast<std::uint8_t>(data[i]) << 16) | (static_cast<std::uint8_t>(data[i + 1]) << 8) |
                              static_cast<std::uint8_t>(data[i + 2]);
        out += kAlphabet[(value >> 18) & 63];
        out += kAlphabet[(value >> 12) & 63];
        out += kAlphabet[(value >> 6) & 63];
        out += kAlphabet[value & 63];
        i += 3;
    }
    std::size_t rest = data.size() - i;
    if (rest == 1) {
        std::uint32_t value = static_cast<std::uint8_t>(data[i]) << 16;
        out += kAlphabet[(value >> 18) & 63];
        out += kAlphabet[(value >> 12) & 63];
    } else if (rest == 2) {
        std::uint32_t value = (static_cast<std::uint8_t>(data[i]) << 16) | (static_cast<std::uint8_t>(data[i + 1]) << 8);
        out += kAlphabet[(value >> 18) & 63];
        out += kAlphabet[(value >> 12) & 63];
        out += kAlphabet[(value >> 6) & 63];
    }
    return out;
}

bool base64UrlDecode(const std::string& text, std::string& out) {
    std::string clean = text;
    while (!clean.empty() && clean.back() == '=') clean.pop_back();
    if (clean.size() % 4 == 1) return false;
    std::string result;
    std::uint32_t buffer = 0;
    int bits = 0;
    for (char c : clean) {
        int value = alphabetValue(c);
        if (value < 0) return false;
        buffer = (buffer << 6) | static_cast<std::uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result += static_cast<char>((buffer >> bits) & 0xFF);
        }
    }
    out = std::move(result);
    return true;
}

std::string randomBytes(std::size_t count) {
    std::random_device device;
    std::string bytes;
    bytes.reserve(count);
    while (bytes.size() < count) {
        unsigned int value = device();
        for (int i = 0; i < 4 && bytes.size() < count; ++i) bytes += static_cast<char>((value >> (i * 8)) & 0xFF);
    }
    return bytes;
}

std::string randomHex(std::size_t count) {
    std::string bytes = randomBytes(count);
    return toHex(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
}

std::string formEncode(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::string out;
    for (const auto& field : fields) {
        if (!out.empty()) out += '&';
        out += percentEncode(field.first, "") + "=" + percentEncode(field.second, "");
    }
    return out;
}

std::vector<std::pair<std::string, std::string>> formDecode(const std::string& text) {
    std::vector<std::pair<std::string, std::string>> fields;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find('&', start);
        if (end == std::string::npos) end = text.size();
        std::string pair = text.substr(start, end - start);
        start = end + 1;
        if (pair.empty()) continue;
        std::size_t equals = pair.find('=');
        std::string key = pair.substr(0, equals);
        std::string value = equals == std::string::npos ? std::string() : pair.substr(equals + 1);
        std::replace(key.begin(), key.end(), '+', ' ');
        std::replace(value.begin(), value.end(), '+', ' ');
        std::string decodedKey;
        std::string decodedValue;
        if (percentDecode(key, decodedKey) && percentDecode(value, decodedValue)) fields.emplace_back(decodedKey, decodedValue);
    }
    return fields;
}

}
