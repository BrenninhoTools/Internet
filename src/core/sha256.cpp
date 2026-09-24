#include "sha256.hpp"

#include <algorithm>
#include <cstring>

namespace internet {

namespace {

const std::uint32_t kRound[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

std::uint32_t rotate(std::uint32_t value, int bits) { return (value >> bits) | (value << (32 - bits)); }

}

Sha256::Sha256() : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}, buffer_{} {}

void Sha256::block(const std::uint8_t* chunk) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(chunk[i * 4]) << 24) | (static_cast<std::uint32_t>(chunk[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(chunk[i * 4 + 2]) << 8) | static_cast<std::uint32_t>(chunk[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        std::uint32_t s0 = rotate(w[i - 15], 7) ^ rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        std::uint32_t s1 = rotate(w[i - 2], 17) ^ rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        std::uint32_t choose = (e & f) ^ (~e & g);
        std::uint32_t t1 = h + s1 + choose + kRound[i] + w[i];
        std::uint32_t s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        std::uint32_t t2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t size) {
    total_ += size;
    while (size > 0) {
        std::size_t take = std::min<std::size_t>(size, 64 - buffered_);
        std::memcpy(buffer_.data() + buffered_, data, take);
        buffered_ += take;
        data += take;
        size -= take;
        if (buffered_ == 64) {
            block(buffer_.data());
            buffered_ = 0;
        }
    }
}

std::array<std::uint8_t, 32> Sha256::finish() {
    std::uint64_t bits = total_ * 8;
    std::uint8_t pad = 0x80;
    update(&pad, 1);
    std::uint8_t zero = 0;
    while (buffered_ != 56) update(&zero, 1);
    std::uint8_t length[8];
    for (int i = 0; i < 8; ++i) length[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    update(length, 8);
    std::array<std::uint8_t, 32> digest{};
    for (int i = 0; i < 8; ++i) {
        digest[static_cast<std::size_t>(i) * 4] = static_cast<std::uint8_t>(state_[static_cast<std::size_t>(i)] >> 24);
        digest[static_cast<std::size_t>(i) * 4 + 1] = static_cast<std::uint8_t>(state_[static_cast<std::size_t>(i)] >> 16);
        digest[static_cast<std::size_t>(i) * 4 + 2] = static_cast<std::uint8_t>(state_[static_cast<std::size_t>(i)] >> 8);
        digest[static_cast<std::size_t>(i) * 4 + 3] = static_cast<std::uint8_t>(state_[static_cast<std::size_t>(i)]);
    }
    return digest;
}

std::string toHex(const std::uint8_t* data, std::size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        text += digits[data[i] >> 4];
        text += digits[data[i] & 15];
    }
    return text;
}

bool fromHex(const std::string& text, std::string& bytes) {
    auto value = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (text.size() % 2 != 0) return false;
    bytes.clear();
    for (std::size_t i = 0; i < text.size(); i += 2) {
        int high = value(text[i]);
        int low = value(text[i + 1]);
        if (high < 0 || low < 0) return false;
        bytes += static_cast<char>(high * 16 + low);
    }
    return true;
}

std::string sha256Hex(const std::uint8_t* data, std::size_t size) {
    Sha256 hash;
    hash.update(data, size);
    std::array<std::uint8_t, 32> digest = hash.finish();
    return toHex(digest.data(), digest.size());
}

std::string sha256Hex(const std::string& data) {
    return sha256Hex(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
    unsigned char difference = static_cast<unsigned char>(a.size() != b.size());
    std::size_t length = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < length; ++i) difference |= static_cast<unsigned char>(a[i] ^ b[i]);
    return difference == 0;
}

}
