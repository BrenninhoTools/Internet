#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace internet {

class Sha256 {
public:
    Sha256();
    void update(const std::uint8_t* data, std::size_t size);
    std::array<std::uint8_t, 32> finish();

private:
    void block(const std::uint8_t* chunk);

    std::array<std::uint32_t, 8> state_;
    std::array<std::uint8_t, 64> buffer_;
    std::size_t buffered_ = 0;
    std::uint64_t total_ = 0;
};

std::string sha256Hex(const std::uint8_t* data, std::size_t size);
std::string sha256Hex(const std::string& data);
std::string toHex(const std::uint8_t* data, std::size_t size);
bool fromHex(const std::string& text, std::string& bytes);
bool constantTimeEquals(const std::string& a, const std::string& b);

}
