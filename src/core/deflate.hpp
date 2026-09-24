#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace internet {

std::uint32_t crc32(const std::uint8_t* data, std::size_t size);
std::vector<std::uint8_t> deflateCompress(const std::vector<std::uint8_t>& data);
bool inflateRaw(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out, std::size_t limit);

struct ZipEntry {
    std::string name;
    std::uint16_t method = 0;
    std::uint16_t flags = 0;
    std::uint32_t crc = 0;
    std::uint64_t compressedSize = 0;
    std::uint64_t size = 0;
    std::uint64_t offset = 0;
    bool directory = false;
    bool encrypted = false;
};

bool readZip(const std::uint8_t* data, std::size_t size, std::vector<ZipEntry>& entries, std::string& error);
bool extractZip(const std::uint8_t* data, std::size_t size, const ZipEntry& entry, std::size_t limit,
                std::vector<std::uint8_t>& out, std::string& error);
std::vector<std::uint8_t> buildZip(const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>& files,
                                   bool compress);

}
