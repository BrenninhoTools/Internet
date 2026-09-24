#include "deflate.hpp"

#include <algorithm>
#include <array>

namespace internet {

namespace {

const int kLengthBase[] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                           31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const int kLengthExtra[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const int kDistanceBase[] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                             193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
const int kDistanceExtra[] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

class BitWriter {
public:
    explicit BitWriter(std::vector<std::uint8_t>& out) : out_(out) {}

    void put(std::uint32_t value, int bits) {
        buffer_ |= value << count_;
        count_ += bits;
        while (count_ >= 8) {
            out_.push_back(static_cast<std::uint8_t>(buffer_ & 0xFF));
            buffer_ >>= 8;
            count_ -= 8;
        }
    }

    void putCode(std::uint32_t code, int bits) {
        std::uint32_t reversed = 0;
        for (int i = 0; i < bits; ++i) reversed |= ((code >> i) & 1u) << (bits - 1 - i);
        put(reversed, bits);
    }

    void flush() {
        if (count_ > 0) out_.push_back(static_cast<std::uint8_t>(buffer_ & 0xFF));
        buffer_ = 0;
        count_ = 0;
    }

private:
    std::vector<std::uint8_t>& out_;
    std::uint32_t buffer_ = 0;
    int count_ = 0;
};

void putSymbol(BitWriter& writer, int symbol) {
    if (symbol < 144) {
        writer.putCode(static_cast<std::uint32_t>(0x30 + symbol), 8);
    } else if (symbol < 256) {
        writer.putCode(static_cast<std::uint32_t>(0x190 + (symbol - 144)), 9);
    } else if (symbol < 280) {
        writer.putCode(static_cast<std::uint32_t>(symbol - 256), 7);
    } else {
        writer.putCode(static_cast<std::uint32_t>(0xC0 + (symbol - 280)), 8);
    }
}

class BitReader {
public:
    BitReader(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}

    bool bit(int& value) {
        if (position_ >= size_ * 8) return false;
        value = (data_[position_ >> 3] >> (position_ & 7)) & 1;
        ++position_;
        return true;
    }

    bool bits(int count, std::uint32_t& value) {
        value = 0;
        for (int i = 0; i < count; ++i) {
            int b = 0;
            if (!bit(b)) return false;
            value |= static_cast<std::uint32_t>(b) << i;
        }
        return true;
    }

    void align() { position_ = (position_ + 7) & ~static_cast<std::size_t>(7); }

    bool bytes(std::size_t count, std::vector<std::uint8_t>& out, std::size_t limit) {
        std::size_t start = position_ >> 3;
        if (start + count > size_ || out.size() + count > limit) return false;
        out.insert(out.end(), data_ + start, data_ + start + count);
        position_ += count * 8;
        return true;
    }

private:
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t position_ = 0;
};

struct Huffman {
    std::array<std::uint16_t, 16> count{};
    std::vector<std::uint16_t> symbol;
};

int buildHuffman(Huffman& table, const std::uint8_t* lengths, int n) {
    table.count.fill(0);
    for (int i = 0; i < n; ++i) ++table.count[lengths[i]];
    if (table.count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len <= 15; ++len) {
        left <<= 1;
        left -= table.count[static_cast<std::size_t>(len)];
        if (left < 0) return left;
    }
    std::array<std::uint16_t, 16> offsets{};
    for (int len = 1; len < 15; ++len)
        offsets[static_cast<std::size_t>(len) + 1] =
            static_cast<std::uint16_t>(offsets[static_cast<std::size_t>(len)] + table.count[static_cast<std::size_t>(len)]);
    table.symbol.assign(static_cast<std::size_t>(n), 0);
    for (int symbol = 0; symbol < n; ++symbol) {
        if (lengths[symbol] != 0) table.symbol[offsets[lengths[symbol]]++] = static_cast<std::uint16_t>(symbol);
    }
    return left;
}

int decodeSymbol(BitReader& reader, const Huffman& table) {
    int code = 0;
    int first = 0;
    int index = 0;
    for (int len = 1; len <= 15; ++len) {
        int b = 0;
        if (!reader.bit(b)) return -1;
        code |= b;
        int count = table.count[static_cast<std::size_t>(len)];
        if (code - count < first) return table.symbol[static_cast<std::size_t>(index + (code - first))];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

bool inflateBlock(BitReader& reader, const Huffman& literals, const Huffman& distances, std::vector<std::uint8_t>& out,
                  std::size_t limit) {
    for (;;) {
        int symbol = decodeSymbol(reader, literals);
        if (symbol < 0) return false;
        if (symbol < 256) {
            if (out.size() >= limit) return false;
            out.push_back(static_cast<std::uint8_t>(symbol));
        } else if (symbol == 256) {
            return true;
        } else {
            symbol -= 257;
            if (symbol >= 29) return false;
            std::uint32_t extra = 0;
            if (!reader.bits(kLengthExtra[symbol], extra)) return false;
            std::size_t length = static_cast<std::size_t>(kLengthBase[symbol]) + extra;
            int distanceSymbol = decodeSymbol(reader, distances);
            if (distanceSymbol < 0 || distanceSymbol >= 30) return false;
            if (!reader.bits(kDistanceExtra[distanceSymbol], extra)) return false;
            std::size_t distance = static_cast<std::size_t>(kDistanceBase[distanceSymbol]) + extra;
            if (distance > out.size() || out.size() + length > limit) return false;
            for (std::size_t i = 0; i < length; ++i) out.push_back(out[out.size() - distance]);
        }
    }
}

void putLittle(std::vector<std::uint8_t>& out, std::uint32_t value, int bytes) {
    for (int i = 0; i < bytes; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

std::uint32_t readLittle(const std::uint8_t* data, int bytes) {
    std::uint32_t value = 0;
    for (int i = 0; i < bytes; ++i) value |= static_cast<std::uint32_t>(data[i]) << (8 * i);
    return value;
}

}

std::uint32_t crc32(const std::uint8_t* data, std::size_t size) {
    static const std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> result{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            result[i] = c;
        }
        return result;
    }();
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < size; ++i) c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

std::vector<std::uint8_t> deflateCompress(const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> out;
    BitWriter writer(out);
    writer.put(1, 1);
    writer.put(1, 2);

    const std::size_t size = data.size();
    std::vector<int> head(65536, -1);
    std::vector<int> previous(32768, -1);
    auto hash = [&](std::size_t p) {
        return ((static_cast<std::uint32_t>(data[p]) << 10) ^ (static_cast<std::uint32_t>(data[p + 1]) << 5) ^ data[p + 2]) & 0xFFFF;
    };
    auto insert = [&](std::size_t p) {
        if (p + 2 < size) {
            std::uint32_t h = hash(p);
            previous[p & 32767] = head[h];
            head[h] = static_cast<int>(p);
        }
    };

    std::size_t i = 0;
    while (i < size) {
        std::size_t bestLength = 0;
        std::size_t bestDistance = 0;
        if (i + 2 < size) {
            int candidate = head[hash(i)];
            int chain = 48;
            const std::size_t maxLength = std::min<std::size_t>(258, size - i);
            while (candidate >= 0 && i - static_cast<std::size_t>(candidate) <= 32768 && chain-- > 0) {
                std::size_t length = 0;
                while (length < maxLength && data[static_cast<std::size_t>(candidate) + length] == data[i + length]) ++length;
                if (length > bestLength) {
                    bestLength = length;
                    bestDistance = i - static_cast<std::size_t>(candidate);
                    if (length == maxLength) break;
                }
                candidate = previous[static_cast<std::size_t>(candidate) & 32767];
            }
        }
        if (bestLength >= 3) {
            int code = 28;
            while (kLengthBase[code] > static_cast<int>(bestLength)) --code;
            putSymbol(writer, 257 + code);
            if (kLengthExtra[code] > 0) writer.put(static_cast<std::uint32_t>(bestLength - kLengthBase[code]), kLengthExtra[code]);
            int distanceCode = 29;
            while (kDistanceBase[distanceCode] > static_cast<int>(bestDistance)) --distanceCode;
            writer.putCode(static_cast<std::uint32_t>(distanceCode), 5);
            if (kDistanceExtra[distanceCode] > 0)
                writer.put(static_cast<std::uint32_t>(bestDistance - kDistanceBase[distanceCode]), kDistanceExtra[distanceCode]);
            for (std::size_t k = 0; k < bestLength; ++k) insert(i + k);
            i += bestLength;
        } else {
            putSymbol(writer, data[i]);
            insert(i);
            ++i;
        }
    }
    putSymbol(writer, 256);
    writer.flush();
    return out;
}

bool inflateRaw(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out, std::size_t limit) {
    out.clear();
    BitReader reader(data, size);
    int last = 0;
    do {
        int finalBit = 0;
        std::uint32_t type = 0;
        if (!reader.bit(finalBit) || !reader.bits(2, type)) return false;
        last = finalBit;
        if (type == 0) {
            reader.align();
            std::vector<std::uint8_t> header;
            if (!reader.bytes(4, header, 4)) return false;
            std::uint32_t length = readLittle(header.data(), 2);
            std::uint32_t inverse = readLittle(header.data() + 2, 2);
            if ((length ^ 0xFFFFu) != inverse) return false;
            if (!reader.bytes(length, out, limit)) return false;
        } else if (type == 1) {
            std::uint8_t lengths[288];
            for (int i = 0; i < 144; ++i) lengths[i] = 8;
            for (int i = 144; i < 256; ++i) lengths[i] = 9;
            for (int i = 256; i < 280; ++i) lengths[i] = 7;
            for (int i = 280; i < 288; ++i) lengths[i] = 8;
            Huffman literals;
            buildHuffman(literals, lengths, 288);
            std::uint8_t distanceLengths[30];
            for (int i = 0; i < 30; ++i) distanceLengths[i] = 5;
            Huffman distances;
            buildHuffman(distances, distanceLengths, 30);
            if (!inflateBlock(reader, literals, distances, out, limit)) return false;
        } else if (type == 2) {
            std::uint32_t hlit = 0, hdist = 0, hclen = 0;
            if (!reader.bits(5, hlit) || !reader.bits(5, hdist) || !reader.bits(4, hclen)) return false;
            hlit += 257;
            hdist += 1;
            hclen += 4;
            if (hlit > 286 || hdist > 30) return false;
            static const int order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
            std::uint8_t codeLengths[19] = {0};
            for (std::uint32_t i = 0; i < hclen; ++i) {
                std::uint32_t value = 0;
                if (!reader.bits(3, value)) return false;
                codeLengths[order[i]] = static_cast<std::uint8_t>(value);
            }
            Huffman lengthTable;
            if (buildHuffman(lengthTable, codeLengths, 19) != 0) return false;
            std::uint8_t lengths[316] = {0};
            std::uint32_t index = 0;
            while (index < hlit + hdist) {
                int symbol = decodeSymbol(reader, lengthTable);
                if (symbol < 0) return false;
                if (symbol < 16) {
                    lengths[index++] = static_cast<std::uint8_t>(symbol);
                } else {
                    std::uint8_t previousLength = 0;
                    std::uint32_t repeat = 0;
                    std::uint32_t extra = 0;
                    if (symbol == 16) {
                        if (index == 0) return false;
                        previousLength = lengths[index - 1];
                        if (!reader.bits(2, extra)) return false;
                        repeat = 3 + extra;
                    } else if (symbol == 17) {
                        if (!reader.bits(3, extra)) return false;
                        repeat = 3 + extra;
                    } else {
                        if (!reader.bits(7, extra)) return false;
                        repeat = 11 + extra;
                    }
                    if (index + repeat > hlit + hdist) return false;
                    while (repeat-- > 0) lengths[index++] = previousLength;
                }
            }
            if (lengths[256] == 0) return false;
            Huffman literals;
            int status = buildHuffman(literals, lengths, static_cast<int>(hlit));
            if (status < 0 || (status > 0 && hlit - literals.count[0] != 1)) return false;
            Huffman distances;
            status = buildHuffman(distances, lengths + hlit, static_cast<int>(hdist));
            if (status < 0 || (status > 0 && hdist - distances.count[0] != 1)) return false;
            if (!inflateBlock(reader, literals, distances, out, limit)) return false;
        } else {
            return false;
        }
    } while (!last);
    return true;
}

bool readZip(const std::uint8_t* data, std::size_t size, std::vector<ZipEntry>& entries, std::string& error) {
    entries.clear();
    if (size < 22) {
        error = "Not a ZIP file";
        return false;
    }
    std::size_t searchStart = size > 65557 ? size - 65557 : 0;
    std::size_t end = std::string::npos;
    for (std::size_t i = size - 22 + 1; i-- > searchStart;) {
        if (readLittle(data + i, 4) == 0x06054b50u) {
            end = i;
            break;
        }
    }
    if (end == std::string::npos) {
        error = "Missing end of central directory";
        return false;
    }
    std::uint32_t total = readLittle(data + end + 10, 2);
    std::uint32_t directorySize = readLittle(data + end + 12, 4);
    std::uint32_t directoryOffset = readLittle(data + end + 16, 4);
    if (total == 0xFFFF || directoryOffset == 0xFFFFFFFFu || directorySize == 0xFFFFFFFFu) {
        error = "ZIP64 archives are not supported";
        return false;
    }
    if (static_cast<std::uint64_t>(directoryOffset) + directorySize > size || total > 50000) {
        error = "Corrupt central directory";
        return false;
    }
    std::size_t position = directoryOffset;
    for (std::uint32_t i = 0; i < total; ++i) {
        if (position + 46 > size || readLittle(data + position, 4) != 0x02014b50u) {
            error = "Corrupt central directory entry";
            return false;
        }
        ZipEntry entry;
        entry.flags = static_cast<std::uint16_t>(readLittle(data + position + 8, 2));
        entry.method = static_cast<std::uint16_t>(readLittle(data + position + 10, 2));
        entry.crc = readLittle(data + position + 16, 4);
        entry.compressedSize = readLittle(data + position + 20, 4);
        entry.size = readLittle(data + position + 24, 4);
        std::uint32_t nameLength = readLittle(data + position + 28, 2);
        std::uint32_t extraLength = readLittle(data + position + 30, 2);
        std::uint32_t commentLength = readLittle(data + position + 32, 2);
        entry.offset = readLittle(data + position + 42, 4);
        if (position + 46 + nameLength + extraLength + commentLength > size) {
            error = "Corrupt central directory entry";
            return false;
        }
        entry.name.assign(reinterpret_cast<const char*>(data + position + 46), nameLength);
        entry.encrypted = (entry.flags & 1) != 0;
        entry.directory = !entry.name.empty() && entry.name.back() == '/';
        entries.push_back(std::move(entry));
        position += 46 + nameLength + extraLength + commentLength;
    }
    return true;
}

bool extractZip(const std::uint8_t* data, std::size_t size, const ZipEntry& entry, std::size_t limit,
                std::vector<std::uint8_t>& out, std::string& error) {
    out.clear();
    if (entry.encrypted) {
        error = "Entry is encrypted";
        return false;
    }
    if (entry.offset + 30 > size || readLittle(data + entry.offset, 4) != 0x04034b50u) {
        error = "Corrupt local header";
        return false;
    }
    std::uint32_t nameLength = readLittle(data + entry.offset + 26, 2);
    std::uint32_t extraLength = readLittle(data + entry.offset + 28, 2);
    std::uint64_t start = entry.offset + 30 + nameLength + extraLength;
    if (start + entry.compressedSize > size) {
        error = "Entry data is truncated";
        return false;
    }
    if (entry.size > limit) {
        error = "Entry is too large";
        return false;
    }
    const std::uint8_t* payload = data + start;
    if (entry.method == 0) {
        out.assign(payload, payload + entry.compressedSize);
    } else if (entry.method == 8) {
        if (!inflateRaw(payload, static_cast<std::size_t>(entry.compressedSize), out, limit)) {
            error = "Cannot inflate entry";
            return false;
        }
    } else {
        error = "Unsupported compression method";
        return false;
    }
    if (crc32(out.data(), out.size()) != entry.crc) {
        error = "CRC mismatch";
        return false;
    }
    return true;
}

std::vector<std::uint8_t> buildZip(const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>& files,
                                   bool compress) {
    std::vector<std::uint8_t> out;
    std::vector<std::uint8_t> directory;
    for (const auto& [name, content] : files) {
        std::vector<std::uint8_t> packed;
        std::uint16_t method = 0;
        if (compress) {
            packed = deflateCompress(content);
            method = 8;
            if (packed.size() >= content.size()) {
                packed = content;
                method = 0;
            }
        } else {
            packed = content;
        }
        std::uint32_t crc = crc32(content.data(), content.size());
        std::uint32_t offset = static_cast<std::uint32_t>(out.size());

        putLittle(out, 0x04034b50u, 4);
        putLittle(out, 20, 2);
        putLittle(out, 0, 2);
        putLittle(out, method, 2);
        putLittle(out, 0, 2);
        putLittle(out, 0x21, 2);
        putLittle(out, crc, 4);
        putLittle(out, static_cast<std::uint32_t>(packed.size()), 4);
        putLittle(out, static_cast<std::uint32_t>(content.size()), 4);
        putLittle(out, static_cast<std::uint32_t>(name.size()), 2);
        putLittle(out, 0, 2);
        out.insert(out.end(), name.begin(), name.end());
        out.insert(out.end(), packed.begin(), packed.end());

        putLittle(directory, 0x02014b50u, 4);
        putLittle(directory, 20, 2);
        putLittle(directory, 20, 2);
        putLittle(directory, 0, 2);
        putLittle(directory, method, 2);
        putLittle(directory, 0, 2);
        putLittle(directory, 0x21, 2);
        putLittle(directory, crc, 4);
        putLittle(directory, static_cast<std::uint32_t>(packed.size()), 4);
        putLittle(directory, static_cast<std::uint32_t>(content.size()), 4);
        putLittle(directory, static_cast<std::uint32_t>(name.size()), 2);
        putLittle(directory, 0, 2);
        putLittle(directory, 0, 2);
        putLittle(directory, 0, 2);
        putLittle(directory, 0, 2);
        putLittle(directory, 0, 4);
        putLittle(directory, offset, 4);
        directory.insert(directory.end(), name.begin(), name.end());
    }
    std::uint32_t directoryOffset = static_cast<std::uint32_t>(out.size());
    out.insert(out.end(), directory.begin(), directory.end());
    putLittle(out, 0x06054b50u, 4);
    putLittle(out, 0, 2);
    putLittle(out, 0, 2);
    putLittle(out, static_cast<std::uint32_t>(files.size()), 2);
    putLittle(out, static_cast<std::uint32_t>(files.size()), 2);
    putLittle(out, static_cast<std::uint32_t>(directory.size()), 4);
    putLittle(out, directoryOffset, 4);
    putLittle(out, 0, 2);
    return out;
}

}
