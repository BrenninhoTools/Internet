#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "icon.hpp"

namespace fs = std::filesystem;

namespace {

using Bytes = std::vector<std::uint8_t>;

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

std::uint32_t adler32(const Bytes& data) {
    std::uint32_t a = 1;
    std::uint32_t b = 0;
    for (std::uint8_t byte : data) {
        a = (a + byte) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

void putBigEndian(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

void putLittleEndian(Bytes& out, std::uint32_t value, int bytes) {
    for (int i = 0; i < bytes; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

void putText(Bytes& out, const char* text) {
    for (; *text; ++text) out.push_back(static_cast<std::uint8_t>(*text));
}

class BitWriter {
public:
    explicit BitWriter(Bytes& out) : out_(out) {}

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
    Bytes& out_;
    std::uint32_t buffer_ = 0;
    int count_ = 0;
};

void putSymbol(BitWriter& writer, int symbol) {
    if (symbol < 144) {
        writer.putCode(0x30 + symbol, 8);
    } else if (symbol < 256) {
        writer.putCode(0x190 + (symbol - 144), 9);
    } else if (symbol < 280) {
        writer.putCode(symbol - 256, 7);
    } else {
        writer.putCode(0xC0 + (symbol - 280), 8);
    }
}

Bytes deflate(const Bytes& data) {
    static const int lengthBase[] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                     31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
    static const int lengthExtra[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    static const int distanceBase[] = {1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
                                       193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
    static const int distanceExtra[] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

    Bytes out;
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
                while (length < maxLength && data[candidate + length] == data[i + length]) ++length;
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
            while (lengthBase[code] > static_cast<int>(bestLength)) --code;
            putSymbol(writer, 257 + code);
            if (lengthExtra[code] > 0) writer.put(static_cast<std::uint32_t>(bestLength - lengthBase[code]), lengthExtra[code]);
            int distanceCode = 29;
            while (distanceBase[distanceCode] > static_cast<int>(bestDistance)) --distanceCode;
            writer.putCode(static_cast<std::uint32_t>(distanceCode), 5);
            if (distanceExtra[distanceCode] > 0)
                writer.put(static_cast<std::uint32_t>(bestDistance - distanceBase[distanceCode]), distanceExtra[distanceCode]);
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

void putChunk(Bytes& png, const char* type, const Bytes& body) {
    putBigEndian(png, static_cast<std::uint32_t>(body.size()));
    Bytes typed;
    putText(typed, type);
    typed.insert(typed.end(), body.begin(), body.end());
    png.insert(png.end(), typed.begin(), typed.end());
    putBigEndian(png, crc32(typed.data(), typed.size()));
}

Bytes encodePng(int size, const Bytes& rgba, bool withAlpha) {
    const int channels = withAlpha ? 4 : 3;
    const std::size_t stride = static_cast<std::size_t>(size) * channels;
    Bytes raw;
    raw.reserve((stride + 1) * size);
    Bytes row(stride);
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            const std::uint8_t* pixel = &rgba[(static_cast<std::size_t>(y) * size + x) * 4];
            for (int c = 0; c < channels; ++c) row[static_cast<std::size_t>(x) * channels + c] = pixel[c];
        }
        raw.push_back(1);
        for (std::size_t i = 0; i < stride; ++i) {
            std::uint8_t left = i >= static_cast<std::size_t>(channels) ? row[i - channels] : 0;
            raw.push_back(static_cast<std::uint8_t>(row[i] - left));
        }
    }

    Bytes zlib = {0x78, 0x01};
    Bytes compressed = deflate(raw);
    zlib.insert(zlib.end(), compressed.begin(), compressed.end());
    putBigEndian(zlib, adler32(raw));

    Bytes header;
    putBigEndian(header, static_cast<std::uint32_t>(size));
    putBigEndian(header, static_cast<std::uint32_t>(size));
    header.push_back(8);
    header.push_back(withAlpha ? 6 : 2);
    header.push_back(0);
    header.push_back(0);
    header.push_back(0);

    Bytes png = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    putChunk(png, "IHDR", header);
    putChunk(png, "IDAT", zlib);
    putChunk(png, "IEND", {});
    return png;
}

Bytes pngFor(int size, bool rounded) { return encodePng(size, internet::renderIcon(size, rounded), rounded); }

void writeFile(const fs::path& path, const Bytes& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) throw std::runtime_error("cannot write " + path.string());
}

Bytes buildIco(const std::vector<int>& sizes) {
    std::vector<Bytes> images;
    for (int size : sizes) images.push_back(pngFor(size, true));

    Bytes ico;
    putLittleEndian(ico, 0, 2);
    putLittleEndian(ico, 1, 2);
    putLittleEndian(ico, static_cast<std::uint32_t>(sizes.size()), 2);
    std::uint32_t offset = 6 + 16 * static_cast<std::uint32_t>(sizes.size());
    for (std::size_t i = 0; i < sizes.size(); ++i) {
        ico.push_back(static_cast<std::uint8_t>(sizes[i] >= 256 ? 0 : sizes[i]));
        ico.push_back(static_cast<std::uint8_t>(sizes[i] >= 256 ? 0 : sizes[i]));
        ico.push_back(0);
        ico.push_back(0);
        putLittleEndian(ico, 1, 2);
        putLittleEndian(ico, 32, 2);
        putLittleEndian(ico, static_cast<std::uint32_t>(images[i].size()), 4);
        putLittleEndian(ico, offset, 4);
        offset += static_cast<std::uint32_t>(images[i].size());
    }
    for (const Bytes& image : images) ico.insert(ico.end(), image.begin(), image.end());
    return ico;
}

Bytes buildIcns() {
    struct Entry {
        const char* type;
        int size;
    };
    const Entry entries[] = {{"ic07", 128}, {"ic08", 256}, {"ic09", 512}, {"ic10", 1024}};
    Bytes body;
    for (const Entry& entry : entries) {
        Bytes image = pngFor(entry.size, true);
        putText(body, entry.type);
        putBigEndian(body, static_cast<std::uint32_t>(image.size() + 8));
        body.insert(body.end(), image.begin(), image.end());
    }
    Bytes icns;
    putText(icns, "icns");
    putBigEndian(icns, static_cast<std::uint32_t>(body.size() + 8));
    icns.insert(icns.end(), body.begin(), body.end());
    return icns;
}

}

int main(int argc, char** argv) {
    try {
        fs::path root = argc > 1 ? fs::path(argv[1]) : fs::path(".");

        writeFile(root / "assets/icons/internet.ico", buildIco({16, 24, 32, 48, 64, 128, 256}));
        writeFile(root / "assets/icons/internet.icns", buildIcns());
        writeFile(root / "assets/icons/icon-512.png", pngFor(512, true));
        writeFile(root / "assets/icons/icon-1024.png", pngFor(1024, true));

        const std::pair<const char*, int> android[] = {{"mdpi", 48}, {"hdpi", 72}, {"xhdpi", 96}, {"xxhdpi", 144}, {"xxxhdpi", 192}};
        for (const auto& [density, size] : android) {
            writeFile(root / "android/app/src/main/res" / (std::string("mipmap-") + density) / "ic_launcher.png",
                      pngFor(size, true));
        }

        const std::pair<const char*, int> ios[] = {{"Icon-60@2x.png", 120}, {"Icon-60@3x.png", 180}, {"Icon-76.png", 76},
                                                   {"Icon-76@2x.png", 152}, {"Icon-83.5@2x.png", 167}, {"Icon-1024.png", 1024}};
        for (const auto& [name, size] : ios) writeFile(root / "ios/icons" / name, pngFor(size, false));

        std::cout << "icons written to " << fs::absolute(root).string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
