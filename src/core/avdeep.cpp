#include "avdeep.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <set>

#include "deflate.hpp"
#include "encoding.hpp"
#include "sha256.hpp"

namespace internet {

namespace {

constexpr std::size_t kMaxLayers = 8;
constexpr std::size_t kMaxLayerBytes = 2u * 1024u * 1024u;
constexpr std::size_t kMaxVbaSource = 1024u * 1024u;
constexpr std::size_t kMaxStreamBytes = 8u * 1024u * 1024u;
constexpr std::uint32_t kEndOfChain = 0xFFFFFFFEu;
constexpr std::uint32_t kNoStream = 0xFFFFFFFFu;

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool endsWith(const std::string& text, const std::string& suffix) {
    return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool contains(const std::string& text, const char* part) { return text.find(part) != std::string::npos; }

std::uint32_t le(const std::uint8_t* data, int bytes) {
    std::uint32_t value = 0;
    for (int i = 0; i < bytes; ++i) value |= static_cast<std::uint32_t>(data[i]) << (8 * i);
    return value;
}

double printableRatio(const std::string& text) {
    if (text.empty()) return 0.0;
    std::size_t good = 0;
    for (unsigned char c : text) {
        if ((c >= 32 && c < 127) || c == '\t' || c == '\n' || c == '\r') ++good;
    }
    return static_cast<double>(good) / static_cast<double>(text.size());
}

bool startsWithMagic(const std::string& bytes, const char* magic, std::size_t length) {
    return bytes.size() >= length && std::memcmp(bytes.data(), magic, length) == 0;
}

bool imageMagic(const std::string& bytes) {
    return startsWithMagic(bytes, "\x89PNG", 4) || startsWithMagic(bytes, "\xFF\xD8\xFF", 3) || startsWithMagic(bytes, "GIF8", 4) ||
           startsWithMagic(bytes, "RIFF", 4) || startsWithMagic(bytes, "wOFF", 4) || startsWithMagic(bytes, "wOF2", 4) ||
           startsWithMagic(bytes, "\x00\x01\x00\x00", 4) || startsWithMagic(bytes, "\x00\x00\x01\x00", 4);
}

bool utf16Text(const std::string& bytes) {
    if (bytes.size() < 16) return false;
    std::size_t zeros = 0;
    std::size_t odd = 0;
    for (std::size_t i = 1; i < bytes.size(); i += 2) {
        ++odd;
        if (bytes[i] == 0) ++zeros;
    }
    return odd > 0 && zeros * 10 >= odd * 8;
}

std::string narrow(const std::string& bytes) {
    std::string text;
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
        if (bytes[i + 1] == 0 && bytes[i] != 0) text += bytes[i];
    }
    return text;
}

void appendUtf8(std::string& out, std::uint32_t code) {
    if (code < 0x80) {
        out += static_cast<char>(code);
    } else if (code < 0x800) {
        out += static_cast<char>(0xC0 | (code >> 6));
        out += static_cast<char>(0x80 | (code & 0x3F));
    } else if (code < 0x10000) {
        out += static_cast<char>(0xE0 | (code >> 12));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (code >> 18));
        out += static_cast<char>(0x80 | ((code >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
    }
}

class LayerCollector {
public:
    LayerCollector(std::size_t budget) : budget_(std::min(budget, kMaxLayerBytes)) {}

    bool full() const { return layers_.size() >= kMaxLayers || total_ >= budget_; }
    std::vector<DecodedLayer> take() { return std::move(layers_); }

    void offer(const std::string& source, const std::string& bytes, int depth = 0) {
        if (full() || bytes.size() < 8 || bytes.size() > budget_ || imageMagic(bytes)) return;
        std::string key = std::to_string(bytes.size()) + ":" + bytes.substr(0, 48);
        if (!seen_.insert(key).second) return;
        if (startsWithMagic(bytes, "MZ", 2)) return add("pe", "bin", bytes);
        if (startsWithMagic(bytes, "\x7f" "ELF", 4)) return add("elf", "bin", bytes);
        if (startsWithMagic(bytes, "PK\x03\x04", 4)) return add("zip", "zip", bytes);
        if (startsWithMagic(bytes, "\x1F\x8B\x08", 3)) return add("gzip", "gz", bytes);
        if (utf16Text(bytes)) {
            std::string text = narrow(bytes);
            if (text.size() >= 8 && printableRatio(text) >= 0.85) return add(source == "enc" ? "powershell" : "text", source == "enc" ? "ps1" : "txt", text);
        }
        if (printableRatio(bytes) >= 0.9) return add(source == "enc" ? "powershell" : "text", source == "enc" ? "ps1" : "txt", bytes);
        if (depth >= 2) return;
        std::vector<std::uint8_t> inflated;
        if (inflateRaw(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size(), inflated, kMaxLayerBytes) && inflated.size() >= 8) {
            std::string expanded(inflated.begin(), inflated.end());
            std::size_t before = layers_.size();
            offer(source, expanded, depth + 1);
            if (layers_.size() > before) layers_.back().label += "+deflate";
        }
    }

private:
    void add(const std::string& label, const std::string& extension, const std::string& bytes) {
        if (total_ + bytes.size() > budget_) return;
        total_ += bytes.size();
        layers_.push_back(DecodedLayer{label, extension, bytes});
    }

    std::size_t budget_;
    std::size_t total_ = 0;
    std::vector<DecodedLayer> layers_;
    std::set<std::string> seen_;
};

bool base64Char(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/'; }

bool hexChar(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }

void decodeBase64Runs(const std::string& text, const std::string& lower, LayerCollector& collector) {
    std::size_t i = 0;
    while (i < text.size() && !collector.full()) {
        if (!base64Char(text[i])) {
            ++i;
            continue;
        }
        std::size_t start = i;
        while (i < text.size() && base64Char(text[i])) ++i;
        std::size_t end = i;
        while (i < text.size() && text[i] == '=' && i - end < 2) ++i;
        std::size_t length = end - start;
        std::size_t contextStart = start > 48 ? start - 48 : 0;
        std::string context = lower.substr(contextStart, start - contextStart);
        bool encoded = context.find("-enc") != std::string::npos || context.find("-ec ") != std::string::npos ||
                       context.find("frombase64string") != std::string::npos || context.find("atob") != std::string::npos ||
                       context.find("base64") != std::string::npos;
        bool powershell = context.find("-enc") != std::string::npos || context.find("-ec ") != std::string::npos ||
                          context.find("frombase64string") != std::string::npos;
        if (length < (encoded ? 24u : 64u)) continue;
        std::string decoded;
        if (!base64UrlDecode(text.substr(start, i - start), decoded)) continue;
        collector.offer(powershell ? "enc" : "base64", decoded);
    }
}

void decodeHexRuns(const std::string& text, LayerCollector& collector) {
    std::size_t i = 0;
    while (i < text.size() && !collector.full()) {
        if (!hexChar(text[i])) {
            ++i;
            continue;
        }
        std::size_t start = i;
        while (i < text.size() && hexChar(text[i])) ++i;
        std::size_t length = i - start;
        if (length < 400) continue;
        if (length % 2 != 0) --length;
        std::string bytes;
        if (fromHex(text.substr(start, length), bytes)) collector.offer("hex", bytes);
    }
}

void decodeEscapeRuns(const std::string& text, LayerCollector& collector) {
    std::size_t i = 0;
    while (i + 3 < text.size() && !collector.full()) {
        if (!(text[i] == '\\' && text[i + 1] == 'x' && hexChar(text[i + 2]) && hexChar(text[i + 3]))) {
            ++i;
            continue;
        }
        std::string bytes;
        while (i + 3 < text.size() && text[i] == '\\' && text[i + 1] == 'x' && hexChar(text[i + 2]) && hexChar(text[i + 3])) {
            bytes += static_cast<char>(std::stoi(text.substr(i + 2, 2), nullptr, 16));
            i += 4;
        }
        if (bytes.size() >= 100) collector.offer("escapes", bytes);
    }
}

std::string numberList(const std::string& text, std::size_t position, std::size_t minimum) {
    std::string out;
    std::size_t count = 0;
    while (position < text.size()) {
        while (position < text.size() && (text[position] == ' ' || text[position] == '\t' || text[position] == '\r' || text[position] == '\n')) ++position;
        if (position >= text.size() || !std::isdigit(static_cast<unsigned char>(text[position]))) break;
        std::uint32_t value = 0;
        std::size_t digits = 0;
        while (position < text.size() && std::isdigit(static_cast<unsigned char>(text[position])) && digits < 7) {
            value = value * 10 + static_cast<std::uint32_t>(text[position] - '0');
            ++position;
            ++digits;
        }
        if (value > 0x10FFFF) break;
        appendUtf8(out, value);
        ++count;
        while (position < text.size() && (text[position] == ' ' || text[position] == '\t')) ++position;
        if (position < text.size() && text[position] == ',') {
            ++position;
        } else {
            break;
        }
    }
    return count >= minimum ? out : std::string();
}

void decodeCharCodes(const std::string& lower, LayerCollector& collector) {
    for (const char* marker : {"fromcharcode(", "[char[]](", "[char[]] (", "[char[]]@("}) {
        std::size_t length = std::strlen(marker);
        std::size_t position = lower.find(marker);
        while (position != std::string::npos && !collector.full()) {
            std::string text = numberList(lower, position + length, 20);
            if (!text.empty()) collector.offer("charcodes", text);
            position = lower.find(marker, position + length);
        }
    }
    std::size_t position = 0;
    while ((position = lower.find("chr", position)) != std::string::npos && !collector.full()) {
        std::size_t open = position + 3;
        if (open < lower.size() && (lower[open] == 'w' || lower[open] == '$')) ++open;
        if (open >= lower.size() || lower[open] != '(') {
            position += 3;
            continue;
        }
        std::string text;
        std::size_t count = 0;
        std::size_t cursor = position;
        for (;;) {
            std::size_t inner = cursor + 3;
            if (inner < lower.size() && (lower[inner] == 'w' || lower[inner] == '$')) ++inner;
            if (inner >= lower.size() || lower[inner] != '(' || lower.compare(cursor, 3, "chr") != 0) break;
            ++inner;
            std::uint32_t value = 0;
            std::size_t digits = 0;
            while (inner < lower.size() && std::isdigit(static_cast<unsigned char>(lower[inner])) && digits < 7) {
                value = value * 10 + static_cast<std::uint32_t>(lower[inner] - '0');
                ++inner;
                ++digits;
            }
            if (digits == 0 || inner >= lower.size() || lower[inner] != ')' || value > 0x10FFFF) break;
            appendUtf8(text, value);
            ++count;
            cursor = inner + 1;
            while (cursor < lower.size() && (lower[cursor] == ' ' || lower[cursor] == '&' || lower[cursor] == '+' || lower[cursor] == '_' ||
                                             lower[cursor] == '\r' || lower[cursor] == '\n' || lower[cursor] == '\t'))
                ++cursor;
        }
        if (count >= 20) collector.offer("chr", text);
        position = std::max(cursor, position + 3);
    }
}

}

std::vector<DecodedLayer> decodeLayers(const std::string& text, std::size_t budget) {
    LayerCollector collector(budget);
    if (text.size() < 24) return {};
    std::string lower = lowered(text);
    decodeBase64Runs(text, lower, collector);
    decodeHexRuns(text, collector);
    decodeEscapeRuns(text, collector);
    decodeCharCodes(lower, collector);
    return collector.take();
}

bool ovbaDecompress(const std::uint8_t* data, std::size_t size, std::string& out) {
    out.clear();
    if (size < 3 || data[0] != 0x01) return false;
    std::size_t position = 1;
    while (position + 2 <= size) {
        std::uint32_t header = data[position] | (static_cast<std::uint32_t>(data[position + 1]) << 8);
        if (((header >> 12) & 7u) != 3u) break;
        std::size_t chunkEnd = std::min(size, position + (header & 0x0FFFu) + 3);
        bool compressed = (header & 0x8000u) != 0;
        std::size_t cursor = position + 2;
        std::size_t chunkOutput = out.size();
        position = chunkEnd;
        if (!compressed) {
            std::size_t length = std::min<std::size_t>(4096, chunkEnd - cursor);
            out.append(reinterpret_cast<const char*>(data + cursor), length);
            continue;
        }
        while (cursor < chunkEnd) {
            std::uint8_t flags = data[cursor++];
            for (int bit = 0; bit < 8 && cursor < chunkEnd; ++bit) {
                if (!(flags & (1 << bit))) {
                    out += static_cast<char>(data[cursor++]);
                    continue;
                }
                if (cursor + 2 > chunkEnd) return false;
                std::uint32_t token = data[cursor] | (static_cast<std::uint32_t>(data[cursor + 1]) << 8);
                cursor += 2;
                std::size_t difference = out.size() - chunkOutput;
                int bits = 4;
                while ((static_cast<std::size_t>(1) << bits) < difference && bits < 12) ++bits;
                std::uint32_t lengthMask = 0xFFFFu >> bits;
                std::size_t length = (token & lengthMask) + 3;
                std::size_t offset = ((token & ~lengthMask & 0xFFFFu) >> (16 - bits)) + 1;
                if (offset > difference) return false;
                for (std::size_t i = 0; i < length; ++i) out += out[out.size() - offset];
                if (out.size() - chunkOutput > 4096) return false;
                if (out.size() > kMaxVbaSource * 4) return false;
            }
        }
        if (out.size() > kMaxVbaSource * 4) return false;
    }
    return !out.empty();
}

namespace {

class CompoundFile {
public:
    struct Entry {
        std::string name;
        std::string path;
        int type = 0;
        std::uint32_t start = 0;
        std::uint64_t size = 0;
    };

    bool open(const std::uint8_t* data, std::size_t size) {
        data_ = data;
        size_ = size;
        static const unsigned char signature[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
        if (size < 512 || std::memcmp(data, signature, 8) != 0) return false;
        std::uint32_t shift = le(data + 30, 2);
        if (shift != 9 && shift != 12) return false;
        sectorSize_ = static_cast<std::size_t>(1) << shift;
        if (le(data + 32, 2) != 6) return false;
        std::uint32_t fatCount = le(data + 44, 4);
        std::uint32_t firstDirectory = le(data + 48, 4);
        cutoff_ = le(data + 56, 4);
        std::uint32_t firstMiniFat = le(data + 60, 4);
        std::uint32_t difatSector = le(data + 68, 4);
        std::uint32_t difatCount = le(data + 72, 4);
        if (fatCount > 4096) return false;

        std::vector<std::uint32_t> fatSectors;
        for (int i = 0; i < 109 && fatSectors.size() < fatCount; ++i) {
            std::uint32_t id = le(data + 76 + 4 * i, 4);
            if (id < 0xFFFFFFFAu) fatSectors.push_back(id);
        }
        for (std::uint32_t d = 0; d < difatCount && d < 64 && difatSector < 0xFFFFFFFAu && fatSectors.size() < fatCount; ++d) {
            const std::uint8_t* sector = sectorAt(difatSector);
            if (!sector) return false;
            std::size_t entries = sectorSize_ / 4 - 1;
            for (std::size_t i = 0; i < entries && fatSectors.size() < fatCount; ++i) {
                std::uint32_t id = le(sector + 4 * i, 4);
                if (id < 0xFFFFFFFAu) fatSectors.push_back(id);
            }
            difatSector = le(sector + 4 * entries, 4);
        }
        for (std::uint32_t id : fatSectors) {
            const std::uint8_t* sector = sectorAt(id);
            if (!sector) return false;
            for (std::size_t i = 0; i < sectorSize_ / 4; ++i) fat_.push_back(le(sector + 4 * i, 4));
        }
        if (fat_.empty()) return false;

        std::string directory;
        if (!readChain(firstDirectory, kMaxStreamBytes, directory)) return false;
        std::size_t count = std::min<std::size_t>(directory.size() / 128, 4096);
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint8_t* raw = reinterpret_cast<const std::uint8_t*>(directory.data()) + i * 128;
            RawEntry entry;
            std::uint32_t nameBytes = std::min<std::uint32_t>(le(raw + 64, 2), 64);
            for (std::uint32_t k = 0; k + 2 < nameBytes; k += 2) {
                std::uint32_t unit = le(raw + k, 2);
                entry.entry.name += unit < 128 ? static_cast<char>(unit) : '?';
            }
            entry.entry.type = raw[66];
            entry.left = le(raw + 68, 4);
            entry.right = le(raw + 72, 4);
            entry.child = le(raw + 76, 4);
            entry.entry.start = le(raw + 116, 4);
            entry.entry.size = le(raw + 120, 4);
            raw_.push_back(std::move(entry));
        }
        if (raw_.empty() || raw_[0].entry.type != 5) return false;
        if (!readChain(raw_[0].entry.start, kMaxStreamBytes, ministream_)) ministream_.clear();
        std::string miniFatBytes;
        if (firstMiniFat < 0xFFFFFFFAu && readChain(firstMiniFat, kMaxStreamBytes, miniFatBytes)) {
            for (std::size_t i = 0; i + 4 <= miniFatBytes.size(); i += 4)
                miniFat_.push_back(le(reinterpret_cast<const std::uint8_t*>(miniFatBytes.data()) + i, 4));
        }
        std::set<std::uint32_t> visited;
        walk(raw_[0].child, std::string(), 0, visited);
        return true;
    }

    const std::vector<Entry>& entries() const { return entries_; }

    bool readStream(const Entry& entry, std::string& out, std::size_t limit) const {
        out.clear();
        if (entry.size > limit) return false;
        if (entry.size < cutoff_) {
            std::uint32_t id = entry.start;
            for (std::size_t steps = 0; id < 0xFFFFFFFAu && out.size() < entry.size && steps < 1u << 20; ++steps) {
                std::size_t offset = static_cast<std::size_t>(id) * 64;
                if (offset + 64 > ministream_.size() || id >= miniFat_.size()) return false;
                out.append(ministream_, offset, 64);
                id = miniFat_[id];
            }
        } else if (!readChain(entry.start, limit + sectorSize_, out)) {
            return false;
        }
        if (out.size() > entry.size) out.resize(static_cast<std::size_t>(entry.size));
        return true;
    }

private:
    struct RawEntry {
        Entry entry;
        std::uint32_t left = kNoStream;
        std::uint32_t right = kNoStream;
        std::uint32_t child = kNoStream;
    };

    const std::uint8_t* sectorAt(std::uint32_t id) const {
        std::uint64_t offset = (static_cast<std::uint64_t>(id) + 1) * sectorSize_;
        if (offset + sectorSize_ > size_) return nullptr;
        return data_ + offset;
    }

    bool readChain(std::uint32_t start, std::size_t limit, std::string& out) const {
        out.clear();
        std::uint32_t id = start;
        for (std::size_t steps = 0; id < 0xFFFFFFFAu; ++steps) {
            if (steps > (1u << 22) || out.size() >= limit) return out.size() >= limit ? false : true;
            const std::uint8_t* sector = sectorAt(id);
            if (!sector || id >= fat_.size()) return false;
            out.append(reinterpret_cast<const char*>(sector), sectorSize_);
            id = fat_[id];
        }
        return true;
    }

    void walk(std::uint32_t id, const std::string& prefix, int depth, std::set<std::uint32_t>& visited) {
        if (id == kNoStream || id >= raw_.size() || depth > 32 || entries_.size() > 4096 || !visited.insert(id).second) return;
        const RawEntry& raw = raw_[id];
        walk(raw.left, prefix, depth, visited);
        Entry entry = raw.entry;
        entry.path = prefix + entry.name;
        entries_.push_back(entry);
        if (entry.type == 1) walk(raw.child, entry.path + "/", depth + 1, visited);
        walk(raw.right, prefix, depth, visited);
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t sectorSize_ = 512;
    std::uint32_t cutoff_ = 4096;
    std::vector<std::uint32_t> fat_;
    std::vector<std::uint32_t> miniFat_;
    std::string ministream_;
    std::vector<RawEntry> raw_;
    std::vector<Entry> entries_;
};

bool containsUtf16(const std::string& lower, const char* text) {
    std::string wide;
    for (const char* p = text; *p; ++p) {
        wide += *p;
        wide += '\0';
    }
    return lower.find(wide) != std::string::npos;
}

bool peAt(const std::string& bytes, std::size_t offset) {
    if (offset + 0x40 > bytes.size() || bytes[offset] != 'M' || bytes[offset + 1] != 'Z') return false;
    std::uint32_t header = le(reinterpret_cast<const std::uint8_t*>(bytes.data()) + offset + 0x3C, 4);
    return header < 0x1000 && offset + header + 4 <= bytes.size() && std::memcmp(bytes.data() + offset + header, "PE\0\0", 4) == 0;
}

}

OleReport readOle(const std::uint8_t* data, std::size_t size) {
    OleReport report;
    CompoundFile file;
    if (!file.open(data, size)) return report;
    report.valid = true;
    std::string whole(reinterpret_cast<const char*>(data), std::min<std::size_t>(size, kMaxStreamBytes));
    std::string lower = lowered(whole);
    if (contains(lower, "equation.3") || contains(lower, "eqnedt32") || containsUtf16(lower, "equation.3")) report.equationEditor = true;

    for (const CompoundFile::Entry& entry : file.entries()) {
        std::string path = lowered(entry.path);
        std::string name = lowered(entry.name);
        if (name == "_vba_project" || name == "vba" || path.find("macros/vba") != std::string::npos) report.hasVba = true;
        if (path.find("objectpool") != std::string::npos || name.find("ole10native") != std::string::npos) report.hasEmbedded = true;
        if (entry.type != 2) continue;

        bool inVba = path.find("vba/") != std::string::npos;
        if (inVba && name != "dir" && name != "_vba_project" && name.rfind("__srp", 0) != 0 && report.modules.size() < 64) {
            std::string stream;
            if (!file.readStream(entry, stream, kMaxStreamBytes)) continue;
            const std::uint8_t* bytes = reinterpret_cast<const std::uint8_t*>(stream.data());
            int tried = 0;
            for (std::size_t offset = 0; offset + 3 <= stream.size() && tried < 64; ++offset) {
                if (bytes[offset] != 0x01) continue;
                std::uint32_t header = bytes[offset + 1] | (static_cast<std::uint32_t>(bytes[offset + 2]) << 8);
                if (((header >> 12) & 7u) != 3u) continue;
                ++tried;
                std::string source;
                if (ovbaDecompress(bytes + offset, stream.size() - offset, source) && source.size() >= 8 && printableRatio(source) >= 0.85) {
                    if (source.size() > kMaxVbaSource) source.resize(kMaxVbaSource);
                    report.modules.push_back(VbaModule{entry.name, source});
                    report.hasVba = true;
                    break;
                }
            }
        }
        if (name.find("ole10native") != std::string::npos && report.embeddedPayloads.size() < 4) {
            std::string stream;
            if (!file.readStream(entry, stream, kMaxStreamBytes)) continue;
            for (std::size_t offset = 0; offset < std::min<std::size_t>(stream.size(), 2048); ++offset) {
                if (peAt(stream, offset)) {
                    report.embeddedPayloads.push_back(stream.substr(offset));
                    break;
                }
            }
        }
    }
    return report;
}

std::vector<DeepIssue> reviewVba(const std::string& source) {
    std::vector<DeepIssue> issues;
    std::string lower = lowered(source);
    auto any = [&](std::initializer_list<const char*> parts) {
        for (const char* part : parts) {
            if (contains(lower, part)) return true;
        }
        return false;
    };
    bool autoExec = any({"sub autoopen", "sub auto_open", "sub document_open", "sub workbook_open", "sub autoexec", "sub document_new",
                         "sub workbook_activate", "sub autoclose", "sub auto_close", "private sub document_open", "sub workbook_beforeclose"});
    bool shell = any({"wscript.shell", "shell(", "shell.application", "createobject(\"wscript", "powershell", "cmd.exe", "cmd /c", "mshta", "regsvr32",
                      "rundll32", "certutil", "bitsadmin", "wmic ", "winmgmts", "shellexecute", "scriptcontrol"});
    bool download = any({"urldownloadtofile", "msxml2.xmlhttp", "microsoft.xmlhttp", "winhttp.winhttprequest", "adodb.stream", "msxml2.serverxmlhttp"});
    bool injection = any({"virtualalloc", "createthread", "rtlmovememory", "writeprocessmemory", "ntallocatevirtualmemory"});
    std::size_t chrs = 0;
    for (const char* marker : {"chr(", "chrw(", "chr$("}) {
        std::size_t at = lower.find(marker);
        while (at != std::string::npos) {
            ++chrs;
            at = lower.find(marker, at + 1);
        }
    }
    if (autoExec) issues.push_back({"Heur.Macro.AutoExec", "Macro", "Macro that runs by itself when the document is opened", 20});
    if (autoExec && download) issues.push_back({"Heur.Macro.Downloader", "Trojan", "Macro that runs by itself and downloads files", 85});
    if (autoExec && shell) issues.push_back({"Heur.Macro.RunsPrograms", "Trojan", "Macro that runs by itself and starts programs", 80});
    if (injection) issues.push_back({"Heur.Macro.ShellcodeLoader", "Exploit", "Macro that loads machine code into memory", 85});
    if (shell && !autoExec) issues.push_back({"Heur.Macro.ProgramLaunch", "Macro", "Macro that can start programs", 35});
    if (chrs >= 40) issues.push_back({"Heur.Macro.Obfuscated", "Macro", "Macro that builds its text from character codes", 40});
    return issues;
}

std::vector<DeepIssue> reviewOleReport(const OleReport& report) {
    std::vector<DeepIssue> issues;
    if (!report.valid) return issues;
    std::set<std::string> seen;
    auto add = [&](const DeepIssue& issue) {
        if (seen.insert(issue.rule).second) issues.push_back(issue);
    };
    if (report.hasVba || !report.modules.empty()) add({"Heur.Macro.Present", "Macro", "Document contains macros", 25});
    for (const VbaModule& module : report.modules) {
        for (const DeepIssue& issue : reviewVba(module.source)) add(issue);
    }
    if (report.hasEmbedded) add({"Heur.Office.EmbeddedObject", "Suspicious", "Document carries an embedded object", 20});
    if (!report.embeddedPayloads.empty()) add({"Heur.Office.EmbeddedProgram", "Trojan", "Document hides a program inside an embedded object", 70});
    if (report.equationEditor) add({"Heur.Office.EquationEditor", "Exploit", "Document uses the old Equation Editor, a common way to run code", 45});
    return issues;
}

namespace {

std::string attributeValue(const std::string& tag, const std::string& lowerTag, const std::string& name) {
    std::size_t at = lowerTag.find(" " + name + "=");
    if (at == std::string::npos) return std::string();
    at += name.size() + 2;
    if (at >= tag.size() || (tag[at] != '"' && tag[at] != '\'')) return std::string();
    std::size_t close = tag.find(tag[at], at + 1);
    if (close == std::string::npos) return std::string();
    return tag.substr(at + 1, close - at - 1);
}

bool remoteTarget(const std::string& target) {
    return target.rfind("http://", 0) == 0 || target.rfind("https://", 0) == 0 || target.rfind("ftp://", 0) == 0 || target.rfind("\\\\", 0) == 0 ||
           target.rfind("//", 0) == 0 || target.rfind("file:", 0) == 0 || target.rfind("mhtml:", 0) == 0;
}

}

std::vector<DeepIssue> reviewOfficePart(const std::string& partName, const std::string& content) {
    std::vector<DeepIssue> issues;
    std::string name = lowered(partName);
    std::string lower = lowered(content.substr(0, std::min<std::size_t>(content.size(), 4u * 1024u * 1024u)));
    std::set<std::string> seen;
    auto add = [&](const DeepIssue& issue) {
        if (seen.insert(issue.rule).second) issues.push_back(issue);
    };
    if (contains(lower, "ms-msdt:")) add({"Heur.Office.Follina", "Exploit", "Document tries to start the Windows support tool, a known attack", 90});

    if (endsWith(name, ".rels")) {
        std::size_t at = 0;
        while ((at = lower.find("<relationship ", at)) != std::string::npos) {
            std::size_t close = lower.find('>', at);
            if (close == std::string::npos) break;
            std::string tag = content.substr(at, close - at);
            std::string lowerTag = lower.substr(at, close - at);
            at = close;
            if (lowered(attributeValue(tag, lowerTag, "targetmode")) != "external") continue;
            std::string target = lowered(attributeValue(tag, lowerTag, "target"));
            std::string type = lowered(attributeValue(tag, lowerTag, "type"));
            std::string kind = type.substr(type.rfind('/') == std::string::npos ? 0 : type.rfind('/') + 1);
            if (target.rfind("mhtml:", 0) == 0) add({"Heur.Office.Follina", "Exploit", "Document loads a remote page that can run code", 90});
            if (!remoteTarget(target)) continue;
            bool unc = target.rfind("\\\\", 0) == 0 || target.rfind("//", 0) == 0 || target.rfind("file:", 0) == 0;
            if (kind == "attachedtemplate") {
                add({"Heur.Office.RemoteTemplate", "Exploit", "Document loads a template from another computer", 75});
            } else if (kind == "oleobject" || kind == "frame" || kind == "subdocument") {
                if (unc) {
                    add({"Heur.Office.UncPath", "Suspicious", "Document reaches for a file on another computer", 40});
                } else {
                    add({"Heur.Office.RemoteObject", "Exploit", "Document loads an object from the internet", 55});
                }
            }
        }
    } else if (endsWith(name, ".xml")) {
        bool dde = contains(lower, "ddeauto");
        std::size_t field = lower.find("instrtext");
        while (!dde && field != std::string::npos) {
            std::size_t start = lower.find('>', field);
            if (start != std::string::npos) {
                std::string head = lower.substr(start + 1, 24);
                std::size_t first = head.find_first_not_of(" \t\r\n");
                if (first != std::string::npos && head.compare(first, 4, "dde ") == 0) dde = true;
            }
            field = lower.find("instrtext", field + 9);
        }
        if (!dde && contains(lower, "<ddelink") &&
            (contains(lower, "ddeservice=\"cmd") || contains(lower, "ddeservice=\"powershell") || contains(lower, "ddeservice=\"mshta") ||
             contains(lower, "ddeservice='cmd")))
            dde = true;
        if (dde) add({"Heur.Office.DdeField", "Exploit", "Document uses a dynamic data field to start a program", 75});
    }
    return issues;
}

std::string foldToAscii(const std::uint8_t* data, std::size_t size) {
    std::string text;
    text.reserve(size / 2);
    for (std::size_t i = 0; i < size; ++i) {
        if (data[i] >= 9 && data[i] < 127) text += static_cast<char>(data[i]);
    }
    return text;
}

bool looksLikeLnk(const std::uint8_t* data, std::size_t size) {
    static const unsigned char guid[16] = {0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
    return size >= 76 && le(data, 4) == 0x4C && std::memcmp(data + 4, guid, 16) == 0;
}

std::vector<DeepIssue> reviewLnk(const std::uint8_t* data, std::size_t size) {
    std::vector<DeepIssue> issues;
    std::string lower = lowered(foldToAscii(data, std::min<std::size_t>(size, 4u * 1024u * 1024u)));
    auto any = [&](std::initializer_list<const char*> parts) {
        for (const char* part : parts) {
            if (contains(lower, part)) return true;
        }
        return false;
    };
    bool interpreter = any({"powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "msiexec", "certutil", "bitsadmin", "wmic"});
    if (!interpreter) return issues;
    bool hidden = any({"-w hidden", "-windowstyle hidden", "-win hidden", "-w 1", "/c start /min", "-nop"});
    bool encoded = any({"-enc", "-encodedcommand", "frombase64string"});
    bool remote = any({"http://", "https://", "downloadstring", "downloadfile", "invoke-webrequest", "iwr ", "bitsadmin /transfer", "certutil -urlcache"});
    bool run = any({"invoke-expression", "iex ", "iex(", "-ep bypass", "-executionpolicy bypass", "start-process", "mshta http"});
    if ((hidden && (remote || encoded || run)) || (remote && run)) {
        issues.push_back({"Heur.Lnk.HiddenDownloader", "Trojan", "Shortcut that quietly downloads and runs code", 85});
    } else if (encoded) {
        issues.push_back({"Heur.Lnk.EncodedCommand", "Trojan", "Shortcut that runs a hidden encoded command", 70});
    } else if (remote || run) {
        issues.push_back({"Heur.Lnk.ScriptLauncher", "Suspicious", "Shortcut that starts a script engine with a remote address", 45});
    }
    if (size > 30000) issues.push_back({"Heur.Lnk.EmbeddedPayload", "Suspicious", "Shortcut far larger than normal, it may carry a payload", 40});
    return issues;
}

namespace {

struct ImportSection {
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t rawPointer = 0;
    std::uint32_t rawSize = 0;
};

bool rvaToOffset(const std::vector<ImportSection>& sections, std::uint32_t rva, std::uint32_t& offset) {
    for (const ImportSection& section : sections) {
        std::uint32_t span = std::max(section.virtualSize, section.rawSize);
        if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
            offset = section.rawPointer + (rva - section.virtualAddress);
            return true;
        }
    }
    return false;
}

}

std::vector<DeepIssue> reviewPeImports(const std::uint8_t* data, std::size_t size) {
    std::vector<DeepIssue> issues;
    if (size < 0x100) return issues;
    std::uint32_t header = le(data + 0x3C, 4);
    if (static_cast<std::uint64_t>(header) + 24 > size || std::memcmp(data + header, "PE\0\0", 4) != 0) return issues;
    std::uint32_t sectionCount = std::min<std::uint32_t>(le(data + header + 6, 2), 96);
    std::uint32_t optionalSize = le(data + header + 20, 2);
    std::uint64_t optional = static_cast<std::uint64_t>(header) + 24;
    if (optional + 2 > size) return issues;
    std::uint32_t magic = le(data + optional, 2);
    bool wide = magic == 0x20B;
    if (!wide && magic != 0x10B) return issues;
    std::uint64_t directories = optional + (wide ? 112 : 96);
    if (directories + 16 * 8 > size || optionalSize < (wide ? 112u : 96u) + 16 * 8) return issues;
    std::uint32_t importRva = le(data + directories + 8, 4);
    bool dotNet = le(data + directories + 14 * 8, 4) != 0;

    std::vector<ImportSection> sections;
    std::uint64_t table = optional + optionalSize;
    for (std::uint32_t i = 0; i < sectionCount; ++i) {
        std::uint64_t at = table + static_cast<std::uint64_t>(i) * 40;
        if (at + 40 > size) break;
        ImportSection section;
        section.virtualSize = le(data + at + 8, 4);
        section.virtualAddress = le(data + at + 12, 4);
        section.rawSize = le(data + at + 16, 4);
        section.rawPointer = le(data + at + 20, 4);
        sections.push_back(section);
    }

    std::set<std::string> functions;
    std::size_t libraries = 0;
    std::uint32_t descriptor = 0;
    if (importRva != 0 && rvaToOffset(sections, importRva, descriptor)) {
        for (std::size_t index = 0; index < 512; ++index) {
            std::uint64_t at = static_cast<std::uint64_t>(descriptor) + index * 20;
            if (at + 20 > size) break;
            std::uint32_t original = le(data + at, 4);
            std::uint32_t nameRva = le(data + at + 12, 4);
            std::uint32_t first = le(data + at + 16, 4);
            if (original == 0 && nameRva == 0 && first == 0) break;
            ++libraries;
            std::uint32_t thunkOffset = 0;
            if (!rvaToOffset(sections, original != 0 ? original : first, thunkOffset)) continue;
            std::size_t step = wide ? 8 : 4;
            for (std::size_t n = 0; n < 4096 && functions.size() < 8000; ++n) {
                std::uint64_t entryAt = static_cast<std::uint64_t>(thunkOffset) + n * step;
                if (entryAt + step > size) break;
                std::uint64_t value = wide ? (static_cast<std::uint64_t>(le(data + entryAt, 4)) | (static_cast<std::uint64_t>(le(data + entryAt + 4, 4)) << 32))
                                           : le(data + entryAt, 4);
                if (value == 0) break;
                if (value >> (wide ? 63 : 31)) continue;
                std::uint32_t nameOffset = 0;
                if (!rvaToOffset(sections, static_cast<std::uint32_t>(value), nameOffset) || static_cast<std::uint64_t>(nameOffset) + 3 >= size) continue;
                const char* name = reinterpret_cast<const char*>(data + nameOffset + 2);
                std::size_t length = strnlen(name, std::min<std::size_t>(size - nameOffset - 2, 128));
                functions.insert(lowered(std::string(name, length)));
            }
        }
    }

    auto has = [&](const char* base) {
        std::string name = base;
        return functions.count(name) || functions.count(name + "a") || functions.count(name + "w") || functions.count(name + "ex") ||
               functions.count(name + "exa") || functions.count(name + "exw");
    };
    if (!dotNet && size >= 60000 && libraries > 0 && functions.size() <= 6 && has("loadlibrary") && has("getprocaddress"))
        issues.push_back({"Heur.PE.SparseImports", "Suspicious", "Program imports almost nothing and finds its functions when it runs, a trait of packers", 25});
    return issues;
}

}
