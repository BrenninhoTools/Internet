#include "av.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <functional>
#include <cstring>
#include <queue>
#include <unordered_map>

#include "deflate.hpp"
#include "sha256.hpp"

namespace internet {

namespace {

constexpr int kMaliciousScore = 85;
constexpr int kSuspiciousScore = 50;

std::uint32_t littleEndian(const std::uint8_t* data, int bytes) {
    std::uint32_t value = 0;
    for (int i = 0; i < bytes; ++i) value |= static_cast<std::uint32_t>(data[i]) << (8 * i);
    return value;
}

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string baseName(const std::string& name) {
    std::size_t cut = name.find_last_of("/\\!");
    return cut == std::string::npos ? name : name.substr(cut + 1);
}

std::string extensionOf(const std::string& name) {
    std::string base = lowered(baseName(name));
    std::size_t dot = base.rfind('.');
    return dot == std::string::npos ? "" : base.substr(dot + 1);
}

bool inList(const std::vector<std::string>& list, const std::string& value) {
    return std::find(list.begin(), list.end(), value) != list.end();
}

const std::vector<std::string>& executableExtensions() {
    static const std::vector<std::string> list = {"exe", "scr", "com", "bat", "cmd", "js",  "jse", "vbs", "vbe",
                                                  "ps1", "msi", "jar", "hta", "lnk", "pif", "wsf", "cpl", "dll",
                                                  "sys", "ocx", "drv", "efi", "sh",  "apk"};
    return list;
}

const std::vector<std::string>& documentExtensions() {
    static const std::vector<std::string> list = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg",
                                                  "png", "gif", "txt",  "zip", "rtf",  "mp3", "mp4",  "html", "htm"};
    return list;
}

const std::vector<std::string>& scriptExtensions() {
    static const std::vector<std::string> list = {"js",  "mjs", "vbs", "vbe", "jse", "wsf",  "wsh",  "ps1", "psm1", "bat",
                                                  "cmd", "sh",  "bash", "php", "py",  "pl",   "rb",   "hta", "lua",  "jsp",
                                                  "asp", "aspx"};
    return list;
}

bool looksLikeText(const std::uint8_t* data, std::size_t size) {
    std::size_t sample = std::min<std::size_t>(size, 8192);
    if (sample == 0) return true;
    std::size_t controls = 0;
    for (std::size_t i = 0; i < sample; ++i) {
        std::uint8_t c = data[i];
        if (c == 0) return false;
        if ((c < 9) || (c > 13 && c < 32)) ++controls;
    }
    return controls * 20 <= sample;
}

bool startsWith(const std::uint8_t* data, std::size_t size, const char* magic, std::size_t length) {
    return size >= length && std::memcmp(data, magic, length) == 0;
}

std::uint32_t scopeFor(const std::string& type) {
    if (type == "html") return kScopeHtml | kScopeScript | kScopeText | kScopeShell;
    if (type == "script") return kScopeScript;
    if (type == "text") return kScopeText | kScopeShell;
    if (type == "pe") return kScopePe;
    if (type == "elf" || type == "macho") return kScopeElf;
    if (type == "zip" || type == "archive") return kScopeArchive;
    if (type == "pdf") return kScopePdf;
    return kScopeOther;
}

struct PeSection {
    std::string name;
    std::uint32_t virtualSize = 0;
    std::uint32_t virtualAddress = 0;
    std::uint32_t rawSize = 0;
    std::uint32_t rawPointer = 0;
    std::uint32_t flags = 0;
};

struct PeInfo {
    std::uint32_t characteristics = 0;
    std::uint32_t entryPoint = 0;
    std::vector<PeSection> sections;
};

bool parsePe(const std::uint8_t* data, std::size_t size, PeInfo& info) {
    if (size < 0x40) return false;
    std::uint32_t header = littleEndian(data + 0x3C, 4);
    if (static_cast<std::uint64_t>(header) + 24 > size || std::memcmp(data + header, "PE\0\0", 4) != 0) return false;
    std::uint32_t sectionCount = littleEndian(data + header + 6, 2);
    std::uint32_t optionalSize = littleEndian(data + header + 20, 2);
    info.characteristics = littleEndian(data + header + 22, 2);
    std::uint64_t optional = static_cast<std::uint64_t>(header) + 24;
    if (optional + 20 <= size) info.entryPoint = littleEndian(data + optional + 16, 4);
    std::uint64_t table = optional + optionalSize;
    if (sectionCount > 96) sectionCount = 96;
    for (std::uint32_t i = 0; i < sectionCount; ++i) {
        std::uint64_t at = table + static_cast<std::uint64_t>(i) * 40;
        if (at + 40 > size) break;
        PeSection section;
        section.name.assign(reinterpret_cast<const char*>(data + at), strnlen(reinterpret_cast<const char*>(data + at), 8));
        section.virtualSize = littleEndian(data + at + 8, 4);
        section.virtualAddress = littleEndian(data + at + 12, 4);
        section.rawSize = littleEndian(data + at + 16, 4);
        section.rawPointer = littleEndian(data + at + 20, 4);
        section.flags = littleEndian(data + at + 36, 4);
        info.sections.push_back(std::move(section));
    }
    return true;
}

std::size_t countOccurrences(const std::string& haystack, const char* needle) {
    std::size_t count = 0;
    std::size_t length = std::strlen(needle);
    std::size_t position = haystack.find(needle);
    while (position != std::string::npos) {
        ++count;
        position = haystack.find(needle, position + length);
    }
    return count;
}

bool isHex(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }

}

const char* verdictName(Verdict verdict) {
    switch (verdict) {
        case Verdict::Clean: return "clean";
        case Verdict::Suspicious: return "suspicious";
        case Verdict::Malicious: return "malicious";
        case Verdict::Unscannable: return "unscannable";
    }
    return "clean";
}

double shannonEntropy(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0.0;
    std::array<std::size_t, 256> histogram{};
    for (std::size_t i = 0; i < size; ++i) ++histogram[data[i]];
    double entropy = 0.0;
    for (std::size_t count : histogram) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / static_cast<double>(size);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::string detectFileType(const std::string& name, const std::uint8_t* data, std::size_t size) {
    if (startsWith(data, size, "MZ", 2) && size >= 0x40) {
        std::uint32_t header = littleEndian(data + 0x3C, 4);
        if (static_cast<std::uint64_t>(header) + 4 <= size && std::memcmp(data + header, "PE\0\0", 4) == 0) return "pe";
    }
    if (startsWith(data, size, "\x7f" "ELF", 4)) return "elf";
    if (size >= 4) {
        std::uint32_t magic = littleEndian(data, 4);
        if (magic == 0xFEEDFACEu || magic == 0xFEEDFACFu || magic == 0xCEFAEDFEu || magic == 0xCFFAEDFEu || magic == 0xBEBAFECAu)
            return "macho";
    }
    if (startsWith(data, size, "PK\x03\x04", 4) || startsWith(data, size, "PK\x05\x06", 4)) return "zip";
    if (startsWith(data, size, "%PDF", 4)) return "pdf";
    if (startsWith(data, size, "\x89PNG", 4) || startsWith(data, size, "\xFF\xD8\xFF", 3) || startsWith(data, size, "GIF8", 4) ||
        startsWith(data, size, "RIFF", 4))
        return "image";
    if (startsWith(data, size, "\xD0\xCF\x11\xE0", 4)) return "office";
    if (startsWith(data, size, "\x1F\x8B", 2) || startsWith(data, size, "7z\xBC\xAF", 4) || startsWith(data, size, "Rar!", 4))
        return "archive";
    if (!looksLikeText(data, size)) return "binary";

    std::string head(reinterpret_cast<const char*>(data), std::min<std::size_t>(size, 4096));
    head = lowered(head);
    std::string extension = extensionOf(name);
    bool sourceFile = inList(scriptExtensions(), extension) && extension != "hta" && extension != "asp" && extension != "aspx" && extension != "jsp" && extension != "php";
    if (sourceFile) return "script";
    if (extension == "html" || extension == "htm" || extension == "xhtml" || head.find("<html") != std::string::npos ||
        head.find("<!doctype html") != std::string::npos || head.find("<body") != std::string::npos ||
        head.find("<script") != std::string::npos || head.find("<iframe") != std::string::npos ||
        head.find("<head") != std::string::npos)
        return "html";
    if (inList(scriptExtensions(), extension) || head.compare(0, 2, "#!") == 0 || head.find("<?php") != std::string::npos)
        return "script";
    return "text";
}

const Finding* strongestFinding(const ScanResult& result) {
    const Finding* best = nullptr;
    for (const Finding& finding : result.findings) {
        if (!best || finding.severity > best->severity) best = &finding;
    }
    return best;
}

struct Scanner::Impl {
    struct PatternRef {
        std::size_t rule;
        std::size_t index;
    };

    Definitions definitions;
    std::vector<PatternRef> patterns;
    std::vector<std::size_t> ruleFirst;
    std::vector<std::int32_t> next;
    std::vector<std::vector<int>> outputs;
    std::unordered_map<std::string, std::size_t> hashIndex;
    std::array<std::uint8_t, 256> fold{};

    explicit Impl(Definitions defs) : definitions(std::move(defs)) {
        for (int i = 0; i < 256; ++i) fold[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(std::tolower(i));
        for (std::size_t r = 0; r < definitions.rules.size(); ++r) {
            ruleFirst.push_back(patterns.size());
            for (std::size_t p = 0; p < definitions.rules[r].patterns.size(); ++p) patterns.push_back(PatternRef{r, p});
        }
        for (std::size_t h = 0; h < definitions.hashes.size(); ++h) hashIndex[definitions.hashes[h].sha256] = h;
        buildAutomaton();
    }

    const PatternDef& pattern(const PatternRef& ref) const { return definitions.rules[ref.rule].patterns[ref.index]; }

    void buildAutomaton() {
        std::array<std::int32_t, 256> empty;
        empty.fill(-1);
        std::vector<std::array<std::int32_t, 256>> trie(1, empty);
        std::vector<std::vector<int>> out(1);
        for (std::size_t id = 0; id < patterns.size(); ++id) {
            std::int32_t node = 0;
            for (char raw : pattern(patterns[id]).bytes) {
                std::uint8_t byte = fold[static_cast<std::uint8_t>(raw)];
                if (trie[static_cast<std::size_t>(node)][byte] == -1) {
                    trie[static_cast<std::size_t>(node)][byte] = static_cast<std::int32_t>(trie.size());
                    trie.push_back(empty);
                    out.emplace_back();
                }
                node = trie[static_cast<std::size_t>(node)][byte];
            }
            out[static_cast<std::size_t>(node)].push_back(static_cast<int>(id));
        }
        std::vector<std::int32_t> fail(trie.size(), 0);
        std::queue<std::int32_t> queue;
        for (int c = 0; c < 256; ++c) {
            std::int32_t child = trie[0][static_cast<std::size_t>(c)];
            if (child == -1) {
                trie[0][static_cast<std::size_t>(c)] = 0;
            } else {
                fail[static_cast<std::size_t>(child)] = 0;
                queue.push(child);
            }
        }
        while (!queue.empty()) {
            std::int32_t u = queue.front();
            queue.pop();
            for (int c = 0; c < 256; ++c) {
                std::int32_t v = trie[static_cast<std::size_t>(u)][static_cast<std::size_t>(c)];
                std::int32_t fallback = trie[static_cast<std::size_t>(fail[static_cast<std::size_t>(u)])][static_cast<std::size_t>(c)];
                if (v == -1) {
                    trie[static_cast<std::size_t>(u)][static_cast<std::size_t>(c)] = fallback;
                } else {
                    fail[static_cast<std::size_t>(v)] = fallback;
                    const std::vector<int>& inherited = out[static_cast<std::size_t>(fallback)];
                    out[static_cast<std::size_t>(v)].insert(out[static_cast<std::size_t>(v)].end(), inherited.begin(), inherited.end());
                    queue.push(v);
                }
            }
        }
        next.resize(trie.size() * 256);
        for (std::size_t n = 0; n < trie.size(); ++n) {
            for (std::size_t c = 0; c < 256; ++c) next[n * 256 + c] = trie[n][c];
        }
        outputs = std::move(out);
    }

    void addFinding(ScanResult& result, const std::string& rule, const std::string& category, const std::string& description,
                    int severity, const std::string& location) const {
        for (const Finding& existing : result.findings) {
            if (existing.rule == rule && existing.location == location) return;
        }
        Finding finding;
        finding.rule = rule;
        finding.category = category;
        finding.description = description;
        finding.severity = severity;
        finding.location = location;
        result.findings.push_back(std::move(finding));
    }

    bool withinWindow(const std::vector<std::vector<std::uint64_t>>& where, std::size_t first, const RuleDef& rule,
                      std::uint64_t window) const {
        struct Occurrence {
            std::uint64_t offset;
            std::size_t index;
        };
        std::vector<Occurrence> occurrences;
        int requiredTotal = 0;
        for (std::size_t k = 0; k < rule.patterns.size(); ++k) {
            if (rule.patterns[k].required) ++requiredTotal;
            for (std::uint64_t offset : where[first + k]) occurrences.push_back(Occurrence{offset, k});
        }
        std::sort(occurrences.begin(), occurrences.end(),
                  [](const Occurrence& a, const Occurrence& b) { return a.offset < b.offset; });
        std::vector<int> counts(rule.patterns.size(), 0);
        int requiredHave = 0;
        int optionalHave = 0;
        std::size_t left = 0;
        for (std::size_t right = 0; right < occurrences.size(); ++right) {
            std::size_t added = occurrences[right].index;
            if (counts[added]++ == 0) {
                if (rule.patterns[added].required) {
                    ++requiredHave;
                } else {
                    ++optionalHave;
                }
            }
            while (occurrences[right].offset - occurrences[left].offset > window) {
                std::size_t removed = occurrences[left].index;
                if (--counts[removed] == 0) {
                    if (rule.patterns[removed].required) {
                        --requiredHave;
                    } else {
                        --optionalHave;
                    }
                }
                ++left;
            }
            if (requiredHave == requiredTotal && optionalHave >= rule.need) return true;
        }
        return false;
    }

    void matchPatterns(const std::uint8_t* data, std::size_t size, std::uint32_t scope, bool textual, ScanResult& result,
                       const std::string& location) const {
        if (patterns.empty()) return;
        constexpr std::size_t kKeep = 24;
        std::vector<std::vector<std::uint64_t>> where(patterns.size());
        std::int32_t state = 0;
        for (std::size_t i = 0; i < size; ++i) {
            state = next[static_cast<std::size_t>(state) * 256 + fold[data[i]]];
            const std::vector<int>& list = outputs[static_cast<std::size_t>(state)];
            for (int id : list) {
                std::vector<std::uint64_t>& seen = where[static_cast<std::size_t>(id)];
                if (seen.size() >= kKeep) continue;
                const PatternDef& def = pattern(patterns[static_cast<std::size_t>(id)]);
                std::size_t length = def.bytes.size();
                if (i + 1 < length) continue;
                if (!def.caseInsensitive && std::memcmp(data + i + 1 - length, def.bytes.data(), length) != 0) continue;
                seen.push_back(i);
            }
        }
        const std::uint64_t window = textual ? 16384u : 262144u;
        for (std::size_t r = 0; r < definitions.rules.size(); ++r) {
            const RuleDef& rule = definitions.rules[r];
            if (!(rule.scope & scope)) continue;
            std::size_t first = ruleFirst[r];
            int requiredTotal = 0;
            int requiredHit = 0;
            int optionalHit = 0;
            for (std::size_t k = 0; k < rule.patterns.size(); ++k) {
                bool hit = !where[first + k].empty();
                if (rule.patterns[k].required) {
                    ++requiredTotal;
                    requiredHit += hit ? 1 : 0;
                } else {
                    optionalHit += hit ? 1 : 0;
                }
            }
            if (requiredHit != requiredTotal || optionalHit < rule.need) continue;
            if (rule.patterns.size() > 1 && !withinWindow(where, first, rule, window)) continue;
            addFinding(result, rule.name, rule.category, rule.description, rule.severity, location);
        }
    }

    void analyzeName(const std::string& name, const std::string& type, ScanResult& result, const std::string& location) const {
        std::string base = baseName(name);
        if (base.find("\xE2\x80\xAE") != std::string::npos)
            addFinding(result, "Heur.Name.RightToLeftOverride", "Suspicious", "File name uses a hidden character to fake its extension", 80, location);
        std::string lower = lowered(base);
        std::vector<std::string> parts;
        std::size_t start = 0;
        while (start <= lower.size()) {
            std::size_t dot = lower.find('.', start);
            if (dot == std::string::npos) dot = lower.size();
            parts.push_back(lower.substr(start, dot - start));
            start = dot + 1;
        }
        if (parts.size() >= 3 && inList(executableExtensions(), parts.back()) &&
            inList(documentExtensions(), parts[parts.size() - 2]))
            addFinding(result, "Heur.Name.DoubleExtension", "Suspicious", "Program disguised as a document", 70, location);
        std::string extension = extensionOf(name);
        static const std::vector<std::string> nativeExtensions = {"exe", "dll", "sys", "ocx", "scr", "cpl", "efi", "drv",
                                                                   "com", "ax",  "mui", "tlb", "node", "so",  "dylib"};
        if (type == "pe" && !extension.empty() && !inList(nativeExtensions, extension))
            addFinding(result, "Heur.Type.ExecutableDisguised", "Trojan", "Program with a file name that hides what it is", 65, location);
    }

    void analyzePe(const std::uint8_t* data, std::size_t size, ScanResult& result, const std::string& location) const {
        PeInfo info;
        if (!parsePe(data, size, info)) return;
        static const std::vector<std::string> packers = {"upx0", "upx1", "upx2", ".aspack", ".adata", "aspack", ".petite",
                                                         ".themida", ".vmp0", ".vmp1", ".mpress1", ".mpress2", ".enigma1",
                                                         ".nsp0", ".nsp1", "pebundle", "pec1", "pec2"};
        bool insideSection = false;
        std::size_t last = info.sections.size();
        for (std::size_t i = 0; i < info.sections.size(); ++i) {
            const PeSection& section = info.sections[i];
            bool executable = (section.flags & 0x20000000u) != 0 || (section.flags & 0x20u) != 0;
            bool writable = (section.flags & 0x80000000u) != 0;
            if (executable && writable)
                addFinding(result, "Heur.PE.WritableExecutable", "Suspicious", "Section that can both change and run code", 30, location);
            if (inList(packers, lowered(section.name)))
                addFinding(result, "Heur.PE.PackerSection", "Suspicious", "Program packed with a tool that is also used to hide malware", 40, location);
            if (section.rawSize >= 4096 && static_cast<std::uint64_t>(section.rawPointer) + section.rawSize <= size &&
                (executable || lowered(section.name) == ".text")) {
                double entropy = shannonEntropy(data + section.rawPointer, section.rawSize);
                if (entropy >= 7.2)
                    addFinding(result, "Heur.PE.EncryptedCode", "Suspicious", "Code section looks encrypted or compressed", 40, location);
            }
            if (section.rawSize == 0 && section.virtualSize >= 0x10000 && executable)
                addFinding(result, "Heur.PE.UnpackStub", "Suspicious", "Empty code section that is filled in when the program runs", 30, location);
            std::uint32_t span = std::max(section.virtualSize, section.rawSize);
            if (info.entryPoint >= section.virtualAddress && info.entryPoint < section.virtualAddress + span) {
                insideSection = true;
                last = i;
            }
        }
        if (!info.sections.empty() && info.entryPoint != 0 && !insideSection)
            addFinding(result, "Heur.PE.EntryOutsideSections", "Suspicious", "Program starts running outside of its own sections", 35, location);
        if (info.sections.size() > 1 && last == info.sections.size() - 1)
            addFinding(result, "Heur.PE.EntryInLastSection", "Suspicious", "Program starts in its last section, a trait of packers and infectors", 20, location);
        if (info.sections.size() > 24)
            addFinding(result, "Heur.PE.ManySections", "Suspicious", "Unusually many sections", 25, location);
    }

    void analyzeText(const std::uint8_t* data, std::size_t size, const std::string& type, ScanResult& result,
                     const std::string& location) const {
        std::size_t limit = std::min<std::size_t>(size, 4u * 1024u * 1024u);
        std::string text(reinterpret_cast<const char*>(data), limit);
        std::string lower = lowered(text);
        bool script = type == "html" || type == "script";

        std::size_t longestRun = 0;
        std::size_t run = 0;
        std::size_t percent = 0;
        std::size_t unicodeEscapes = 0;
        std::size_t hexEscapes = 0;
        std::size_t longestLine = 0;
        std::size_t line = 0;
        for (std::size_t i = 0; i < text.size(); ++i) {
            char c = text[i];
            bool base64 = std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=';
            run = base64 ? run + 1 : 0;
            longestRun = std::max(longestRun, run);
            line = c == '\n' ? 0 : line + 1;
            longestLine = std::max(longestLine, line);
            if (c == '%' && i + 2 < text.size()) {
                if (isHex(text[i + 1]) && isHex(text[i + 2])) ++percent;
                if ((text[i + 1] == 'u' || text[i + 1] == 'U') && i + 5 < text.size() && isHex(text[i + 2]) && isHex(text[i + 3]) &&
                    isHex(text[i + 4]) && isHex(text[i + 5]))
                    ++unicodeEscapes;
            }
            if (c == '\\' && i + 3 < text.size() && text[i + 1] == 'x' && isHex(text[i + 2]) && isHex(text[i + 3])) ++hexEscapes;
        }
        std::size_t evals = countOccurrences(lower, "eval(");
        std::size_t charCodes = countOccurrences(lower, "fromcharcode");

        if (script && longestRun >= 2000)
            addFinding(result, "Heur.Script.Base64Blob", "Script", "Very long encoded block inside a script", 30, location);
        if (script && percent >= 300)
            addFinding(result, "Heur.Script.PercentEncoded", "Script", "Script hides its content with percent encoding", 45, location);
        if (script && unicodeEscapes >= 50)
            addFinding(result, "Heur.Script.UnicodeShellcode", "Exploit", "Script contains what looks like encoded machine code", 55, location);
        if (script && hexEscapes >= 200 && evals >= 1)
            addFinding(result, "Heur.Script.HexEscapes", "Script", "Script hides its content with hex escapes", 35, location);
        if (script && charCodes >= 6)
            addFinding(result, "Heur.Script.CharCodeChain", "Script", "Script builds text from character codes", 30, location);
        if (script && evals >= 4)
            addFinding(result, "Heur.Script.ManyEval", "Script", "Script runs generated code many times", 30, location);
        if (script && evals >= 1 && longestLine >= 20000)
            addFinding(result, "Heur.Script.MinifiedEval", "Script", "Very long script line that runs generated code", 30, location);
        if (script) {
            double peak = 0.0;
            for (std::size_t offset = 0; offset + 4096 <= limit; offset += 4096)
                peak = std::max(peak, shannonEntropy(data + offset, 4096));
            if (peak >= 7.6)
                addFinding(result, "Heur.Script.EncryptedPayload", "Script", "Script carries a block that looks encrypted", 40, location);
        }
    }

    void analyzeZip(const std::string& name, const std::uint8_t* data, std::size_t size, const ScanOptions& options, int depth,
                    std::size_t& budget, ScanResult& result, const std::string& location) const {
        std::vector<ZipEntry> entries;
        std::string error;
        if (!readZip(data, size, entries, error)) {
            addFinding(result, "Heur.Archive.Corrupt", "Suspicious", "Archive is damaged or uses unsupported features: " + error, 20, location);
            return;
        }
        std::uint64_t total = 0;
        bool encrypted = false;
        std::size_t inspected = 0;
        if (entries.size() > 20000)
            addFinding(result, "Heur.Archive.TooManyEntries", "Suspicious", "Archive holds an unusual number of files", 40, location);
        for (const ZipEntry& entry : entries) {
            total += entry.size;
            std::string path = entry.name;
            if (path.rfind("../", 0) == 0 || path.find("/../") != std::string::npos || path.find("..\\") != std::string::npos ||
                (!path.empty() && (path[0] == '/' || path[0] == '\\')) || (path.size() > 1 && path[1] == ':'))
                addFinding(result, "Heur.Archive.PathTraversal", "Exploit", "Archive entry tries to write outside its folder", 70, location + "!" + path);
            if (entry.encrypted) {
                encrypted = true;
                continue;
            }
            if (entry.directory) continue;
            if (entry.compressedSize > 0 && entry.size / std::max<std::uint64_t>(1, entry.compressedSize) > 1000 && entry.size > 100u * 1024u * 1024u)
                addFinding(result, "Heur.Archive.Bomb", "Exploit", "Archive expands to a huge size", 80, location + "!" + path);
            if (inspected >= options.maxEntries || depth >= options.archiveDepth) continue;
            if (entry.size > options.entryLimit || budget + entry.size > options.archiveLimit) continue;
            std::vector<std::uint8_t> content;
            if (!extractZip(data, size, entry, options.entryLimit, content, error)) continue;
            ++inspected;
            budget += content.size();
            ScanResult child = scanInternal(location + "!" + path, content.data(), content.size(), options, depth + 1, budget);
            for (Finding& finding : child.findings) {
                if (finding.location.empty()) finding.location = location + "!" + path;
                addFinding(result, finding.rule, finding.category, finding.description, finding.severity, finding.location);
            }
        }
        if (total > 1024ull * 1024ull * 1024ull)
            addFinding(result, "Heur.Archive.Bomb", "Exploit", "Archive expands to a huge size", 80, location);
        if (encrypted) {
            addFinding(result, "Heur.Archive.Encrypted", "Suspicious", "Archive is password protected and cannot be inspected", 30, location);
            result.note = "Contains encrypted entries that could not be scanned";
        }
        (void)name;
    }

    ScanResult scanInternal(const std::string& name, const std::uint8_t* data, std::size_t size, const ScanOptions& options,
                            int depth, std::size_t& budget) const {
        ScanResult result;
        result.name = name;
        result.size = size;
        std::size_t used = std::min(size, options.maxBytes);
        result.truncated = size > used;
        result.sha256 = sha256Hex(data, size);
        result.type = detectFileType(name, data, used);
        result.entropy = shannonEntropy(data, used);
        std::string location = depth == 0 ? std::string() : name;

        auto known = hashIndex.find(result.sha256);
        if (known != hashIndex.end()) {
            const HashDef& hash = definitions.hashes[known->second];
            addFinding(result, hash.name, hash.category, "Known malicious file", hash.severity, location);
        }

        std::uint32_t scope = scopeFor(result.type);
        if (result.type == "script") {
            static const std::vector<std::string> shellExtensions = {"ps1", "psm1", "bat", "cmd", "sh", "bash", "vbs", "vbe", "wsf", "wsh", "hta", ""};
            if (inList(shellExtensions, extensionOf(name))) scope |= kScopeShell;
        }
        if (result.type == "pe") {
            PeInfo peInfo;
            if (parsePe(data, used, peInfo) && (peInfo.characteristics & 0x2000u) == 0) scope |= kScopePeExe;
        }
        bool textual = result.type == "html" || result.type == "script" || result.type == "text";
        matchPatterns(data, used, scope, textual, result, location);
        analyzeName(name, result.type, result, location);
        if (result.type == "pe") analyzePe(data, used, result, location);
        if (result.type == "html" || result.type == "script" || result.type == "text") analyzeText(data, used, result.type, result, location);
        if (result.type == "zip") analyzeZip(name, data, used, options, depth, budget, result, location);
        if (result.type == "binary" && used >= 8192 && result.entropy >= 7.7)
            addFinding(result, "Heur.Entropy.EncryptedBlob", "Suspicious", "Data that looks encrypted and has no known format", 30, location);
        if (result.truncated) result.note = "Only the first part of the file was scanned";
        return result;
    }
};

Scanner::Scanner(Definitions definitions) : impl_(std::make_shared<Impl>(std::move(definitions))) {}

const Definitions& Scanner::definitions() const { return impl_->definitions; }

std::size_t Scanner::ruleCount() const { return impl_->definitions.rules.size() + impl_->definitions.hashes.size(); }

ScanResult Scanner::scan(const std::string& name, const std::uint8_t* data, std::size_t size, const ScanOptions& options) const {
    std::size_t budget = 0;
    ScanResult result = impl_->scanInternal(name, data, size, options, 0, budget);
    std::vector<int> severities;
    for (const Finding& finding : result.findings) severities.push_back(finding.severity);
    std::sort(severities.begin(), severities.end(), std::greater<int>());
    int score = 0;
    if (!severities.empty()) {
        int rest = 0;
        bool largeText = (result.type == "html" || result.type == "script" || result.type == "text") && size > 256u * 1024u;
        for (std::size_t i = 1; i < severities.size(); ++i) rest += (largeText && severities[i] < 50) ? 0 : severities[i];
        score = std::min(100, severities[0] + rest / 3);
        bool textual = result.type == "html" || result.type == "script" || result.type == "text";
        if (textual && size > 1024u * 1024u && severities[0] < 90) score = std::min(score, kMaliciousScore - 5);
    }
    result.score = score;
    if (score >= kMaliciousScore) {
        result.verdict = Verdict::Malicious;
    } else if (score >= kSuspiciousScore) {
        result.verdict = Verdict::Suspicious;
    } else {
        result.verdict = Verdict::Clean;
    }
    std::stable_sort(result.findings.begin(), result.findings.end(),
                     [](const Finding& a, const Finding& b) { return a.severity > b.severity; });
    return result;
}

ScanResult Scanner::scan(const std::string& name, const std::string& data, const ScanOptions& options) const {
    return scan(name, reinterpret_cast<const std::uint8_t*>(data.data()), data.size(), options);
}

std::shared_ptr<const Scanner> makeScanner(const std::string& updateText, std::string& error) {
    Definitions builtin;
    if (!parseDefinitions(builtinDefinitionsText(), builtin, error)) {
        error = "built-in definitions: " + error;
        return nullptr;
    }
    if (!updateText.empty()) {
        Definitions update;
        if (!parseDefinitions(updateText, update, error)) return nullptr;
        builtin = mergeDefinitions(builtin, update);
    }
    return std::make_shared<const Scanner>(std::move(builtin));
}

}
