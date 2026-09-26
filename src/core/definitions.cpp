#include "definitions.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "builtin_defs.inc"
#include "sha256.hpp"

namespace internet {

namespace {

std::string trimmed(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

std::vector<std::string> words(const std::string& text) {
    std::vector<std::string> result;
    std::istringstream stream(text);
    std::string word;
    while (stream >> word) result.push_back(word);
    return result;
}

bool parseScope(const std::string& text, std::uint32_t& scope) {
    scope = 0;
    std::istringstream stream(text);
    std::string item;
    while (std::getline(stream, item, ',')) {
        if (item == "any") {
            scope |= kScopeAny;
        } else if (item == "html") {
            scope |= kScopeHtml;
        } else if (item == "script") {
            scope |= kScopeScript;
        } else if (item == "shell") {
            scope |= kScopeShell;
        } else if (item == "gotiny") {
            scope |= kScopeGoTiny;
        } else if (item == "gobin") {
            scope |= kScopeGoBin;
        } else if (item == "go") {
            scope |= kScopeGo;
        } else if (item == "pexe") {
            scope |= kScopePeExe;
        } else if (item == "pe") {
            scope |= kScopePe;
        } else if (item == "elf") {
            scope |= kScopeElf;
        } else if (item == "text") {
            scope |= kScopeText;
        } else if (item == "archive") {
            scope |= kScopeArchive;
        } else if (item == "pdf") {
            scope |= kScopePdf;
        } else if (item == "other") {
            scope |= kScopeOther;
        } else {
            return false;
        }
    }
    return scope != 0;
}

bool parseQuoted(const std::string& text, std::string& out) {
    out.clear();
    std::size_t i = text.find('"');
    if (i == std::string::npos) return false;
    for (++i; i < text.size(); ++i) {
        char c = text[i];
        if (c == '"') return true;
        if (c != '\\') {
            out += c;
            continue;
        }
        if (++i >= text.size()) return false;
        switch (text[i]) {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case '\\': out += '\\'; break;
            case '"': out += '"'; break;
            case 'x': {
                if (i + 2 >= text.size()) return false;
                std::string bytes;
                if (!fromHex(text.substr(i + 1, 2), bytes)) return false;
                out += bytes;
                i += 2;
                break;
            }
            default: return false;
        }
    }
    return false;
}

std::string toWide(const std::string& ascii) {
    std::string wide;
    for (char c : ascii) {
        wide += c;
        wide += '\0';
    }
    return wide;
}

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

}

bool parseDefinitions(const std::string& text, Definitions& out, std::string& error) {
    out = Definitions{};
    std::istringstream stream(text);
    std::string line;
    int number = 0;
    RuleDef current;
    std::string currentMode;
    bool inRule = false;

    auto fail = [&](const std::string& message) {
        error = "line " + std::to_string(number) + ": " + message;
        return false;
    };

    while (std::getline(stream, line)) {
        ++number;
        line = trimmed(line);
        if (line.empty() || line[0] == '#') continue;
        std::size_t space = line.find_first_of(" \t");
        std::string keyword = space == std::string::npos ? line : line.substr(0, space);
        std::string rest = space == std::string::npos ? "" : trimmed(line.substr(space));

        if (keyword == "version") {
            out.version = rest;
        } else if (keyword == "hash") {
            std::vector<std::string> parts = words(rest);
            if (parts.size() != 4 || parts[0].size() != 64) return fail("expected: hash <sha256> <name> <severity> <category>");
            HashDef hash;
            hash.sha256 = lowered(parts[0]);
            hash.name = parts[1];
            hash.severity = std::atoi(parts[2].c_str());
            hash.category = parts[3];
            out.hashes.push_back(std::move(hash));
        } else if (keyword == "rule") {
            if (inRule) return fail("rule is missing its end");
            std::vector<std::string> parts = words(rest);
            if (parts.size() != 5) return fail("expected: rule <name> <severity> <category> <scope> <need>");
            current = RuleDef{};
            current.name = parts[0];
            current.severity = std::atoi(parts[1].c_str());
            current.category = parts[2];
            if (!parseScope(parts[3], current.scope)) return fail("unknown scope '" + parts[3] + "'");
            currentMode = parts[4];
            inRule = true;
        } else if (keyword == "desc") {
            if (!inRule) return fail("desc outside a rule");
            std::string value;
            if (parseQuoted(rest, value)) {
                current.description = value;
            } else {
                current.description = rest;
            }
        } else if (keyword == "window") {
            if (!inRule) return fail("window outside a rule");
            if (rest == "any") {
                current.window = ~static_cast<std::uint64_t>(0);
            } else {
                long long value = std::atoll(rest.c_str());
                if (value < 1) return fail("invalid window");
                current.window = static_cast<std::uint64_t>(value);
            }
        } else if (keyword == "end") {
            if (!inRule) return fail("end outside a rule");
            if (current.patterns.empty()) return fail("rule has no patterns");
            int optional = 0;
            for (const PatternDef& pattern : current.patterns) optional += pattern.required ? 0 : 1;
            if (optional == 0) {
                current.need = 0;
            } else if (currentMode == "any") {
                current.need = 1;
            } else if (currentMode == "all") {
                current.need = optional;
            } else {
                current.need = std::atoi(currentMode.c_str());
                if (current.need < 1 || current.need > optional) return fail("invalid match count");
            }
            out.rules.push_back(std::move(current));
            current = RuleDef{};
            inRule = false;
        } else if (keyword.size() == 1 && std::string("sSiIwWxX").find(keyword[0]) != std::string::npos) {
            if (!inRule) return fail("pattern outside a rule");
            PatternDef pattern;
            pattern.required = std::isupper(static_cast<unsigned char>(keyword[0])) != 0;
            char kind = static_cast<char>(std::tolower(static_cast<unsigned char>(keyword[0])));
            if (kind == 'x') {
                std::string compact;
                for (char c : rest) {
                    if (!std::isspace(static_cast<unsigned char>(c))) compact += c;
                }
                if (!fromHex(compact, pattern.bytes) || pattern.bytes.empty()) return fail("invalid hex pattern");
            } else {
                std::string value;
                if (!parseQuoted(rest, value) || value.empty()) return fail("invalid pattern string");
                if (kind == 'w') {
                    pattern.bytes = toWide(lowered(value));
                    pattern.caseInsensitive = true;
                } else if (kind == 'i') {
                    pattern.bytes = lowered(value);
                    pattern.caseInsensitive = true;
                } else {
                    pattern.bytes = value;
                }
            }
            current.patterns.push_back(std::move(pattern));
        } else {
            return fail("unknown keyword '" + keyword + "'");
        }
    }
    if (inRule) {
        error = "the last rule is missing its end";
        return false;
    }
    return true;
}

Definitions mergeDefinitions(const Definitions& base, const Definitions& update) {
    Definitions merged = base;
    if (!update.version.empty() && update.version > merged.version) merged.version = update.version;
    for (const RuleDef& rule : update.rules) {
        auto existing = std::find_if(merged.rules.begin(), merged.rules.end(),
                                     [&](const RuleDef& item) { return item.name == rule.name; });
        if (existing != merged.rules.end()) {
            *existing = rule;
        } else {
            merged.rules.push_back(rule);
        }
    }
    for (const HashDef& hash : update.hashes) {
        auto existing = std::find_if(merged.hashes.begin(), merged.hashes.end(),
                                     [&](const HashDef& item) { return item.sha256 == hash.sha256; });
        if (existing != merged.hashes.end()) {
            *existing = hash;
        } else {
            merged.hashes.push_back(hash);
        }
    }
    return merged;
}

std::string builtinDefinitionsText() {
    std::string text;
    text.resize(sizeof kBuiltinDefinitions);
    for (std::size_t i = 0; i < sizeof kBuiltinDefinitions; ++i) {
        text[i] = static_cast<char>(kBuiltinDefinitions[i] ^ static_cast<unsigned char>((0xA5 + i * 7) & 0xFF));
    }
    return text;
}

}
