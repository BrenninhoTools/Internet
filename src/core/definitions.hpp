#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace internet {

enum ScopeBit : std::uint32_t {
    kScopeHtml = 1,
    kScopeScript = 2,
    kScopePe = 4,
    kScopeElf = 8,
    kScopeText = 16,
    kScopeArchive = 32,
    kScopePdf = 64,
    kScopeOther = 128,
    kScopePeExe = 256,
    kScopeShell = 512,
    kScopeGo = 1024,
    kScopeGoBin = 2048,
    kScopeGoTiny = 4096,
    kScopeAny = 0xFFFF
};

struct PatternDef {
    std::string bytes;
    bool caseInsensitive = false;
    bool required = false;
};

struct RuleDef {
    std::string name;
    std::string category;
    std::string description;
    int severity = 0;
    std::uint32_t scope = kScopeAny;
    int need = 0;
    std::uint64_t window = 0;
    std::vector<PatternDef> patterns;
};

struct HashDef {
    std::string sha256;
    std::string name;
    std::string category;
    int severity = 100;
};

struct Definitions {
    std::string version;
    std::vector<RuleDef> rules;
    std::vector<HashDef> hashes;
};

bool parseDefinitions(const std::string& text, Definitions& out, std::string& error);
Definitions mergeDefinitions(const Definitions& base, const Definitions& update);
std::string builtinDefinitionsText();

}
