#include "goscan.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sstream>
#include <string_view>

namespace internet {

namespace {

const char kBuildInfoMagic[] = "\xff Go buildinf:";

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string trimmed(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return std::string();
    return text.substr(start, text.find_last_not_of(" \t\r\n") - start + 1);
}

std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = text.find(separator, start);
        if (end == std::string::npos) end = text.size();
        parts.push_back(text.substr(start, end - start));
        start = end + 1;
    }
    return parts;
}

bool readUvarint(const std::uint8_t* data, std::size_t size, std::size_t& position, std::uint64_t& value) {
    value = 0;
    for (int shift = 0; shift < 63 && position < size; shift += 7) {
        std::uint8_t byte = data[position++];
        value |= static_cast<std::uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) return true;
    }
    return false;
}

bool readString(const std::uint8_t* data, std::size_t size, std::size_t& position, std::string& out) {
    std::uint64_t length = 0;
    if (!readUvarint(data, size, position, length) || length > size - std::min(size, position) || length > (1u << 20)) return false;
    out.assign(reinterpret_cast<const char*>(data + position), static_cast<std::size_t>(length));
    position += static_cast<std::size_t>(length);
    return true;
}

void parseModuleInfo(std::string info, GoBuildInfo& out) {
    if (info.size() >= 32) info = info.substr(16, info.size() - 32);
    for (const std::string& line : split(info, '\n')) {
        std::vector<std::string> fields = split(line, '\t');
        if (fields.size() < 2) continue;
        if (fields[0] == "path") {
            out.path = fields[1];
        } else if (fields[0] == "mod") {
            out.module = fields[1];
        } else if (fields[0] == "dep") {
            out.deps.push_back(fields[1]);
        } else if (fields[0] == "=>") {
            out.replacements.push_back(fields[1]);
        } else if (fields[0] == "build") {
            out.flags.push_back(fields[1]);
        }
    }
}

bool hasTables(std::string_view view) {
    static const char* const prefixes[] = {"\xF1\xFF\xFF\xFF\x00\x00", "\xF0\xFF\xFF\xFF\x00\x00", "\xFA\xFF\xFF\xFF\x00\x00",
                                           "\xFB\xFF\xFF\xFF\x00\x00"};
    for (const char* prefix : prefixes) {
        std::string_view needle(prefix, 6);
        std::size_t at = view.find(needle);
        while (at != std::string_view::npos) {
            if (at + 8 <= view.size()) {
                unsigned char quantum = static_cast<unsigned char>(view[at + 6]);
                unsigned char pointer = static_cast<unsigned char>(view[at + 7]);
                if ((quantum == 1 || quantum == 2 || quantum == 4) && (pointer == 4 || pointer == 8)) return true;
            }
            at = view.find(needle, at + 1);
        }
    }
    return false;
}

const std::set<std::string>& popularModules() {
    static const std::set<std::string> list = {
        "github.com/gorilla/mux", "github.com/gorilla/websocket", "github.com/gorilla/handlers", "github.com/gorilla/sessions",
        "github.com/gorilla/schema", "github.com/gorilla/csrf", "github.com/gorilla/securecookie", "github.com/sirupsen/logrus",
        "github.com/spf13/cobra", "github.com/spf13/viper", "github.com/spf13/pflag", "github.com/spf13/afero",
        "github.com/spf13/cast", "github.com/spf13/jwalterweatherman", "github.com/stretchr/testify", "github.com/stretchr/objx",
        "github.com/gin-gonic/gin", "github.com/gin-contrib/sse", "github.com/labstack/echo", "github.com/labstack/gommon",
        "github.com/go-sql-driver/mysql", "github.com/lib/pq", "github.com/jinzhu/gorm", "github.com/jinzhu/inflection",
        "github.com/golang/protobuf", "github.com/golang/glog", "github.com/golang/mock", "github.com/golang/snappy",
        "github.com/google/uuid", "github.com/google/go-cmp", "github.com/google/gopacket", "github.com/google/go-github",
        "github.com/google/btree", "github.com/google/gofuzz", "github.com/pkg/errors", "github.com/pkg/sftp",
        "github.com/pkg/browser", "github.com/urfave/cli", "github.com/fsnotify/fsnotify", "github.com/go-redis/redis",
        "github.com/redis/go-redis", "github.com/streadway/amqp", "github.com/rabbitmq/amqp091-go", "github.com/aws/aws-sdk-go",
        "github.com/aws/aws-sdk-go-v2", "github.com/aws/smithy-go", "github.com/mattn/go-sqlite3", "github.com/mattn/go-isatty",
        "github.com/mattn/go-colorable", "github.com/mattn/go-runewidth", "github.com/prometheus/client_golang",
        "github.com/prometheus/common", "github.com/prometheus/procfs", "github.com/hashicorp/consul", "github.com/hashicorp/vault",
        "github.com/hashicorp/terraform", "github.com/hashicorp/go-multierror", "github.com/hashicorp/hcl",
        "github.com/hashicorp/go-version", "github.com/docker/docker", "github.com/docker/cli", "github.com/docker/go-units",
        "github.com/moby/moby", "github.com/kubernetes/kubernetes", "github.com/fatih/color", "github.com/olekukonko/tablewriter",
        "github.com/joho/godotenv", "github.com/dgrijalva/jwt-go", "github.com/golang-jwt/jwt", "github.com/gofiber/fiber",
        "github.com/go-chi/chi", "github.com/valyala/fasthttp", "github.com/json-iterator/go", "github.com/tidwall/gjson",
        "github.com/nats-io/nats.go", "github.com/segmentio/kafka-go", "github.com/shopify/sarama", "github.com/ethereum/go-ethereum",
        "github.com/btcsuite/btcd", "github.com/miekg/dns", "github.com/creack/pty", "github.com/kr/pty", "github.com/shirou/gopsutil",
        "github.com/atotto/clipboard", "github.com/kbinani/screenshot", "github.com/go-ole/go-ole", "github.com/mitchellh/mapstructure",
        "github.com/rs/zerolog", "github.com/go-playground/validator", "github.com/onsi/ginkgo", "github.com/onsi/gomega",
        "github.com/davecgh/go-spew", "github.com/pmezard/go-difflib", "github.com/burntsushi/toml", "github.com/pelletier/go-toml",
        "github.com/klauspost/compress", "github.com/pierrec/lz4", "github.com/andybalholm/brotli", "github.com/cespare/xxhash",
        "github.com/inconshreveable/mousetrap", "github.com/cpuguy83/go-md2man", "github.com/russross/blackfriday",
        "github.com/beorn7/perks", "github.com/jmespath/go-jmespath", "github.com/rivo/uniseg", "github.com/magiconair/properties",
        "github.com/cli/cli", "github.com/charmbracelet/bubbletea", "github.com/charmbracelet/lipgloss", "github.com/go-git/go-git",
        "github.com/go-kit/kit", "github.com/go-logr/logr", "github.com/go-yaml/yaml", "github.com/ghodss/yaml",
        "github.com/gogo/protobuf", "github.com/grpc-ecosystem/grpc-gateway", "github.com/opentracing/opentracing-go",
        "github.com/uber-go/zap", "github.com/coreos/etcd", "github.com/patrickmn/go-cache", "github.com/robfig/cron",
        "github.com/satori/go.uuid", "github.com/tmc/grpc-websocket-proxy", "github.com/vmihailenco/msgpack",
        "gopkg.in/yaml.v2", "gopkg.in/yaml.v3", "gopkg.in/check.v1", "gopkg.in/natefinch/lumberjack.v2", "gopkg.in/ini.v1",
        "gopkg.in/tomb.v1", "gopkg.in/inf.v0", "gopkg.in/mgo.v2",
        "golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sys", "golang.org/x/text", "golang.org/x/tools", "golang.org/x/oauth2",
        "golang.org/x/sync", "golang.org/x/term", "golang.org/x/time", "golang.org/x/mod", "golang.org/x/image", "golang.org/x/exp",
        "golang.org/x/xerrors", "golang.org/x/build", "golang.org/x/mobile", "golang.org/x/lint", "golang.org/x/vuln",
        "golang.org/x/perf", "golang.org/x/arch", "golang.org/x/debug", "golang.org/x/telemetry", "golang.org/x/tour",
        "golang.org/x/blog", "golang.org/x/pkgsite", "golang.org/x/playground", "golang.org/x/review", "golang.org/x/website",
        "golang.org/x/benchmarks", "golang.org/x/oscar", "golang.org/x/example", "golang.org/x/net/context", "golang.org/x/vulndb",
        "golang.org/x/pkgsite", "golang.org/x/exp/typeparams", "golang.org/x/tools/gopls", "golang.org/x/talks",
        "google.golang.org/grpc", "google.golang.org/protobuf", "google.golang.org/api", "google.golang.org/appengine",
        "google.golang.org/genproto", "go.uber.org/zap", "go.uber.org/atomic", "go.uber.org/multierr", "go.uber.org/goleak",
        "go.uber.org/fx", "go.uber.org/dig", "k8s.io/client-go", "k8s.io/api", "k8s.io/apimachinery", "k8s.io/klog",
        "k8s.io/kubernetes", "k8s.io/utils", "k8s.io/apiserver", "go.mongodb.org/mongo-driver", "go.etcd.io/etcd",
        "go.opentelemetry.io/otel", "go.opencensus.io", "cloud.google.com/go", "gorm.io/gorm", "gorm.io/driver",
        "sigs.k8s.io/yaml", "sigs.k8s.io/controller-runtime", "honnef.co/go", "modernc.org/sqlite", "nhooyr.io/websocket",
        "gonum.org/v1/gonum", "rsc.io/quote", "rsc.io/sampler", "mvdan.cc/gofumpt", "mvdan.cc/sh", "storj.io/uplink",
        "go.starlark.net", "github.com/microsoft/go-mssqldb", "github.com/denisenkom/go-mssqldb", "github.com/masterzen/winrm",
    };
    return list;
}

int segmentsFor(const std::string& host) {
    if (host == "github.com" || host == "gitlab.com" || host == "bitbucket.org" || host == "golang.org" || host == "gopkg.in" ||
        host == "go.googlesource.com" || host == "codeberg.org")
        return host == "gopkg.in" ? 2 : 3;
    return 2;
}

bool looksLikeIp(const std::string& host) {
    std::string bare = host;
    std::size_t colon = bare.find(':');
    if (colon != std::string::npos) bare.erase(colon);
    int dots = 0;
    if (bare.empty()) return false;
    for (char c : bare) {
        if (c == '.') {
            ++dots;
        } else if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return dots == 3;
}

std::string ownerOf(const std::string& key) {
    std::size_t cut = key.rfind('/');
    return cut == std::string::npos ? key : key.substr(0, cut);
}

bool endsWith(const std::string& text, const std::string& suffix) {
    return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool suspiciousHost(const std::string& host) {
    static const char* const tunnels[] = {".ngrok.io", ".ngrok-free.app", ".duckdns.org", ".no-ip.org", ".no-ip.biz", ".trycloudflare.com",
                                          ".serveo.net", ".hopto.org", ".zapto.org", ".ddns.net", ".workers.dev", ".pastebin.com"};
    for (const char* suffix : tunnels) {
        if (endsWith(host, suffix)) return true;
    }
    return host == "pastebin.com" || host == "transfer.sh";
}

void addIssue(std::vector<GoIssue>& issues, const std::string& rule, const std::string& category, const std::string& description, int severity) {
    for (const GoIssue& issue : issues) {
        if (issue.rule == rule && issue.description == description) return;
    }
    issues.push_back(GoIssue{rule, category, description, severity});
}

std::size_t occurrences(const std::string& text, const std::string& needle) {
    std::size_t count = 0;
    std::size_t at = text.find(needle);
    while (at != std::string::npos) {
        ++count;
        at = text.find(needle, at + needle.size());
    }
    return count;
}

std::string bodyAfter(const std::string& text, std::size_t start, std::size_t limit) {
    std::size_t open = text.find('{', start);
    if (open == std::string::npos) return std::string();
    int depth = 0;
    std::size_t end = std::min(text.size(), open + limit);
    for (std::size_t i = open; i < end; ++i) {
        if (text[i] == '{') ++depth;
        if (text[i] == '}' && --depth == 0) return text.substr(open, i - open + 1);
    }
    return text.substr(open, end - open);
}

std::vector<std::string> importPaths(const std::string& text) {
    std::vector<std::string> paths;
    std::stringstream stream(text);
    std::string raw;
    bool block = false;
    auto take =[&](const std::string& line) {
        std::size_t first = line.find('"');
        if (first == std::string::npos) return;
        std::size_t second = line.find('"', first + 1);
        if (second == std::string::npos) return;
        std::string path = line.substr(first + 1, second - first - 1);
        if (path.find('.') != std::string::npos && path.find('.') < path.find('/')) paths.push_back(path);
    };
    while (std::getline(stream, raw)) {
        std::string line = trimmed(raw);
        if (block) {
            if (!line.empty() && line[0] == ')') {
                block = false;
                continue;
            }
            take(line);
        } else if (line.rfind("import (", 0) == 0) {
            block = true;
            std::size_t close = line.find(')');
            if (close != std::string::npos) block = false;
        } else if (line.rfind("import ", 0) == 0) {
            take(line);
        }
    }
    return paths;
}

}

int editDistance(const std::string& a, const std::string& b) {
    std::size_t n = a.size();
    std::size_t m = b.size();
    std::vector<std::vector<int>> d(n + 1, std::vector<int>(m + 1, 0));
    for (std::size_t i = 0; i <= n; ++i) d[i][0] = static_cast<int>(i);
    for (std::size_t j = 0; j <= m; ++j) d[0][j] = static_cast<int>(j);
    for (std::size_t i = 1; i <= n; ++i) {
        for (std::size_t j = 1; j <= m; ++j) {
            int cost = a[i - 1] == b[j - 1] ? 0 : 1;
            d[i][j] = std::min({d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost});
            if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) d[i][j] = std::min(d[i][j], d[i - 2][j - 2] + 1);
        }
    }
    return d[n][m];
}

bool isGoModuleFile(const std::string& baseName) {
    std::string name = lowered(baseName);
    return name == "go.mod" || name == "go.sum" || name == "go.work" || name == "go.work.sum";
}

bool looksLikeGoSource(const std::string& head) {
    std::size_t i = 0;
    while (i < head.size()) {
        if (std::isspace(static_cast<unsigned char>(head[i]))) {
            ++i;
        } else if (head.compare(i, 2, "//") == 0) {
            i = head.find('\n', i);
            if (i == std::string::npos) return false;
        } else if (head.compare(i, 2, "/*") == 0) {
            i = head.find("*/", i + 2);
            if (i == std::string::npos) return false;
            i += 2;
        } else {
            break;
        }
    }
    if (head.compare(i, 8, "package ") != 0) return false;
    return head.find("func ", i) != std::string::npos || head.find("import", i) != std::string::npos;
}

bool detectGoBinary(const std::uint8_t* data, std::size_t size, GoBuildInfo& info) {
    info = GoBuildInfo{};
    std::string_view view(reinterpret_cast<const char*>(data), size);
    std::size_t at = view.find(std::string_view(kBuildInfoMagic, 14));
    if (at != std::string_view::npos && at + 32 <= size) {
        info.found = true;
        unsigned char flags = static_cast<unsigned char>(view[at + 15]);
        if (flags & 2) {
            std::size_t position = at + 32;
            std::string version;
            std::string modules;
            if (readString(data, size, position, version)) {
                info.version = version;
                if (readString(data, size, position, modules)) parseModuleInfo(modules, info);
            }
        }
        return true;
    }
    if (hasTables(view)) {
        info.tables = true;
        return true;
    }
    return false;
}

std::vector<GoIssue> reviewModulePaths(const std::vector<std::string>& paths) {
    std::vector<GoIssue> issues;
    const std::set<std::string>& popular = popularModules();
    for (const std::string& original : paths) {
        std::vector<std::string> segments = split(lowered(original), '/');
        if (segments.empty() || segments[0].empty()) continue;
        const std::string& host = segments[0];
        if (looksLikeIp(host) || host == "localhost" || host.find(':') != std::string::npos) {
            addIssue(issues, "Heur.Go.RawHostDependency", "Trojan", "Go module is loaded from a bare address instead of a code host: " + original, 70);
            continue;
        }
        if (suspiciousHost(host)) {
            addIssue(issues, "Heur.Go.SuspiciousHost", "Trojan", "Go module is loaded from a tunnel or paste service: " + original, 60);
            continue;
        }
        if (host.find('.') == std::string::npos || host == "gopkg.in") continue;
        std::size_t count = static_cast<std::size_t>(segmentsFor(host));
        if (segments.size() < count) count = segments.size();
        std::string key;
        for (std::size_t i = 0; i < count; ++i) key += (i ? "/" : "") + segments[i];
        if (popular.count(key)) continue;
        int best = 99;
        std::string nearest;
        for (const std::string& known : popular) {
            if (std::abs(static_cast<int>(known.size()) - static_cast<int>(key.size())) > 2) continue;
            if (std::count(known.begin(), known.end(), '/') != std::count(key.begin(), key.end(), '/')) continue;
            if (ownerOf(known) == ownerOf(key)) continue;
            int distance = editDistance(key, known);
            if (distance < best) {
                best = distance;
                nearest = known;
            }
        }
        if (best == 1 && key.size() >= 12) {
            addIssue(issues, "Heur.Go.Typosquat", "Trojan", "Go module " + key + " looks like the well known " + nearest + " but is not the same", 75);
        } else if (best == 2 && key.size() >= 20) {
            addIssue(issues, "Heur.Go.Typosquat", "Trojan", "Go module " + key + " is very close to the well known " + nearest, 55);
        }
    }
    return issues;
}

std::vector<GoIssue> reviewGoBinary(const GoBuildInfo& info) {
    std::vector<GoIssue> issues = reviewModulePaths(info.deps);
    for (const GoIssue& issue : reviewModulePaths(info.replacements)) addIssue(issues, issue.rule, issue.category, issue.description, issue.severity);
    for (const std::string& flag : info.flags) {
        if (flag.find("-H=windowsgui") != std::string::npos || flag.find("-H windowsgui") != std::string::npos)
            addIssue(issues, "Heur.Go.HiddenConsole", "Suspicious", "Go program is built to run without any window", 15);
    }
    if (info.found && info.path == "command-line-arguments")
        addIssue(issues, "Heur.Go.LooseBuild", "Suspicious", "Go program built from loose files instead of a module", 12);
    return issues;
}

std::vector<GoIssue> reviewGoModule(const std::string& text) {
    std::vector<std::string> paths;
    std::stringstream stream(text);
    bool block = false;
    std::string blockKind;
    for (std::string line; std::getline(stream, line);) {
        std::size_t comment = line.find("//");
        if (comment != std::string::npos) line.erase(comment);
        std::string trimmedLine = trimmed(line);
        if (trimmedLine.empty()) continue;
        std::vector<std::string> tokens;
        std::stringstream words(trimmedLine);
        for (std::string word; words >> word;) tokens.push_back(word);
        if (block) {
            if (tokens[0] == ")") {
                block = false;
                continue;
            }
            if (blockKind == "require") {
                paths.push_back(tokens[0]);
            } else if (blockKind == "replace") {
                for (std::size_t i = 0; i + 1 < tokens.size(); ++i) {
                    if (tokens[i] == "=>") paths.push_back(tokens[i + 1]);
                }
                paths.push_back(tokens[0]);
            }
            continue;
        }
        if ((tokens[0] == "require" || tokens[0] == "replace") && tokens.size() >= 2 && tokens[1] == "(") {
            block = true;
            blockKind = tokens[0];
        } else if (tokens[0] == "require" && tokens.size() >= 2) {
            paths.push_back(tokens[1]);
        } else if (tokens[0] == "replace") {
            for (std::size_t i = 0; i + 1 < tokens.size(); ++i) {
                if (tokens[i] == "=>") paths.push_back(tokens[i + 1]);
            }
        } else if (tokens.size() >= 3 && tokens[1].size() > 1 && tokens[1][0] == 'v' && tokens[2].rfind("h1:", 0) == 0) {
            paths.push_back(tokens[0]);
        }
    }
    std::vector<std::string> external;
    for (const std::string& path : paths) {
        if (path.empty() || path[0] == '.' || path[0] == '/' || path.find(":\\") != std::string::npos) continue;
        external.push_back(path);
    }
    return reviewModulePaths(external);
}

std::vector<GoIssue> reviewGoSource(const std::string& text) {
    std::vector<GoIssue> issues = reviewModulePaths(importPaths(text));

    std::size_t at = text.find("func init()");
    static const char* const risky[] = {"http.Get(", "http.Post(", "http.NewRequest(", "net.Dial(", "net.DialTimeout(", "exec.Command(",
                                        "exec.CommandContext(", "syscall.NewLazyDLL(", "syscall.Exec(", "os.StartProcess("};
    while (at != std::string::npos) {
        std::string body = bodyAfter(text, at, 6000);
        for (const char* call : risky) {
            if (body.find(call) != std::string::npos) {
                addIssue(issues, "Heur.Go.InitHook", "Backdoor", "An init function talks to the network or starts programs before main runs", 45);
                break;
            }
        }
        at = text.find("func init()", at + 1);
    }

    std::size_t hexBytes = 0;
    for (std::size_t i = 0; i + 4 < text.size(); ++i) {
        if (text[i] == '0' && text[i + 1] == 'x' && std::isxdigit(static_cast<unsigned char>(text[i + 2])) &&
            std::isxdigit(static_cast<unsigned char>(text[i + 3])) && (text[i + 4] == ',' || text[i + 4] == '}')) {
            ++hexBytes;
            i += 4;
        }
    }
    if (hexBytes >= 1500) addIssue(issues, "Heur.Go.ByteArrayPayload", "Suspicious", "Source holds a very large byte array, like an embedded program or shellcode", 30);

    if (occurrences(text, "string([]byte{") >= 8 || occurrences(text, "string([]rune{") >= 8)
        addIssue(issues, "Heur.Go.StringObfuscation", "Suspicious", "Strings are built byte by byte to hide what they say", 40);
    if (occurrences(text, "//go:linkname") >= 1 && text.find("runtime.") != std::string::npos)
        addIssue(issues, "Heur.Go.RuntimeLinkname", "Suspicious", "Source reaches into private parts of the Go runtime", 20);
    return issues;
}

}
