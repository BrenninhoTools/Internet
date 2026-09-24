#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "client.hpp"
#include "firewall.hpp"
#include "node.hpp"
#include "protocol.hpp"
#include "registry.hpp"
#include "security.hpp"
#include "siteserver.hpp"
#include "storage.hpp"

namespace fs = std::filesystem;

namespace {

std::atomic<bool> interrupted{false};

void onSignal(int) { interrupted = true; }

struct Options {
    std::vector<std::string> positional;
    internet::Endpoint registry{"127.0.0.1", internet::kDefaultRegistryPort};
    std::uint16_t port = 0;
    bool portGiven = false;
    std::string output;
    std::string token;
    std::string data;
    bool json = false;
    bool quarantine = false;
    bool noGuard = false;
};

Options parseOptions(const std::vector<std::string>& args, std::size_t start) {
    Options options;
    for (std::size_t i = start; i < args.size(); ++i) {
        const std::string& arg = args[i];
        bool hasValue = i + 1 < args.size();
        if (arg == "--registry" && hasValue) {
            options.registry = internet::parseEndpoint(args[++i]);
        } else if (arg == "--port" && hasValue) {
            int value = std::stoi(args[++i]);
            if (value < 0 || value > 65535) throw std::invalid_argument("invalid port");
            options.port = static_cast<std::uint16_t>(value);
            options.portGiven = true;
        } else if (arg == "--out" && hasValue) {
            options.output = args[++i];
        } else if (arg == "--token" && hasValue) {
            options.token = args[++i];
        } else if (arg == "--data" && hasValue) {
            options.data = args[++i];
        } else if (arg == "--json") {
            options.json = true;
        } else if (arg == "--quarantine") {
            options.quarantine = true;
        } else if (arg == "--no-guard") {
            options.noGuard = true;
        } else if (arg.rfind("--", 0) == 0) {
            throw std::invalid_argument("unknown option " + arg);
        } else {
            options.positional.push_back(arg);
        }
    }
    return options;
}

int usage() {
    std::cerr << "usage:\n"
                 "  internet registry [--port N]\n"
                 "  internet serve <name> <directory> [--port N] [--registry host:port] [--no-guard]\n"
                 "  internet get <internet://name/path> [--registry host:port] [--out file]\n"
                 "  internet list [--registry host:port]\n"
                 "  internet api <METHOD> <path> [--token T] [--out file] [--registry host:port]   (body is read from stdin for PUT and POST)\n"
                 "  internet av scan <file-or-folder> [--quarantine] [--json]\n"
                 "  internet av info\n"
                 "  internet av update <definitions-file-or-internet-url> [--registry host:port]\n"
                 "  internet av quarantine list|restore <id> <destination>|delete <id>\n";
    return 2;
}

void waitForInterrupt() {
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    while (!interrupted) std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

fs::path securityDirectory(const Options& options) {
    return options.data.empty() ? internet::userDataDirectory() / "security" : fs::path(options.data);
}

std::string readAll(std::istream& stream) {
    return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

int runRegistry(const Options& options) {
    internet::Firewall firewall;
    internet::Registry registry;
    registry.setFirewall(&firewall);
    registry.start(options.portGiven ? options.port : internet::kDefaultRegistryPort);
    waitForInterrupt();
    registry.stop();
    return 0;
}

int runServe(const Options& options) {
    if (options.positional.size() != 2) return usage();
    internet::Firewall firewall;
    internet::Security security(securityDirectory(options));
    internet::Node node(options.positional[0], options.positional[1], options.registry);
    node.setFirewall(&firewall);
    if (!options.noGuard) node.setGuard([&security](const fs::path& path) { return security.guard(path); });
    node.start(options.port);
    waitForInterrupt();
    node.stop();
    return 0;
}

int runGet(const Options& options) {
    if (options.positional.size() != 1) return usage();
    internet::Page page = internet::fetch(options.registry, options.positional[0]);
    if (!options.output.empty()) {
        std::ofstream file(options.output, std::ios::binary);
        if (!file) throw std::runtime_error("cannot open " + options.output);
        file.write(page.body.data(), static_cast<std::streamsize>(page.body.size()));
        return 0;
    }
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    std::fwrite(page.body.data(), 1, page.body.size(), stdout);
    return 0;
}

int runList(const Options& options) {
    if (!options.positional.empty()) return usage();
    for (const internet::NodeInfo& node : internet::listNodes(options.registry)) {
        std::cout << node.name << ' ' << internet::formatEndpoint(node.endpoint) << '\n';
    }
    return 0;
}

int runApi(const Options& options) {
    if (options.positional.size() != 2) return usage();
    std::string method = options.positional[0];
    std::string body;
    if (method == "PUT" || method == "POST") {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
#endif
        body = readAll(std::cin);
    }
    internet::ApiResponse response = internet::apiCall(options.registry, method, options.positional[1], options.token, body);
    if (!options.output.empty()) {
        std::ofstream file(options.output, std::ios::binary);
        file << response.body;
    } else {
        std::cout << response.body << '\n';
    }
    if (!response.reachable) return 1;
    return response.ok ? 0 : 1;
}

int runAvScan(const Options& options) {
    if (options.positional.size() != 2) return usage();
    internet::Security security(securityDirectory(options));
    fs::path target = options.positional[1];
    std::error_code error;
    if (fs::is_regular_file(target, error) && options.json) {
        internet::ScanResult result = security.scanFile(target, "cli");
        std::cout << internet::scanResultJson(result).dump() << '\n';
        return result.verdict == internet::Verdict::Clean ? 0 : 1;
    }
    internet::ScanProgress progress;
    security.scanTree({target}, "cli", progress, options.quarantine);
    for (const internet::ScanRecord& record : progress.records) {
        const internet::Finding* strongest = internet::strongestFinding(record.result);
        std::cout << internet::verdictName(record.result.verdict) << "  " << record.result.score << "  " << record.path << "  "
                  << (strongest ? strongest->rule : "") << "  " << record.action << '\n';
        for (const internet::Finding& finding : record.result.findings)
            std::cout << "    " << finding.severity << "  " << finding.rule << "  " << finding.description << '\n';
    }
    std::cout << progress.files << " files scanned, " << progress.malicious << " malicious, " << progress.suspicious
              << " suspicious\n";
    return progress.malicious + progress.suspicious == 0 ? 0 : 1;
}

int runAvUpdate(const Options& options) {
    if (options.positional.size() != 2) return usage();
    internet::Security security(securityDirectory(options));
    std::string text;
    const std::string& source = options.positional[1];
    if (internet::isInternetUrl(source)) {
        text = internet::fetch(options.registry, source).body;
    } else {
        std::ifstream file(source, std::ios::binary);
        if (!file) throw std::runtime_error("cannot read " + source);
        text = readAll(file);
    }
    std::string problem;
    if (!security.updateDefinitions(text, problem)) throw std::runtime_error("invalid definitions: " + problem);
    std::cout << "definitions " << security.definitionsVersion() << ", " << security.ruleCount() << " rules\n";
    return 0;
}

int runAvQuarantine(const Options& options) {
    if (options.positional.size() < 2) return usage();
    internet::Security security(securityDirectory(options));
    const std::string& action = options.positional[1];
    std::string problem;
    if (action == "list") {
        for (const internet::QuarantineItem& item : security.quarantineItems()) {
            std::cout << item.id << "  " << item.verdict << "  " << item.score << "  " << item.rule << "  " << item.originalPath << '\n';
        }
        return 0;
    }
    if (action == "restore" && options.positional.size() == 4) {
        if (!security.restoreQuarantined(options.positional[2], options.positional[3], problem)) throw std::runtime_error(problem);
        return 0;
    }
    if (action == "delete" && options.positional.size() == 3) {
        if (!security.deleteQuarantined(options.positional[2], problem)) throw std::runtime_error(problem);
        return 0;
    }
    return usage();
}

int runAv(const Options& options) {
    if (options.positional.empty()) return usage();
    const std::string& action = options.positional[0];
    if (action == "scan") return runAvScan(options);
    if (action == "update") return runAvUpdate(options);
    if (action == "quarantine") {
        Options shifted = options;
        return runAvQuarantine(shifted);
    }
    if (action == "info") {
        internet::Security security(securityDirectory(options));
        std::cout << "definitions " << security.definitionsVersion() << ", " << security.ruleCount() << " rules\n";
        return 0;
    }
    return usage();
}

}

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) return usage();
    try {
        Options options = parseOptions(args, 1);
        const std::string& command = args[0];
        if (command == "registry") return runRegistry(options);
        if (command == "serve") return runServe(options);
        if (command == "get") return runGet(options);
        if (command == "list") return runList(options);
        if (command == "api") return runApi(options);
        if (command == "av") return runAv(options);
        return usage();
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
