#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "sitefiles.hpp"
#include "siteserver.hpp"

namespace fs = std::filesystem;

namespace {

std::atomic<bool> interrupted{false};

void onSignal(int) { interrupted = true; }

std::string timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%S", &local);
    return buffer;
}

std::string trim(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

std::map<std::string, std::string> readConfig(const fs::path& file) {
    std::map<std::string, std::string> values;
    std::ifstream stream(file);
    std::string line;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        values[trim(line.substr(0, equals))] = trim(line.substr(equals + 1));
    }
    return values;
}

int intValue(const std::map<std::string, std::string>& values, const std::string& key, int fallback) {
    auto found = values.find(key);
    if (found == values.end()) return fallback;
    try {
        return std::stoi(found->second);
    } catch (const std::exception&) {
        return fallback;
    }
}

double doubleValue(const std::map<std::string, std::string>& values, const std::string& key, double fallback) {
    auto found = values.find(key);
    if (found == values.end()) return fallback;
    try {
        return std::stod(found->second);
    } catch (const std::exception&) {
        return fallback;
    }
}

bool boolValue(const std::map<std::string, std::string>& values, const std::string& key, bool fallback) {
    auto found = values.find(key);
    if (found == values.end()) return fallback;
    return found->second == "true" || found->second == "1" || found->second == "yes";
}

std::string stringValue(const std::map<std::string, std::string>& values, const std::string& key, const std::string& fallback) {
    auto found = values.find(key);
    return found == values.end() || found->second.empty() ? fallback : found->second;
}

fs::path resolveIn(const fs::path& base, const std::string& text) {
    fs::path path(text);
    return path.is_absolute() ? path : base / path;
}

struct Options {
    std::string command;
    fs::path directory = ".";
};

Options parse(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dir" && i + 1 < argc) {
            options.directory = argv[++i];
        } else if (options.command.empty() && arg.rfind("--", 0) != 0) {
            options.command = arg;
        } else {
            throw std::invalid_argument("unknown argument " + arg);
        }
    }
    return options;
}

internet::ServerConfig loadConfig(const fs::path& directory, std::function<void(const std::string&)> log) {
    std::map<std::string, std::string> values = readConfig(directory / "server.conf");
    internet::ServerConfig config;
    config.sitesDir = resolveIn(directory, stringValue(values, "sites_dir", "sites"));
    config.dataDir = resolveIn(directory, stringValue(values, "data_dir", "data"));
    config.registryPort = static_cast<std::uint16_t>(intValue(values, "registry_port", internet::kDefaultRegistryPort));
    config.hostRegistry = boolValue(values, "host_registry", true);
    if (values.count("external_registry")) config.externalRegistry = internet::parseEndpoint(values["external_registry"]);
    config.token = stringValue(values, "token", "");
    config.rescanSeconds = intValue(values, "rescan_seconds", 300);
    config.scanOnStart = boolValue(values, "scan_on_start", true);
    config.gatewayPort = intValue(values, "gateway_port", 8080);
    config.gatewayLocalOnly = boolValue(values, "gateway_local_only", true);
    config.gatewayScripts = boolValue(values, "gateway_scripts", false);
    config.firewall.ratePerSecond = doubleValue(values, "rate_limit", 25.0);
    config.firewall.burst = doubleValue(values, "burst", 60.0);
    config.firewall.maxConnectionsPerHost = intValue(values, "max_connections", 64);
    config.firewall.banSeconds = intValue(values, "ban_seconds", 300);
    config.firewall.violationsToBan = intValue(values, "violations_to_ban", 12);
    config.firewall.enabled = boolValue(values, "firewall", true);
    config.log = std::move(log);
    return config;
}

int init(const fs::path& directory) {
    std::error_code error;
    fs::create_directories(directory / "sites" / "home", error);
    fs::create_directories(directory / "data", error);
    fs::path conf = directory / "server.conf";
    if (!fs::exists(conf)) {
        std::ofstream out(conf);
        out << "# Internet server settings\n"
               "registry_port=4000\n"
               "host_registry=true\n"
               "sites_dir=sites\n"
               "data_dir=data\n"
               "rate_limit=25\n"
               "burst=60\n"
               "max_connections=64\n"
               "violations_to_ban=12\n"
               "ban_seconds=300\n"
               "rescan_seconds=300\n"
               "scan_on_start=true\n"
               "gateway_port=8080\n"
               "gateway_local_only=true\n"
               "gateway_scripts=false\n"
               "firewall=true\n";
    }
    std::string problem;
    if (!fs::exists(directory / "sites" / "home" / "index.html")) {
        internet::writeSiteFile(directory / "sites" / "home", "index.html",
                                internet::siteTemplate(2, "home", "Welcome to Internet"), problem);
    }

    internet::ServerConfig config = loadConfig(directory, nullptr);
    internet::SiteServer server(config);
    std::cout << "Server folder: " << fs::absolute(directory).string() << "\n"
              << "Settings:      " << conf.string() << "\n"
              << "Sites:         " << config.sitesDir.string() << "  (one folder per site)\n"
              << "API token:     " << server.token() << "\n\n"
              << "Start it with: internet-server run --dir " << directory.string() << "\n";
    return 0;
}

int run(const fs::path& directory) {
    std::mutex output;
    fs::path logFile = directory / "data" / "server.log";
    std::error_code error;
    fs::create_directories(logFile.parent_path(), error);
    auto log = [&](const std::string& text) {
        std::lock_guard<std::mutex> lock(output);
        std::string line = timestamp() + "  " + text;
        std::cout << line << std::endl;
        std::ofstream(logFile, std::ios::app) << line << '\n';
    };
    internet::ServerConfig config = loadConfig(directory, log);
    internet::SiteServer server(config);
    server.start();
    log("Internet server started. Registry " + internet::formatEndpoint(server.registryEndpoint()) + ", definitions " +
        server.security().definitionsVersion() + ", " + std::to_string(server.security().ruleCount()) + " rules");
    log("API token is in " + (config.dataDir / "token.txt").string());
    if (server.gatewayPort() != 0) log("Open the sites in Chrome or any browser at http://localhost:" + std::to_string(server.gatewayPort()) + "/");

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    while (!interrupted) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    log("Shutting down");
    server.stop();
    return 0;
}

int scan(const fs::path& directory) {
    internet::ServerConfig config = loadConfig(directory, nullptr);
    internet::Security security(config.dataDir / "security");
    internet::ScanProgress progress;
    security.scanTree({config.sitesDir}, "server", progress);
    for (const internet::ScanRecord& record : progress.records) {
        const internet::Finding* strongest = internet::strongestFinding(record.result);
        std::cout << internet::verdictName(record.result.verdict) << "  " << record.result.score << "  " << record.path << "  "
                  << (strongest ? strongest->rule : "") << "  " << record.action << '\n';
    }
    std::cout << progress.files << " files scanned, " << progress.malicious << " malicious, " << progress.suspicious
              << " suspicious\n";
    return progress.malicious == 0 ? 0 : 1;
}

int usage() {
    std::cerr << "usage:\n"
                 "  internet-server init [--dir D]   create settings, a sample site and an API token\n"
                 "  internet-server run [--dir D]    run the registry, the sites, the API and the protection\n"
                 "  internet-server scan [--dir D]   scan the sites once\n"
                 "  internet-server token [--dir D]  print the API token\n";
    return 2;
}

}

int main(int argc, char** argv) {
    try {
        Options options = parse(argc, argv);
        if (options.command == "init") return init(options.directory);
        if (options.command == "run") return run(options.directory);
        if (options.command == "scan") return scan(options.directory);
        if (options.command == "token") {
            internet::ServerConfig config = loadConfig(options.directory, nullptr);
            internet::SiteServer server(config);
            std::cout << server.token() << '\n';
            return 0;
        }
        return usage();
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
