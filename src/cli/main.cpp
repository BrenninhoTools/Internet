#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "client.hpp"
#include "node.hpp"
#include "protocol.hpp"
#include "registry.hpp"

namespace {

std::atomic<bool> interrupted{false};

void onSignal(int) { interrupted = true; }

struct Options {
    std::vector<std::string> positional;
    internet::Endpoint registry{"127.0.0.1", internet::kDefaultRegistryPort};
    std::uint16_t port = 0;
    bool portGiven = false;
    std::string output;
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
                 "  internet serve <name> <directory> [--port N] [--registry host:port]\n"
                 "  internet get <internet://name/path> [--registry host:port] [--out file]\n"
                 "  internet list [--registry host:port]\n";
    return 2;
}

void waitForInterrupt() {
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    while (!interrupted) std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

int runRegistry(const Options& options) {
    internet::Registry registry;
    registry.start(options.portGiven ? options.port : internet::kDefaultRegistryPort);
    waitForInterrupt();
    registry.stop();
    return 0;
}

int runServe(const Options& options) {
    if (options.positional.size() != 2) return usage();
    internet::Node node(options.positional[0], options.positional[1], options.registry);
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
        return usage();
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
