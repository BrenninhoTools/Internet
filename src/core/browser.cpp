#include "browser.hpp"

#include <cstdint>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#elif defined(__ANDROID__)
#elif defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <sys/wait.h>
extern char** environ;
#else
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace fs = std::filesystem;

namespace internet {

namespace {

bool webUrl(const std::string& url) {
    if (url.compare(0, 7, "http://") != 0 && url.compare(0, 8, "https://") != 0) return false;
    for (char c : url) {
        if (static_cast<unsigned char>(c) < 0x21 || c == '"' || c == '\'' || c == '`' || c == '<' || c == '>' || c == '\\') return false;
    }
    return true;
}

#if defined(_WIN32)

std::wstring widen(const std::string& text) {
    if (text.empty()) return std::wstring();
    int length = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), length);
    return wide;
}

std::string narrow(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int length = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string text(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), text.data(), length, nullptr, nullptr);
    return text;
}

std::wstring readRegistry(HKEY root, const std::wstring& key, const wchar_t* value) {
    DWORD size = 0;
    if (RegGetValueW(root, key.c_str(), value, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS || size < sizeof(wchar_t)) return std::wstring();
    std::wstring text(size / sizeof(wchar_t), L'\0');
    if (RegGetValueW(root, key.c_str(), value, RRF_RT_REG_SZ, nullptr, text.data(), &size) != ERROR_SUCCESS) return std::wstring();
    while (!text.empty() && text.back() == L'\0') text.pop_back();
    return text;
}

bool writeRegistry(const std::wstring& key, const wchar_t* name, const std::wstring& value) {
    DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    return RegSetKeyValueW(HKEY_CURRENT_USER, key.c_str(), name, REG_SZ, value.c_str(), bytes) == ERROR_SUCCESS;
}

std::wstring environmentPath(const wchar_t* name) {
    wchar_t buffer[MAX_PATH * 2];
    DWORD length = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(sizeof buffer / sizeof buffer[0]));
    if (length == 0 || length >= sizeof buffer / sizeof buffer[0]) return std::wstring();
    return std::wstring(buffer, length);
}

const wchar_t* const kClassKey = L"Software\\Classes\\internet";

#endif

#if !defined(_WIN32) && !defined(__ANDROID__)

bool spawnProcess(const std::vector<std::string>& arguments) {
    std::vector<char*> argv;
    for (const std::string& item : arguments) argv.push_back(const_cast<char*>(item.c_str()));
    argv.push_back(nullptr);
    pid_t child = 0;
    if (posix_spawnp(&child, argv[0], nullptr, nullptr, argv.data(), environ) != 0) return false;
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

#if !defined(__APPLE__)

fs::path onPath(const std::string& name) {
    const char* path = std::getenv("PATH");
    if (!path) return fs::path();
    std::stringstream stream(path);
    std::string directory;
    while (std::getline(stream, directory, ':')) {
        if (directory.empty()) continue;
        std::error_code error;
        fs::path candidate = fs::path(directory) / name;
        if (fs::is_regular_file(candidate, error)) return candidate;
    }
    return fs::path();
}

#endif

#endif

}

std::string findChrome() {
#if defined(_WIN32)
    std::vector<std::wstring> candidates;
    const wchar_t* keys[] = {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe"};
    for (const wchar_t* key : keys) {
        std::wstring local = readRegistry(HKEY_LOCAL_MACHINE, key, nullptr);
        if (!local.empty()) candidates.push_back(local);
        std::wstring user = readRegistry(HKEY_CURRENT_USER, key, nullptr);
        if (!user.empty()) candidates.push_back(user);
    }
    const wchar_t* roots[] = {L"ProgramFiles", L"ProgramFiles(x86)", L"LocalAppData"};
    for (const wchar_t* root : roots) {
        std::wstring base = environmentPath(root);
        if (!base.empty()) candidates.push_back(base + L"\\Google\\Chrome\\Application\\chrome.exe");
    }
    for (const std::wstring& candidate : candidates) {
        std::error_code error;
        if (fs::is_regular_file(fs::path(candidate), error)) return narrow(candidate);
    }
    return std::string();
#elif defined(__ANDROID__) || (defined(__APPLE__) && TARGET_OS_IPHONE)
    return std::string();
#elif defined(__APPLE__)
    std::error_code error;
    const char* bundle = "/Applications/Google Chrome.app";
    return fs::is_directory(bundle, error) ? std::string(bundle) : std::string();
#else
    const char* names[] = {"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"};
    for (const char* name : names) {
        fs::path found = onPath(name);
        if (!found.empty()) return found.string();
    }
    return std::string();
#endif
}

bool openInDefaultBrowser(const std::string& url) {
    if (!webUrl(url)) return false;
#if defined(_WIN32)
    HINSTANCE result = ShellExecuteW(nullptr, L"open", widen(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(result) > 32;
#elif defined(__ANDROID__) || (defined(__APPLE__) && TARGET_OS_IPHONE)
    return false;
#elif defined(__APPLE__)
    return spawnProcess({"open", url});
#else
    return spawnProcess({"xdg-open", url});
#endif
}

bool openInChrome(const std::string& url) {
    if (!webUrl(url)) return false;
    std::string chrome = findChrome();
    if (chrome.empty()) return openInDefaultBrowser(url);
#if defined(_WIN32)
    HINSTANCE result = ShellExecuteW(nullptr, L"open", widen(chrome).c_str(), widen("\"" + url + "\"").c_str(), nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(result) > 32;
#elif defined(__ANDROID__) || (defined(__APPLE__) && TARGET_OS_IPHONE)
    return false;
#elif defined(__APPLE__)
    return spawnProcess({"open", "-a", "Google Chrome", url});
#else
    return spawnProcess({chrome, url});
#endif
}

std::string executablePath() {
#if defined(_WIN32)
    wchar_t buffer[MAX_PATH * 2];
    DWORD length = GetModuleFileNameW(nullptr, buffer, static_cast<DWORD>(sizeof buffer / sizeof buffer[0]));
    if (length == 0 || length >= sizeof buffer / sizeof buffer[0]) return std::string();
    return narrow(std::wstring(buffer, length));
#elif defined(__ANDROID__) || (defined(__APPLE__) && TARGET_OS_IPHONE)
    return std::string();
#elif defined(__APPLE__)
    char buffer[4096];
    std::uint32_t size = sizeof buffer;
    if (_NSGetExecutablePath(buffer, &size) != 0) return std::string();
    std::error_code error;
    fs::path resolved = fs::weakly_canonical(buffer, error);
    return error ? std::string(buffer) : resolved.string();
#else
    std::error_code error;
    fs::path resolved = fs::read_symlink("/proc/self/exe", error);
    return error ? std::string() : resolved.string();
#endif
}

bool browserSupported() {
#if defined(__ANDROID__) || (defined(__APPLE__) && TARGET_OS_IPHONE)
    return false;
#else
    return true;
#endif
}

bool urlHandlerSupported() {
#if defined(_WIN32)
    return true;
#elif defined(__ANDROID__) || defined(__APPLE__)
    return false;
#else
    return true;
#endif
}

#if !defined(_WIN32) && !defined(__ANDROID__) && !defined(__APPLE__)

namespace {

fs::path desktopFile() {
    const char* data = std::getenv("XDG_DATA_HOME");
    const char* home = std::getenv("HOME");
    fs::path base = data && *data ? fs::path(data) : (home ? fs::path(home) / ".local" / "share" : fs::path());
    return base.empty() ? fs::path() : base / "applications" / "internet.desktop";
}

}

#endif

bool registerUrlHandler(const std::string& executable, std::string& error) {
    if (executable.empty()) {
        error = "The program location is unknown";
        return false;
    }
#if defined(_WIN32)
    std::wstring exe = widen(executable);
    std::wstring key = kClassKey;
    bool done = writeRegistry(key, nullptr, L"URL:Internet Protocol") && writeRegistry(key, L"URL Protocol", L"") &&
                writeRegistry(key + L"\\DefaultIcon", nullptr, L"\"" + exe + L"\",0") &&
                writeRegistry(key + L"\\shell\\open\\command", nullptr, L"\"" + exe + L"\" \"%1\"");
    if (!done) error = "Windows refused the registry change";
    return done;
#elif defined(__ANDROID__) || defined(__APPLE__)
    error = "This platform registers internet:// links through the app bundle";
    return false;
#else
    fs::path file = desktopFile();
    if (file.empty()) {
        error = "Cannot find the applications folder";
        return false;
    }
    std::error_code failure;
    fs::create_directories(file.parent_path(), failure);
    std::ofstream out(file, std::ios::trunc);
    if (!out) {
        error = "Cannot write " + file.string();
        return false;
    }
    out << "[Desktop Entry]\nType=Application\nName=Internet\nExec=\"" << executable
        << "\" %u\nTerminal=false\nNoDisplay=true\nMimeType=x-scheme-handler/internet;\n";
    out.close();
    if (!spawnProcess({"xdg-mime", "default", "internet.desktop", "x-scheme-handler/internet"})) {
        error = "xdg-mime could not set the default handler";
        return false;
    }
    return true;
#endif
}

bool unregisterUrlHandler() {
#if defined(_WIN32)
    return RegDeleteTreeW(HKEY_CURRENT_USER, kClassKey) == ERROR_SUCCESS;
#elif defined(__ANDROID__) || defined(__APPLE__)
    return false;
#else
    fs::path file = desktopFile();
    std::error_code error;
    return !file.empty() && fs::remove(file, error);
#endif
}

bool urlHandlerRegistered(const std::string& executable) {
    if (executable.empty()) return false;
#if defined(_WIN32)
    std::wstring command = readRegistry(HKEY_CURRENT_USER, std::wstring(kClassKey) + L"\\shell\\open\\command", nullptr);
    if (command.empty()) return false;
    std::wstring exe = widen(executable);
    auto lower = [](std::wstring text) {
        for (wchar_t& c : text) c = static_cast<wchar_t>(towlower(c));
        return text;
    };
    return lower(command).find(lower(exe)) != std::wstring::npos;
#elif defined(__ANDROID__) || defined(__APPLE__)
    return false;
#else
    fs::path file = desktopFile();
    std::ifstream in(file);
    if (!in) return false;
    std::stringstream content;
    content << in.rdbuf();
    return content.str().find(executable) != std::string::npos;
#endif
}

}
