#include "sitefiles.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <system_error>

namespace fs = std::filesystem;

namespace internet {

namespace {

constexpr std::size_t kMaxEntries = 2000;

std::vector<std::string> components(const std::string& path) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= path.size()) {
        std::size_t end = path.find('/', start);
        if (end == std::string::npos) end = path.size();
        if (end > start) parts.push_back(path.substr(start, end - start));
        start = end + 1;
    }
    return parts;
}

std::string escapeHtml(const std::string& text) {
    std::string escaped;
    for (char c : text) {
        switch (c) {
            case '&': escaped += "&amp;"; break;
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            default: escaped += c;
        }
    }
    return escaped;
}

std::string stripTrailingSlash(std::string path) {
    while (!path.empty() && path.back() == '/') path.pop_back();
    return path;
}

bool fail(std::string& error, const std::string& message) {
    error = message;
    return false;
}

}

bool isSafeSitePath(const std::string& relative) {
    if (relative.empty() || relative.size() > 240) return false;
    if (relative.front() == '/' || relative.find("//") != std::string::npos) return false;
    for (unsigned char c : relative) {
        if (c < 0x20 || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            return false;
    }
    std::vector<std::string> parts = components(relative);
    if (parts.empty()) return false;
    for (const std::string& part : parts) {
        if (part == "." || part == ".." || part.size() > 120) return false;
        if (part.back() == '.' || part.back() == ' ') return false;
    }
    return true;
}

std::optional<fs::path> resolveSitePath(const fs::path& root, const std::string& relative) {
    std::string trimmed = stripTrailingSlash(relative);
    if (!isSafeSitePath(trimmed)) return std::nullopt;
    std::error_code error;
    fs::path base = fs::weakly_canonical(root, error);
    if (error) return std::nullopt;
    fs::path full = fs::weakly_canonical(base / fs::u8path(trimmed), error);
    if (error) return std::nullopt;
    fs::path inside = full.lexically_relative(base);
    if (inside.empty() || *inside.begin() == "..") return std::nullopt;
    return full;
}

bool isTextPath(const std::string& relative) {
    std::size_t dot = relative.rfind('.');
    if (dot == std::string::npos) return false;
    std::string extension = relative.substr(dot + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    static const char* known[] = {"html", "htm", "txt", "md", "css", "js", "json", "xml", "svg", "csv", "yml", "yaml"};
    for (const char* item : known) {
        if (extension == item) return true;
    }
    return false;
}

std::vector<SiteFile> listSiteFiles(const fs::path& root) {
    std::vector<SiteFile> files;
    std::error_code error;
    fs::path base = fs::weakly_canonical(root, error);
    if (error || !fs::is_directory(base, error)) return files;

    fs::recursive_directory_iterator it(base, fs::directory_options::skip_permission_denied, error);
    fs::recursive_directory_iterator end;
    for (; !error && it != end && files.size() < kMaxEntries; it.increment(error)) {
        std::error_code entryError;
        SiteFile file;
        file.path = it->path().lexically_relative(base).generic_u8string();
        file.directory = it->is_directory(entryError);
        if (!file.directory) file.size = it->file_size(entryError);
        if (!file.path.empty()) files.push_back(std::move(file));
    }

    std::sort(files.begin(), files.end(), [](const SiteFile& a, const SiteFile& b) {
        std::vector<std::string> left = components(a.path);
        std::vector<std::string> right = components(b.path);
        std::size_t common = std::min(left.size(), right.size());
        for (std::size_t i = 0; i < common; ++i) {
            if (left[i] == right[i]) continue;
            bool leftDirectory = i + 1 < left.size() || a.directory;
            bool rightDirectory = i + 1 < right.size() || b.directory;
            if (leftDirectory != rightDirectory) return leftDirectory;
            return left[i] < right[i];
        }
        return left.size() < right.size();
    });
    return files;
}

std::string uniqueSitePath(const fs::path& root, const std::string& relative) {
    std::optional<fs::path> first = resolveSitePath(root, relative);
    std::error_code error;
    if (!first || !fs::exists(*first, error)) return relative;

    std::string stem = relative;
    std::string extension;
    std::size_t dot = relative.rfind('.');
    std::size_t slash = relative.rfind('/');
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash)) {
        stem = relative.substr(0, dot);
        extension = relative.substr(dot);
    }
    for (int i = 2; i < 1000; ++i) {
        std::string candidate = stem + "-" + std::to_string(i) + extension;
        std::optional<fs::path> resolved = resolveSitePath(root, candidate);
        if (resolved && !fs::exists(*resolved, error)) return candidate;
    }
    return relative;
}

bool readSiteFile(const fs::path& root, const std::string& relative, std::string& content, std::string& error) {
    std::optional<fs::path> path = resolveSitePath(root, relative);
    if (!path) return fail(error, "Invalid file name");
    std::error_code code;
    if (!fs::is_regular_file(*path, code)) return fail(error, "File not found");
    if (fs::file_size(*path, code) > kMaxEditableSize) return fail(error, "File is too large to edit");
    std::ifstream stream(*path, std::ios::binary);
    if (!stream) return fail(error, "Cannot open the file");
    content.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    if (content.find('\0') != std::string::npos) return fail(error, "Binary file");
    return true;
}

bool writeSiteFile(const fs::path& root, const std::string& relative, const std::string& content, std::string& error) {
    std::optional<fs::path> path = resolveSitePath(root, relative);
    if (!path) return fail(error, "Invalid file name");
    std::error_code code;
    fs::create_directories(path->parent_path(), code);
    std::ofstream stream(*path, std::ios::binary | std::ios::trunc);
    if (!stream) return fail(error, "Cannot write the file");
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!stream) return fail(error, "Cannot write the file");
    return true;
}

bool createSitePath(const fs::path& root, const std::string& relative, const std::string& content, std::string& error) {
    std::optional<fs::path> path = resolveSitePath(root, relative);
    if (!path) return fail(error, "Invalid name");
    std::error_code code;
    if (fs::exists(*path, code)) return fail(error, "A file with that name already exists");
    if (!relative.empty() && relative.back() == '/') {
        if (!fs::create_directories(*path, code) || code) return fail(error, "Cannot create the folder");
        return true;
    }
    return writeSiteFile(root, relative, content, error);
}

bool deleteSitePath(const fs::path& root, const std::string& relative, std::string& error) {
    std::optional<fs::path> path = resolveSitePath(root, relative);
    if (!path) return fail(error, "Invalid name");
    std::error_code code;
    if (!fs::exists(*path, code)) return fail(error, "File not found");
    fs::remove_all(*path, code);
    if (code) return fail(error, "Cannot delete: " + code.message());
    return true;
}

bool renameSitePath(const fs::path& root, const std::string& from, const std::string& to, std::string& error) {
    std::optional<fs::path> source = resolveSitePath(root, from);
    std::optional<fs::path> target = resolveSitePath(root, to);
    if (!source || !target) return fail(error, "Invalid name");
    std::error_code code;
    if (!fs::exists(*source, code)) return fail(error, "File not found");
    if (fs::exists(*target, code)) return fail(error, "A file with that name already exists");
    fs::create_directories(target->parent_path(), code);
    fs::rename(*source, *target, code);
    if (code) return fail(error, "Cannot rename: " + code.message());
    return true;
}

std::vector<std::string> siteTemplateNames() { return {"Blank page", "Article", "Landing page", "Link list"}; }

std::string siteTemplate(int index, const std::string& siteName, const std::string& title) {
    std::string name = escapeHtml(siteName);
    std::string heading = escapeHtml(title.empty() ? "Untitled" : title);
    std::string head = "<!DOCTYPE html>\n<html>\n<head><title>" + heading + "</title></head>\n<body>\n";
    std::string tail = "</body>\n</html>\n";
    switch (index) {
        case 1:
            return head + "<h1>" + heading + "</h1>\n<p>Written for internet://" + name +
                   "/ - a short introduction that tells readers what this article is about.</p>\n"
                   "<h2>First idea</h2>\n<p>Explain the first idea here. Keep paragraphs short and clear.</p>\n"
                   "<h2>Second idea</h2>\n<p>Add the second idea and link to <a href=\"index.html\">the start page</a>.</p>\n"
                   "<pre>Code or a quote can go in a preformatted block.</pre>\n<hr>\n"
                   "<p><a href=\"index.html\">Back to the start page</a></p>\n" + tail;
        case 2:
            return head + "<h1>" + heading + "</h1>\n<p>One sentence that explains what " + name + " offers.</p>\n"
                   "<h2>Why visit</h2>\n<ul>\n<li>Fast pages served straight from a folder</li>\n"
                   "<li>Easy to edit and share</li>\n<li>Runs on your own network</li>\n</ul>\n"
                   "<h2>Get started</h2>\n<p><a href=\"about.html\">Read more about this site</a></p>\n<hr>\n"
                   "<p>Made with the Internet app.</p>\n" + tail;
        case 3:
            return head + "<h1>" + heading + "</h1>\n<p>A few places worth visiting.</p>\n<ul>\n"
                   "<li><a href=\"index.html\">Start page</a></li>\n"
                   "<li><a href=\"internet://home/\">The home site</a></li>\n"
                   "<li><a href=\"about.html\">About</a></li>\n</ul>\n" + tail;
        default:
            return head + "<h1>" + heading + "</h1>\n<p>Start writing here.</p>\n" + tail;
    }
}

}
