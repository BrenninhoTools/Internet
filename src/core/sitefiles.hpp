#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace internet {

struct SiteFile {
    std::string path;
    bool directory = false;
    std::uintmax_t size = 0;
};

constexpr std::uintmax_t kMaxEditableSize = 1024 * 1024;

std::vector<SiteFile> listSiteFiles(const std::filesystem::path& root);
bool isSafeSitePath(const std::string& relative);
std::optional<std::filesystem::path> resolveSitePath(const std::filesystem::path& root, const std::string& relative);
bool isTextPath(const std::string& relative);
std::string uniqueSitePath(const std::filesystem::path& root, const std::string& relative);

bool readSiteFile(const std::filesystem::path& root, const std::string& relative, std::string& content,
                  std::string& error);
bool writeSiteFile(const std::filesystem::path& root, const std::string& relative, const std::string& content,
                   std::string& error);
bool createSitePath(const std::filesystem::path& root, const std::string& relative, const std::string& content,
                    std::string& error);
bool deleteSitePath(const std::filesystem::path& root, const std::string& relative, std::string& error);
bool renameSitePath(const std::filesystem::path& root, const std::string& from, const std::string& to,
                    std::string& error);

std::vector<std::string> siteTemplateNames();
std::string siteTemplate(int index, const std::string& siteName, const std::string& title);

}
