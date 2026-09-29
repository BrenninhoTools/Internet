#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace internet {

std::string base64UrlEncode(const std::string& data);
bool base64UrlDecode(const std::string& text, std::string& out);
std::string randomBytes(std::size_t count);
std::string randomHex(std::size_t count);
std::string formEncode(const std::vector<std::pair<std::string, std::string>>& fields);
std::vector<std::pair<std::string, std::string>> formDecode(const std::string& text);

}
