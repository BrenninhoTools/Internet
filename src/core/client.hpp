#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include "protocol.hpp"

namespace internet {

struct Page {
    std::string url;
    std::string contentType;
    std::string body;
};

class FetchError : public std::runtime_error {
public:
    FetchError(std::string code, const std::string& message);
    const std::string& code() const;

private:
    std::string code_;
};

bool isInternetUrl(const std::string& url);
std::string resolveUrl(const std::string& base, const std::string& href);
Endpoint resolveNode(const Endpoint& registry, const std::string& name);
Page fetch(const Endpoint& registry, const std::string& url);
std::vector<NodeInfo> listNodes(const Endpoint& registry);

}
