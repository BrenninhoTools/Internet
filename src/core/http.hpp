#pragma once

#include <string>

namespace internet {

struct HttpResult {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
};

HttpResult httpPost(const std::string& url, const std::string& contentType, const std::string& body, int timeoutMs = 15000);
HttpResult httpGet(const std::string& url, int timeoutMs = 15000);
bool httpsAvailable();
bool parseHttpResponse(const std::string& raw, HttpResult& result);

}
