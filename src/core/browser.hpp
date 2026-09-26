#pragma once

#include <string>

namespace internet {

std::string findChrome();
bool openInChrome(const std::string& url);
bool openInDefaultBrowser(const std::string& url);
bool browserSupported();

std::string executablePath();
bool urlHandlerSupported();
bool registerUrlHandler(const std::string& executable, std::string& error);
bool unregisterUrlHandler();
bool urlHandlerRegistered(const std::string& executable);

}
