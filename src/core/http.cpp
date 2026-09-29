#include "http.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <utility>
#include <vector>

#include "socket.hpp"

#if defined(INTERNET_TLS_WINHTTP)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#elif defined(INTERNET_TLS_MBEDTLS)
#include <cstdio>
#include <cstdlib>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#endif

namespace internet {

namespace {

constexpr std::size_t kMaxResponse = 4 * 1024 * 1024;

struct ParsedUrl {
    std::string scheme;
    std::string host;
    std::uint16_t port = 0;
    std::string path;
};

std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string trimmedText(const std::string& text) {
    std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return std::string();
    return text.substr(start, text.find_last_not_of(" \t\r\n") - start + 1);
}

bool parseUrl(const std::string& url, ParsedUrl& parsed) {
    std::size_t marker = url.find("://");
    if (marker == std::string::npos) return false;
    parsed.scheme = lowered(url.substr(0, marker));
    if (parsed.scheme != "http" && parsed.scheme != "https") return false;
    std::size_t start = marker + 3;
    std::size_t end = url.find_first_of("/?#", start);
    std::string authority = url.substr(start, end == std::string::npos ? std::string::npos : end - start);
    std::string rest = end == std::string::npos ? std::string("/") : url.substr(end);
    std::size_t fragment = rest.find('#');
    if (fragment != std::string::npos) rest.erase(fragment);
    if (rest.empty() || rest[0] != '/') rest = "/" + rest;
    parsed.path = rest;
    parsed.port = parsed.scheme == "https" ? 443 : 80;
    parsed.host = authority;
    std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        std::string digits = authority.substr(colon + 1);
        if (digits.empty() || digits.size() > 5 || digits.find_first_not_of("0123456789") != std::string::npos) return false;
        int port = std::atoi(digits.c_str());
        if (port < 1 || port > 65535) return false;
        parsed.port = static_cast<std::uint16_t>(port);
        parsed.host = authority.substr(0, colon);
    }
    return !parsed.host.empty();
}

bool loopbackHost(const std::string& host) {
    std::string name = lowered(host);
    return name == "localhost" || name == "127.0.0.1" || name == "::1";
}

std::string buildRequest(const ParsedUrl& url, const std::string& contentType, const std::string& body) {
    bool defaultPort = (url.scheme == "https" && url.port == 443) || (url.scheme == "http" && url.port == 80);
    std::string request = "POST " + url.path + " HTTP/1.1\r\n";
    request += "Host: " + url.host + (defaultPort ? std::string() : ":" + std::to_string(url.port)) + "\r\n";
    request += "User-Agent: Internet/1.0\r\nAccept: application/json\r\n";
    request += "Content-Type: " + contentType + "\r\n";
    request += "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
    request += body;
    return request;
}

bool decodeChunked(const std::string& data, std::string& out) {
    std::size_t position = 0;
    for (;;) {
        std::size_t end = data.find("\r\n", position);
        if (end == std::string::npos) return false;
        std::string sizeText = trimmedText(data.substr(position, end - position));
        std::size_t semicolon = sizeText.find(';');
        if (semicolon != std::string::npos) sizeText.erase(semicolon);
        if (sizeText.empty() || sizeText.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) return false;
        unsigned long size = std::strtoul(sizeText.c_str(), nullptr, 16);
        position = end + 2;
        if (size == 0) return true;
        if (position + size > data.size()) return false;
        out.append(data, position, size);
        position += size + 2;
    }
}

HttpResult failure(const std::string& message) {
    HttpResult result;
    result.error = message;
    return result;
}

HttpResult plainPost(const ParsedUrl& url, const std::string& request, int timeoutMs) {
    Socket socket = Socket::connect(url.host, url.port);
    if (!socket.valid()) return failure("cannot connect to " + url.host);
    socket.setTimeout(timeoutMs);
    if (!socket.sendAll(request)) return failure("cannot send the request");
    std::string raw;
    while (raw.size() < kMaxResponse && socket.recvSome(raw)) {
    }
    HttpResult result;
    if (!parseHttpResponse(raw, result)) return failure("the server sent an invalid reply");
    return result;
}

#if defined(INTERNET_TLS_WINHTTP)

std::wstring widen(const std::string& text) {
    if (text.empty()) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &wide[0], size);
    return wide;
}

struct WinHandle {
    HINTERNET handle = nullptr;
    explicit WinHandle(HINTERNET value) : handle(value) {}
    ~WinHandle() {
        if (handle) WinHttpCloseHandle(handle);
    }
    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;
};

HttpResult securePost(const ParsedUrl& url, const std::string& contentType, const std::string& body, int timeoutMs) {
    WinHandle session(WinHttpOpen(L"Internet/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.handle) return failure("cannot start the HTTPS client");
    WinHttpSetTimeouts(session.handle, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
    WinHandle connection(WinHttpConnect(session.handle, widen(url.host).c_str(), url.port, 0));
    if (!connection.handle) return failure("cannot connect to " + url.host);
    WinHandle request(WinHttpOpenRequest(connection.handle, L"POST", widen(url.path).c_str(), nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!request.handle) return failure("cannot open the HTTPS request");
    std::wstring headers = L"Content-Type: " + widen(contentType) + L"\r\nAccept: application/json\r\n";
    DWORD size = static_cast<DWORD>(body.size());
    if (!WinHttpSendRequest(request.handle, headers.c_str(), static_cast<DWORD>(-1), body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
                            size, size, 0))
        return failure("cannot send the HTTPS request (error " + std::to_string(GetLastError()) + ")");
    if (!WinHttpReceiveResponse(request.handle, nullptr)) return failure("no HTTPS reply (error " + std::to_string(GetLastError()) + ")");

    HttpResult result;
    DWORD status = 0;
    DWORD statusSize = sizeof status;
    if (!WinHttpQueryHeaders(request.handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status,
                             &statusSize, WINHTTP_NO_HEADER_INDEX))
        return failure("the HTTPS reply has no status");
    result.status = static_cast<int>(status);
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.handle, &available) || available == 0) break;
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request.handle, &chunk[0], available, &read) || read == 0) break;
        result.body.append(chunk, 0, read);
        if (result.body.size() > kMaxResponse) return failure("the HTTPS reply is too large");
    }
    result.ok = true;
    return result;
}

#elif defined(INTERNET_TLS_MBEDTLS)

constexpr int kSendFailed = -0x004E;

struct Channel {
    Socket* socket;
    std::string pending;
};

int sendCallback(void* context, const unsigned char* data, std::size_t length) {
    Channel* channel = static_cast<Channel*>(context);
    if (!channel->socket->sendAll(std::string(reinterpret_cast<const char*>(data), length))) return kSendFailed;
    return static_cast<int>(length);
}

int receiveCallback(void* context, unsigned char* data, std::size_t length) {
    Channel* channel = static_cast<Channel*>(context);
    if (channel->pending.empty() && !channel->socket->recvSome(channel->pending)) return 0;
    std::size_t count = std::min(length, channel->pending.size());
    std::copy(channel->pending.begin(), channel->pending.begin() + static_cast<std::ptrdiff_t>(count), data);
    channel->pending.erase(0, count);
    return static_cast<int>(count);
}

std::string mbedError(int code) {
    char text[200] = {};
    mbedtls_strerror(code, text, sizeof text);
    return std::string(text) + " (" + std::to_string(code) + ")";
}

std::string environmentValue(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    std::size_t size = 0;
    if (_dupenv_s(&value, &size, name) != 0 || value == nullptr) return std::string();
    std::string text(value);
    std::free(value);
    return text;
#else
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
#endif
}

bool loadRoots(mbedtls_x509_crt& roots) {
    std::vector<std::string> candidates;
    std::string custom = environmentValue("INTERNET_CA_FILE");
    if (!custom.empty()) candidates.push_back(custom);
    const char* known[] = {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem",
                           "/usr/local/etc/openssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem"};
    for (const char* path : known) candidates.emplace_back(path);
    for (const std::string& path : candidates) {
        if (mbedtls_x509_crt_parse_file(&roots, path.c_str()) >= 0 && roots.raw.p != nullptr) return true;
    }
    return false;
}

HttpResult securePost(const ParsedUrl& url, const std::string& request, int timeoutMs) {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_x509_crt roots;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&random);
    mbedtls_x509_crt_init(&roots);
    auto release = [&] {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
        mbedtls_ctr_drbg_free(&random);
        mbedtls_entropy_free(&entropy);
        mbedtls_x509_crt_free(&roots);
    };

    if (psa_crypto_init() != PSA_SUCCESS) {
        release();
        return failure("cannot start the crypto library");
    }
    int code = mbedtls_ctr_drbg_seed(&random, mbedtls_entropy_func, &entropy, nullptr, 0);
    if (code != 0) {
        release();
        return failure("cannot seed the random generator: " + mbedError(code));
    }
    if (!loadRoots(roots)) {
        release();
        return failure("no trusted certificates were found (set INTERNET_CA_FILE to a PEM bundle)");
    }
    code = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (code != 0) {
        release();
        return failure("cannot configure TLS: " + mbedError(code));
    }
    mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&config, &roots, nullptr);
    mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &random);
    code = mbedtls_ssl_setup(&ssl, &config);
    if (code == 0) code = mbedtls_ssl_set_hostname(&ssl, url.host.c_str());
    if (code != 0) {
        release();
        return failure("cannot prepare TLS: " + mbedError(code));
    }

    Socket socket = Socket::connect(url.host, url.port);
    if (!socket.valid()) {
        release();
        return failure("cannot connect to " + url.host);
    }
    socket.setTimeout(timeoutMs);
    Channel channel{&socket, std::string()};
    mbedtls_ssl_set_bio(&ssl, &channel, sendCallback, receiveCallback, nullptr);

    while ((code = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (code == MBEDTLS_ERR_SSL_WANT_READ || code == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        std::string message = "the TLS handshake failed: " + mbedError(code);
        if (code == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
            char info[512] = {};
            mbedtls_x509_crt_verify_info(info, sizeof info, "", mbedtls_ssl_get_verify_result(&ssl));
            message += " " + trimmedText(info);
        }
        release();
        return failure(message);
    }

    std::size_t sent = 0;
    while (sent < request.size()) {
        code = mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(request.data()) + sent, request.size() - sent);
        if (code == MBEDTLS_ERR_SSL_WANT_READ || code == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (code < 0) {
            release();
            return failure("cannot send the request: " + mbedError(code));
        }
        sent += static_cast<std::size_t>(code);
    }

    std::string raw;
    unsigned char buffer[16384];
    while (raw.size() < kMaxResponse) {
        code = mbedtls_ssl_read(&ssl, buffer, sizeof buffer);
        if (code == MBEDTLS_ERR_SSL_WANT_READ || code == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (code <= 0) break;
        raw.append(reinterpret_cast<const char*>(buffer), static_cast<std::size_t>(code));
    }
    mbedtls_ssl_close_notify(&ssl);
    release();

    HttpResult result;
    if (!parseHttpResponse(raw, result)) return failure("the server sent an invalid reply");
    return result;
}

#endif

}

bool parseHttpResponse(const std::string& raw, HttpResult& result) {
    std::size_t headerEnd = raw.find("\r\n\r\n");
    if (headerEnd == std::string::npos) return false;
    std::string head = raw.substr(0, headerEnd);
    std::string body = raw.substr(headerEnd + 4);

    std::size_t lineEnd = head.find("\r\n");
    std::string statusLine = head.substr(0, lineEnd);
    std::size_t space = statusLine.find(' ');
    if (statusLine.rfind("HTTP/", 0) != 0 || space == std::string::npos) return false;
    int status = std::atoi(statusLine.c_str() + space + 1);
    if (status < 100 || status > 599) return false;

    bool chunked = false;
    bool hasLength = false;
    std::size_t length = 0;
    std::size_t position = lineEnd == std::string::npos ? head.size() : lineEnd + 2;
    while (position < head.size()) {
        std::size_t end = head.find("\r\n", position);
        if (end == std::string::npos) end = head.size();
        std::string line = head.substr(position, end - position);
        position = end + 2;
        std::size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = lowered(line.substr(0, colon));
        std::string value = lowered(trimmedText(line.substr(colon + 1)));
        if (name == "transfer-encoding" && value.find("chunked") != std::string::npos) chunked = true;
        if (name == "content-length" && value.find_first_not_of("0123456789") == std::string::npos && !value.empty()) {
            hasLength = true;
            length = static_cast<std::size_t>(std::strtoull(value.c_str(), nullptr, 10));
        }
    }

    std::string decoded;
    if (chunked) {
        if (!decodeChunked(body, decoded)) return false;
    } else if (hasLength) {
        if (body.size() < length) return false;
        decoded = body.substr(0, length);
    } else {
        decoded = std::move(body);
    }
    result.ok = true;
    result.status = status;
    result.body = std::move(decoded);
    return true;
}

bool httpsAvailable() {
#if defined(INTERNET_TLS_WINHTTP) || defined(INTERNET_TLS_MBEDTLS)
    return true;
#else
    return false;
#endif
}

HttpResult httpPost(const std::string& url, const std::string& contentType, const std::string& body, int timeoutMs) {
    ParsedUrl parsed;
    if (!parseUrl(url, parsed)) return failure("invalid address");
    if (parsed.scheme == "http") {
        if (!loopbackHost(parsed.host)) return failure("plain HTTP is only allowed for local addresses");
        return plainPost(parsed, buildRequest(parsed, contentType, body), timeoutMs);
    }
#if defined(INTERNET_TLS_WINHTTP)
    return securePost(parsed, contentType, body, timeoutMs);
#elif defined(INTERNET_TLS_MBEDTLS)
    return securePost(parsed, buildRequest(parsed, contentType, body), timeoutMs);
#else
    return failure("HTTPS is not available in this build");
#endif
}

}
