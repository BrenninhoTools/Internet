#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace internet {

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Json();
    Json(bool value);
    Json(int value);
    Json(std::int64_t value);
    Json(std::uint64_t value);
    Json(double value);
    Json(const char* value);
    Json(const std::string& value);

    static Json array();
    static Json object();

    Json& set(const std::string& key, Json value);
    Json& push(Json value);

    Type type() const;
    bool isString() const;
    bool isObject() const;
    bool isArray() const;
    const std::string& asString() const;
    double asNumber() const;
    bool asBool() const;
    const Json* find(const std::string& key) const;
    std::string stringOr(const std::string& key, const std::string& fallback) const;
    const std::vector<Json>& items() const;
    std::size_t size() const;

    std::string dump() const;
    static bool parse(const std::string& text, Json& out, std::string& error);

private:
    void write(std::string& out) const;

    Type type_ = Type::Null;
    bool boolean_ = false;
    double number_ = 0.0;
    std::string text_;
    std::vector<std::string> keys_;
    std::vector<Json> values_;
};

std::string jsonEscape(const std::string& text);

}
