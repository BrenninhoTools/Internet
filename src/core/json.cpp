#include "json.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace internet {

namespace {

constexpr int kMaxDepth = 32;

void appendUtf8(std::string& out, unsigned long code) {
    if (code < 0x80) {
        out += static_cast<char>(code);
    } else if (code < 0x800) {
        out += static_cast<char>(0xC0 | (code >> 6));
        out += static_cast<char>(0x80 | (code & 0x3F));
    } else if (code < 0x10000) {
        out += static_cast<char>(0xE0 | (code >> 12));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (code >> 18));
        out += static_cast<char>(0x80 | ((code >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
    }
}

class Parser {
public:
    Parser(const std::string& text) : text_(text) {}

    bool run(Json& out, std::string& error) {
        skip();
        if (!value(out, 0)) {
            error = error_.empty() ? "invalid JSON" : error_;
            return false;
        }
        skip();
        if (position_ != text_.size()) {
            error = "unexpected data after the JSON value";
            return false;
        }
        return true;
    }

private:
    bool fail(const std::string& message) {
        if (error_.empty()) error_ = message + " at position " + std::to_string(position_);
        return false;
    }

    void skip() {
        while (position_ < text_.size() && (text_[position_] == ' ' || text_[position_] == '\t' || text_[position_] == '\n' || text_[position_] == '\r'))
            ++position_;
    }

    bool literal(const char* word) {
        std::size_t length = std::char_traits<char>::length(word);
        if (text_.compare(position_, length, word) != 0) return false;
        position_ += length;
        return true;
    }

    bool hex4(unsigned long& value) {
        if (position_ + 4 > text_.size()) return false;
        value = 0;
        for (int i = 0; i < 4; ++i) {
            char c = text_[position_ + static_cast<std::size_t>(i)];
            value <<= 4;
            if (c >= '0' && c <= '9') {
                value |= static_cast<unsigned long>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                value |= static_cast<unsigned long>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                value |= static_cast<unsigned long>(c - 'A' + 10);
            } else {
                return false;
            }
        }
        position_ += 4;
        return true;
    }

    bool string(std::string& out) {
        if (position_ >= text_.size() || text_[position_] != '"') return fail("expected a string");
        ++position_;
        out.clear();
        while (position_ < text_.size()) {
            char c = text_[position_++];
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20) return fail("control character in a string");
            if (c != '\\') {
                out += c;
                continue;
            }
            if (position_ >= text_.size()) return fail("unfinished escape");
            char e = text_[position_++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    unsigned long code = 0;
                    if (!hex4(code)) return fail("invalid unicode escape");
                    if (code >= 0xD800 && code <= 0xDBFF) {
                        unsigned long low = 0;
                        if (text_.compare(position_, 2, "\\u") != 0) return fail("unpaired surrogate");
                        position_ += 2;
                        if (!hex4(low) || low < 0xDC00 || low > 0xDFFF) return fail("invalid surrogate pair");
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                    }
                    appendUtf8(out, code);
                    break;
                }
                default: return fail("invalid escape");
            }
        }
        return fail("unterminated string");
    }

    bool value(Json& out, int depth) {
        if (depth > kMaxDepth) return fail("nesting is too deep");
        skip();
        if (position_ >= text_.size()) return fail("unexpected end");
        char c = text_[position_];
        if (c == '{') {
            ++position_;
            out = Json::object();
            skip();
            if (position_ < text_.size() && text_[position_] == '}') {
                ++position_;
                return true;
            }
            for (;;) {
                skip();
                std::string key;
                if (!string(key)) return false;
                skip();
                if (position_ >= text_.size() || text_[position_] != ':') return fail("expected ':'");
                ++position_;
                Json item;
                if (!value(item, depth + 1)) return false;
                out.set(key, std::move(item));
                skip();
                if (position_ < text_.size() && text_[position_] == ',') {
                    ++position_;
                    continue;
                }
                if (position_ < text_.size() && text_[position_] == '}') {
                    ++position_;
                    return true;
                }
                return fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            ++position_;
            out = Json::array();
            skip();
            if (position_ < text_.size() && text_[position_] == ']') {
                ++position_;
                return true;
            }
            for (;;) {
                Json item;
                if (!value(item, depth + 1)) return false;
                out.push(std::move(item));
                skip();
                if (position_ < text_.size() && text_[position_] == ',') {
                    ++position_;
                    continue;
                }
                if (position_ < text_.size() && text_[position_] == ']') {
                    ++position_;
                    return true;
                }
                return fail("expected ',' or ']'");
            }
        }
        if (c == '"') {
            std::string text;
            if (!string(text)) return false;
            out = Json(text);
            return true;
        }
        if (literal("true")) {
            out = Json(true);
            return true;
        }
        if (literal("false")) {
            out = Json(false);
            return true;
        }
        if (literal("null")) {
            out = Json();
            return true;
        }
        const char* begin = text_.c_str() + position_;
        char* end = nullptr;
        double number = std::strtod(begin, &end);
        if (end == begin) return fail("unexpected character");
        position_ += static_cast<std::size_t>(end - begin);
        out = Json(number);
        return true;
    }

    const std::string& text_;
    std::size_t position_ = 0;
    std::string error_;
};

}

std::string jsonEscape(const std::string& text) {
    std::string out;
    for (char raw : text) {
        unsigned char c = static_cast<unsigned char>(raw);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof buffer, "\\u%04x", c);
                    out += buffer;
                } else {
                    out += raw;
                }
        }
    }
    return out;
}

Json::Json() = default;
Json::Json(bool value) : type_(Type::Bool), boolean_(value) {}
Json::Json(int value) : type_(Type::Number), number_(value) {}
Json::Json(std::int64_t value) : type_(Type::Number), number_(static_cast<double>(value)) {}
Json::Json(std::uint64_t value) : type_(Type::Number), number_(static_cast<double>(value)) {}
Json::Json(double value) : type_(Type::Number), number_(value) {}
Json::Json(const char* value) : type_(Type::String), text_(value) {}
Json::Json(const std::string& value) : type_(Type::String), text_(value) {}

Json Json::array() {
    Json json;
    json.type_ = Type::Array;
    return json;
}

Json Json::object() {
    Json json;
    json.type_ = Type::Object;
    return json;
}

Json& Json::set(const std::string& key, Json value) {
    for (std::size_t i = 0; i < keys_.size(); ++i) {
        if (keys_[i] == key) {
            values_[i] = std::move(value);
            return *this;
        }
    }
    keys_.push_back(key);
    values_.push_back(std::move(value));
    return *this;
}

Json& Json::push(Json value) {
    values_.push_back(std::move(value));
    return *this;
}

Json::Type Json::type() const { return type_; }
bool Json::isString() const { return type_ == Type::String; }
bool Json::isObject() const { return type_ == Type::Object; }
bool Json::isArray() const { return type_ == Type::Array; }
const std::string& Json::asString() const { return text_; }
double Json::asNumber() const { return number_; }
bool Json::asBool() const { return boolean_; }
const std::vector<Json>& Json::items() const { return values_; }
std::size_t Json::size() const { return values_.size(); }

const Json* Json::find(const std::string& key) const {
    if (type_ != Type::Object) return nullptr;
    for (std::size_t i = 0; i < keys_.size(); ++i) {
        if (keys_[i] == key) return &values_[i];
    }
    return nullptr;
}

std::string Json::stringOr(const std::string& key, const std::string& fallback) const {
    const Json* item = find(key);
    return item && item->isString() ? item->asString() : fallback;
}

void Json::write(std::string& out) const {
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += boolean_ ? "true" : "false"; break;
        case Type::Number: {
            char buffer[40];
            if (std::floor(number_) == number_ && std::fabs(number_) < 1e15) {
                std::snprintf(buffer, sizeof buffer, "%lld", static_cast<long long>(number_));
            } else {
                std::snprintf(buffer, sizeof buffer, "%.15g", number_);
            }
            out += buffer;
            break;
        }
        case Type::String:
            out += '"';
            out += jsonEscape(text_);
            out += '"';
            break;
        case Type::Array:
            out += '[';
            for (std::size_t i = 0; i < values_.size(); ++i) {
                if (i > 0) out += ',';
                values_[i].write(out);
            }
            out += ']';
            break;
        case Type::Object:
            out += '{';
            for (std::size_t i = 0; i < keys_.size(); ++i) {
                if (i > 0) out += ',';
                out += '"';
                out += jsonEscape(keys_[i]);
                out += "\":";
                values_[i].write(out);
            }
            out += '}';
            break;
    }
}

std::string Json::dump() const {
    std::string out;
    write(out);
    return out;
}

bool Json::parse(const std::string& text, Json& out, std::string& error) { return Parser(text).run(out, error); }

}
