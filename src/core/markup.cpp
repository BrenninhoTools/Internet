#include "markup.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>
#include <utility>

namespace internet {

namespace {

std::string lowerCase(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool isSpace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'; }

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
    } else if (code < 0x110000) {
        out += static_cast<char>(0xF0 | (code >> 18));
        out += static_cast<char>(0x80 | ((code >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
    }
}

bool decodeEntity(const std::string& name, std::string& out) {
    static const std::map<std::string, unsigned long> named = {
        {"amp", '&'},     {"lt", '<'},      {"gt", '>'},      {"quot", '"'},    {"apos", '\''},
        {"nbsp", ' '},    {"copy", 0xA9},   {"reg", 0xAE},    {"hellip", 0x2026}, {"mdash", 0x2014},
        {"ndash", 0x2013}, {"laquo", 0xAB}, {"raquo", 0xBB},  {"bull", 0x2022},
    };
    if (name.empty()) return false;
    if (name[0] == '#') {
        bool hex = name.size() > 1 && (name[1] == 'x' || name[1] == 'X');
        const char* digits = name.c_str() + (hex ? 2 : 1);
        char* end = nullptr;
        unsigned long code = std::strtoul(digits, &end, hex ? 16 : 10);
        if (end == digits || *end != '\0') return false;
        appendUtf8(out, code);
        return true;
    }
    auto found = named.find(name);
    if (found == named.end()) return false;
    appendUtf8(out, found->second);
    return true;
}

std::string attribute(const std::string& tag, const std::string& lowerTag, const std::string& name) {
    std::size_t position = 0;
    for (;;) {
        position = lowerTag.find(name, position);
        if (position == std::string::npos) return "";
        bool boundary = position == 0 || isSpace(lowerTag[position - 1]);
        std::size_t after = position + name.size();
        while (after < lowerTag.size() && isSpace(lowerTag[after])) ++after;
        if (boundary && after < lowerTag.size() && lowerTag[after] == '=') {
            ++after;
            while (after < tag.size() && isSpace(tag[after])) ++after;
            if (after >= tag.size()) return "";
            if (tag[after] == '"' || tag[after] == '\'') {
                std::size_t close = tag.find(tag[after], after + 1);
                if (close == std::string::npos) return tag.substr(after + 1);
                return tag.substr(after + 1, close - after - 1);
            }
            std::size_t end = after;
            while (end < tag.size() && !isSpace(tag[end]) && tag[end] != '>') ++end;
            return tag.substr(after, end - after);
        }
        position += name.size();
    }
}

class Builder {
public:
    Document build(const std::string& html) {
        std::string lower = lowerCase(html);
        std::size_t i = 0;
        while (i < html.size()) {
            char c = html[i];
            if (c == '<') {
                i = tag(html, lower, i);
            } else if (c == '&') {
                i = entity(html, i);
            } else {
                character(c);
                ++i;
            }
        }
        finishBlock();
        return std::move(document_);
    }

private:
    std::size_t tag(const std::string& html, const std::string& lower, std::size_t start) {
        if (html.compare(start, 4, "<!--") == 0) {
            std::size_t end = html.find("-->", start + 4);
            return end == std::string::npos ? html.size() : end + 3;
        }
        std::size_t end = html.find('>', start);
        if (end == std::string::npos) return html.size();

        std::string body = html.substr(start + 1, end - start - 1);
        std::string lowerBody = lower.substr(start + 1, end - start - 1);
        if (body.empty() || body[0] == '!' || body[0] == '?') return end + 1;

        bool closing = body[0] == '/';
        std::size_t nameStart = closing ? 1 : 0;
        std::size_t nameEnd = nameStart;
        while (nameEnd < lowerBody.size() && !isSpace(lowerBody[nameEnd]) && lowerBody[nameEnd] != '/') ++nameEnd;
        std::string name = lowerBody.substr(nameStart, nameEnd - nameStart);

        if (!closing && (name == "script" || name == "style")) {
            std::size_t close = lower.find("</" + name, end);
            if (close == std::string::npos) return html.size();
            std::size_t after = lower.find('>', close);
            return after == std::string::npos ? html.size() : after + 1;
        }
        handleTag(name, closing, body, lowerBody);
        return end + 1;
    }

    void handleTag(const std::string& name, bool closing, const std::string& body, const std::string& lowerBody) {
        if (name.size() == 2 && name[0] == 'h' && name[1] >= '1' && name[1] <= '6') {
            startBlock(closing ? BlockKind::Paragraph : BlockKind::Heading, name[1] - '0');
        } else if (name == "li") {
            startBlock(closing ? BlockKind::Paragraph : BlockKind::ListItem, 0);
        } else if (name == "pre") {
            preformatted_ = !closing;
            startBlock(closing ? BlockKind::Paragraph : BlockKind::Preformatted, 0);
        } else if (name == "hr") {
            startBlock(BlockKind::Paragraph, 0);
            Block rule;
            rule.kind = BlockKind::Rule;
            document_.blocks.push_back(rule);
        } else if (name == "a") {
            flushText();
            href_ = closing ? "" : attribute(body, lowerBody, "href");
        } else if (name == "title") {
            flushText();
            inTitle_ = !closing;
        } else if (isBlockTag(name)) {
            startBlock(BlockKind::Paragraph, 0);
        }
    }

    static bool isBlockTag(const std::string& name) {
        static const char* names[] = {"p",  "div",    "ul",      "ol",     "table",   "tr",     "br",
                                      "blockquote", "section", "header", "footer", "article", "nav",
                                      "main", "body", "form",    "dl",     "dt",      "dd",     "html"};
        for (const char* item : names) {
            if (name == item) return true;
        }
        return false;
    }

    std::size_t entity(const std::string& html, std::size_t start) {
        std::size_t end = html.find(';', start);
        if (end != std::string::npos && end - start <= 10) {
            std::string decoded;
            if (decodeEntity(html.substr(start + 1, end - start - 1), decoded)) {
                for (char c : decoded) text_ += c;
                return end + 1;
            }
        }
        character('&');
        return start + 1;
    }

    void character(char c) {
        if (preformatted_) {
            text_ += c;
        } else if (isSpace(c)) {
            if (text_.empty() || text_.back() != ' ') text_ += ' ';
        } else {
            text_ += c;
        }
    }

    void flushText() {
        if (text_.empty()) return;
        if (inTitle_) {
            document_.title += text_;
        } else {
            block_.spans.push_back(Span{text_, href_});
        }
        text_.clear();
    }

    void startBlock(BlockKind kind, int level) {
        finishBlock();
        block_ = Block{};
        block_.kind = kind;
        block_.level = level;
    }

    void finishBlock() {
        flushText();
        if (block_.kind != BlockKind::Preformatted) {
            while (!block_.spans.empty() && block_.spans.front().text.find_first_not_of(' ') == std::string::npos &&
                   block_.spans.front().href.empty())
                block_.spans.erase(block_.spans.begin());
            if (!block_.spans.empty()) {
                std::string& first = block_.spans.front().text;
                first.erase(0, first.find_first_not_of(' '));
            }
            while (!block_.spans.empty() && block_.spans.back().text.find_first_not_of(' ') == std::string::npos &&
                   block_.spans.back().href.empty())
                block_.spans.pop_back();
            if (!block_.spans.empty()) {
                std::string& last = block_.spans.back().text;
                std::size_t end = last.find_last_not_of(' ');
                last.erase(end == std::string::npos ? 0 : end + 1);
            }
        }
        if (!block_.spans.empty()) document_.blocks.push_back(std::move(block_));
        block_ = Block{};
    }

    Document document_;
    Block block_;
    std::string text_;
    std::string href_;
    bool preformatted_ = false;
    bool inTitle_ = false;
};

}

Document parseMarkup(const std::string& html) { return Builder().build(html); }

Document parsePlain(const std::string& text) {
    Document document;
    Block block;
    block.kind = BlockKind::Preformatted;
    block.spans.push_back(Span{text, ""});
    document.blocks.push_back(std::move(block));
    return document;
}

bool isTextType(const std::string& contentType) {
    return contentType.rfind("text/", 0) == 0 || contentType == "application/json" ||
           contentType == "application/xml" || contentType == "image/svg+xml";
}

Document parseContent(const std::string& contentType, const std::string& body) {
    if (contentType == "text/html") return parseMarkup(body);
    if (isTextType(contentType)) return parsePlain(body);
    return Document{};
}

}
