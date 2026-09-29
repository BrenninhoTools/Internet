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
        {"amp", '&'},       {"lt", '<'},        {"gt", '>'},        {"quot", '"'},      {"apos", '\''},
        {"nbsp", ' '},      {"copy", 0xA9},     {"reg", 0xAE},      {"hellip", 0x2026}, {"mdash", 0x2014},
        {"ndash", 0x2013},  {"laquo", 0xAB},    {"raquo", 0xBB},    {"bull", 0x2022},   {"lsquo", 0x2018},
        {"rsquo", 0x2019},  {"ldquo", 0x201C},  {"rdquo", 0x201D},  {"middot", 0xB7},   {"times", 0xD7},
        {"deg", 0xB0},      {"plusmn", 0xB1},   {"euro", 0x20AC},
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

std::string unescape(const std::string& text) {
    std::string out;
    std::size_t i = 0;
    while (i < text.size()) {
        if (text[i] == '&') {
            std::size_t end = text.find(';', i);
            std::string decoded;
            if (end != std::string::npos && end - i <= 10 && decodeEntity(text.substr(i + 1, end - i - 1), decoded)) {
                out += decoded;
                i = end + 1;
                continue;
            }
        }
        out += text[i++];
    }
    return out;
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

bool blank(const Span& span) { return span.text.find_first_not_of(' ') == std::string::npos && span.href.empty(); }

void trimSpans(std::vector<Span>& spans) {
    while (!spans.empty() && blank(spans.front())) spans.erase(spans.begin());
    if (!spans.empty()) {
        std::string& first = spans.front().text;
        first.erase(0, first.find_first_not_of(' '));
    }
    while (!spans.empty() && blank(spans.back())) spans.pop_back();
    if (!spans.empty()) {
        std::string& last = spans.back().text;
        std::size_t end = last.find_last_not_of(' ');
        last.erase(end == std::string::npos ? 0 : end + 1);
    }
}

struct ListState {
    bool ordered;
    int counter;
};

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
        endRow();
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

    int* styleCounter(const std::string& name) {
        if (name == "b" || name == "strong") return &bold_;
        if (name == "i" || name == "em" || name == "cite" || name == "dfn" || name == "var") return &italic_;
        if (name == "code" || name == "kbd" || name == "samp" || name == "tt") return &code_;
        if (name == "mark") return &mark_;
        if (name == "s" || name == "del" || name == "strike") return &strike_;
        if (name == "u" || name == "ins") return &underline_;
        return nullptr;
    }

    unsigned currentStyle() const {
        unsigned style = 0;
        if (bold_ > 0) style |= kStyleBold;
        if (italic_ > 0) style |= kStyleItalic;
        if (code_ > 0) style |= kStyleCode;
        if (mark_ > 0) style |= kStyleMark;
        if (strike_ > 0) style |= kStyleStrike;
        if (underline_ > 0) style |= kStyleUnderline;
        return style;
    }

    void emphasisBlock(int& counter, bool closing) {
        if (closing) {
            flushText();
            if (counter > 0) --counter;
            startBlock(BlockKind::Paragraph, 0);
        } else {
            startBlock(BlockKind::Paragraph, 0);
            ++counter;
        }
    }

    void handleTag(const std::string& name, bool closing, const std::string& body, const std::string& lowerBody) {
        if (!closing) {
            std::string id = attribute(body, lowerBody, "id");
            if (id.empty() && name == "a") id = attribute(body, lowerBody, "name");
            if (!id.empty()) pendingAnchor_ = unescape(id);
        }
        if (int* counter = styleCounter(name)) {
            flushText();
            if (!closing) {
                ++*counter;
            } else if (*counter > 0) {
                --*counter;
            }
            return;
        }
        if (handleTable(name, closing)) return;

        bool heading = name.size() == 2 && name[0] == 'h' && name[1] >= '1' && name[1] <= '6';
        if (inCell_ && (heading || name == "li" || name == "pre" || name == "hr" || isBlockTag(name))) {
            character(' ');
            return;
        }
        if (heading) {
            startBlock(closing ? BlockKind::Paragraph : BlockKind::Heading, name[1] - '0');
        } else if (name == "ul" || name == "ol") {
            if (closing) {
                if (!lists_.empty()) lists_.pop_back();
            } else {
                int start = std::atoi(attribute(body, lowerBody, "start").c_str());
                bool ordered = name == "ol";
                lists_.push_back(ListState{ordered, ordered && start > 0 ? start - 1 : 0});
            }
            startBlock(BlockKind::Paragraph, 0);
        } else if (name == "li") {
            startBlock(closing ? BlockKind::Paragraph : BlockKind::ListItem, 0);
            if (!closing && !lists_.empty()) {
                block_.depth = static_cast<int>(lists_.size()) - 1;
                if (lists_.back().ordered) block_.number = ++lists_.back().counter;
            }
        } else if (name == "blockquote") {
            if (closing) {
                if (quote_ > 0) --quote_;
            } else {
                ++quote_;
            }
            startBlock(BlockKind::Paragraph, 0);
        } else if (name == "pre") {
            preformatted_ = !closing;
            startBlock(closing ? BlockKind::Paragraph : BlockKind::Preformatted, 0);
        } else if (name == "hr") {
            startBlock(BlockKind::Paragraph, 0);
            Block rule;
            rule.kind = BlockKind::Rule;
            rule.quote = quote_;
            document_.blocks.push_back(rule);
        } else if (name == "img") {
            if (!closing) addImage(body, lowerBody);
        } else if (name == "caption" || name == "summary" || name == "dt") {
            emphasisBlock(bold_, closing);
        } else if (name == "figcaption") {
            emphasisBlock(italic_, closing);
        } else if (name == "a") {
            flushText();
            href_ = closing ? "" : unescape(attribute(body, lowerBody, "href"));
        } else if (name == "title") {
            flushText();
            inTitle_ = !closing;
        } else if (isBlockTag(name)) {
            startBlock(BlockKind::Paragraph, 0);
        }
    }

    bool handleTable(const std::string& name, bool closing) {
        if (name == "table") {
            endRow();
            startBlock(BlockKind::Paragraph, 0);
            return true;
        }
        if (name == "tr") {
            endRow();
            startBlock(BlockKind::Paragraph, 0);
            if (!closing) beginRow();
            return true;
        }
        if (name == "td" || name == "th") {
            endCell();
            if (closing) return true;
            if (!inRow_) beginRow();
            text_.clear();
            inCell_ = true;
            cell_ = Cell{};
            cell_.header = name == "th";
            if (cell_.header) {
                ++bold_;
                cellBold_ = true;
            }
            return true;
        }
        return false;
    }

    void beginRow() {
        inRow_ = true;
        row_ = Block{};
        row_.kind = BlockKind::TableRow;
        row_.quote = quote_;
    }

    void endCell() {
        if (!inCell_) return;
        flushText();
        trimSpans(cell_.spans);
        row_.cells.push_back(std::move(cell_));
        cell_ = Cell{};
        inCell_ = false;
        if (cellBold_) {
            if (bold_ > 0) --bold_;
            cellBold_ = false;
        }
    }

    void endRow() {
        endCell();
        if (!inRow_) return;
        if (!row_.cells.empty()) document_.blocks.push_back(std::move(row_));
        row_ = Block{};
        inRow_ = false;
    }

    void addImage(const std::string& body, const std::string& lowerBody) {
        std::string source = unescape(attribute(body, lowerBody, "src"));
        std::string alt = unescape(attribute(body, lowerBody, "alt"));
        if (source.rfind("data:", 0) == 0) source.clear();
        std::string target = href_.empty() ? source : href_;
        if (inCell_) {
            flushText();
            cell_.spans.push_back(Span{alt.empty() ? "[image]" : "[" + alt + "]", target, currentStyle()});
            return;
        }
        startBlock(BlockKind::Paragraph, 0);
        Block image;
        image.kind = BlockKind::Image;
        image.quote = quote_;
        image.anchor = std::move(pendingAnchor_);
        pendingAnchor_.clear();
        image.spans.push_back(Span{alt, target, 0});
        document_.blocks.push_back(std::move(image));
    }

    static bool isBlockTag(const std::string& name) {
        static const char* names[] = {"p",       "div",     "ul",      "ol",      "table",    "tr",     "br",
                                      "blockquote", "section", "header", "footer",  "article",  "nav",    "main",
                                      "body",    "form",    "dl",      "dt",      "dd",       "html",   "aside",
                                      "figure",  "details", "address", "fieldset", "hgroup"};
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
            std::vector<Span>& spans = inCell_ ? cell_.spans : block_.spans;
            spans.push_back(Span{text_, href_, currentStyle()});
        }
        text_.clear();
    }

    void startBlock(BlockKind kind, int level) {
        finishBlock();
        block_ = Block{};
        block_.kind = kind;
        block_.level = level;
        block_.quote = quote_;
        block_.anchor = std::move(pendingAnchor_);
        pendingAnchor_.clear();
    }

    void finishBlock() {
        flushText();
        if (block_.kind != BlockKind::Preformatted) trimSpans(block_.spans);
        if (!block_.spans.empty()) {
            document_.blocks.push_back(std::move(block_));
        } else if (!block_.anchor.empty() && pendingAnchor_.empty()) {
            pendingAnchor_ = block_.anchor;
        }
        block_ = Block{};
    }

    Document document_;
    Block block_;
    Block row_;
    Cell cell_;
    std::vector<ListState> lists_;
    std::string text_;
    std::string href_;
    std::string pendingAnchor_;
    int bold_ = 0;
    int italic_ = 0;
    int code_ = 0;
    int mark_ = 0;
    int strike_ = 0;
    int underline_ = 0;
    int quote_ = 0;
    bool preformatted_ = false;
    bool inTitle_ = false;
    bool inRow_ = false;
    bool inCell_ = false;
    bool cellBold_ = false;
};

}

Document parseMarkup(const std::string& html) { return Builder().build(html); }

Document parsePlain(const std::string& text) {
    Document document;
    Block block;
    block.kind = BlockKind::Preformatted;
    block.spans.push_back(Span{text, "", 0});
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

std::string plainText(const Block& block) {
    std::string text;
    for (const Span& span : block.spans) text += span.text;
    return text;
}

}
