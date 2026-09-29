#pragma once

#include <string>
#include <vector>

namespace internet {

enum class BlockKind { Paragraph, Heading, ListItem, Preformatted, Rule, TableRow, Image };

enum SpanStyle : unsigned {
    kStyleBold = 1u << 0,
    kStyleItalic = 1u << 1,
    kStyleCode = 1u << 2,
    kStyleMark = 1u << 3,
    kStyleStrike = 1u << 4,
    kStyleUnderline = 1u << 5,
};

struct Span {
    std::string text;
    std::string href;
    unsigned style = 0;
};

struct Cell {
    std::vector<Span> spans;
    bool header = false;
};

struct Block {
    BlockKind kind = BlockKind::Paragraph;
    int level = 0;
    int depth = 0;
    int number = 0;
    int quote = 0;
    std::string anchor;
    std::vector<Span> spans;
    std::vector<Cell> cells;
};

struct Document {
    std::string title;
    std::vector<Block> blocks;
};

Document parseMarkup(const std::string& html);
Document parsePlain(const std::string& text);
bool isTextType(const std::string& contentType);
Document parseContent(const std::string& contentType, const std::string& body);
std::string plainText(const Block& block);

}
