#pragma once

#include <string>
#include <vector>

namespace internet {

enum class BlockKind { Paragraph, Heading, ListItem, Preformatted, Rule };

struct Span {
    std::string text;
    std::string href;
};

struct Block {
    BlockKind kind = BlockKind::Paragraph;
    int level = 0;
    std::vector<Span> spans;
};

struct Document {
    std::string title;
    std::vector<Block> blocks;
};

Document parseMarkup(const std::string& html);
Document parsePlain(const std::string& text);
bool isTextType(const std::string& contentType);
Document parseContent(const std::string& contentType, const std::string& body);

}
