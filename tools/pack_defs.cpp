#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: pack_defs <input.def> <output.inc>\n";
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        std::cerr << "cannot read " << argv[1] << '\n';
        return 1;
    }
    std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::ofstream output(argv[2], std::ios::trunc);
    output << "static const unsigned char kBuiltinDefinitions[] = {";
    for (std::size_t i = 0; i < text.size(); ++i) {
        unsigned char value = static_cast<unsigned char>(text[i]) ^ static_cast<unsigned char>((0xA5 + i * 7) & 0xFF);
        char buffer[8];
        std::snprintf(buffer, sizeof buffer, "0x%02x,", value);
        if (i % 24 == 0) output << "\n";
        output << buffer;
    }
    output << "\n};\n";
    return output ? 0 : 1;
}
