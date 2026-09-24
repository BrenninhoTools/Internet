#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <thread>

#include "client.hpp"
#include "markup.hpp"
#include "node.hpp"
#include "protocol.hpp"
#include "registry.hpp"
#include "sitefiles.hpp"
#include "storage.hpp"

namespace fs = std::filesystem;

namespace {

int failures = 0;

void check(bool condition, const std::string& label) {
    if (!condition) {
        ++failures;
        std::cerr << "FAILED: " << label << '\n';
    }
}

void writeFile(const fs::path& path, const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary) << content;
}

bool waitFor(const std::function<bool()>& condition) {
    for (int i = 0; i < 100; ++i) {
        if (condition()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

void testUrls() {
    using internet::resolveUrl;
    check(resolveUrl("internet://home/docs/a.html", "b.html") == "internet://home/docs/b.html", "relative link");
    check(resolveUrl("internet://home/docs/a.html", "/x") == "internet://home/x", "absolute path link");
    check(resolveUrl("internet://home/docs/a.html", "../x.html") == "internet://home/x.html", "parent link");
    check(resolveUrl("internet://home/", "internet://other/") == "internet://other/", "absolute url");
    check(resolveUrl("internet://home/a", "#top") == "internet://home/a", "fragment only");

    std::string decoded;
    check(internet::percentDecode("a%20b%2Fc", decoded) && decoded == "a b/c", "percent decode");
    check(!internet::percentDecode("bad%2", decoded), "percent decode truncated");
    check(internet::percentEncode("a b", "/") == "a%20b", "percent encode");
    check(internet::validName("my-site.1") && !internet::validName("Bad Name") && !internet::validName(""),
          "name validation");
}

void testMarkup() {
    internet::Document document = internet::parseMarkup(
        "<html><head><title>Hi &amp; bye</title><style>p{}</style></head><body><h1>Title</h1>"
        "<p>Hello <a href=\"/x\">link</a>, world &lt;3</p><ul><li>one</li><li>two</li></ul>"
        "<script>var a = '<p>';</script><hr><pre>a\n b</pre></body></html>");
    check(document.title == "Hi & bye", "title");
    check(document.blocks.size() == 6, "block count");
    if (document.blocks.size() != 6) return;
    check(document.blocks[0].kind == internet::BlockKind::Heading && document.blocks[0].level == 1, "heading");
    check(document.blocks[1].spans.size() == 3 && document.blocks[1].spans[1].href == "/x", "link span");
    check(document.blocks[1].spans[2].text == ", world <3", "entity decoding");
    check(document.blocks[2].kind == internet::BlockKind::ListItem, "list item");
    check(document.blocks[4].kind == internet::BlockKind::Rule, "rule");
    check(document.blocks[5].kind == internet::BlockKind::Preformatted && document.blocks[5].spans[0].text == "a\n b",
          "preformatted");
}

void testNetwork() {
    fs::path root = fs::temp_directory_path() / "internet-tests-site";
    fs::remove_all(root);
    writeFile(root / "index.html", "<h1>Home</h1>");
    writeFile(root / "notes" / "a b.txt", "spaced");
    writeFile(root / "data.bin", std::string("\0\1\2\3", 4));

    internet::Registry registry;
    registry.start(0);
    internet::Endpoint registryEndpoint{"127.0.0.1", registry.port()};

    {
        internet::Node node("test", root, registryEndpoint);
        node.start(0);
        check(waitFor([&] { return node.registered(); }), "node registers");

        internet::Page home = internet::fetch(registryEndpoint, "internet://test/");
        check(home.contentType == "text/html" && home.body == "<h1>Home</h1>", "index page");

        internet::Page spaced = internet::fetch(registryEndpoint, "internet://test/notes/a b.txt");
        check(spaced.contentType == "text/plain" && spaced.body == "spaced", "path with spaces");

        internet::Page binary = internet::fetch(registryEndpoint, "internet://test/data.bin");
        check(binary.body.size() == 4 && binary.body[3] == 3, "binary body");

        internet::Page listing = internet::fetch(registryEndpoint, "internet://test/notes/");
        check(listing.body.find("a%20b.txt") != std::string::npos, "directory listing");

        bool missing = false;
        try {
            internet::fetch(registryEndpoint, "internet://test/missing");
        } catch (const internet::FetchError& error) {
            missing = error.code() == "404";
        }
        check(missing, "missing file is 404");

        bool traversal = false;
        try {
            internet::fetch(registryEndpoint, "internet://test/../../etc/passwd");
        } catch (const internet::FetchError& error) {
            traversal = error.code() == "404";
        }
        check(traversal, "traversal is rejected");

        bool encodedTraversal = false;
        try {
            internet::fetch(registryEndpoint, "internet://test/%2e%2e/%2e%2e/secret");
        } catch (const internet::FetchError& error) {
            encodedTraversal = error.code() == "404";
        }
        check(encodedTraversal, "encoded traversal is rejected");

        check(internet::listNodes(registryEndpoint).size() == 1, "node listed");
        check(node.requests() >= 4, "request counter");
    }

    check(waitFor([&] { return internet::listNodes(registryEndpoint).empty(); }), "node unregisters on stop");

    bool unknown = false;
    try {
        internet::fetch(registryEndpoint, "internet://ghost/");
    } catch (const internet::FetchError& error) {
        unknown = error.code() == "404";
    }
    check(unknown, "unknown node is 404");

    registry.stop();
    fs::remove_all(root);
}

}

void testStorage() {
    fs::path root = fs::temp_directory_path() / "internet-tests-storage";
    fs::remove_all(root);
    fs::create_directories(root);

    std::vector<internet::Entry> entries = {{"internet://a/", "Alpha	Page"}, {"internet://b/x", ""}};
    internet::saveEntries(root / "entries.txt", entries);
    std::vector<internet::Entry> loaded = internet::loadEntries(root / "entries.txt");
    check(loaded.size() == 2 && loaded[0].url == "internet://a/" && loaded[0].title == "Alpha Page" && loaded[1].title.empty(),
          "entries round trip");
    check(internet::loadEntries(root / "missing.txt").empty(), "missing entries file");

    internet::Settings settings;
    settings.palette = 3;
    settings.intro = false;
    settings.animations = false;
    settings.zoom = 1.25f;
    internet::saveSettings(root / "settings.txt", settings);
    internet::Settings restored = internet::loadSettings(root / "settings.txt");
    check(restored.palette == 3 && !restored.intro && !restored.animations && restored.zoom > 1.24f && restored.zoom < 1.26f,
          "settings round trip");
    internet::Settings defaults = internet::loadSettings(root / "missing.txt");
    check(defaults.palette == 0 && defaults.intro && defaults.animations, "default settings");

    fs::remove_all(root);
}

void testSiteFiles() {
    fs::path root = fs::temp_directory_path() / "internet-tests-editor";
    fs::remove_all(root);
    fs::create_directories(root);
    std::string error;

    check(internet::isSafeSitePath("docs/page.html") && internet::isSafeSitePath("a.txt"), "safe paths");
    check(!internet::isSafeSitePath("../x") && !internet::isSafeSitePath("/abs") && !internet::isSafeSitePath("a//b") &&
              !internet::isSafeSitePath("a\b") && !internet::isSafeSitePath("c:/x") && !internet::isSafeSitePath("") &&
              !internet::isSafeSitePath("a/../b"),
          "unsafe paths are rejected");
    check(!internet::resolveSitePath(root, "../outside.txt"), "resolve rejects escape");

    check(internet::createSitePath(root, "index.html", internet::siteTemplate(0, "demo", "Home"), error), "create file");
    check(!internet::createSitePath(root, "index.html", "x", error) && !error.empty(), "create refuses duplicates");
    check(internet::createSitePath(root, "docs/", "", error), "create folder");
    check(internet::createSitePath(root, "docs/guide.html", internet::siteTemplate(1, "demo", "Guide <1>"), error),
          "create nested file");

    std::string content;
    check(internet::readSiteFile(root, "docs/guide.html", content, error) && content.find("Guide &lt;1&gt;") != std::string::npos,
          "read escapes titles");
    check(internet::writeSiteFile(root, "index.html", "<h1>Changed</h1>", error), "write file");
    check(internet::readSiteFile(root, "index.html", content, error) && content == "<h1>Changed</h1>", "read written file");

    std::vector<internet::SiteFile> files = internet::listSiteFiles(root);
    check(files.size() == 3 && files[0].path == "docs" && files[0].directory && files[1].path == "docs/guide.html" &&
              files[2].path == "index.html",
          "listing puts folders first");

    check(internet::renameSitePath(root, "docs/guide.html", "docs/manual.html", error), "rename");
    check(!internet::renameSitePath(root, "docs/manual.html", "index.html", error), "rename refuses overwrite");
    check(internet::uniqueSitePath(root, "index.html") == "index-2.html", "unique name");
    check(internet::isTextPath("a.HTML") && !internet::isTextPath("photo.png"), "text detection");

    check(internet::deleteSitePath(root, "docs", error), "delete folder");
    check(internet::listSiteFiles(root).size() == 1, "folder contents deleted");
    check(!internet::deleteSitePath(root, "../x", error), "delete rejects escape");

    for (std::size_t i = 0; i < internet::siteTemplateNames().size(); ++i) {
        check(internet::siteTemplate(static_cast<int>(i), "demo", "T").find("<h1>T</h1>") != std::string::npos,
              "template has heading");
    }
    fs::remove_all(root);
}

int runSecurityTests();
int runServerTests();

int main() {
    testUrls();
    testMarkup();
    testStorage();
    testSiteFiles();
    testNetwork();
    failures += runSecurityTests();
    failures += runServerTests();
    if (failures == 0) std::cout << "all tests passed\n";
    return failures == 0 ? 0 : 1;
}
