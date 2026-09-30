# Changelog

All notable changes to Internet are written here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/). Releases are published by hand with the **release** workflow, which uses the section of the version it publishes as the release notes.

## [Unreleased]

## [0.1.0] - Unreleased

The first release. Internet is a small network of its own, written in C++17, with a graphical browser, a command line, a server and a security engine, for Windows, macOS, Linux, Android and iOS.

### Added

#### The network

- A **registry** that maps names to addresses, like DNS. Entries expire after 180 seconds unless they are refreshed, nodes unregister themselves when they stop, reserved names such as `api` and `admin` are kept for the server, and one computer can register only a limited number of names.
- **Nodes** that serve a folder under a name with content types, generated directory listings and protection against path traversal.
- A **client** that opens `internet://name/path` through the registry.
- A small text **wire protocol** (`REGISTER`, `UNREGISTER`, `RESOLVE`, `LIST`, `GET` and `API`) with percent-encoded paths and numeric error codes.

#### The app

- A graphical browser and host with a **home screen** (animated hero, search box, action cards, sites that are online, bookmarks and recent pages), an animated intro and five accent palettes (Ocean, Sunset, Forest, Violet, Candy).
- **Tabs** with their own history, a colored avatar for each site and a spinner while a page loads.
- An **address bar** with a badge for the current site that turns into a search icon while typing and shows a warning ring for suspicious or blocked pages.
- A **command palette** (`Ctrl+K`), keyboard shortcuts, **bookmarks** and **history** that are kept between runs, **find in page**, page zoom from 60% to 250%, a raw **source** view and a save button for binary files.
- **Hosting** a folder as `internet://name/`, running a registry on the computer, a **directory** of the sites that are online, and **Quick start** to do it all in one click.
- A **site editor** with a file tree, page templates (blank page, article, landing page, link list, documentation), snippet buttons, a page link picker, a live preview, unsaved-changes protection and one-click **Publish**.
- **Phones and tablets**: a single column layout, drag scrolling, and native integration on Android (share sheet, haptics, `internet://` links, a foreground service that keeps hosting alive) and iOS (share sheet, haptics, `internet://` links).
- Launch options `--registry`, an `internet://` address, `--security` and `--scan`.

#### Pages

- HTML rendering with headings, paragraphs, bold, italic, underline, strikethrough and highlighted text, inline code and code blocks, bulleted and numbered lists nested to any depth, quotes, tables, images (as a card with their description), links and rules. Scripts and styles are never run.
- Links to `#name` anchors that scroll to the target smoothly.
- A **reading** experience with a centered column, a progress line under the toolbar, a back to top button and an **On this page** outline in the sidebar.

#### Security

- An **antivirus engine** shared by the app, the command line and the server: SHA-256 reputation, byte-pattern rules, file type detection, script, PE and ELF heuristics, name heuristics and inspection of zip, tar and gzip archives, with a score for every file.
- **Go protection** for source files, `go.mod`, `go.sum` and programs compiled with Go, including typosquatting and supply chain checks.
- **Deeper analysis**: content hidden in base64, PowerShell encoded commands, hex, escapes and character codes is decoded and scanned again, layer by layer. Office documents are opened (VBA macros are decompressed and reviewed, remote templates, dynamic data fields, the Follina address and embedded programs are flagged), shortcuts that launch script engines are reviewed, and packed programs are recognized by their import table. Checked against more than 36,000 real files with no false alarms.
- **Real-time protection**: pages are scanned before they are shown, malicious downloads are refused and hosted sites never serve a malicious file.
- A **quarantine**, a **firewall** with rate and connection limits and temporary bans, updatable **definitions**, and a **Security Center** (`Ctrl+J`) with an overview, scans, quarantine, firewall statistics and settings.

#### Command line and server

- The `internet` command: `registry`, `serve`, `get`, `list`, `gateway`, `link`, `api` and `av`.
- `internet-server`: a headless server that hosts every folder of a directory as a site, runs a registry, rescans its sites, keeps a log and exposes a **JSON API** with a token (sites, files, scans, quarantine, firewall and definitions).

#### Chrome and other browsers

- A **gateway** that opens `internet://` sites in Chrome or any browser at `http://site.localhost:8080/`, with the same protection, an origin for every site, scripts blocked by default and links rewritten to gateway links.
- Buttons and palette commands to open a page in Chrome, a way to register `internet://` links with the operating system (Windows and Linux) and a **Chrome extension** for typing `in` and a site name in the address bar.
- **Web links**: when the server has a web address, **Share** creates `https://site.example.com/page` links that open anywhere, the app detects that address from the server, and a pasted or clicked link of that server opens in the app. Other web addresses open in the default browser.

#### Running online

- **Public servers**: `internet-server init --public` creates a configuration for the internet, with a public address for the registry, a registry that only the server can write to, a fixed range of ports for the sites and a domain (`site.example.com`) for ordinary browsers.
- Certificate checks for **HTTPS through Caddy**, a `Dockerfile`, compose files (with and without HTTPS) and a systemd unit.

#### Accounts

- **Sign in with Google** on the web (`/login`, `/account`) and in the app. Signed in people own the sites they create, see and change only their own sites, upload the folder they host, and keep bookmarks, history and settings on every device.
- **Checked sign-in**: the identity from Google has its RS256 signature verified with Google's keys, and its issuer, audience, authorized party, times and the nonce of the sign-in are checked. A server can accept only some organizations or addresses. Sessions expire when unused, can be listed and ended one by one or everywhere, an account can be deleted, the cookie is locked to the host on https, and the account pages forbid caching, framing and scripts.
- An **HTTPS client** for the server (WinHTTP on Windows, Mbed TLS on Linux and macOS) and new API endpoints for accounts, sessions and synced data.

#### Building and releasing

- One CMake project for the app, the command line, the server and the tests, an Android Gradle project and an iOS project.
- Icons and the window icon drawn by code, and a banner for the README.
- A **build** workflow that builds, tests and packages Windows, macOS and Linux, builds the Android APK and the unsigned iOS app, and checks the Docker image, and a **release** workflow that publishes a version when you start it.

### Known limitations

- The iOS app is not signed, so it needs your own Apple developer identity or a sideloading tool, and iOS pauses hosting when the app is in the background.
- The Android APK is signed with the debug key.
- Images are shown as cards and are not decoded.
- Registering `internet://` links is not available on macOS.
- The antivirus is a compact engine written for this project and is not a replacement for a commercial one.

[Unreleased]: https://github.com/BrenninhoTools/Internet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/BrenninhoTools/Internet/releases/tag/v0.1.0
