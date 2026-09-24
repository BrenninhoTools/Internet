# Internet

A custom Internet written in C++17 that runs on Windows, macOS, Linux, Android and iOS.

## Parts

- **Registry**: maps node names to addresses (like DNS). Entries expire after 180 seconds unless refreshed, and nodes unregister themselves when they stop.
- **Node**: serves a directory of files under a name, with content types, generated directory listings and path-traversal protection.
- **Client**: resolves `internet://name/path` through the registry and fetches it from the node.
- **Internet app**: a graphical browser that can also run a registry and host sites. It renders HTML (headings, paragraphs, lists, links, rules, preformatted text), shows plain text, and saves binary files.
- **`internet` command**: the same features for the terminal.
- **`internet-server`**: a headless server that hosts every folder of a directory as a site, runs a registry and exposes a JSON API.
- **Security**: an antivirus engine, quarantine and firewall built into the app, the command line and the server.

## Build

### Windows, macOS and Linux

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --config Release
    ctest --test-dir build -C Release

This produces `internet` (command line), `internet-server`, `internet-app` (graphical app, called `Internet.app` on macOS) and `internet-tests`.
The app downloads GLFW and Dear ImGui at configure time. Use `-DINTERNET_BUILD_APP=OFF` to build only the command line tools.
Use `-DINTERNET_APP_BACKEND=SDL` to build the desktop app on the same SDL3 backend the phones use.

On Linux install the X11 and OpenGL development packages first:

    sudo apt-get install libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev libgl1-mesa-dev

Run `cpack --config build/CPackConfig.cmake -C Release` to create a `.zip` (Windows, macOS) or `.tar.gz` (Linux).

### Android

Needs JDK 17, the Android SDK and NDK, and Gradle 8.10.

    git clone --depth 1 --branch release-3.2.30 https://github.com/libsdl-org/SDL.git android/SDL
    gradle -p android assembleDebug

The APK is written to `android/app/build/outputs/apk/debug/`. Add `-PinternetAbis=arm64-v8a` to build a single architecture and `-PinternetNdk=<major.minor.micro>` to pick an NDK. If CMake is not installed in the Android SDK, point `cmake.dir` in `android/local.properties` at a CMake install.

### iOS

Needs macOS with Xcode.

    cmake -S . -B build-ios -G Xcode -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphoneos \
        -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
        -DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO
    cmake --build build-ios --config Release

The result is an unsigned `Internet.app`. Sign it with your own Apple developer identity (or a sideloading tool) before installing it on a device.

### Continuous integration

`.github/workflows/build.yml` builds, tests and packages Windows, macOS and Linux, builds the Android APK, and builds the unsigned iOS app.

## Icon

The app icon is drawn by code in `src/app/icon.cpp`. To regenerate every icon file (Windows `.ico`, macOS `.icns`, Android launcher icons, iOS icons):

    cmake -S . -B build -DINTERNET_BUILD_TOOLS=ON
    cmake --build build --target internet-icons
    build/internet-icons .

The window icon is rendered from the same code at startup.

## The app

Start `internet-app`. An animated intro plays (click or press any key to skip), then the home screen opens. Press **Quick start** to run a registry, host the sample site and open `internet://home/`.

- **Home screen**: an animated hero, a search box, action cards (Quick start, Host a site, Start or stop a registry, Edit site, Find a site), the sites that are online, your bookmarks and your recent pages.
- **Tabs**: open as many as you like with the `+` button. Each tab has its own history, and the status bar shows how many are open.
- **Command palette** (`Ctrl+K`): type a few letters to run any action, open a site, a bookmark or a recent page, switch the theme, or jump to a file in the editor.
- **Site editor**: see below.
- **Registry**: the address the app uses, plus a button to run a registry on this computer.
- **Host a site**: pick a name and a folder to serve it as `internet://name/`, then copy or share the link.
- **Directory**: every node currently registered, click one to open it.
- **Bookmarks and history**: the star saves a page, the home screen lists bookmarks and recent pages, and both are kept between runs.
- **Find in page** highlights matching words, and page zoom goes from 60% to 250%.
- **Appearance**: five accent palettes (Ocean, Sunset, Forest, Violet, Candy), and switches for the intro and the animated backgrounds. The sidebar can be hidden with `Ctrl+B`.
- **Source** shows the raw page. Binary files offer a save button that writes to `downloads/`.

Shortcuts: `Ctrl+K` command palette, `Ctrl+T` new tab, `Ctrl+W` close tab, `Ctrl+Tab` next tab, `Ctrl+E` site editor, `Ctrl+S` save, `Ctrl+B` sidebar, `Ctrl+L` address bar, `Ctrl+F` find, `Ctrl+D` bookmark, `Ctrl+H` home, `F5` reload, `Alt+Left` and `Alt+Right` back and forward, `Ctrl` with `+`, `-` or `0` for zoom.

Settings, bookmarks and history are stored in `settings.txt`, `bookmarks.txt` and `history.txt` inside the app's data folder (`%APPDATA%\Internet` on Windows, `~/Library/Application Support/Internet` on macOS, `~/.local/share/Internet` on Linux).

## The site editor

Press the pencil button, `Ctrl+E`, or the **Edit site** card to edit the folder you host.

- **Files**: a tree of the site folder. Create pages and folders from templates (blank page, article, landing page, link list), rename them, delete them. Names are checked so nothing can escape the site folder.
- **Editor**: a monospaced text editor with snippet buttons (headings, text, links, lists, rule, bold, code) that insert at the cursor, and a **Page link** picker that lists the pages of your site.
- **Live preview**: shows the page as you type. Choose **Split**, **Edit** or **Preview**.
- **Save** with `Ctrl+S`. Unsaved files are marked in the tree and in the tab title, and switching files asks before discarding changes. If the saved page is open in a tab it reloads.
- **Publish** starts hosting (and a registry when none is reachable) and opens the live site.

## Phones and tablets

On narrow screens (phones, small windows) the app switches to a single column: the Menu button opens the sidebar and the page fills the screen. In the editor the **Files**, **Edit** and **Preview** buttons switch between the three panes. Dragging scrolls, tapping a link opens it, and the Android back button goes back.

Native integration:

- **Android**: the share button opens the system share sheet, taps give a short vibration, `internet://` links from other apps open in the app, and hosting a site starts a foreground service with a notification so the site stays online while the app is in the background.
- **iOS**: the share button opens the share sheet, taps give haptic feedback, and `internet://` links open the app. iOS suspends apps in the background, so hosting pauses when you leave the app.
- Hosted sites and downloads live in the app's private data folder.

The app also accepts launch options: `--registry host:port`, an `internet://` URL, `--security [tab]` and `--scan <path>`.

## Security

The engine lives in `src/core` and is shared by the app, the command line and the server.

- **Scanner**: SHA-256 reputation, byte-pattern rules matched with Aho-Corasick, file type detection, script and PE heuristics, name heuristics (double extensions, executables posing as documents) and ZIP inspection (nesting, path traversal, zip bombs, encrypted entries). Every file gets a score: 85 and above is malicious, 50 and above is suspicious.
- **Real-time protection**: pages are scanned before they are shown, downloads are refused when malicious, files are scanned when saved in the editor, and hosted sites never serve a malicious file (status `451`).
- **Quarantine**: dangerous files found by a scan are moved to `security/quarantine` in the data folder, scrambled, and can be restored or deleted.
- **Firewall**: rate limit, connection limit and temporary bans for abusive computers. Loopback is never limited. The registry also reserves names such as `api` and limits how many names one computer can register.
- **Definitions**: rules and hashes ship inside the program (`definitions/builtin.def`, packed into `src/core/builtin_defs.inc` with `tools/pack_defs.cpp`) and can be updated from a file or an `internet://` address with `internet av update <source>` or from the Security Center.
- **Security Center**: open it with the shield button or `Ctrl+J` for the overview, scans, quarantine, firewall statistics and settings. **Test protection** scans a harmless test marker (`Internet.Test.Marker`) to show that the engine works.

This is a compact engine written for this project. It finds what its rules and hashes describe and flags suspicious behaviour, but it is not a replacement for a commercial antivirus.

## The server

    internet-server init [--dir D]
    internet-server run [--dir D]
    internet-server scan [--dir D]
    internet-server token [--dir D]

`init` creates the directory with `sites/`, `data/` and `server.conf`. `run` starts a registry, an API node and one node per folder under `sites/` (folders added or removed while it runs are picked up), scans everything on start and periodically afterwards, and logs to `data/server.log`. The API token is in `data/token.txt`.

## The API

The API is a node named `api`. A request is sent as `API <METHOD> <path> <token>` with an optional JSON or file body, and replies are JSON.

| Method and path | Description |
| --- | --- |
| `GET /v1/status` | server state (public) |
| `GET /v1/sites`, `POST /v1/sites` | list or create sites (`{"name": "..."}`) |
| `GET`, `DELETE /v1/sites/{name}` | show or remove a site |
| `GET /v1/sites/{name}/files` | list files |
| `GET`, `PUT`, `DELETE /v1/sites/{name}/files/{path}` | read, write or delete a file (uploads are scanned, malicious ones return `422`) |
| `POST /v1/sites/{name}/scan` | scan a site |
| `POST /v1/scan/{name}` | scan the request body as if it were a file called `name` |
| `GET /v1/security/status`, `/v1/security/threats` | protection state and recent threats |
| `GET /v1/security/quarantine`, `DELETE /v1/security/quarantine/{id}` | list or delete quarantined files |
| `GET /v1/security/firewall`, `DELETE /v1/security/firewall/bans/{host}` | firewall statistics, lift a ban |
| `POST /v1/security/definitions` | replace the definitions with the request body |

Everything except `/v1/status` needs the token. From the terminal (the body of `PUT` and `POST` is read from standard input):

    internet api GET /v1/sites --token <token>
    internet api PUT /v1/sites/home/files/index.html --token <token> < index.html

## The command line

    internet registry [--port N]
    internet serve <name> <directory> [--port N] [--registry host:port] [--no-guard]
    internet get <internet://name/path> [--registry host:port] [--out file]
    internet list [--registry host:port]
    internet api <METHOD> <path> [--token T] [--out file] [--registry host:port]
    internet av scan <file-or-folder> [--quarantine] [--json]
    internet av info
    internet av update <definitions-file-or-internet-url>
    internet av quarantine list|restore <id> <destination>|delete <id>

The registry defaults to `127.0.0.1:4000`.

    internet registry
    internet serve home sites/home
    internet get internet://home/

## Wire protocol

Every message is one header line followed by a body:

    FIELD FIELD ... <body-length>\n<body>

| Request | Reply |
| --- | --- |
| `REGISTER <name> <port>` | `OK` |
| `UNREGISTER <name> <port>` | `OK` |
| `RESOLVE <name>` | `OK <host> <port>` |
| `LIST` | `OK`, body of `name host port` lines |
| `GET <path>` (to a node) | `OK <content-type>`, body is the file |

The API uses `API <METHOD> <path> <token>`. Errors are `ERR <code>` with `400`, `401`, `403`, `404`, `405`, `409`, `413`, `422`, `429`, `451` or `500`. Paths are percent-encoded, so `a b.txt` is sent as `a%20b.txt`.

## Limits

The registry records the address a node connects from, so nodes on the same computer are found at `127.0.0.1`. Reaching a node from another machine needs the registry to see that node's LAN address, which happens when the node runs on that other machine and registers over the network.
