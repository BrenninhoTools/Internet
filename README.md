# Internet

A custom Internet written in C++17 that runs on Windows, macOS, Linux, Android and iOS.

## Parts

- **Registry**: maps node names to addresses (like DNS). Entries expire after 180 seconds unless refreshed, and nodes unregister themselves when they stop.
- **Node**: serves a directory of files under a name, with content types, generated directory listings and path-traversal protection.
- **Client**: resolves `internet://name/path` through the registry and fetches it from the node.
- **Internet app**: a graphical browser that can also run a registry and host sites. It renders HTML (headings, paragraphs, lists, links, rules, preformatted text), shows plain text, and saves binary files.
- **`internet` command**: the same features for the terminal.

## Build

### Windows, macOS and Linux

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --config Release
    ctest --test-dir build -C Release

This produces `internet` (command line), `internet-app` (graphical app, called `Internet.app` on macOS) and `internet-tests`.
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

Start `internet-app` and press **Quick start**. It runs a registry, hosts the sample site and opens `internet://home/`.

- **Registry**: the address the app uses, plus a button to run a registry on this computer.
- **Host a site**: pick a name and a folder to serve it as `internet://name/`.
- **Directory**: every node currently registered, click one to open it.
- **Source** shows the raw page. Binary files offer a save button that writes to `downloads/`.

On narrow screens (phones, small windows) the app switches to a single column: the Menu button opens the sidebar and the page fills the screen. Dragging scrolls, tapping a link opens it, and the Android back button goes back. On phones, hosted sites and downloads live in the app's private data folder.

## The command line

    internet registry [--port N]
    internet serve <name> <directory> [--port N] [--registry host:port]
    internet get <internet://name/path> [--registry host:port] [--out file]
    internet list [--registry host:port]

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

Errors are `ERR <code>` with `400`, `404`, `409`, `413` or `500`. Paths are percent-encoded, so `a b.txt` is sent as `a%20b.txt`.

## Limits

The registry records the address a node connects from, so nodes on the same computer are found at `127.0.0.1`. Reaching a node from another machine needs the registry to see that node's LAN address, which happens when the node runs on that other machine and registers over the network.
