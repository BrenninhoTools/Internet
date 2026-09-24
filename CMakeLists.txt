cmake_minimum_required(VERSION 3.20)
project(Internet VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(INTERNET_MOBILE OFF)
if(ANDROID OR IOS)
    set(INTERNET_MOBILE ON)
endif()

if(INTERNET_MOBILE)
    set(INTERNET_DEFAULT_BACKEND SDL)
else()
    set(INTERNET_DEFAULT_BACKEND GLFW)
endif()

option(INTERNET_BUILD_APP "Build the graphical Internet app" ON)
option(INTERNET_BUILD_TESTS "Build the test suite" ON)
option(INTERNET_BUILD_TOOLS "Build the icon generator" OFF)
set(INTERNET_APP_BACKEND ${INTERNET_DEFAULT_BACKEND} CACHE STRING "Window backend for the app: GLFW or SDL")
set(INTERNET_SDL_DIR "" CACHE PATH "Use this SDL3 source tree instead of downloading one")

if(WIN32)
    enable_language(RC)
endif()

find_package(Threads REQUIRED)


add_library(internet_core STATIC
    src/core/socket.cpp
    src/core/protocol.cpp
    src/core/server.cpp
    src/core/registry.cpp
    src/core/node.cpp
    src/core/client.cpp
    src/core/markup.cpp
)
target_include_directories(internet_core PUBLIC src/core)
target_link_libraries(internet_core PUBLIC Threads::Threads)
if(WIN32)
    target_link_libraries(internet_core PUBLIC ws2_32)
endif()
if(MSVC)
    target_compile_options(internet_core PRIVATE /W4 /utf-8)
else()
    target_compile_options(internet_core PRIVATE -Wall -Wextra)
endif()

if(NOT INTERNET_MOBILE)
    set(INTERNET_CLI_SOURCES src/cli/main.cpp)
    if(WIN32)
        list(APPEND INTERNET_CLI_SOURCES windows/internet.rc)
    endif()
    add_executable(internet ${INTERNET_CLI_SOURCES})
    target_link_libraries(internet PRIVATE internet_core)
    install(TARGETS internet RUNTIME DESTINATION bin)

    if(INTERNET_BUILD_TESTS)
        enable_testing()
        add_executable(internet-tests tests/tests.cpp)
        target_link_libraries(internet-tests PRIVATE internet_core)
        add_test(NAME internet-tests COMMAND internet-tests)
    endif()

    if(INTERNET_BUILD_TOOLS)
        add_executable(internet-icons tools/generate_icons.cpp src/app/icon.cpp)
        target_include_directories(internet-icons PRIVATE src/app)
    endif()
endif()

if(INTERNET_BUILD_APP)
    include(FetchContent)

    FetchContent_Declare(imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG v1.91.9b
        GIT_SHALLOW TRUE
    )

    if(INTERNET_APP_BACKEND STREQUAL "SDL")
        set(SDL_TESTS OFF CACHE BOOL "" FORCE)
        set(SDL_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(SDL_INSTALL OFF CACHE BOOL "" FORCE)
        set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
        if(ANDROID)
            set(SDL_SHARED ON CACHE BOOL "" FORCE)
            set(SDL_STATIC OFF CACHE BOOL "" FORCE)
        else()
            set(SDL_SHARED OFF CACHE BOOL "" FORCE)
            set(SDL_STATIC ON CACHE BOOL "" FORCE)
        endif()
        if(INTERNET_SDL_DIR)
            add_subdirectory(${INTERNET_SDL_DIR} sdl EXCLUDE_FROM_ALL)
            FetchContent_MakeAvailable(imgui)
        else()
            FetchContent_Declare(SDL3
                GIT_REPOSITORY https://github.com/libsdl-org/SDL.git
                GIT_TAG release-3.2.30
                GIT_SHALLOW TRUE
            )
            FetchContent_MakeAvailable(SDL3 imgui)
        endif()
    else()
        set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
        set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
        if(UNIX AND NOT APPLE)
            set(GLFW_BUILD_WAYLAND OFF CACHE BOOL "" FORCE)
        endif()
        FetchContent_Declare(glfw
            GIT_REPOSITORY https://github.com/glfw/glfw.git
            GIT_TAG 3.4
            GIT_SHALLOW TRUE
        )
        FetchContent_MakeAvailable(glfw imgui)
    endif()

    set(INTERNET_FONT_SOURCE ${imgui_SOURCE_DIR}/misc/fonts/Roboto-Medium.ttf)
    set(INTERNET_FONT_CPP ${CMAKE_BINARY_DIR}/generated/font_data.cpp)
    if(NOT EXISTS ${INTERNET_FONT_CPP})
        file(READ ${INTERNET_FONT_SOURCE} INTERNET_FONT_HEX HEX)
        string(LENGTH "${INTERNET_FONT_HEX}" INTERNET_FONT_HEX_LENGTH)
        math(EXPR INTERNET_FONT_BYTES "${INTERNET_FONT_HEX_LENGTH} / 2")
        string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," INTERNET_FONT_ARRAY "${INTERNET_FONT_HEX}")
        file(WRITE ${INTERNET_FONT_CPP}
            "namespace internet {\nextern const unsigned char kFontData[] = {${INTERNET_FONT_ARRAY}};\nextern const unsigned long kFontSize = ${INTERNET_FONT_BYTES};\n}\n")
    endif()

    set(INTERNET_IMGUI_SOURCES
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
    )
    if(INTERNET_APP_BACKEND STREQUAL "SDL")
        list(APPEND INTERNET_IMGUI_SOURCES ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl3.cpp)
    else()
        list(APPEND INTERNET_IMGUI_SOURCES ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp)
    endif()

    add_library(imgui_backend STATIC ${INTERNET_IMGUI_SOURCES})
    target_include_directories(imgui_backend PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends)
    if(INTERNET_APP_BACKEND STREQUAL "SDL")
        target_link_libraries(imgui_backend PUBLIC SDL3::SDL3)
    else()
        target_link_libraries(imgui_backend PUBLIC glfw)
    endif()
    if(ANDROID)
        target_compile_definitions(imgui_backend PUBLIC IMGUI_IMPL_OPENGL_ES3)
        target_link_libraries(imgui_backend PUBLIC GLESv3 EGL log android)
    elseif(IOS)
        target_compile_definitions(imgui_backend PUBLIC IMGUI_IMPL_OPENGL_ES3)
        target_link_libraries(imgui_backend PUBLIC "-framework OpenGLES")
    else()
        find_package(OpenGL REQUIRED)
        target_link_libraries(imgui_backend PUBLIC OpenGL::GL)
    endif()

    set(INTERNET_APP_SOURCES
        src/app/app.cpp
        src/app/ui.cpp
        src/app/icon.cpp
        ${INTERNET_FONT_CPP}
    )
    if(INTERNET_APP_BACKEND STREQUAL "SDL")
        list(APPEND INTERNET_APP_SOURCES src/app/main_sdl.cpp)
    else()
        list(APPEND INTERNET_APP_SOURCES src/app/main.cpp)
    endif()

    if(WIN32)
        list(APPEND INTERNET_APP_SOURCES windows/internet.rc)
    endif()

    if(ANDROID)
        add_library(internet-app SHARED ${INTERNET_APP_SOURCES})
        set_target_properties(internet-app PROPERTIES OUTPUT_NAME main)
    elseif(IOS)
        file(GLOB INTERNET_IOS_ICONS ${CMAKE_SOURCE_DIR}/ios/icons/*.png)
        set_source_files_properties(${INTERNET_IOS_ICONS} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
        add_executable(internet-app MACOSX_BUNDLE ${INTERNET_APP_SOURCES} ${INTERNET_IOS_ICONS})
        set_target_properties(internet-app PROPERTIES
            MACOSX_BUNDLE_INFO_PLIST ${CMAKE_SOURCE_DIR}/ios/Info.plist
            XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER com.internet.app
            XCODE_ATTRIBUTE_PRODUCT_NAME Internet
            XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
            XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET 13.0
        )
    elseif(APPLE)
        set(INTERNET_MAC_ICON ${CMAKE_SOURCE_DIR}/assets/icons/internet.icns)
        set_source_files_properties(${INTERNET_MAC_ICON} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
        add_executable(internet-app MACOSX_BUNDLE ${INTERNET_APP_SOURCES} ${INTERNET_MAC_ICON})
        set_target_properties(internet-app PROPERTIES
            OUTPUT_NAME "Internet"
            MACOSX_BUNDLE_BUNDLE_NAME "Internet"
            MACOSX_BUNDLE_GUI_IDENTIFIER "com.internet.app"
            MACOSX_BUNDLE_ICON_FILE "internet.icns"
            MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION}
            MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
        )
    else()
        add_executable(internet-app ${INTERNET_APP_SOURCES})
    endif()

    target_include_directories(internet-app PRIVATE src/app)
    target_link_libraries(internet-app PRIVATE internet_core imgui_backend)

    if(MSVC)
        target_compile_options(internet-app PRIVATE /W4 /utf-8)
        if(INTERNET_APP_BACKEND STREQUAL "GLFW")
            target_link_options(internet-app PRIVATE /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup)
        endif()
    elseif(WIN32 AND INTERNET_APP_BACKEND STREQUAL "GLFW")
        target_link_options(internet-app PRIVATE -mwindows)
    endif()

    if(NOT INTERNET_MOBILE)
        install(TARGETS internet-app BUNDLE DESTINATION . RUNTIME DESTINATION bin)
    endif()
endif()

if(NOT INTERNET_MOBILE)
    install(DIRECTORY sites/ DESTINATION share/internet/sites)

    if(WIN32 OR APPLE)
        set(CPACK_GENERATOR ZIP)
    else()
        set(CPACK_GENERATOR TGZ)
    endif()
    set(CPACK_PACKAGE_NAME "Internet")
    set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
    include(CPack)
endif()
