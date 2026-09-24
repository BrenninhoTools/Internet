cmake_minimum_required(VERSION 3.20)
project(Internet VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(INTERNET_BUILD_APP "Build the graphical Internet app" ON)
option(INTERNET_BUILD_TESTS "Build the test suite" ON)

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

add_executable(internet src/cli/main.cpp)
target_link_libraries(internet PRIVATE internet_core)
install(TARGETS internet RUNTIME DESTINATION bin)

if(INTERNET_BUILD_TESTS)
    enable_testing()
    add_executable(internet-tests tests/tests.cpp)
    target_link_libraries(internet-tests PRIVATE internet_core)
    add_test(NAME internet-tests COMMAND internet-tests)
endif()

if(INTERNET_BUILD_APP)
    include(FetchContent)
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
    FetchContent_Declare(imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG v1.91.9b
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(glfw imgui)

    find_package(OpenGL REQUIRED)

    add_library(imgui_glfw_opengl3 STATIC
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
    )
    target_include_directories(imgui_glfw_opengl3 PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends)
    target_link_libraries(imgui_glfw_opengl3 PUBLIC glfw OpenGL::GL)

    add_executable(internet-app src/app/main.cpp src/app/app.cpp)
    target_include_directories(internet-app PRIVATE src/app)
    target_link_libraries(internet-app PRIVATE internet_core imgui_glfw_opengl3)
    if(MSVC)
        target_compile_options(internet-app PRIVATE /W4 /utf-8)
        target_link_options(internet-app PRIVATE /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup)
    elseif(WIN32)
        target_link_options(internet-app PRIVATE -mwindows)
    endif()
    if(APPLE)
        set_target_properties(internet-app PROPERTIES MACOSX_BUNDLE TRUE OUTPUT_NAME "Internet")
    endif()
    install(TARGETS internet-app BUNDLE DESTINATION . RUNTIME DESTINATION bin)
endif()

install(DIRECTORY sites/ DESTINATION share/internet/sites)

if(WIN32 OR APPLE)
    set(CPACK_GENERATOR ZIP)
else()
    set(CPACK_GENERATOR TGZ)
endif()
set(CPACK_PACKAGE_NAME "Internet")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
include(CPack)
