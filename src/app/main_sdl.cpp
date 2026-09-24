#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#if defined(__ANDROID__)
#include <GLES3/gl3.h>
#define INTERNET_MOBILE_GL 1
#elif defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
#define GLES_SILENCE_DEPRECATION
#include <OpenGLES/ES3/gl.h>
#define INTERNET_MOBILE_GL 1
#else
#include <SDL3/SDL_opengl.h>
#endif

#include "app.hpp"
#include "icon.hpp"
#include "platform.hpp"
#include "imgui.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_sdl3.h"
#include "ui.hpp"

namespace {

#ifdef INTERNET_MOBILE_GL
constexpr bool kMobile = true;
#else
constexpr bool kMobile = false;
#endif

void configureGl() {
#ifdef INTERNET_MOBILE_GL
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#elif defined(__APPLE__)
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
#else
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#endif
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
}

const char* glslVersion() {
#ifdef INTERNET_MOBILE_GL
    return "#version 300 es";
#elif defined(__APPLE__)
    return "#version 150";
#else
    return "#version 130";
#endif
}

std::filesystem::path dataDirectory() {
    char* preferences = SDL_GetPrefPath("Internet", "Internet");
    if (!preferences) return std::filesystem::path(".");
    std::filesystem::path path(preferences);
    SDL_free(preferences);
    return path;
}

void applySafeArea(SDL_Window* window, internet::App& app) {
    SDL_Rect safe{};
    int width = 0;
    int height = 0;
    SDL_GetWindowSize(window, &width, &height);
    if (!SDL_GetWindowSafeArea(window, &safe) || safe.w <= 0 || safe.h <= 0) {
        app.setInsets(0, 0, 0, 0);
        return;
    }
    app.setInsets(static_cast<float>(safe.x), static_cast<float>(safe.y),
                  static_cast<float>(width - (safe.x + safe.w)), static_cast<float>(height - (safe.y + safe.h)));
}

}

int main(int, char**) {
    if (!SDL_Init(SDL_INIT_VIDEO)) return 1;

    configureGl();

    float scale = SDL_GetDisplayContentScale(SDL_GetPrimaryDisplay());
    if (scale < 1.0f) scale = 1.0f;

    SDL_WindowFlags flags = SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY;
    SDL_Window* window =
        SDL_CreateWindow("Internet", static_cast<int>(1180 * scale), static_cast<int>(720 * scale), flags);
    if (!window) {
        SDL_Quit();
        return 1;
    }
    SDL_GLContext context = SDL_GL_CreateContext(window);
    if (!context) {
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }
    SDL_GL_MakeCurrent(window, context);
    SDL_GL_SetSwapInterval(1);

    if (!kMobile) {
        std::vector<std::uint8_t> pixels = internet::renderIcon(128, true);
        SDL_Surface* surface = SDL_CreateSurfaceFrom(128, 128, SDL_PIXELFORMAT_RGBA32, pixels.data(), 128 * 4);
        if (surface) {
            SDL_SetWindowIcon(window, surface);
            SDL_DestroySurface(surface);
        }
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    internet::setupUi(scale, kMobile);

    ImGui_ImplSDL3_InitForOpenGL(window, context);
    ImGui_ImplOpenGL3_Init(glslVersion());

    {
        internet::App app(dataDirectory());
        app.setTouchMode(kMobile);
        app.openLink(internet::platform::takeLaunchLink());
        ImGuiIO& io = ImGui::GetIO();

        bool done = false;
        bool paused = false;
        bool textInput = false;
        while (!done) {
            SDL_Event event;
            if (SDL_WaitEventTimeout(&event, 50)) {
                do {
                    ImGui_ImplSDL3_ProcessEvent(&event);
                    if (event.type == SDL_EVENT_QUIT) done = true;
                    if (event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED && event.window.windowID == SDL_GetWindowID(window))
                        done = true;
                    if (event.type == SDL_EVENT_WILL_ENTER_BACKGROUND) paused = true;
                    if (event.type == SDL_EVENT_DID_ENTER_FOREGROUND) {
                        paused = false;
                        app.openLink(internet::platform::takeLaunchLink());
                    }
                    if (event.type == SDL_EVENT_DROP_FILE && event.drop.data != nullptr) {
                        std::string dropped(event.drop.data);
                        if (dropped.rfind("internet://", 0) == 0) app.openLink(dropped);
                    }
                    if (event.type == SDL_EVENT_KEY_DOWN && event.key.key == SDLK_AC_BACK) app.back();
                } while (SDL_PollEvent(&event));
            }
            if (paused || (SDL_GetWindowFlags(window) & SDL_WINDOW_MINIMIZED)) continue;

            applySafeArea(window, app);

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplSDL3_NewFrame();
            ImGui::NewFrame();
            app.draw();
            ImGui::Render();

            if (kMobile && io.WantTextInput != textInput) {
                textInput = io.WantTextInput;
                if (textInput) {
                    SDL_StartTextInput(window);
                } else {
                    SDL_StopTextInput(window);
                }
            }

            int width = 0;
            int height = 0;
            SDL_GetWindowSizeInPixels(window, &width, &height);
            glViewport(0, 0, width, height);
            glClearColor(0.09f, 0.09f, 0.10f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            SDL_GL_SwapWindow(window);
        }
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DestroyContext(context);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
