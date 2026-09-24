#ifdef __APPLE__
#define GL_SILENCE_DEPRECATION
#endif

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include <GLFW/glfw3.h>

#include "app.hpp"
#include "icon.hpp"
#include "storage.hpp"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "ui.hpp"

int main(int argc, char** argv) {
    if (!glfwInit()) return 1;

#ifdef __APPLE__
    const char* glsl = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
#else
    const char* glsl = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif

    GLFWwindow* window = glfwCreateWindow(1180, 720, "Internet", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

#ifndef __APPLE__
    std::vector<std::uint8_t> small = internet::renderIcon(48, true);
    std::vector<std::uint8_t> large = internet::renderIcon(128, true);
    GLFWimage icons[2] = {{48, 48, small.data()}, {128, 128, large.data()}};
    glfwSetWindowIcon(window, 2, icons);
#endif

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    float scale = 1.0f;
#ifndef __APPLE__
    float scaleY = 1.0f;
    glfwGetWindowContentScale(window, &scale, &scaleY);
    if (scale < 1.0f) scale = 1.0f;
#endif
    internet::setupUi(scale, false);

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl);

    {
        internet::App app(internet::userDataDirectory());
        std::string link;
        std::string scanTarget;
        int securityTab = -1;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--registry" && i + 1 < argc) {
                app.setRegistry(argv[++i]);
            } else if (arg == "--security") {
                securityTab = 0;
                if (i + 1 < argc && std::string(argv[i + 1]).find_first_not_of("0123456789") == std::string::npos) securityTab = std::atoi(argv[++i]);
            } else if (arg == "--scan" && i + 1 < argc) {
                scanTarget = argv[++i];
            } else if (arg.rfind("internet://", 0) == 0) {
                link = arg;
            }
        }
        if (!link.empty()) app.openLink(link);
        if (!scanTarget.empty()) app.scanFolder(scanTarget);
        if (securityTab >= 0) app.showSecurity(securityTab);
        while (!glfwWindowShouldClose(window)) {
            glfwWaitEventsTimeout(0.05);

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();
            app.draw();
            ImGui::Render();

            int width = 0;
            int height = 0;
            glfwGetFramebufferSize(window, &width, &height);
            glViewport(0, 0, width, height);
            glClearColor(0.09f, 0.09f, 0.10f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            glfwSwapBuffers(window);
        }
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
