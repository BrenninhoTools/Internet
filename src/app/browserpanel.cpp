#include <algorithm>
#include <cmath>

#include "app.hpp"
#include "ui.hpp"

namespace internet {

namespace {

const ImVec4 kChromeBlue(0.26f, 0.52f, 0.96f, 1.0f);
const ImVec4 kGood(0.28f, 0.84f, 0.52f, 1.0f);
const ImVec4 kMuted(0.62f, 0.64f, 0.72f, 1.0f);
const ImVec4 kInk(0.03f, 0.04f, 0.09f, 1.0f);
const ImVec4 kSnow(1.0f, 1.0f, 1.0f, 1.0f);
const ImVec4 kAlert(1.0f, 0.42f, 0.42f, 1.0f);

constexpr std::uint16_t kGatewayPort = 8080;

}

bool App::ensureGateway() {
    if (gateway_ && gateway_->running()) return true;
    auto created = std::make_unique<Gateway>();
    created->setRegistry(registryEndpoint());
    created->setSecurity(security_.get());
    created->setFirewall(&firewall_);
    created->setAllowScripts(settings_.browserScripts);
    created->setLoopbackOnly(true);
    try {
        created->start(kGatewayPort);
    } catch (const std::exception&) {
        try {
            created->start(0);
        } catch (const std::exception& error) {
            toast(std::string("Cannot start the browser gateway: ") + error.what(), ToastKind::Error);
            return false;
        }
    }
    gateway_ = std::move(created);
    return true;
}

std::string App::browserTarget() const {
    if (securityView_) return std::string();
    if (editor_) return ed_.siteName.empty() ? std::string() : editorLiveUrl(ed_.current);
    if (!home_ && isInternetUrl(currentUrl_)) return currentUrl_;
    return std::string();
}

void App::openInBrowser(const std::string& internetUrl) {
    if (!browserSupported()) {
        toast("Opening a browser is not available on this device", ToastKind::Warning);
        return;
    }
    if (!ensureGateway()) return;
    std::string url = internetUrl.empty() ? gateway_->indexUrl() : gateway_->urlFor(internetUrl);
    bool chrome = !findChrome().empty();
    if (openInChrome(url)) {
        toast(chrome ? "Opened in Chrome" : "Chrome was not found, opened your default browser", chrome ? ToastKind::Success : ToastKind::Warning);
    } else {
        ImGui::SetClipboardText(url.c_str());
        toast("Could not start a browser. The address was copied.", ToastKind::Error);
    }
}

void App::copyGatewayAddress() {
    if (!ensureGateway()) return;
    std::string target = browserTarget();
    std::string url = target.empty() ? gateway_->indexUrl() : gateway_->urlFor(target);
    ImGui::SetClipboardText(url.c_str());
    toast("Browser address copied", ToastKind::Success);
}

void App::toggleLinkRegistration() {
    std::string exe = executablePath();
    if (linksRegistered_) {
        unregisterUrlHandler();
        toast("internet:// links are no longer handled by this app");
    } else {
        std::string problem;
        if (registerUrlHandler(exe, problem)) {
            toast("internet:// links now open in this app", ToastKind::Success);
        } else {
            toast(problem, ToastKind::Error);
        }
    }
    linksRegistered_ = urlHandlerRegistered(exe);
    browserPolled_ = time_;
}

void App::pollBrowser() {
    if (!chromeChecked_) {
        chromePath_ = findChrome();
        linksRegistered_ = urlHandlerRegistered(executablePath());
        chromeChecked_ = true;
        browserPolled_ = time_;
    }
    if (time_ - browserPolled_ < 1.0) return;
    browserPolled_ = time_;
    if (gateway_ && gateway_->running()) {
        gateway_->setRegistry(registryEndpoint());
        gateway_->setAllowScripts(settings_.browserScripts);
    }
    linksRegistered_ = urlHandlerRegistered(executablePath());
}

void App::drawBrowserPanel(float width) {
    if (!browserSupported()) return;
    float unit = ImGui::GetFontSize();
    ImDrawList* list = ImGui::GetWindowDrawList();
    float time = settings_.animations ? static_cast<float>(time_) : 0.0f;
    bool live = gateway_ && gateway_->running();
    bool narrow = compact_ || width < unit * 46.0f;

    struct Chip {
        std::string label;
        ImVec4 tint;
    };
    std::vector<Chip> chips = {
        {chromePath_.empty() ? "Chrome not found" : "Chrome found", chromePath_.empty() ? kAlert : kGood},
        {live ? "Gateway " + std::to_string(gateway_->port()) + ", " + std::to_string(gateway_->requests()) + " requests"
              : "Gateway starts on demand",
         live ? kGood : kMuted},
        {settings_.browserScripts ? "Scripts allowed" : "Scripts blocked", settings_.browserScripts ? kAlert : kGood},
        {linksRegistered_ ? "Links registered" : "Links not registered", linksRegistered_ ? kGood : kMuted},
    };
    float chipSize = unit * 0.82f;
    float chipHeight = unit * 1.5f;
    float pad = unit * 1.0f;
    int rows = 1;
    float cursor = pad;
    for (const Chip& chip : chips) {
        float w = textWidth(chipSize, chip.label) + unit * 1.3f;
        if (cursor + w > width - pad && cursor > pad) {
            ++rows;
            cursor = pad;
        }
        cursor += w + unit * 0.5f;
    }
    float frame = ImGui::GetFrameHeight();
    bool links = urlHandlerSupported();
    float buttonWidths = textWidth(ImGui::GetFontSize(), "Open this page in Chrome") + textWidth(ImGui::GetFontSize(), "Copy address") +
                         (links ? textWidth(ImGui::GetFontSize(), "Register internet:// links") : 0.0f) + unit * 11.0f;
    int buttonRows = buttonWidths + pad * 2.0f > width ? (narrow ? 3 : 2) : 1;
    float chipsTop = unit * 4.0f;
    float buttonsTop = chipsTop + static_cast<float>(rows) * (chipHeight + unit * 0.3f) + unit * 0.5f;
    float height = buttonsTop + static_cast<float>(buttonRows) * (frame + unit * 0.4f) + unit * 0.5f;

    sectionTitle("Browser", kChromeBlue);
    ImVec2 origin = ImGui::GetCursorScreenPos();
    ImVec2 end(origin.x + width, origin.y + height);
    list->AddRectFilled(origin, end, packColor(mixColor(kInk, kChromeBlue, 0.16f)), unit * 0.9f);
    list->AddRect(origin, end, packColor(withAlpha(kChromeBlue, 0.55f)), unit * 0.9f, ImDrawFlags_None, 1.5f);

    ImVec2 badge(origin.x + unit * 2.4f, origin.y + unit * 2.2f);
    float pulse = 0.5f + 0.5f * std::sin(time * 2.0f);
    if (live) list->AddCircleFilled(badge, unit * (1.7f + 0.18f * pulse), packColor(withAlpha(kChromeBlue, 0.2f)), 32);
    list->AddCircleFilled(badge, unit * 1.4f, packColor(kChromeBlue), 32);
    list->AddCircleFilled(badge, unit * 0.62f, IM_COL32(255, 255, 255, 255), 24);
    list->AddCircleFilled(badge, unit * 0.36f, packColor(kChromeBlue), 20);

    float textX = origin.x + unit * 4.7f;
    float limit = width - unit * 5.4f;
    drawText(list, unit * 1.3f, ImVec2(textX, origin.y + unit * 0.8f), IM_COL32(255, 255, 255, 255),
             fitText("Use Internet in Chrome", unit * 1.3f, limit).c_str());
    std::string line = live ? "Gateway on " + gateway_->indexUrl() : "Sites open at http://name.localhost, checked by the antivirus first";
    drawText(list, unit * 0.9f, ImVec2(textX, origin.y + unit * 2.4f), packColor(kMuted), fitText(line, unit * 0.9f, limit).c_str());

    float chipX = origin.x + pad;
    float chipY = origin.y + chipsTop;
    for (const Chip& chip : chips) {
        float w = textWidth(chipSize, chip.label) + unit * 1.3f;
        if (chipX + w > end.x - pad && chipX > origin.x + pad) {
            chipX = origin.x + pad;
            chipY += chipHeight + unit * 0.3f;
        }
        list->AddRectFilled(ImVec2(chipX, chipY), ImVec2(chipX + w, chipY + chipHeight), packColor(withAlpha(chip.tint, 0.22f)), chipHeight * 0.5f);
        list->AddCircleFilled(ImVec2(chipX + unit * 0.62f, chipY + chipHeight * 0.5f), unit * 0.2f, packColor(chip.tint), 12);
        drawText(list, chipSize, ImVec2(chipX + unit * 1.05f, chipY + (chipHeight - chipSize) * 0.5f), IM_COL32(255, 255, 255, 255), chip.label.c_str());
        chipX += w + unit * 0.5f;
    }

    std::string target = browserTarget();
    ImGui::SetCursorScreenPos(ImVec2(origin.x + pad, origin.y + buttonsTop));
    if (textButton("browser-open", target.empty() ? "Open the gateway" : "Open this page in Chrome", Icon::External, true)) openInBrowser(target);
    if (buttonRows == 1) {
        ImGui::SameLine();
    } else {
        ImGui::SetCursorScreenPos(ImVec2(origin.x + pad, origin.y + buttonsTop + frame + unit * 0.4f));
    }
    if (textButton("browser-copy", "Copy address", Icon::Copy, false)) copyGatewayAddress();
    if (links) {
        if (buttonRows == 3) {
            ImGui::SetCursorScreenPos(ImVec2(origin.x + pad, origin.y + buttonsTop + 2.0f * (frame + unit * 0.4f)));
        } else {
            ImGui::SameLine();
        }
        if (textButton("browser-links", linksRegistered_ ? "Unregister links" : "Register internet:// links", Icon::Check, false)) toggleLinkRegistration();
    }
    ImGui::SetCursorScreenPos(ImVec2(origin.x, end.y));
    ImGui::Dummy(ImVec2(width, unit * 0.6f));
}

void App::drawBrowserSidebar(float width) {
    if (!browserSupported()) return;
    ImGui::TextColored(kMuted, chromePath_.empty() ? "Chrome was not found" : "Chrome is installed");
    if (gateway_ && gateway_->running()) {
        ImGui::TextColored(kGood, "Gateway on port %d", static_cast<int>(gateway_->port()));
        ImGui::TextColored(kMuted, "%llu requests", static_cast<unsigned long long>(gateway_->requests()));
    } else {
        ImGui::TextColored(kMuted, "Gateway starts on demand");
    }
    std::string target = browserTarget();
    if (ImGui::Button(target.empty() ? "Open the gateway" : "Open this page in Chrome", ImVec2(width, 0))) openInBrowser(target);
    if (ImGui::Button("Copy browser address", ImVec2(width, 0))) copyGatewayAddress();
    if (ImGui::Checkbox("Allow scripts in Chrome", &settings_.browserScripts)) {
        settingsDirty_ = true;
        if (gateway_) gateway_->setAllowScripts(settings_.browserScripts);
    }
    if (settings_.browserScripts) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(kAlert, "Sites can run code in your browser. Turn this on only for sites you trust.");
        ImGui::PopTextWrapPos();
    }
    if (urlHandlerSupported()) {
        if (ImGui::Button(linksRegistered_ ? "Unregister internet:// links" : "Register internet:// links", ImVec2(width, 0))) toggleLinkRegistration();
    }
}

}
