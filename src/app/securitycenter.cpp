#include <algorithm>
#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <thread>

#include "app.hpp"
#include "ui.hpp"

namespace fs = std::filesystem;

namespace internet {

namespace {

const ImVec4 kDanger(0.95f, 0.30f, 0.34f, 1.0f);
const ImVec4 kWarn(1.0f, 0.74f, 0.20f, 1.0f);
const ImVec4 kSafe(0.28f, 0.84f, 0.52f, 1.0f);
const ImVec4 kDim(0.62f, 0.64f, 0.72f, 1.0f);
const ImVec4 kWhite(1.0f, 1.0f, 1.0f, 1.0f);
const ImVec4 kNavy(0.03f, 0.04f, 0.09f, 1.0f);

void copyBuffer(char* target, std::size_t size, const std::string& text) {
    std::snprintf(target, size, "%s", text.c_str());
}

ImVec4 verdictColor(Verdict verdict) {
    switch (verdict) {
        case Verdict::Malicious: return kDanger;
        case Verdict::Suspicious: return kWarn;
        case Verdict::Unscannable: return kDim;
        default: return kSafe;
    }
}

std::string formatBytes(std::uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }
    char buffer[32];
    std::snprintf(buffer, sizeof buffer, unit == 0 ? "%.0f %s" : "%.1f %s", value, units[unit]);
    return buffer;
}

std::string formatClock(std::int64_t seconds) {
    std::time_t time = static_cast<std::time_t>(seconds);
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &time);
#else
    localtime_r(&time, &local);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof buffer, "%d/%m %H:%M", &local);
    return buffer;
}

std::string readFile(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

}

ThreatInfo App::makeThreat(const ScanResult& result) const {
    ThreatInfo info;
    info.verdict = result.verdict;
    info.score = result.score;
    info.sha256 = result.sha256;
    info.note = result.note;
    info.findings = result.findings;
    return info;
}

SecurityState App::securityState() const {
    if (scan_ && !scan_->done) return SecurityState::Scanning;
    if (blocked_ && !blockOverride_) return SecurityState::Danger;
    for (const ScanRecord& record : scanRecords_) {
        if (record.result.verdict == Verdict::Malicious && record.action != "quarantined") return SecurityState::Danger;
    }
    if (!security_->settings().realtime) return SecurityState::Attention;
    for (const ScanRecord& record : scanRecords_) {
        if (record.result.verdict == Verdict::Suspicious) return SecurityState::Attention;
    }
    if (threat_.verdict == Verdict::Suspicious) return SecurityState::Attention;
    return SecurityState::Protected;
}

ImVec4 App::stateColor(SecurityState state) const {
    switch (state) {
        case SecurityState::Danger: return kDanger;
        case SecurityState::Attention: return kWarn;
        case SecurityState::Scanning: return palette().secondary;
        default: return kSafe;
    }
}

const char* App::stateText(SecurityState state) const {
    switch (state) {
        case SecurityState::Danger: return "Threats need your attention";
        case SecurityState::Attention: return "Protection needs attention";
        case SecurityState::Scanning: return "Scanning...";
        default: return "You are protected";
    }
}

void App::openSecurity(int tab) {
    securityView_ = true;
    editor_ = false;
    menuOpen_ = false;
    securityTab_ = std::clamp(tab, 0, 4);
    pageFade_ = 0.0f;
    quarantineRefreshed_ = -100.0;
    eventsRefreshed_ = -100.0;
}

void App::closeSecurity() { securityView_ = false; }

void App::applyFirewallSettings() {
    FirewallConfig config = firewall_.config();
    config.enabled = security_->settings().firewall;
    firewall_.setConfig(config);
}

void App::startScan(const std::vector<fs::path>& roots, const std::string& label) {
    if (scan_ && !scan_->done) {
        toast("A scan is already running", ToastKind::Warning);
        return;
    }
    if (scanThread_.joinable()) scanThread_.join();
    scanLabel_ = label;
    scanRecords_.clear();
    scan_ = std::make_unique<ScanProgress>();
    ScanProgress* progress = scan_.get();
    std::shared_ptr<Security> security = security_;
    scanThread_ = std::thread([security, roots, progress] { security->scanTree(roots, "scan", *progress); });
    toast("Scan started: " + label, ToastKind::Info);
}

void App::finishScan() {
    if (scanThread_.joinable()) scanThread_.join();
    if (!scan_) return;
    std::uint64_t malicious = scan_->malicious;
    std::uint64_t suspicious = scan_->suspicious;
    {
        std::lock_guard<std::mutex> lock(scan_->mutex);
        scanRecords_ = scan_->records;
    }
    quarantineRefreshed_ = -100.0;
    eventsRefreshed_ = -100.0;
    if (malicious == 0 && suspicious == 0) {
        toast("Scan finished: no threats found in " + std::to_string(scan_->files.load()) + " files", ToastKind::Success);
    } else {
        toast("Scan finished: " + std::to_string(malicious) + " dangerous, " + std::to_string(suspicious) + " suspicious",
              malicious > 0 ? ToastKind::Error : ToastKind::Warning);
    }
}

void App::updateDefinitions(const std::string& source) {
    if (definitionsJob_ && !definitionsJob_->done) return;
    Endpoint registry;
    try {
        registry = registryEndpoint();
    } catch (const std::exception&) {
    }
    std::shared_ptr<Security> security = security_;
    definitionsMessage_ = "Updating...";
    definitionsJob_ = std::make_shared<Job<std::string>>();
    auto job = definitionsJob_;
    std::thread([job, security, registry, source] {
        std::string outcome;
        try {
            std::string text = isInternetUrl(source) ? fetch(registry, source).body : readFile(fs::path(source));
            std::string error;
            if (text.empty()) {
                outcome = "error: the source is empty or unreadable";
            } else if (security->updateDefinitions(text, error)) {
                outcome = "Definitions " + security->definitionsVersion() + ", " + std::to_string(security->ruleCount()) + " rules";
            } else {
                outcome = "error: " + error;
            }
        } catch (const std::exception& problem) {
            outcome = std::string("error: ") + problem.what();
        }
        job->result = std::move(outcome);
        job->done = true;
    }).detach();
}

void App::pollSecurity() {
    if (scan_ && scanThread_.joinable() && scan_->done) finishScan();
    if (scan_ && !scan_->done) {
        std::lock_guard<std::mutex> lock(scan_->mutex);
        scanRecords_ = scan_->records;
    }
    if (definitionsJob_ && definitionsJob_->done) {
        const std::string& outcome = definitionsJob_->result;
        definitionsMessage_ = outcome;
        bool failed = outcome.rfind("error", 0) == 0;
        toast(failed ? "Definitions update failed" : "Definitions updated", failed ? ToastKind::Error : ToastKind::Success);
        definitionsJob_.reset();
    }
    std::string notice;
    {
        std::lock_guard<std::mutex> lock(firewallMutex_);
        notice.swap(pendingFirewallNotice_);
    }
    if (!notice.empty()) toast("Firewall: " + notice, ToastKind::Warning);
}

bool App::toggleSwitch(const char* id, bool* value) {
    float unit = ImGui::GetFontSize();
    ImVec2 size(unit * 2.6f, unit * 1.4f);
    ImVec2 position = ImGui::GetCursorScreenPos();
    ImGui::PushID(id);
    bool pressed = ImGui::InvisibleButton("##toggle", size);
    bool hovered = ImGui::IsItemHovered();
    ImGui::PopID();
    if (pressed) *value = !*value;
    float& knob = hover_[std::string("toggle:") + id];
    approach(knob, *value ? 1.0f : 0.0f, 16.0f, dt_);
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec4 off(0.22f, 0.25f, 0.34f, 1.0f);
    ImVec4 on = mixColor(palette().primary, kSafe, 0.55f);
    list->AddRectFilled(position, ImVec2(position.x + size.x, position.y + size.y), ImGui::GetColorU32(mixColor(off, on, knob)), size.y * 0.5f);
    float radius = size.y * (hovered ? 0.44f : 0.4f);
    float x = position.x + size.y * 0.5f + (size.x - size.y) * knob;
    list->AddCircleFilled(ImVec2(x, position.y + size.y * 0.5f), radius, IM_COL32(255, 255, 255, 255), 20);
    return pressed;
}

void App::drawStatCard(const char* id, const char* label, const std::string& value, Icon icon, const ImVec4& tint, ImVec2 size) {
    float unit = ImGui::GetFontSize();
    CardState state = card(std::string("stat:") + id, size, tint, false);
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 badge(state.min.x + unit * 1.6f, state.min.y + size.y * 0.5f);
    list->AddCircleFilled(badge, unit * 1.0f, packColor(withAlpha(tint, 0.9f)), 24);
    drawIcon(list, icon, badge, unit * 1.2f, IM_COL32(255, 255, 255, 255));
    drawText(list, unit * 1.7f, ImVec2(state.min.x + unit * 3.2f, state.min.y + unit * 0.7f), IM_COL32(255, 255, 255, 255), value.c_str());
    drawText(list, unit * 0.85f, ImVec2(state.min.x + unit * 3.2f, state.min.y + size.y - unit * 1.6f), packColor(kDim), label);
}

void App::drawSecurity() {
    touchScroll();
    float unit = ImGui::GetFontSize();
    float width = ImGui::GetContentRegionAvail().x;
    ImDrawList* list = ImGui::GetWindowDrawList();
    SecurityState state = securityState();
    ImVec4 tint = stateColor(state);
    float time = settings_.animations ? static_cast<float>(time_) : 0.0f;
    SecuritySettings settings = security_->settings();

    ImVec2 origin = ImGui::GetCursorScreenPos();
    float heroHeight = compact_ ? unit * 11.0f : unit * 9.0f;
    ImVec2 max(origin.x + width, origin.y + heroHeight);
    const int strips = 36;
    ImVec4 left = mixColor(kNavy, tint, 0.34f);
    ImVec4 right = mixColor(kNavy, palette().primary, 0.42f);
    for (int i = 0; i < strips; ++i) {
        float t0 = static_cast<float>(i) / strips;
        float t1 = static_cast<float>(i + 1) / strips;
        ImDrawFlags flags = ImDrawFlags_RoundCornersNone;
        if (i == 0) flags = ImDrawFlags_RoundCornersLeft;
        if (i == strips - 1) flags = ImDrawFlags_RoundCornersRight;
        list->AddRectFilled(ImVec2(origin.x + width * t0 - (i > 0 ? 0.6f : 0.0f), origin.y),
                            ImVec2(origin.x + width * t1 + (i < strips - 1 ? 0.6f : 0.0f), max.y),
                            packColor(mixColor(left, right, (t0 + t1) * 0.5f)), unit, flags);
    }
    list->PushClipRect(origin, max, true);
    if (settings_.animations) particles_.draw(list, origin, ImVec2(width, heroHeight), packColor(withAlpha(kWhite, 1.0f)), unit * 6.0f, 0.28f);
    list->PopClipRect();

    float pulse = 0.5f + 0.5f * std::sin(time * 2.4f);
    int mark = state == SecurityState::Protected ? 0 : (state == SecurityState::Danger ? 2 : (state == SecurityState::Scanning ? 3 : 1));
    float shieldSize = unit * 5.6f;
    ImVec2 shieldCenter(origin.x + unit * 4.6f, origin.y + heroHeight * 0.5f);
    drawShield(list, shieldCenter, shieldSize, packColor(tint), pulse, mark, time);

    float textX = origin.x + unit * 9.2f;
    float textLimit = width - unit * 10.0f;
    drawText(list, unit * 2.0f, ImVec2(textX, origin.y + unit * 1.5f), IM_COL32(255, 255, 255, 255),
             fitText(stateText(state), unit * 2.0f, textLimit).c_str());
    std::string detail = settings.realtime ? "Real-time protection is on" : "Real-time protection is off";
    detail += " - definitions " + security_->definitionsVersion() + ", " + std::to_string(security_->ruleCount()) + " rules";
    drawText(list, unit * 0.95f, ImVec2(textX, origin.y + unit * 4.0f), packColor(ImVec4(0.9f, 0.93f, 1.0f, 0.85f)),
             fitText(detail, unit * 0.95f, textLimit).c_str());
    ImGui::Dummy(ImVec2(width, heroHeight));

    ImGui::Dummy(ImVec2(0, unit * 0.2f));
    bool scanning = scan_ && !scan_->done;
    if (textButton("sec-quick", scanning ? "Scanning..." : "Quick scan", Icon::Search, true) && !scanning) {
        std::vector<fs::path> roots = {fs::path(nodeFolder_)};
        fs::path downloads = dataDir_ / "downloads";
        std::error_code error;
        if (fs::exists(downloads, error)) roots.push_back(downloads);
        startScan(roots, "site folder and downloads");
        securityTab_ = 1;
    }
    ImGui::SameLine();
    if (textButton("sec-self", "Test protection", Icon::Bug, false)) {
        ScanResult result = security_->scanBuffer("self-test.txt", std::string("INTERNET-AV-TEST-") + "MARKER-7f3a9c", "self-test");
        toast(result.verdict == Verdict::Malicious ? "Protection engine is working: test threat detected" : "The engine did not detect the test threat",
              result.verdict == Verdict::Malicious ? ToastKind::Success : ToastKind::Error);
        eventsRefreshed_ = -100.0;
    }
    ImGui::Dummy(ImVec2(0, unit * 0.3f));

    const char* names[] = {"Overview", "Scan", "Quarantine", "Firewall", "Settings"};
    float gap = ImGui::GetStyle().ItemSpacing.x;
    float pillHeight = ImGui::GetFrameHeight();
    for (int i = 0; i < 5; ++i) {
        std::string label = names[i];
        if (i == 2 && !quarantineCache_.empty()) label += " (" + std::to_string(quarantineCache_.size()) + ")";
        float w = textWidth(unit, label) + unit * 1.8f;
        if (i > 0) {
            float remaining = ImGui::GetContentRegionAvail().x - gap;
            (void)remaining;
            if (ImGui::GetItemRectMax().x + gap + w < ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x) ImGui::SameLine(0.0f, gap);
        }
        ImGui::PushID(i);
        ImVec2 position = ImGui::GetCursorScreenPos();
        bool pressed = ImGui::InvisibleButton("##tab", ImVec2(w, pillHeight));
        bool hovered = ImGui::IsItemHovered();
        ImGui::PopID();
        float& hover = hover_["sectab:" + std::to_string(i)];
        bool active = securityTab_ == i;
        approach(hover, (hovered || active) ? 1.0f : 0.0f, 14.0f, dt_);
        ImVec4 fill = mixColor(ImGui::GetStyleColorVec4(ImGuiCol_FrameBg), palette().primary, active ? 0.55f : 0.15f * hover);
        list->AddRectFilled(position, ImVec2(position.x + w, position.y + pillHeight), packColor(fill), pillHeight * 0.5f);
        drawText(list, unit, ImVec2(position.x + unit * 0.9f, position.y + (pillHeight - unit) * 0.5f),
                 packColor(active ? kWhite : ImVec4(0.78f, 0.8f, 0.88f, 1.0f)), label.c_str());
        if (pressed) securityTab_ = i;
    }
    ImGui::Dummy(ImVec2(0, unit * 0.5f));

    if (securityTab_ == 0) {
        drawSecurityOverview(width);
    } else if (securityTab_ == 1) {
        drawSecurityScan(width);
    } else if (securityTab_ == 2) {
        drawSecurityQuarantine(width);
    } else if (securityTab_ == 3) {
        drawSecurityFirewall(width);
    } else {
        drawSecuritySettings(width);
    }
    ImGui::Dummy(ImVec2(0, unit * 2.0f));
}

void App::drawSecurityOverview(float width) {
    float unit = ImGui::GetFontSize();
    float gap = ImGui::GetStyle().ItemSpacing.x;
    SecurityCounters counters = security_->counters();
    FirewallStats firewall = firewall_.stats();
    if (time_ - quarantineRefreshed_ > 2.0) {
        quarantineCache_ = security_->quarantineItems();
        quarantineRefreshed_ = time_;
    }
    if (time_ - eventsRefreshed_ > 1.5) {
        eventsCache_ = security_->events(8);
        eventsRefreshed_ = time_;
    }

    int columns = compact_ ? 2 : 4;
    float cardWidth = (width - gap * static_cast<float>(columns - 1)) / static_cast<float>(columns);
    ImVec2 size(cardWidth, unit * 4.2f);
    struct Stat {
        const char* id;
        const char* label;
        std::string value;
        Icon icon;
        ImVec4 tint;
    };
    std::vector<Stat> stats = {
        {"scanned", "Items scanned", std::to_string(counters.scanned), Icon::Search, palette().primary},
        {"threats", "Threats found", std::to_string(counters.threats), Icon::Bug, kWarn},
        {"blocked", "Blocked", std::to_string(counters.blocked + firewall.refused + firewall.rateLimited), Icon::Shield, kDanger},
        {"quarantine", "In quarantine", std::to_string(quarantineCache_.size()), Icon::Folder, palette().secondary},
    };
    for (std::size_t i = 0; i < stats.size(); ++i) {
        if (i % static_cast<std::size_t>(columns) != 0) ImGui::SameLine(0.0f, gap);
        drawStatCard(stats[i].id, stats[i].label, stats[i].value, stats[i].icon, stats[i].tint, size);
    }
    ImGui::Dummy(ImVec2(0, unit * 0.6f));

    sectionTitle("Protection", palette().secondary);
    SecuritySettings settings = security_->settings();
    struct Toggle {
        const char* id;
        const char* title;
        const char* text;
        bool* value;
    };
    bool realtime = settings.realtime;
    bool guard = settings.guardHosting;
    bool firewallOn = settings.firewall;
    Toggle toggles[] = {
        {"realtime", "Real-time protection", "Scans every page and download before you see it", &realtime},
        {"guard", "Hosting guard", "Stops your site from serving dangerous files", &guard},
        {"firewall", "Network firewall", "Limits floods and bans abusive computers", &firewallOn},
    };
    bool changed = false;
    for (const Toggle& item : toggles) {
        ImVec2 position = ImGui::GetCursorScreenPos();
        ImGui::BeginGroup();
        if (toggleSwitch(item.id, item.value)) changed = true;
        ImGui::SameLine();
        ImGui::BeginGroup();
        ImGui::TextUnformatted(item.title);
        ImGui::TextColored(kDim, "%s", item.text);
        ImGui::EndGroup();
        ImGui::EndGroup();
        (void)position;
        ImGui::Dummy(ImVec2(0, unit * 0.2f));
    }
    if (changed) {
        settings.realtime = realtime;
        settings.guardHosting = guard;
        settings.firewall = firewallOn;
        security_->setSettings(settings);
        applyFirewallSettings();
        toast("Protection settings saved", ToastKind::Success);
    }

    ImGui::Dummy(ImVec2(0, unit * 0.4f));
    sectionTitle("Recent activity", palette().primary);
    if (eventsCache_.empty()) {
        ImGui::TextColored(kDim, "Nothing has been detected yet. Everything you open is checked automatically.");
    }
    ImDrawList* list = ImGui::GetWindowDrawList();
    for (const ThreatEvent& event : eventsCache_) {
        ImVec2 position = ImGui::GetCursorScreenPos();
        float rowHeight = unit * 2.2f;
        ImVec4 dot = event.verdict == "malicious" ? kDanger : (event.verdict == "suspicious" ? kWarn : (event.verdict == "blocked" ? ImVec4(1.0f, 0.55f, 0.25f, 1.0f) : kDim));
        list->AddCircleFilled(ImVec2(position.x + unit * 0.7f, position.y + rowHeight * 0.5f), unit * 0.3f, packColor(dot), 14);
        std::string when = formatClock(event.time);
        drawText(list, unit * 0.85f, ImVec2(position.x + unit * 1.5f, position.y + rowHeight * 0.5f - unit * 0.42f), packColor(kDim), when.c_str());
        std::string text = event.verdict + " - " + (event.rule.empty() ? "scan" : event.rule) + " - " + event.source + ": " + event.target;
        float textX = position.x + unit * 1.5f + textWidth(unit * 0.85f, when) + unit * 0.8f;
        drawText(list, unit * 0.95f, ImVec2(textX, position.y + rowHeight * 0.5f - unit * 0.47f), IM_COL32(235, 238, 250, 255),
                 fitText(text, unit * 0.95f, width - (textX - position.x) - unit).c_str());
        ImGui::Dummy(ImVec2(width, rowHeight));
    }
    if (textButton("sec-clear", "Clear activity", Icon::Trash, false)) {
        security_->clearEvents();
        eventsRefreshed_ = -100.0;
    }
}

void App::drawSecurityScan(float width) {
    float unit = ImGui::GetFontSize();
    ImDrawList* list = ImGui::GetWindowDrawList();
    bool scanning = scan_ && !scan_->done;

    sectionTitle("Scan a folder or a file", palette().secondary);
    ImGui::SetNextItemWidth(width - unit * 12.0f);
    ImGui::InputText("##scanpath", scanPath_, sizeof scanPath_);
    ImGui::SameLine();
    if (textButton("scan-go", "Scan", Icon::Search, true) && !scanning) {
        std::string path = scanPath_;
        if (path.empty()) {
            toast("Type a path to scan", ToastKind::Warning);
        } else {
            startScan({fs::path(path)}, path);
        }
    }
    if (textButton("scan-site", "My site folder", Icon::Folder, false)) copyBuffer(scanPath_, sizeof scanPath_, nodeFolder_);
    ImGui::SameLine();
    if (textButton("scan-dl", "Downloads", Icon::Folder, false)) copyBuffer(scanPath_, sizeof scanPath_, (dataDir_ / "downloads").generic_string());
    ImGui::Dummy(ImVec2(0, unit * 0.6f));

    if (!scan_) {
        ImGui::TextColored(kDim, "Pick a folder and press Scan. Dangerous files are moved to quarantine when that option is on.");
        return;
    }

    ImVec2 position = ImGui::GetCursorScreenPos();
    float boxHeight = unit * 5.6f;
    list->AddRectFilled(position, ImVec2(position.x + width, position.y + boxHeight), packColor(withAlpha(palette().primary, 0.10f)), unit * 0.7f);
    list->AddRect(position, ImVec2(position.x + width, position.y + boxHeight), packColor(withAlpha(palette().primary, 0.45f)), unit * 0.7f, ImDrawFlags_None, 1.5f);
    std::string headline = scanning ? "Scanning " + scanLabel_ : "Finished scanning " + scanLabel_;
    drawText(list, unit * 1.15f, ImVec2(position.x + unit, position.y + unit * 0.8f), IM_COL32(255, 255, 255, 255),
             fitText(headline, unit * 1.15f, width - unit * 2.0f).c_str());
    std::string current;
    {
        std::lock_guard<std::mutex> lock(scan_->mutex);
        current = scan_->current;
    }
    std::string counts = std::to_string(scan_->files.load()) + " files, " + formatBytes(scan_->bytes.load()) + ", " +
                         std::to_string(scan_->malicious.load()) + " dangerous, " + std::to_string(scan_->suspicious.load()) + " suspicious";
    drawText(list, unit * 0.9f, ImVec2(position.x + unit, position.y + unit * 2.5f), packColor(kDim), counts.c_str());
    if (scanning) {
        drawText(list, unit * 0.8f, ImVec2(position.x + unit, position.y + unit * 3.4f), packColor(kDim),
                 fitText(current, unit * 0.8f, width - unit * 2.0f).c_str());
    }
    float barY = position.y + boxHeight - unit * 1.0f;
    float barWidth = width - unit * 2.0f;
    float barHeight = std::max(4.0f, unit * 0.36f);
    list->AddRectFilled(ImVec2(position.x + unit, barY), ImVec2(position.x + unit + barWidth, barY + barHeight), packColor(withAlpha(kWhite, 0.12f)), barHeight * 0.5f);
    if (scanning) {
        float phase = std::fmod(static_cast<float>(time_) * 0.8f, 1.0f);
        float segment = barWidth * 0.3f;
        float start = position.x + unit - segment + (barWidth + segment) * phase;
        float a = std::max(start, position.x + unit);
        float b = std::min(start + segment, position.x + unit + barWidth);
        if (b > a) list->AddRectFilledMultiColor(ImVec2(a, barY), ImVec2(b, barY + barHeight), packColor(palette().primary), packColor(palette().secondary), packColor(palette().secondary), packColor(palette().primary));
    } else {
        list->AddRectFilledMultiColor(ImVec2(position.x + unit, barY), ImVec2(position.x + unit + barWidth, barY + barHeight), packColor(kSafe), packColor(palette().secondary), packColor(palette().secondary), packColor(kSafe));
    }
    ImGui::Dummy(ImVec2(width, boxHeight));
    if (scanning) {
        if (textButton("scan-cancel", "Cancel scan", Icon::Close, false)) scan_->cancel = true;
    }
    ImGui::Dummy(ImVec2(0, unit * 0.4f));

    if (scanRecords_.empty()) {
        if (!scanning) ImGui::TextColored(kSafe, "No threats found.");
        return;
    }
    sectionTitle("Results", kWarn);
    int removal = -1;
    for (std::size_t i = 0; i < scanRecords_.size(); ++i) {
        ScanRecord& record = scanRecords_[i];
        const Finding* strongest = strongestFinding(record.result);
        ImVec4 color = verdictColor(record.result.verdict);
        ImVec2 rowMin = ImGui::GetCursorScreenPos();
        float rowHeight = unit * 4.6f;
        list->AddRectFilled(rowMin, ImVec2(rowMin.x + width, rowMin.y + rowHeight), packColor(withAlpha(color, 0.10f)), unit * 0.6f);
        list->AddRectFilled(rowMin, ImVec2(rowMin.x + unit * 0.3f, rowMin.y + rowHeight), packColor(color), unit * 0.6f, ImDrawFlags_RoundCornersLeft);
        std::string chip = std::string(verdictName(record.result.verdict)) + " " + std::to_string(record.result.score);
        drawText(list, unit * 0.85f, ImVec2(rowMin.x + unit, rowMin.y + unit * 0.6f), packColor(color), chip.c_str());
        std::string rule = strongest ? strongest->rule : "";
        drawText(list, unit * 1.0f, ImVec2(rowMin.x + unit, rowMin.y + unit * 1.5f), IM_COL32(255, 255, 255, 255),
                 fitText(rule + "  -  " + record.path, unit, width - unit * 14.0f).c_str());
        std::string description = strongest ? strongest->description : "";
        drawText(list, unit * 0.85f, ImVec2(rowMin.x + unit, rowMin.y + unit * 2.6f), packColor(kDim),
                 fitText(description + " (" + record.action + ")", unit * 0.85f, width - unit * 14.0f).c_str());
        ImVec2 buttonPos(rowMin.x + width - unit * 12.6f, rowMin.y + (rowHeight - ImGui::GetFrameHeight()) * 0.5f);
        ImGui::SetCursorScreenPos(buttonPos);
        ImGui::PushID(static_cast<int>(i));
        bool canQuarantine = record.action != "quarantined";
        if (canQuarantine) {
            if (textButton("rec-quarantine", "Quarantine", Icon::Folder, true)) {
                std::string error;
                if (security_->quarantineFile(fs::path(record.path), record.result, error)) {
                    {
                        std::lock_guard<std::mutex> lock(scan_->mutex);
                        for (ScanRecord& original : scan_->records) {
                            if (original.path == record.path) original.action = "quarantined";
                        }
                    }
                    record.action = "quarantined";
                    quarantineRefreshed_ = -100.0;
                    toast("Moved to quarantine", ToastKind::Success);
                } else {
                    toast(error, ToastKind::Error);
                }
            }
            ImGui::SameLine();
        }
        if (iconButton("rec-ignore", Icon::Close, "Ignore this result")) removal = static_cast<int>(i);
        ImGui::PopID();
        ImGui::SetCursorScreenPos(ImVec2(rowMin.x, rowMin.y + rowHeight));
        ImGui::Dummy(ImVec2(width, unit * 0.4f));
    }
    if (removal >= 0) {
        std::string path = scanRecords_[static_cast<std::size_t>(removal)].path;
        scanRecords_.erase(scanRecords_.begin() + removal);
        if (scan_) {
            std::lock_guard<std::mutex> lock(scan_->mutex);
            scan_->records.erase(std::remove_if(scan_->records.begin(), scan_->records.end(), [&](const ScanRecord& item) { return item.path == path; }),
                                 scan_->records.end());
        }
    }
}

void App::drawSecurityQuarantine(float width) {
    float unit = ImGui::GetFontSize();
    ImDrawList* list = ImGui::GetWindowDrawList();
    if (time_ - quarantineRefreshed_ > 2.0) {
        quarantineCache_ = security_->quarantineItems();
        quarantineRefreshed_ = time_;
    }
    sectionTitle("Quarantine", palette().secondary);
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextColored(kDim, "Dangerous files are stored here in a scrambled form so they can never run. Restore a file only if you are sure it is safe.");
    ImGui::PopTextWrapPos();
    ImGui::Dummy(ImVec2(0, unit * 0.4f));
    if (quarantineCache_.empty()) {
        ImGui::TextColored(kSafe, "The quarantine is empty.");
        return;
    }
    std::string restoreId;
    std::string deleteId;
    for (const QuarantineItem& item : quarantineCache_) {
        ImVec2 rowMin = ImGui::GetCursorScreenPos();
        float rowHeight = unit * 4.2f;
        list->AddRectFilled(rowMin, ImVec2(rowMin.x + width, rowMin.y + rowHeight), packColor(withAlpha(kDanger, 0.08f)), unit * 0.6f);
        list->AddRectFilled(rowMin, ImVec2(rowMin.x + unit * 0.3f, rowMin.y + rowHeight), packColor(kDanger), unit * 0.6f, ImDrawFlags_RoundCornersLeft);
        drawText(list, unit * 1.05f, ImVec2(rowMin.x + unit, rowMin.y + unit * 0.7f), IM_COL32(255, 255, 255, 255),
                 fitText(item.name.empty() ? item.id : item.name, unit * 1.05f, width - unit * 14.0f).c_str());
        std::string info = item.rule + "  |  score " + std::to_string(item.score) + "  |  " + formatBytes(item.size) + "  |  " + formatClock(item.time);
        drawText(list, unit * 0.85f, ImVec2(rowMin.x + unit, rowMin.y + unit * 1.9f), packColor(kDim), fitText(info, unit * 0.85f, width - unit * 14.0f).c_str());
        drawText(list, unit * 0.8f, ImVec2(rowMin.x + unit, rowMin.y + unit * 2.8f), packColor(kDim),
                 fitText("was at " + item.originalPath, unit * 0.8f, width - unit * 14.0f).c_str());
        ImGui::SetCursorScreenPos(ImVec2(rowMin.x + width - unit * 11.8f, rowMin.y + (rowHeight - ImGui::GetFrameHeight()) * 0.5f));
        ImGui::PushID(item.id.c_str());
        if (textButton("q-restore", "Restore", Icon::Reload, false)) restoreId = item.id;
        ImGui::SameLine();
        if (textButton("q-delete", "Delete", Icon::Trash, false)) deleteId = item.id;
        ImGui::PopID();
        ImGui::SetCursorScreenPos(ImVec2(rowMin.x, rowMin.y + rowHeight));
        ImGui::Dummy(ImVec2(width, unit * 0.4f));
    }
    std::string error;
    if (!restoreId.empty()) {
        std::string name = "restored-file";
        for (const QuarantineItem& item : quarantineCache_) {
            if (item.id == restoreId && !item.name.empty()) name = fs::path(item.name).filename().string();
        }
        fs::path target = dataDir_ / "restored" / name;
        for (int i = 2; fs::exists(target); ++i) target = dataDir_ / "restored" / (std::to_string(i) + "-" + name);
        if (security_->restoreQuarantined(restoreId, target, error)) {
            toast("Restored to " + target.string(), ToastKind::Warning);
        } else {
            toast(error, ToastKind::Error);
        }
        quarantineRefreshed_ = -100.0;
    }
    if (!deleteId.empty()) {
        if (security_->deleteQuarantined(deleteId, error)) {
            toast("Deleted permanently", ToastKind::Success);
        } else {
            toast(error, ToastKind::Error);
        }
        quarantineRefreshed_ = -100.0;
    }
}

void App::drawSecurityFirewall(float width) {
    float unit = ImGui::GetFontSize();
    float gap = ImGui::GetStyle().ItemSpacing.x;
    FirewallStats stats = firewall_.stats();
    FirewallConfig config = firewall_.config();

    int columns = compact_ ? 2 : 4;
    float cardWidth = (width - gap * static_cast<float>(columns - 1)) / static_cast<float>(columns);
    ImVec2 size(cardWidth, unit * 4.2f);
    drawStatCard("fw-allowed", "Connections allowed", std::to_string(stats.allowed), Icon::Check, kSafe, size);
    if (columns > 1) ImGui::SameLine(0.0f, gap);
    drawStatCard("fw-limited", "Requests limited", std::to_string(stats.rateLimited), Icon::Warning, kWarn, size);
    if (columns > 2) {
        ImGui::SameLine(0.0f, gap);
    }
    drawStatCard("fw-refused", "Connections refused", std::to_string(stats.refused), Icon::Shield, kDanger, size);
    if (columns > 3) ImGui::SameLine(0.0f, gap);
    drawStatCard("fw-bans", "Computers banned", std::to_string(stats.bans), Icon::Bug, palette().secondary, size);
    ImGui::Dummy(ImVec2(0, unit * 0.6f));

    sectionTitle("Limits", palette().primary);
    bool changed = false;
    float rate = static_cast<float>(config.ratePerSecond);
    float burst = static_cast<float>(config.burst);
    int connections = config.maxConnectionsPerHost;
    int banSeconds = config.banSeconds;
    ImGui::SetNextItemWidth(std::min(width, unit * 26.0f));
    if (ImGui::SliderFloat("Requests per second", &rate, 1.0f, 200.0f, "%.0f")) changed = true;
    ImGui::SetNextItemWidth(std::min(width, unit * 26.0f));
    if (ImGui::SliderFloat("Burst size", &burst, 5.0f, 500.0f, "%.0f")) changed = true;
    ImGui::SetNextItemWidth(std::min(width, unit * 26.0f));
    if (ImGui::SliderInt("Connections per computer", &connections, 4, 256)) changed = true;
    ImGui::SetNextItemWidth(std::min(width, unit * 26.0f));
    if (ImGui::SliderInt("Ban time (seconds)", &banSeconds, 30, 3600)) changed = true;
    if (changed) {
        config.ratePerSecond = rate;
        config.burst = burst;
        config.maxConnectionsPerHost = connections;
        config.banSeconds = banSeconds;
        firewall_.setConfig(config);
    }
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextColored(kDim, "This computer is never limited. The firewall protects the registry and the sites you host from other computers.");
    ImGui::PopTextWrapPos();
    ImGui::Dummy(ImVec2(0, unit * 0.6f));

    sectionTitle("Banned computers", kDanger);
    std::vector<BanInfo> bans = firewall_.bans();
    if (bans.empty()) ImGui::TextColored(kSafe, "No computers are banned.");
    std::string unban;
    for (const BanInfo& ban : bans) {
        ImGui::PushID(ban.host.c_str());
        ImGui::AlignTextToFramePadding();
        ImGui::Text("%s  -  %s  (%d s left)", ban.host.c_str(), ban.reason.c_str(), ban.remainingSeconds);
        ImGui::SameLine();
        if (textButton("fw-unban", "Unban", Icon::Close, false)) unban = ban.host;
        ImGui::PopID();
    }
    if (!unban.empty()) firewall_.unban(unban);
}

void App::drawSecuritySettings(float width) {
    float unit = ImGui::GetFontSize();
    SecuritySettings settings = security_->settings();
    bool changed = false;

    sectionTitle("Protection options", palette().secondary);
    struct Option {
        const char* id;
        const char* title;
        const char* text;
        bool* value;
    };
    Option options[] = {
        {"o-realtime", "Scan pages and downloads", "Check everything before it is shown", &settings.realtime},
        {"o-block", "Block dangerous downloads", "Refuse to save files that are malicious", &settings.blockDownloads},
        {"o-save", "Scan files when I save them", "Check pages you write in the site editor", &settings.scanOnSave},
        {"o-quarantine", "Quarantine dangerous files automatically", "Scans move malicious files out of the way", &settings.autoQuarantine},
        {"o-guard", "Guard my hosted site", "Never serve a file that is malicious", &settings.guardHosting},
        {"o-firewall", "Network firewall", "Limit floods and ban abusive computers", &settings.firewall},
    };
    for (const Option& option : options) {
        ImGui::BeginGroup();
        if (toggleSwitch(option.id, option.value)) changed = true;
        ImGui::SameLine();
        ImGui::BeginGroup();
        ImGui::TextUnformatted(option.title);
        ImGui::TextColored(kDim, "%s", option.text);
        ImGui::EndGroup();
        ImGui::EndGroup();
        ImGui::Dummy(ImVec2(0, unit * 0.2f));
    }
    if (changed) {
        security_->setSettings(settings);
        applyFirewallSettings();
        toast("Settings saved", ToastKind::Success);
    }

    ImGui::Dummy(ImVec2(0, unit * 0.5f));
    sectionTitle("Definitions", palette().primary);
    ImGui::Text("Version %s, %zu rules", security_->definitionsVersion().c_str(), security_->ruleCount());
    ImGui::TextColored(kDim, "Update from a file or from the network, for example internet://defs/definitions.txt");
    ImGui::SetNextItemWidth(width - unit * 11.0f);
    ImGui::InputText("##defsource", definitionsSource_, sizeof definitionsSource_);
    ImGui::SameLine();
    bool updating = definitionsJob_ && !definitionsJob_->done;
    if (textButton("defs-update", updating ? "Updating..." : "Update", Icon::Reload, true) && !updating) updateDefinitions(definitionsSource_);
    if (!definitionsMessage_.empty()) {
        bool failed = definitionsMessage_.rfind("error", 0) == 0;
        ImGui::TextColored(failed ? kDanger : kSafe, "%s", definitionsMessage_.c_str());
    }
}

void App::drawBlocked() {
    float unit = ImGui::GetFontSize();
    float width = ImGui::GetContentRegionAvail().x;
    ImDrawList* list = ImGui::GetWindowDrawList();
    float time = settings_.animations ? static_cast<float>(time_) : 0.0f;
    ImVec2 origin = ImGui::GetCursorScreenPos();
    float heroHeight = unit * 8.0f;
    list->AddRectFilled(origin, ImVec2(origin.x + width, origin.y + heroHeight), packColor(mixColor(kNavy, kDanger, 0.34f)), unit);
    list->AddRect(origin, ImVec2(origin.x + width, origin.y + heroHeight), packColor(withAlpha(kDanger, 0.7f)), unit, ImDrawFlags_None, 2.0f);
    drawShield(list, ImVec2(origin.x + unit * 4.4f, origin.y + heroHeight * 0.5f), unit * 5.2f, packColor(kDanger), 0.5f + 0.5f * std::sin(time * 3.0f), 2, time);
    float textX = origin.x + unit * 8.6f;
    float limit = width - unit * 9.6f;
    drawText(list, unit * 2.0f, ImVec2(textX, origin.y + unit * 1.4f), IM_COL32(255, 255, 255, 255), fitText("Dangerous page blocked", unit * 2.0f, limit).c_str());
    drawText(list, unit * 1.0f, ImVec2(textX, origin.y + unit * 4.0f), packColor(ImVec4(1.0f, 0.86f, 0.88f, 1.0f)),
             fitText("Internet Security stopped this page before it could be shown.", unit, limit).c_str());
    drawText(list, unit * 0.9f, ImVec2(textX, origin.y + unit * 5.4f), packColor(kDim), fitText(currentUrl_, unit * 0.9f, limit).c_str());
    ImGui::Dummy(ImVec2(width, heroHeight));
    ImGui::Dummy(ImVec2(0, unit * 0.4f));

    sectionTitle("What was found", kDanger);
    std::size_t shown = 0;
    for (const Finding& finding : threat_.findings) {
        if (shown++ >= 8) break;
        ImGui::PushStyleColor(ImGuiCol_Text, verdictColor(finding.severity >= 85 ? Verdict::Malicious : Verdict::Suspicious));
        ImGui::Text("%d", finding.severity);
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextUnformatted(finding.rule.c_str());
        ImGui::SameLine();
        ImGui::TextColored(kDim, "%s", finding.description.c_str());
    }
    ImGui::Dummy(ImVec2(0, unit * 0.4f));
    if (textButton("blocked-back", "Go back", Icon::Back, true)) {
        if (position_ > 0) {
            goBack();
        } else {
            goHome();
        }
    }
    ImGui::SameLine();
    if (textButton("blocked-security", "Security Center", Icon::Shield, false)) openSecurity(0);
    ImGui::Dummy(ImVec2(0, unit * 0.8f));
    static bool understand = false;
    ImGui::Checkbox("I understand the risk", &understand);
    if (understand) {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Button, kDanger);
        if (ImGui::Button("Open anyway")) {
            blockOverride_ = true;
            understand = false;
        }
        ImGui::PopStyleColor();
    }
}

void App::drawThreatBanner() {
    float unit = ImGui::GetFontSize();
    float width = ImGui::GetContentRegionAvail().x;
    bool danger = threat_.verdict == Verdict::Malicious;
    ImVec4 color = danger ? kDanger : kWarn;
    ImDrawList* list = ImGui::GetWindowDrawList();
    ImVec2 position = ImGui::GetCursorScreenPos();
    float height = unit * 2.6f;
    list->AddRectFilled(position, ImVec2(position.x + width, position.y + height), packColor(withAlpha(color, 0.16f)), unit * 0.6f);
    list->AddRect(position, ImVec2(position.x + width, position.y + height), packColor(withAlpha(color, 0.7f)), unit * 0.6f, ImDrawFlags_None, 1.4f);
    drawIcon(list, Icon::Warning, ImVec2(position.x + unit * 1.3f, position.y + height * 0.5f), unit * 1.3f, packColor(color));
    std::string rule = threat_.findings.empty() ? "" : threat_.findings[0].rule + ": " + threat_.findings[0].description;
    std::string text = std::string(danger ? "Dangerous content" : "Suspicious content") + " (score " + std::to_string(threat_.score) + ") - " + rule;
    drawText(list, unit * 0.95f, ImVec2(position.x + unit * 2.6f, position.y + (height - unit * 0.95f) * 0.5f), IM_COL32(255, 255, 255, 255),
             fitText(text, unit * 0.95f, width - unit * 8.0f).c_str());
    ImGui::SetCursorScreenPos(ImVec2(position.x + width - unit * 5.4f, position.y + (height - ImGui::GetFrameHeight()) * 0.5f));
    if (textButton("banner-details", "Details", Icon::Shield, false)) openSecurity(0);
    ImGui::SetCursorScreenPos(ImVec2(position.x, position.y + height));
    ImGui::Dummy(ImVec2(width, unit * 0.5f));
}

}
