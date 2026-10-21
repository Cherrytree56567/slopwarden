#include "Settings.h"

#include <algorithm>

namespace ClientWarden {
    namespace {
        constexpr const char* SettingsFile = "settings.json";

        int ClampAutoLock(int s) { return std::clamp(s, 5, 7 * 24 * 3600); }
        int ClampClipboard(int s) { return std::clamp(s, 5, 600); }
    }

    Settings::Settings(FileStore& files) : files(files) {}

    void Settings::Load() {
        std::optional<std::string> text = files.Read(SettingsFile);
        nlohmann::json j = text ? nlohmann::json::parse(*text, nullptr, false) : nlohmann::json();
        if (!j.is_object()) {
            j = nlohmann::json::object();
        }

        std::lock_guard lock(mutex);
        auto num = [&](const char* key, int fallback) {
            return j.contains(key) && j[key].is_number_integer() ? j[key].get<int>() : fallback;
        };
        autoLockSeconds = ClampAutoLock(num("autoLockDelay", 300));
        clipboardClearSeconds = ClampClipboard(num("clipboardClear", 30));
        allowScreenshots = j.contains("allowScreenshots") && j["allowScreenshots"].is_boolean() && j["allowScreenshots"].get<bool>();
    }

    void Settings::Reset() {
        std::lock_guard lock(mutex);
        autoLockSeconds = 300;
        clipboardClearSeconds = 30;
        allowScreenshots = false;
        files.Remove(SettingsFile);
    }

    void Settings::Persist() {
        nlohmann::json j = {
            { "autoLockDelay", autoLockSeconds },
            { "clipboardClear", clipboardClearSeconds },
            { "allowScreenshots", allowScreenshots }
        };
        files.Write(SettingsFile, j.dump(2));
    }

    int Settings::AutoLockSeconds() const {
        std::lock_guard lock(mutex);
        return autoLockSeconds;
    }

    void Settings::SetAutoLockSeconds(int seconds) {
        std::lock_guard lock(mutex);
        autoLockSeconds = ClampAutoLock(seconds);
        Persist();
    }

    int Settings::ClipboardClearSeconds() const {
        std::lock_guard lock(mutex);
        return clipboardClearSeconds;
    }

    void Settings::SetClipboardClearSeconds(int seconds) {
        std::lock_guard lock(mutex);
        clipboardClearSeconds = ClampClipboard(seconds);
        Persist();
    }

    bool Settings::AllowScreenshots() const {
        std::lock_guard lock(mutex);
        return allowScreenshots;
    }

    void Settings::SetAllowScreenshots(bool allow) {
        std::lock_guard lock(mutex);
        allowScreenshots = allow;
        Persist();
    }
}
