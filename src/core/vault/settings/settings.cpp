#include "settings.h"

#include <algorithm>

#include "utils/encoding/encoding.h"

namespace clientwarden {
    namespace {
        constexpr std::string_view c_settings_file = "settings.json";

        /**
         * @brief Clamps an auto-lock delay to 5 seconds - 7 days.
         *
         * @param seconds The requested delay
         * @return The clamped delay
         */
        int clampAutoLock_(int seconds) {
            return std::clamp(seconds, 5, 7 * 24 * 3600);
        }

        /**
         * @brief Clamps a clipboard clear delay to 5 - 600 seconds.
         *
         * @param seconds The requested delay
         * @return The clamped delay
         */
        int clampClipboard_(int seconds) {
            return std::clamp(seconds, 5, 600);
        }

        /**
         * @brief Reads an integer member, falling back if missing or not an integer.
         *
         * @param json The settings object
         * @param key The member name
         * @param fallback The default
         * @return The value
         */
        int intAt_(const Json& json, std::string_view key, int fallback) {
            const Json& value = at(json, key);
            if (!value.is_number_integer()) {
                return fallback;
            }
            std::int64_t number = value.get<std::int64_t>();
            return static_cast<int>(std::clamp<std::int64_t>(number, INT32_MIN, INT32_MAX));
        }
    }

    Settings::Settings(std::shared_ptr<FileStore> files) : m_files_(std::move(files)) {}

    void Settings::load() {
        std::optional<SecureBytes> bytes = m_files_->read(std::filesystem::path(c_settings_file));
        Json json = bytes ? Json::parse(bytes->begin(), bytes->end(), nullptr, false) : Json();
        if (!json.is_object()) {
            json = Json::object();
        }

        std::lock_guard<std::mutex> lock(m_mutex_);
        m_auto_lock_seconds_ = clampAutoLock_(intAt_(json, "autoLockDelay", 300));
        m_clipboard_clear_seconds_ = clampClipboard_(intAt_(json, "clipboardClear", 30));
        const Json& screenshots = at(json, "allowScreenshots");
        m_allow_screenshots_ = screenshots.is_boolean() && screenshots.get<bool>();
        m_timeout_action_ = stringAt(json, "timeoutAction") == "logout" ? TimeoutAction::Logout
                                                                        : TimeoutAction::Lock;
    }

    void Settings::reset() {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_auto_lock_seconds_ = 300;
        m_clipboard_clear_seconds_ = 30;
        m_allow_screenshots_ = false;
        m_timeout_action_ = TimeoutAction::Lock;
        m_files_->remove(std::filesystem::path(c_settings_file));
    }

    void Settings::persist_() {
        // clang-format off
        Json json = {
            { "autoLockDelay", m_auto_lock_seconds_ },
            { "clipboardClear", m_clipboard_clear_seconds_ },
            { "allowScreenshots", m_allow_screenshots_ },
            { "timeoutAction", m_timeout_action_ == TimeoutAction::Logout ? "logout" : "lock" }
        };
        // clang-format on
        SecureString text = json.dump(2);
        m_files_->write(std::filesystem::path(c_settings_file), encoding::bytesOf(text));
    }

    int Settings::getAutoLockSeconds() const {
        std::lock_guard<std::mutex> lock(m_mutex_);
        return m_auto_lock_seconds_;
    }

    void Settings::setAutoLockSeconds(int seconds) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_auto_lock_seconds_ = clampAutoLock_(seconds);
        persist_();
    }

    TimeoutAction Settings::getTimeoutAction() const {
        std::lock_guard<std::mutex> lock(m_mutex_);
        return m_timeout_action_;
    }

    void Settings::setTimeoutAction(TimeoutAction action) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_timeout_action_ = action;
        persist_();
    }

    int Settings::getClipboardClearSeconds() const {
        std::lock_guard<std::mutex> lock(m_mutex_);
        return m_clipboard_clear_seconds_;
    }

    void Settings::setClipboardClearSeconds(int seconds) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_clipboard_clear_seconds_ = clampClipboard_(seconds);
        persist_();
    }

    bool Settings::getAllowScreenshots() const {
        std::lock_guard<std::mutex> lock(m_mutex_);
        return m_allow_screenshots_;
    }

    void Settings::setAllowScreenshots(bool allow) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_allow_screenshots_ = allow;
        persist_();
    }
}
