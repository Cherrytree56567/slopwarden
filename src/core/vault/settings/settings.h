#pragma once
#include <memory>
#include <mutex>

#include "platform/file_store/file_store.h"

namespace clientwarden {
    /**
     * @brief What happens when the vault times out.
     */
    enum class TimeoutAction { Lock, Logout };

    /**
     * @brief Per-vault preferences persisted to settings.json.
     *
     * Values are clamped on write and on load, so a hand-edited file can't disable auto-lock.
     */
    class Settings {
    public:
        /**
         * @brief Creates settings persisting through `files`.
         *
         * @param files Where settings.json lives
         */
        explicit Settings(std::shared_ptr<FileStore> files);

        /**
         * @brief Loads settings.json, keeping defaults for anything missing or invalid.
         */
        void load();

        /**
         * @brief Restores defaults and deletes settings.json.
         */
        void reset();

        /**
         * @brief Seconds of inactivity before the vault times out.
         *
         * @return 5 seconds to 7 days
         */
        int getAutoLockSeconds() const;

        /**
         * @brief Sets the inactivity timeout.
         *
         * @param seconds Clamped to 5 seconds - 7 days
         */
        void setAutoLockSeconds(int seconds);

        /**
         * @brief Lock or log out on timeout.
         *
         * @return The action
         */
        TimeoutAction getTimeoutAction() const;

        /**
         * @brief Chooses lock or log out on timeout.
         *
         * @param action The action
         */
        void setTimeoutAction(TimeoutAction action);

        /**
         * @brief Seconds before copied secrets are cleared from the clipboard.
         *
         * @return 5 - 600 seconds
         */
        int getClipboardClearSeconds() const;

        /**
         * @brief Sets the clipboard clear delay.
         *
         * @param seconds Clamped to 5 - 600
         */
        void setClipboardClearSeconds(int seconds);

        /**
         * @brief Whether the window may appear in screenshots.
         *
         * @return True if allowed
         */
        bool getAllowScreenshots() const;

        /**
         * @brief Allows or blocks screenshots.
         *
         * @param allow True to allow
         */
        void setAllowScreenshots(bool allow);

    private:
        void persist_();

        std::shared_ptr<FileStore> m_files_;
        mutable std::mutex m_mutex_;
        int m_auto_lock_seconds_ = 300;
        int m_clipboard_clear_seconds_ = 30;
        bool m_allow_screenshots_ = false;
        TimeoutAction m_timeout_action_ = TimeoutAction::Lock;
    };
}
