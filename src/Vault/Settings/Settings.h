#pragma once
#include <mutex>
#include <nlohmann/json.hpp>

#include "Platform/FileStore.h"

namespace ClientWarden {
    /*
     * User preferences persisted to settings.json. Values are clamped on
     * write and on load, so a hand-edited file can't disable auto-lock.
    */
    class Settings {
    public:
        explicit Settings(FileStore& files);

        void Load();
        void Reset();

        int AutoLockSeconds() const;
        void SetAutoLockSeconds(int seconds);

        int ClipboardClearSeconds() const;
        void SetClipboardClearSeconds(int seconds);

        bool AllowScreenshots() const;
        void SetAllowScreenshots(bool allow);

    private:
        void Persist();

        FileStore& files;
        mutable std::mutex mutex;
        int autoLockSeconds = 300;
        int clipboardClearSeconds = 30;
        bool allowScreenshots = false;
    };
}
