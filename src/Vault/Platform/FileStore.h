#pragma once
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "Clientwarden.h"
#include "Storage/Storage.h"

namespace ClientWarden {
    /*
     * App-private file storage. Relative paths resolve against Root().
     * Writes are atomic: readers see the old file or the new one, never a
     * truncated mix, so a crash mid-save can't corrupt vault.json.
    */
    class FileStore {
    public:
        virtual ~FileStore() = default;

        virtual std::optional<std::string> Read(const std::filesystem::path& file) = 0;
        virtual void Write(const std::filesystem::path& file, std::span<const uint8_t> data) = 0;
        virtual void Remove(const std::filesystem::path& file) = 0;
        virtual void RemoveTree(const std::filesystem::path& dir) = 0;
        virtual bool Exists(const std::filesystem::path& file) = 0;
        virtual std::filesystem::path Root() const = 0;

        void Write(const std::filesystem::path& file, std::string_view data) {
            Write(file, std::span(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
        }
    };

    class PlatformFileStore : public FileStore {
    public:
        std::optional<std::string> Read(const std::filesystem::path& file) override;
        void Write(const std::filesystem::path& file, std::span<const uint8_t> data) override;
        void Remove(const std::filesystem::path& file) override;
        void RemoveTree(const std::filesystem::path& dir) override;
        bool Exists(const std::filesystem::path& file) override;
        std::filesystem::path Root() const override;

        using FileStore::Write;

    private:
        Storage storage;
    };

    class MemoryFileStore : public FileStore {
    public:
        std::optional<std::string> Read(const std::filesystem::path& file) override;
        void Write(const std::filesystem::path& file, std::span<const uint8_t> data) override;
        void Remove(const std::filesystem::path& file) override;
        void RemoveTree(const std::filesystem::path& dir) override;
        bool Exists(const std::filesystem::path& file) override;
        std::filesystem::path Root() const override;

        using FileStore::Write;

    private:
        std::mutex mutex;
        std::map<std::string, std::string> files;
    };
}
