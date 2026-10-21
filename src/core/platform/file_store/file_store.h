#pragma once
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>

#include "utils/secure_string/secure_string.h"

namespace clientwarden {
    /**
     * @brief App-private file storage. Relative paths resolve against root().
     *
     * Writes are atomic: readers see the old file or the new one, never a truncated mix, so a
     * crash mid-save can't corrupt the vault cache.
     */
    class FileStore {
    public:
        virtual ~FileStore() = default;

        /**
         * @brief Reads a whole file.
         *
         * @param file Path relative to root(), or absolute
         * @return The contents, or nullopt if the file doesn't exist
         */
        virtual std::optional<SecureBytes> read(std::filesystem::path file) = 0;

        /**
         * @brief Atomically replaces a file, creating parent directories.
         *
         * @param file Path relative to root(), or absolute
         * @param data The new contents
         */
        virtual void write(std::filesystem::path file, std::span<const uint8_t> data) = 0;

        /**
         * @brief Deletes a file if it exists.
         *
         * @param file Path relative to root(), or absolute
         */
        virtual void remove(std::filesystem::path file) = 0;

        /**
         * @brief Deletes a directory and everything in it.
         *
         * @param dir Path relative to root(), or absolute
         */
        virtual void removeTree(std::filesystem::path dir) = 0;

        /**
         * @brief Whether a file exists.
         *
         * @param file Path relative to root(), or absolute
         * @return True if present
         */
        virtual bool exists(std::filesystem::path file) = 0;

        /**
         * @brief The directory relative paths resolve against.
         *
         * @return The root directory
         */
        virtual std::filesystem::path root() = 0;
    };

    /**
     * @brief Files on disk under a root directory.
     */
    class DiskFileStore : public FileStore {
    public:
        /**
         * @brief Creates a store rooted at `root` (created if missing).
         *
         * @param root The app data directory
         */
        explicit DiskFileStore(std::filesystem::path root);

        std::optional<SecureBytes> read(std::filesystem::path file) override;
        void write(std::filesystem::path file, std::span<const uint8_t> data) override;
        void remove(std::filesystem::path file) override;
        void removeTree(std::filesystem::path dir) override;
        bool exists(std::filesystem::path file) override;
        std::filesystem::path root() override;

    private:
        std::filesystem::path resolve_(std::filesystem::path file);

        std::filesystem::path m_root_;
    };

    /**
     * @brief In-memory store for tests.
     */
    class MemoryFileStore : public FileStore {
    public:
        std::optional<SecureBytes> read(std::filesystem::path file) override;
        void write(std::filesystem::path file, std::span<const uint8_t> data) override;
        void remove(std::filesystem::path file) override;
        void removeTree(std::filesystem::path dir) override;
        bool exists(std::filesystem::path file) override;
        std::filesystem::path root() override;

    private:
        std::filesystem::path resolve_(std::filesystem::path file);

        std::mutex m_mutex_;
        std::map<std::filesystem::path, SecureBytes> m_files_;
    };

    /**
     * @brief Confines another store to a subdirectory, giving each vault its own files.
     */
    class ScopedFileStore : public FileStore {
    public:
        /**
         * @brief Wraps a store.
         *
         * @param inner The shared underlying store
         * @param subdir Relative directory for this scope (empty for the legacy layout)
         */
        ScopedFileStore(std::shared_ptr<FileStore> inner, std::filesystem::path subdir);

        std::optional<SecureBytes> read(std::filesystem::path file) override;
        void write(std::filesystem::path file, std::span<const uint8_t> data) override;
        void remove(std::filesystem::path file) override;
        void removeTree(std::filesystem::path dir) override;
        bool exists(std::filesystem::path file) override;
        std::filesystem::path root() override;

    private:
        std::filesystem::path scoped_(std::filesystem::path file);

        std::shared_ptr<FileStore> m_inner_;
        std::filesystem::path m_subdir_;
    };
}
