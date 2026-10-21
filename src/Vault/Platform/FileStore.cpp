#include "FileStore.h"

#include <vector>

namespace ClientWarden {
    std::optional<std::string> PlatformFileStore::Read(const std::filesystem::path& file) {
        if (!storage.exists(file)) {
            return std::nullopt;
        }
        return storage.read(file);
    }

    void PlatformFileStore::Write(const std::filesystem::path& file, std::span<const uint8_t> data) {
        std::filesystem::path tmp = file;
        tmp += ".tmp";

        storage.write(tmp, std::vector<uint8_t>(data.begin(), data.end()));
        storage.rename(tmp, file.filename().string());
    }

    void PlatformFileStore::Remove(const std::filesystem::path& file) {
        storage.remove(file);
    }

    void PlatformFileStore::RemoveTree(const std::filesystem::path& dir) {
        std::error_code ec;
        std::filesystem::remove_all(dir.is_absolute() ? dir : storage.path / dir, ec);
    }

    bool PlatformFileStore::Exists(const std::filesystem::path& file) {
        return storage.exists(file);
    }

    std::filesystem::path PlatformFileStore::Root() const {
        return storage.path;
    }

    std::optional<std::string> MemoryFileStore::Read(const std::filesystem::path& file) {
        std::lock_guard lock(mutex);
        auto it = files.find(file.string());
        if (it == files.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    void MemoryFileStore::Write(const std::filesystem::path& file, std::span<const uint8_t> data) {
        std::lock_guard lock(mutex);
        files[file.string()] = std::string(data.begin(), data.end());
    }

    void MemoryFileStore::Remove(const std::filesystem::path& file) {
        std::lock_guard lock(mutex);
        files.erase(file.string());
    }

    void MemoryFileStore::RemoveTree(const std::filesystem::path& dir) {
        std::lock_guard lock(mutex);
        std::string prefix = dir.string() + "/";
        std::erase_if(files, [&](const auto& kv) { return kv.first.starts_with(prefix); });
    }

    bool MemoryFileStore::Exists(const std::filesystem::path& file) {
        std::lock_guard lock(mutex);
        return files.contains(file.string());
    }

    std::filesystem::path MemoryFileStore::Root() const {
        return "/memory";
    }
}
