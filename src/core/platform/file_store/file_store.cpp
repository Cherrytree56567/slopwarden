#include "file_store.h"

#include <fstream>
#include <system_error>

#include "utils/errors/errors.h"

namespace clientwarden {
    DiskFileStore::DiskFileStore(std::filesystem::path root) : m_root_(std::move(root)) {
        std::error_code ec;
        std::filesystem::create_directories(m_root_, ec);
    }

    std::filesystem::path DiskFileStore::resolve_(std::filesystem::path file) {
        return file.is_absolute() ? file : m_root_ / file;
    }

    std::optional<SecureBytes> DiskFileStore::read(std::filesystem::path file) {
        std::filesystem::path path = resolve_(std::move(file));

        /*
         * A write interrupted between removing the old file and renaming the new one into
         * place (see write()) leaves only the finished .tmp.
         */
        std::filesystem::path tmp = path;
        tmp += ".tmp";
        std::error_code missing;
        if (!std::filesystem::exists(path, missing) && std::filesystem::exists(tmp, missing)) {
            std::filesystem::rename(tmp, path, missing);
        }

        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return std::nullopt;
        }

        std::error_code ec;
        std::uintmax_t size = std::filesystem::file_size(path, ec);
        if (ec) {
            return std::nullopt;
        }

        SecureBytes data(static_cast<size_t>(size));
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!in) {
            throw VaultError("failed to read file");
        }
        return data;
    }

    void DiskFileStore::write(std::filesystem::path file, std::span<const uint8_t> data) {
        std::filesystem::path path = resolve_(std::move(file));
        std::filesystem::path tmp = path;
        tmp += ".tmp";

        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
            if (!out) {
                throw VaultError("failed to write file");
            }
        }
        std::filesystem::rename(tmp, path, ec);
        if (ec && std::filesystem::exists(path)) {
            /*
             * FAT (the Wii's SD card) can't rename over an existing file. The new contents are
             * complete in .tmp, which read() recovers if we stop between these two steps.
             */
            ec.clear();
            std::filesystem::remove(path, ec);
            if (!ec) {
                std::filesystem::rename(tmp, path, ec);
            }
        }
        if (ec) {
            throw VaultError("failed to replace file");
        }
    }

    void DiskFileStore::remove(std::filesystem::path file) {
        std::error_code ec;
        std::filesystem::remove(resolve_(std::move(file)), ec);
    }

    void DiskFileStore::removeTree(std::filesystem::path dir) {
        std::error_code ec;
        std::filesystem::remove_all(resolve_(std::move(dir)), ec);
    }

    bool DiskFileStore::exists(std::filesystem::path file) {
        std::error_code ec;
        return std::filesystem::exists(resolve_(std::move(file)), ec);
    }

    std::filesystem::path DiskFileStore::root() {
        return m_root_;
    }

    std::filesystem::path MemoryFileStore::resolve_(std::filesystem::path file) {
        return (file.is_absolute() ? file : root() / file).lexically_normal();
    }

    std::optional<SecureBytes> MemoryFileStore::read(std::filesystem::path file) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        std::map<std::filesystem::path, SecureBytes>::iterator it =
                m_files_.find(resolve_(std::move(file)));
        if (it == m_files_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    void MemoryFileStore::write(std::filesystem::path file, std::span<const uint8_t> data) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_files_[resolve_(std::move(file))] = SecureBytes(data.begin(), data.end());
    }

    void MemoryFileStore::remove(std::filesystem::path file) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_files_.erase(resolve_(std::move(file)));
    }

    void MemoryFileStore::removeTree(std::filesystem::path dir) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        std::filesystem::path prefix = resolve_(std::move(dir));
        std::erase_if(m_files_,
                [&prefix](const std::pair<const std::filesystem::path, SecureBytes>& entry) {
                    std::filesystem::path relative = entry.first.lexically_relative(prefix);
                    return !relative.empty() && *relative.begin() != "..";
                });
    }

    bool MemoryFileStore::exists(std::filesystem::path file) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        return m_files_.contains(resolve_(std::move(file)));
    }

    std::filesystem::path MemoryFileStore::root() {
        return "/memory";
    }

    ScopedFileStore::ScopedFileStore(std::shared_ptr<FileStore> inner, std::filesystem::path subdir)
        : m_inner_(std::move(inner)), m_subdir_(std::move(subdir)) {}

    std::filesystem::path ScopedFileStore::scoped_(std::filesystem::path file) {
        return file.is_absolute() ? file : m_subdir_ / file;
    }

    std::optional<SecureBytes> ScopedFileStore::read(std::filesystem::path file) {
        return m_inner_->read(scoped_(std::move(file)));
    }

    void ScopedFileStore::write(std::filesystem::path file, std::span<const uint8_t> data) {
        m_inner_->write(scoped_(std::move(file)), data);
    }

    void ScopedFileStore::remove(std::filesystem::path file) {
        m_inner_->remove(scoped_(std::move(file)));
    }

    void ScopedFileStore::removeTree(std::filesystem::path dir) {
        m_inner_->removeTree(scoped_(std::move(dir)));
    }

    bool ScopedFileStore::exists(std::filesystem::path file) {
        return m_inner_->exists(scoped_(std::move(file)));
    }

    std::filesystem::path ScopedFileStore::root() {
        return m_inner_->root() / m_subdir_;
    }
}
