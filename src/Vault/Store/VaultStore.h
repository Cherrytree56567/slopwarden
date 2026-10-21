#pragma once
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <nlohmann/json.hpp>

#include "Platform/FileStore.h"

namespace ClientWarden {
    /*
     * Records are immutable once stored; edits replace the pointer. That
     * makes snapshots a cheap pointer copy and lets sync notice records
     * that changed while it was talking to the server.
    */
    using Record = std::shared_ptr<const nlohmann::json>;

    /*
     * Ordered id -> record collection with O(1) lookup.
    */
    class RecordSet {
    public:
        Record Find(const std::string& id) const;
        void Put(Record record);
        bool Remove(const std::string& id);
        void Clear();

        const std::vector<Record>& All() const { return records; }
        nlohmann::json ToJson() const;
        static RecordSet FromJson(const nlohmann::json& array);

    private:
        std::vector<Record> records;
        std::unordered_map<std::string, size_t> index;
    };

    /*
     * The locally cached, still-encrypted vault (vault.json): profile,
     * ciphers, folders, plus queues of deletions that haven't reached the
     * server yet. Thread-safe; every mutation is persisted atomically.
     *
     * Records created offline carry "createdOffline": true until sync
     * uploads them.
    */
    class VaultStore {
    public:
        explicit VaultStore(FileStore& files);

        bool Load();
        void Clear();
        bool Empty() const;

        nlohmann::json Profile() const;
        std::optional<std::string> ProtectedUserKey() const;
        std::string ServerVersion() const;
        void SetServerVersion(const std::string& version);

        Record Cipher(const std::string& id) const;
        std::vector<Record> Ciphers() const;
        void PutCipher(nlohmann::json cipher);
        void RemoveCipher(const std::string& id, bool queueRemoteDelete);

        Record Folder(const std::string& id) const;
        std::vector<Record> Folders() const;
        void PutFolder(nlohmann::json folder);
        void RemoveFolder(const std::string& id, bool queueRemoteDelete);

        std::vector<std::string> PendingCipherDeletes() const;
        std::vector<std::string> PendingFolderDeletes() const;
        void ClearPendingCipherDelete(const std::string& id);
        void ClearPendingFolderDelete(const std::string& id);

        struct Snapshot {
            std::vector<Record> ciphers;
            std::vector<Record> folders;
        };
        Snapshot Take() const;

        /*
         * Commits a sync result. Records that differ from `before` were
         * edited during the sync and are kept as they are now.
        */
        void ApplySync(const Snapshot& before, nlohmann::json remoteTopLevel, std::vector<Record> ciphers, std::vector<Record> folders);

    private:
        void Persist();
        static void Commit(RecordSet& target, const std::vector<Record>& before, std::vector<Record> merged);

        FileStore& files;
        mutable std::shared_mutex mutex;

        nlohmann::json topLevel = nlohmann::json::object();     // profile, domains, policies, ...
        RecordSet ciphers;
        RecordSet folders;
        std::unordered_set<std::string> deletedCiphers;
        std::unordered_set<std::string> deletedFolders;
    };
}
