#pragma once
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "platform/file_store/file_store.h"
#include "utils/secure_string/secure_string.h"

namespace clientwarden {
    /**
     * @brief An immutable cipher or folder record.
     *
     * Records are never edited in place; changes replace the pointer. Snapshots are therefore
     * a cheap pointer copy, and sync can tell which records changed while it was running.
     */
    using Record = std::shared_ptr<const Json>;

    /**
     * @brief Hashes SecureString keys for unordered containers.
     */
    struct SecureStringHash {
        using is_transparent = void;

        /**
         * @brief Hashes the characters of a string.
         *
         * @param text The string to hash
         * @return The hash
         */
        size_t operator()(std::string_view text) const;
    };

    /**
     * @brief Ordered id -> record collection with O(1) lookup.
     */
    class RecordSet {
    public:
        /**
         * @brief Finds a record by id.
         *
         * @param id The record id
         * @return The record, or nullptr if absent
         */
        Record find(std::string_view id) const;

        /**
         * @brief Inserts a record or replaces the one with the same id (keeping its position).
         *
         * @param record The record; ignored if it has no string id
         */
        void put(Record record);

        /**
         * @brief Removes a record.
         *
         * @param id The record id
         * @return True if something was removed
         */
        bool remove(std::string_view id);

        /**
         * @brief Removes everything.
         */
        void clear();

        /**
         * @brief All records in insertion order.
         *
         * @return The records
         */
        std::vector<Record> all() const;

        /**
         * @brief Serialises to a JSON array.
         *
         * @return The records as an array
         */
        Json toJson() const;

        /**
         * @brief Builds a set from a JSON array, skipping non-objects.
         *
         * @param array The stored array
         * @return The record set
         */
        static RecordSet fromJson(const Json& array);

    private:
        std::vector<Record> m_records_;
        std::unordered_map<SecureString, size_t, SecureStringHash, std::equal_to<>> m_index_;
    };

    /**
     * @brief The locally cached, still-encrypted vault (vault.json).
     *
     * Holds the server's sync response (profile, ciphers, folders, domains, policies, ...) plus
     * queues of deletions that haven't reached the server. Records created offline carry
     * "createdOffline": true until sync uploads them. Thread-safe; every mutation is persisted.
     */
    class Store {
    public:
        /**
         * @brief A consistent view of ciphers and folders at one moment.
         */
        struct Snapshot {
            std::vector<Record> m_ciphers;
            std::vector<Record> m_folders;
        };

        /**
         * @brief Creates a store persisting through `files`.
         *
         * @param files Where vault.json lives
         */
        explicit Store(std::shared_ptr<FileStore> files);

        /**
         * @brief Loads vault.json.
         *
         * @return False if missing or corrupt (the cache is then empty)
         */
        bool load();

        /**
         * @brief Forgets everything and deletes vault.json.
         */
        void clear();

        /**
         * @brief Whether a profile has been synced.
         *
         * @return True if there is no cached account
         */
        bool empty() const;

        /**
         * @brief The cached profile object.
         *
         * @return The profile, or an empty object
         */
        Json getProfile() const;

        /**
         * @brief A top-level member of the sync response (e.g. "domains", "policies").
         *
         * @param key The member name
         * @return A copy of the member, or null
         */
        Json getSection(std::string_view key) const;

        /**
         * @brief The server version recorded by Features.
         *
         * @return The version, or empty if unknown
         */
        SecureString getServerVersion() const;

        /**
         * @brief Records the server version.
         *
         * @param version e.g. "2026.8.1"
         */
        void setServerVersion(std::string_view version);

        /**
         * @brief Looks up a cipher.
         *
         * @param id The cipher id
         * @return The record, or nullptr
         */
        Record getCipher(std::string_view id) const;

        /**
         * @brief All ciphers.
         *
         * @return The records in order
         */
        std::vector<Record> getCiphers() const;

        /**
         * @brief Inserts or replaces a cipher and persists.
         *
         * @param cipher The encrypted cipher
         */
        void putCipher(Json cipher);

        /**
         * @brief Removes a cipher and persists.
         *
         * @param id The cipher id
         * @param queue_remote_delete Remember to delete it on the server at the next sync
         */
        void removeCipher(std::string_view id, bool queue_remote_delete);

        /**
         * @brief Looks up a folder.
         *
         * @param id The folder id
         * @return The record, or nullptr
         */
        Record getFolder(std::string_view id) const;

        /**
         * @brief All folders.
         *
         * @return The records in order
         */
        std::vector<Record> getFolders() const;

        /**
         * @brief Inserts or replaces a folder and persists.
         *
         * @param folder The encrypted folder
         */
        void putFolder(Json folder);

        /**
         * @brief Removes a folder and persists.
         *
         * @param id The folder id
         * @param queue_remote_delete Remember to delete it on the server at the next sync
         */
        void removeFolder(std::string_view id, bool queue_remote_delete);

        /**
         * @brief Records in a top-level array of the sync response (e.g. "sends").
         *
         * @param section The array's key
         * @return Its object entries
         */
        std::vector<Record> getSectionRecords(std::string_view section) const;

        /**
         * @brief Inserts or replaces a record (by id) in a top-level array, and persists.
         *
         * @param section The array's key
         * @param record The record
         */
        void putSectionRecord(std::string_view section, Json record);

        /**
         * @brief Removes a record (by id) from a top-level array, and persists.
         *
         * @param section The array's key
         * @param id The record id
         */
        void removeSectionRecord(std::string_view section, std::string_view id);

        /**
         * @brief All collections from the last sync.
         *
         * @return The collection records
         */
        std::vector<Record> getCollections() const;

        /**
         * @brief Inserts or replaces a collection (after creating or renaming it online).
         *
         * @param collection The collection JSON
         */
        void putCollection(Json collection);

        /**
         * @brief Removes a collection and drops it from every cipher's collectionIds.
         *
         * @param id The collection id
         */
        void removeCollection(std::string_view id);

        /**
         * @brief Cipher ids deleted locally but not yet on the server.
         *
         * @return The ids
         */
        std::vector<SecureString> getPendingCipherDeletes() const;

        /**
         * @brief Folder ids deleted locally but not yet on the server.
         *
         * @return The ids
         */
        std::vector<SecureString> getPendingFolderDeletes() const;

        /**
         * @brief Marks a queued cipher delete as done.
         *
         * @param id The cipher id
         */
        void clearPendingCipherDelete(std::string_view id);

        /**
         * @brief Marks a queued folder delete as done.
         *
         * @param id The folder id
         */
        void clearPendingFolderDelete(std::string_view id);

        /**
         * @brief Takes a snapshot of ciphers and folders.
         *
         * @return The snapshot
         */
        Snapshot takeSnapshot() const;

        /**
         * @brief Commits a sync result.
         *
         * Records that differ from `before` were added, edited or deleted during the sync and
         * are kept as they are now.
         *
         * @param before The snapshot the sync started from
         * @param remote The server's sync response (ciphers/folders members are ignored)
         * @param ciphers The merged ciphers
         * @param folders The merged folders
         */
        void applySync(const Snapshot& before, Json remote, std::vector<Record> ciphers,
                std::vector<Record> folders);

    private:
        void persist_();
        void putSectionRecordLocked_(std::string_view section, Json record);
        static void commit_(
                RecordSet& target, const std::vector<Record>& before, std::vector<Record> merged);

        std::shared_ptr<FileStore> m_files_;
        mutable std::shared_mutex m_mutex_;
        Json m_top_level_ = Json::object();
        RecordSet m_ciphers_;
        RecordSet m_folders_;
        std::unordered_set<SecureString, SecureStringHash, std::equal_to<>> m_deleted_ciphers_;
        std::unordered_set<SecureString, SecureStringHash, std::equal_to<>> m_deleted_folders_;
    };
}
