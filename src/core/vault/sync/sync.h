#pragma once
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "vault/features/features.h"
#include "vault/network/network.h"
#include "vault/store/store.h"

namespace clientwarden {
    /**
     * @brief Two-way synchronisation between the local cache and the server.
     *
     * Merge rules (by id, resolved by revisionDate):
     *  - local createdOffline         -> keep, upload as new
     *  - both, local newer            -> keep local, upload as update
     *  - both, remote newer or equal  -> take remote
     *  - local only                   -> deleted remotely, drop
     *  - remote only, not pending del -> add
     */
    class Sync {
    public:
        /**
         * @brief The outcome of merging one record type.
         */
        struct MergeResult {
            std::vector<Record> m_merged;
            std::vector<Record> m_to_create;
            std::vector<Record> m_to_update;
        };

        /**
         * @brief Creates the sync engine.
         *
         * @param network The API client
         * @param store The vault cache
         * @param features For the legacy data format
         */
        Sync(std::shared_ptr<Network> network, std::shared_ptr<Store> store,
                std::shared_ptr<Features> features);

        /**
         * @brief Pure merge of local and remote records; no I/O.
         *
         * @param local The local records
         * @param remote The server's array
         * @param pending_deletes Ids deleted locally but not yet remotely
         * @return The merged set and what to upload
         */
        static MergeResult merge(const std::vector<Record>& local, const Json& remote,
                const std::unordered_set<SecureString, SecureStringHash, std::equal_to<>>&
                        pending_deletes);

        /**
         * @brief Called when the account key changed on the server (password changed elsewhere).
         *
         * @param callback Usually logs the vault out
         */
        void onAccountKeyChanged(std::function<void()> callback);

        /**
         * @brief Called after every committed sync (e.g. to reload organisation keys).
         *
         * @param callback The listener
         */
        void onSynced(std::function<void()> callback);

        /**
         * @brief Bumps the epoch so an in-flight sync won't commit (call on logout).
         */
        void invalidate();

        /**
         * @brief Flushes queued deletes, merges with the server and uploads local changes.
         *
         * @return True if the server was reached and the result committed
         */
        bool run();

    private:
        std::shared_ptr<Network> m_network_;
        std::shared_ptr<Store> m_store_;
        std::shared_ptr<Features> m_features_;
        std::function<void()> m_on_key_changed_;
        std::function<void()> m_on_synced_;

        std::mutex m_run_mutex_;
        std::mutex m_epoch_mutex_;
        uint64_t m_epoch_ = 0;
    };
}
