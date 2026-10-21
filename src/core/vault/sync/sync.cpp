#include "sync.h"

#include <algorithm>
#include <unordered_map>

#include "items/schema/schema.h"
#include "utils/logger/logger.h"
#include "utils/timestamp/timestamp.h"

namespace clientwarden {
    namespace {
        using IdSet = std::unordered_set<SecureString, SecureStringHash, std::equal_to<>>;

        /**
         * @brief The string id of a record.
         *
         * @param record A cipher or folder
         * @return The id, or empty
         */
        SecureString idOf_(const Json& record) {
            return stringAt(record, "id");
        }

        /**
         * @brief When a record was last changed.
         *
         * @param record A cipher or folder
         * @return Seconds since the epoch, or 0
         */
        std::time_t revisionOf_(const Json& record) {
            return timestamp::parse(stringAt(record, "revisionDate"));
        }

        /**
         * @brief Whether a record hasn't reached the server yet.
         *
         * @param record A cipher or folder
         * @return True if created offline
         */
        bool createdOffline_(const Json& record) {
            const Json& flag = at(record, "createdOffline");
            return flag.is_boolean() && flag.get<bool>();
        }

        /**
         * @brief Swaps one record in a merged list for the server's copy.
         *
         * @param records The merged list
         * @param old The record that was uploaded
         * @param replacement The server's response
         */
        void replace_(std::vector<Record>& records, Record old, Json replacement) {
            std::vector<Record>::iterator it = std::find(records.begin(), records.end(), old);
            if (it != records.end()) {
                *it = std::make_shared<const Json>(std::move(replacement));
            }
        }

        /**
         * @brief Builds a set from a list of ids.
         *
         * @param ids The ids
         * @return The set
         */
        IdSet toSet_(const std::vector<SecureString>& ids) {
            return IdSet(ids.begin(), ids.end());
        }
    }

    Sync::Sync(std::shared_ptr<Network> network, std::shared_ptr<Store> store,
            std::shared_ptr<Features> features)
        : m_network_(std::move(network)), m_store_(std::move(store)),
          m_features_(std::move(features)) {}

    Sync::MergeResult Sync::merge(
            const std::vector<Record>& local, const Json& remote, const IdSet& pending_deletes) {
        std::unordered_map<SecureString, size_t, SecureStringHash, std::equal_to<>> remote_by_id;
        std::vector<SecureString> remote_order;
        if (remote.is_array()) {
            for (size_t i = 0; i < remote.size(); ++i) {
                SecureString id = idOf_(remote[i]);
                if (!id.empty() && remote_by_id.emplace(id, i).second) {
                    remote_order.push_back(std::move(id));
                }
            }
        }

        MergeResult out;
        IdSet seen;
        for (const Record& record : local) {
            SecureString id = idOf_(*record);
            if (id.empty() || !seen.insert(id).second) {
                continue;
            }

            if (createdOffline_(*record)) {
                out.m_merged.push_back(record);
                out.m_to_create.push_back(record);
                continue;
            }

            std::unordered_map<SecureString, size_t, SecureStringHash, std::equal_to<>>::iterator
                    match = remote_by_id.find(id);
            if (match == remote_by_id.end()) {
                continue; // deleted on the server
            }

            const Json& server_copy = remote[match->second];
            if (revisionOf_(*record) > revisionOf_(server_copy)) {
                out.m_merged.push_back(record);
                out.m_to_update.push_back(record);
            } else {
                out.m_merged.push_back(std::make_shared<const Json>(server_copy));
            }
        }

        for (const SecureString& id : remote_order) {
            if (!seen.contains(id) && !pending_deletes.contains(id)) {
                out.m_merged.push_back(std::make_shared<const Json>(remote[remote_by_id[id]]));
            }
        }
        return out;
    }

    void Sync::onAccountKeyChanged(std::function<void()> callback) {
        std::lock_guard<std::mutex> lock(m_epoch_mutex_);
        m_on_key_changed_ = std::move(callback);
    }

    void Sync::invalidate() {
        std::lock_guard<std::mutex> lock(m_epoch_mutex_);
        ++m_epoch_;
    }

    bool Sync::run() {
        std::lock_guard<std::mutex> serial(m_run_mutex_);
        uint64_t start_epoch = 0;
        {
            std::lock_guard<std::mutex> lock(m_epoch_mutex_);
            start_epoch = m_epoch_;
        }

        for (const SecureString& id : m_store_->getPendingFolderDeletes()) {
            if (m_network_->deleteFolder(id)) {
                m_store_->clearPendingFolderDelete(id);
            }
        }
        for (const SecureString& id : m_store_->getPendingCipherDeletes()) {
            if (m_network_->deleteCipher(id)) {
                m_store_->clearPendingCipherDelete(id);
            }
        }

        /*
         * Snapshot before fetching: anything saved while the request is in flight is then
         * newer than the snapshot and survives the merge, rather than looking like it was
         * deleted on the server (it's missing from the response).
         */
        Store::Snapshot before = m_store_->takeSnapshot();
        IdSet pending_folders = toSet_(m_store_->getPendingFolderDeletes());
        IdSet pending_ciphers = toSet_(m_store_->getPendingCipherDeletes());

        std::optional<Json> remote = m_network_->getSync();
        if (!remote || !remote->is_object()) {
            return false;
        }

        /*
         * A different user key means the password or account changed on another device;
         * everything cached here is now stale.
         */
        SecureString local_key = stringAt(m_store_->getProfile(), "key");
        const Json& profile = at(*remote, "profile");
        if (!local_key.empty() && profile.is_object() && stringAt(profile, "key") != local_key) {
            Logger::get()->warn("Account key changed remotely");
            std::function<void()> callback;
            {
                std::lock_guard<std::mutex> lock(m_epoch_mutex_);
                callback = m_on_key_changed_;
            }
            if (callback) {
                callback();
            }
            return false;
        }

        MergeResult folders = merge(before.m_folders, at(*remote, "folders"), pending_folders);
        std::unordered_map<SecureString, SecureString, SecureStringHash, std::equal_to<>>
                folder_id_remap;
        for (const Record& folder : folders.m_to_create) {
            std::optional<Json> created = m_network_->createFolder(stringAt(*folder, "name"));
            if (created) {
                folder_id_remap[idOf_(*folder)] = idOf_(*created);
                replace_(folders.m_merged, folder, std::move(*created));
            }
        }
        for (const Record& folder : folders.m_to_update) {
            std::optional<Json> updated =
                    m_network_->updateFolder(idOf_(*folder), stringAt(*folder, "name"));
            if (updated) {
                replace_(folders.m_merged, folder, std::move(*updated));
            }
        }

        /*
         * Ciphers filed under a folder that was just uploaded need its server-assigned id.
         */
        std::vector<Record> local_ciphers = before.m_ciphers;
        if (!folder_id_remap.empty()) {
            for (Record& cipher : local_ciphers) {
                SecureString folder_id = stringAt(*cipher, "folderId");
                std::unordered_map<SecureString, SecureString, SecureStringHash,
                        std::equal_to<>>::iterator remapped = folder_id_remap.find(folder_id);
                if (remapped != folder_id_remap.end()) {
                    Json copy = *cipher;
                    copy["folderId"] = remapped->second;
                    cipher = std::make_shared<const Json>(std::move(copy));
                }
            }
        }

        MergeResult ciphers = merge(local_ciphers, at(*remote, "ciphers"), pending_ciphers);
        bool legacy = m_features_->needsLegacyData();
        SecureString user_id = stringAt(at(*remote, "profile"), "id");
        for (const Record& cipher : ciphers.m_to_create) {
            std::optional<Json> created =
                    m_network_->createCipher(Schema::wireFormat(*cipher, legacy, user_id));
            if (created) {
                replace_(ciphers.m_merged, cipher, std::move(*created));
            }
        }
        for (const Record& cipher : ciphers.m_to_update) {
            std::optional<Json> updated =
                    m_network_->updateCipher(Schema::wireFormat(*cipher, legacy, user_id));
            if (updated) {
                replace_(ciphers.m_merged, cipher, std::move(*updated));
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_epoch_mutex_);
            if (m_epoch_ != start_epoch) {
                return false; // logged out while we were talking to the server
            }
            m_store_->applySync(before, std::move(*remote), std::move(ciphers.m_merged),
                    std::move(folders.m_merged));
        }

        if (!m_features_->versionKnown()) {
            std::optional<Json> config = m_network_->getConfig();
            if (config) {
                m_features_->applyConfig(*config);
            }
        }
        if (m_on_synced_) {
            m_on_synced_();
        }
        return true;
    }

    void Sync::onSynced(std::function<void()> callback) {
        m_on_synced_ = std::move(callback);
    }
}
