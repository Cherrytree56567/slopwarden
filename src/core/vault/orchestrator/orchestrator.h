#pragma once
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "items/cipher_query/cipher_query.h"
#include "items/folder/folder.h"
#include "items/generic_item/generic_item.h"
#include "platform/file_store/file_store.h"
#include "utils/errors/errors.h"
#include "vault/crypto/crypto.h"
#include "vault/features/features.h"
#include "vault/network/network.h"
#include "vault/session/session.h"
#include "vault/store/store.h"
#include "vault/sync/sync.h"

namespace clientwarden {
    /**
     * @brief Coordinates every operation on items and folders.
     *
     * Items and folders are builders; when committed they call back here, and the
     * orchestrator talks to the server (Network) and the local cache (Store). Saves are
     * offline-first: if the server can't be reached the change is kept locally and uploaded by
     * the next sync.
     */
    class Orchestrator : public std::enable_shared_from_this<Orchestrator> {
    public:
        /**
         * @brief Creates the orchestrator.
         *
         * @param crypto Cryptography
         * @param network The API client
         * @param store The vault cache
         * @param session Holds the user key
         * @param features Server capabilities
         * @param sync For background syncs after status changes
         * @param files For downloaded attachments and the icon cache
         */
        Orchestrator(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network,
                std::shared_ptr<Store> store, std::shared_ptr<Session> session,
                std::shared_ptr<Features> features, std::shared_ptr<Sync> sync,
                std::shared_ptr<FileStore> files);

        /**
         * @brief Called when personal data fails authentication (tampering or corruption).
         *
         * @param handler Usually puts the vault into the Failed state
         */
        void onIntegrityFailure(std::function<void(std::string_view)> handler);

        /**
         * @brief Reports an integrity failure to the handler.
         *
         * @param reason What failed (no secrets)
         */
        void reportIntegrityFailure(std::string_view reason);

        /**
         * @brief Called after a change that a sync should follow up on.
         *
         * @param handler Usually queues a background sync
         */
        void onSyncRequested(std::function<void()> handler);

        /**
         * @brief Loads an item as a specific type.
         *
         * @tparam T LoginItem, CardItem, ...
         * @param id The cipher id
         * @return The item
         * @throws VaultError if missing, of another type, or the vault is locked
         */
        template <typename T> std::shared_ptr<T> getItem(std::string_view id) {
            Json cipher = getCipherJson_(id);
            if (Schema::typeOf(cipher) != T::c_type) {
                throw VaultError("item is not of the requested type");
            }
            SymmetricKey key = itemKeyFor_(cipher);
            return std::make_shared<T>(
                    shared_from_this(), m_crypto_, std::move(cipher), std::move(key));
        }

        /**
         * @brief Loads an item with only the shared fields.
         *
         * @param id The cipher id
         * @return The item
         */
        std::shared_ptr<GenericItem> getGenericItem(std::string_view id);

        /**
         * @brief Starts a new, unsaved item (call commit() to save).
         *
         * @tparam T LoginItem, CardItem, ...
         * @return The item
         */
        template <typename T> std::shared_ptr<T> createItem() {
            SymmetricKey key;
            Json cipher =
                    GenericItem::createJson(T::c_type, m_crypto_, m_session_->getUserKey(), key);
            return std::make_shared<T>(
                    shared_from_this(), m_crypto_, std::move(cipher), std::move(key));
        }

        /**
         * @brief An item's type, read from the cache without decrypting anything.
         *
         * @param id The cipher id
         * @return The type, or nullopt if no such item
         */
        std::optional<CipherType> getItemType(std::string_view id);

        /**
         * @brief Starts a new, unsaved item owned by an organisation. Organisation items can
         * only be created online, because the server must place them in collections.
         *
         * @tparam T LoginItem, CardItem, ...
         * @param organization_id The owning organisation
         * @param collection_ids Collections to place it in (at least one)
         * @return The item
         * @throws VaultError if the organisation key isn't available or no collection is given
         */
        template <typename T>
        std::shared_ptr<T> createItem(
                std::string_view organization_id, std::vector<SecureString> collection_ids) {
            if (collection_ids.empty()) {
                throw VaultError("organisation items need at least one collection");
            }
            SymmetricKey key;
            Json cipher = GenericItem::createJson(
                    T::c_type, m_crypto_, organizationKey_(organization_id), key);
            cipher["organizationId"] = SecureString(organization_id);
            cipher["collectionIds"] = collection_ids;
            return std::make_shared<T>(
                    shared_from_this(), m_crypto_, std::move(cipher), std::move(key));
        }

        /**
         * @brief Whether an item exists.
         *
         * @param id The cipher id
         * @return True if cached
         */
        bool hasItem(std::string_view id);

        /**
         * @brief Starts a query over all items.
         *
         * @return The query
         */
        CipherQuery query();

        /**
         * @brief Saves an item.
         *
         * @param item The item
         * @return True once the server has it; false if queued
         */
        bool saveItem(GenericItem& item);

        /**
         * @brief Permanently deletes an item.
         *
         * @param item The item
         * @return True once the server has deleted it; false if queued
         */
        bool deleteItem(GenericItem& item);

        /**
         * @brief Moves an item to the bin.
         *
         * @param item The item
         * @return True once the server has it
         */
        bool binItem(GenericItem& item);

        /**
         * @brief Restores an item from the bin.
         *
         * @param item The item
         * @return True once the server has it
         */
        bool restoreItem(GenericItem& item);

        /**
         * @brief Archives an item.
         *
         * @param item The item
         * @return True once the server has it
         */
        bool archiveItem(GenericItem& item);

        /**
         * @brief Unarchives an item.
         *
         * @param item The item
         * @return True once the server has it
         */
        bool unarchiveItem(GenericItem& item);

        /**
         * @brief Saves a re-encrypted copy of an item.
         *
         * @param item The item to copy
         * @return The copy's id
         */
        SecureString duplicateItem(GenericItem& item);

        /**
         * @brief Moves a personal item into an organisation.
         *
         * @param item The item (must be personal and saved online)
         * @param organization_id The organisation
         * @param collection_ids Collections to place it in (at least one)
         * @return True once the server has it
         */
        bool shareItem(GenericItem& item, std::string_view organization_id,
                std::vector<SecureString> collection_ids);

        /**
         * @brief Replaces an organisation item's collections.
         *
         * @param item The item (must belong to an organisation)
         * @param collection_ids The new collections (at least one)
         * @return True once the server has it
         */
        bool updateItemCollections(GenericItem& item, std::vector<SecureString> collection_ids);

        /**
         * @brief Encrypts and uploads an attachment.
         *
         * @param item The owning item (must be saved online)
         * @param file_name The file name
         * @param content The file contents
         * @param on_progress Upload progress, may be null
         * @return The attachment id, or nullopt
         */
        std::optional<SecureString> addAttachment(GenericItem& item, std::string_view file_name,
                std::span<const uint8_t> content, std::function<void(float)> on_progress);

        /**
         * @brief Deletes an attachment.
         *
         * @param item The owning item
         * @param attachment_id The attachment
         * @return True on success
         */
        bool removeAttachment(GenericItem& item, std::string_view attachment_id);

        /**
         * @brief Downloads and decrypts an attachment.
         *
         * @param item The owning item
         * @param attachment_id The attachment
         * @param destination Where to write it
         * @param on_progress Download progress, may be null
         * @return True on success
         */
        bool downloadAttachment(GenericItem& item, std::string_view attachment_id,
                std::filesystem::path destination, std::function<void(float)> on_progress);

        /**
         * @brief All folders.
         *
         * @return The folders
         */
        std::vector<std::shared_ptr<Folder>> getFolders();

        /**
         * @brief Loads a folder.
         *
         * @param id The folder id
         * @return The folder
         * @throws VaultError if missing
         */
        std::shared_ptr<Folder> getFolder(std::string_view id);

        /**
         * @brief Starts a new, unsaved folder.
         *
         * @return The folder
         */
        std::shared_ptr<Folder> createFolder();

        /**
         * @brief Saves a folder.
         *
         * @param folder The folder
         * @return True once the server has it; false if queued
         */
        bool saveFolder(Folder& folder);

        /**
         * @brief Deletes a folder and moves its items to "no folder".
         *
         * @param folder The folder
         * @return True once the server has deleted it; false if queued
         */
        bool deleteFolder(Folder& folder);

        /**
         * @brief A site's favicon, cached on disk under a hash of its domain.
         *
         * @param url Any URL or bare domain
         * @return The PNG's absolute path, or nullopt
         */
        std::optional<std::filesystem::path> getIcon(std::string_view url);

        /**
         * @brief The bare hostname of a URL, rejecting anything that isn't a plain DNS name.
         *
         * @param url An http(s) URL or bare domain
         * @return The lowercased host, or nullopt
         */
        static std::optional<SecureString> hostName(std::string_view url);

    private:
        Json getCipherJson_(std::string_view id);
        SymmetricKey organizationKey_(std::string_view organization_id);
        std::optional<SymmetricKey> wrappingKeyFor_(const Json& cipher);
        void requireEditable_(GenericItem& item);
        SymmetricKey itemKeyFor_(const Json& cipher);
        bool commitStatus_(GenericItem& item, bool ok);

        std::shared_ptr<Crypto> m_crypto_;
        std::shared_ptr<Network> m_network_;
        std::shared_ptr<Store> m_store_;
        std::shared_ptr<Session> m_session_;
        std::shared_ptr<Features> m_features_;
        std::shared_ptr<Sync> m_sync_;
        std::shared_ptr<FileStore> m_files_;
        std::function<void(std::string_view)> m_on_integrity_failure_;
        std::function<void()> m_on_sync_requested_;
    };
}
