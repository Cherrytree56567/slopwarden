#pragma once
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "vault/crypto/crypto.h"
#include "vault/network/network.h"
#include "vault/session/session.h"
#include "vault/store/store.h"

namespace clientwarden {
    /**
     * @brief A member's role in an organisation.
     * See OrganizationUserType.cs in the Bitwarden server (src/Core/AdminConsole/Enums).
     */
    enum class OrganizationRole { Owner = 0, Admin = 1, User = 2, Custom = 4 };

    /**
     * @brief An organisation the user belongs to.
     */
    struct OrganizationInfo {
        SecureString m_id;
        SecureString m_name;
        OrganizationRole m_role;
        bool m_enabled;
        bool m_can_manage_collections; // create, rename and delete collections
        bool m_key_available;          // false if its key couldn't be decrypted
    };

    /**
     * @brief A collection the user can see.
     */
    struct CollectionInfo {
        SecureString m_id;
        SecureString m_organization_id;
        SecureString m_name;
        bool m_read_only;      // items in it can't be edited
        bool m_hide_passwords; // the UI must not reveal passwords
        bool m_manage;         // the user manages this collection
    };

    /**
     * @brief Organisations, their keys and collections.
     *
     * Each organisation has a symmetric key that the server keeps encrypted to the user's RSA
     * public key. loadKeys() decrypts the user's private key with the user key, then every
     * organisation key with the private key, and hands them to the Session (memory only).
     */
    class Organizations {
    public:
        /**
         * @brief Creates the part.
         *
         * @param crypto Cryptography
         * @param network The API client
         * @param store The vault cache (profile and collections)
         * @param session Holds the user key and receives the organisation keys
         */
        Organizations(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network,
                std::shared_ptr<Store> store, std::shared_ptr<Session> session);

        /**
         * @brief Decrypts the organisation keys into the session (after unlock and each sync).
         *
         * @return The number of organisation keys loaded
         * @throws VaultError if locked
         */
        size_t loadKeys();

        /**
         * @brief The organisations the user belongs to.
         *
         * @return Organisations from the last sync
         */
        std::vector<OrganizationInfo> getOrganizations();

        /**
         * @brief Collections with decrypted names.
         *
         * @param organization_id Only this organisation's, or every organisation's if empty
         * @return The collections the user can see
         */
        std::vector<CollectionInfo> getCollections(std::string_view organization_id);

        /**
         * @brief Creates a collection the user manages.
         *
         * @param organization_id The organisation
         * @param name The collection name
         * @return The new collection's id, or nullopt if the server refused or is unreachable
         * @throws VaultError if the user may not manage collections there
         */
        std::optional<SecureString> createCollection(
                std::string_view organization_id, std::string_view name);

        /**
         * @brief Renames a collection.
         *
         * @param collection_id The collection
         * @param name The new name
         * @return True on success
         */
        bool renameCollection(std::string_view collection_id, std::string_view name);

        /**
         * @brief Deletes a collection (its items stay in the organisation).
         *
         * @param collection_id The collection
         * @return True on success
         */
        bool deleteCollection(std::string_view collection_id);

        /**
         * @brief Whether the user may edit items in all of these collections.
         *
         * @param collection_ids The collections
         * @return False if any of them is read-only for the user
         */
        bool canEditIn(const std::vector<SecureString>& collection_ids);

    private:
        Json organizationJson_(std::string_view organization_id);
        SymmetricKey requireKey_(std::string_view organization_id);
        Json collectionJson_(std::string_view collection_id);

        std::shared_ptr<Crypto> m_crypto_;
        std::shared_ptr<Network> m_network_;
        std::shared_ptr<Store> m_store_;
        std::shared_ptr<Session> m_session_;
    };
}
