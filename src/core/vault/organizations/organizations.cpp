#include "organizations.h"

#include <algorithm>

#include "utils/errors/errors.h"
#include "utils/logger/logger.h"

namespace clientwarden {
    namespace {
        /**
         * @brief Reads a boolean member, defaulting to false.
         *
         * @param object The JSON object
         * @param key The member name
         * @return The value
         */
        bool flag_(const Json& object, std::string_view key) {
            const Json& value = at(object, key);
            return value.is_boolean() && value.get<bool>();
        }

        /**
         * @brief Whether an organisation membership grants collection management.
         *
         * @param organization The profile's organisation entry
         * @return True for owners and admins, or custom roles with the permission
         */
        bool canManageCollections_(const Json& organization) {
            const Json& type = at(organization, "type");
            int role = type.is_number_integer() ? type.get<int>()
                                                : static_cast<int>(OrganizationRole::User);
            if (role == static_cast<int>(OrganizationRole::Owner) ||
                    role == static_cast<int>(OrganizationRole::Admin)) {
                return true;
            }
            const Json& permissions = at(organization, "permissions");
            return flag_(permissions, "createNewCollections") ||
                   flag_(permissions, "editAnyCollection") ||
                   flag_(permissions, "deleteAnyCollection");
        }
    }

    Organizations::Organizations(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network,
            std::shared_ptr<Store> store, std::shared_ptr<Session> session)
        : m_crypto_(std::move(crypto)), m_network_(std::move(network)), m_store_(std::move(store)),
          m_session_(std::move(session)) {}

    size_t Organizations::loadKeys() {
        SymmetricKey user_key = m_session_->getUserKey();
        Json profile = m_store_->getProfile();

        std::map<SecureString, SymmetricKey, std::less<>> keys;
        SecureString wrapped_private_key = stringAt(profile, "privateKey");
        if (wrapped_private_key.empty()) {
            m_session_->setOrganizationKeys(std::move(keys));
            return 0;
        }

        SecureBytes private_key;
        try {
            private_key = m_crypto_->decrypt(wrapped_private_key, user_key);
        } catch (const CryptoError&) {
            Logger::get()->error("The account private key failed to decrypt");
            m_session_->setOrganizationKeys(std::move(keys));
            return 0;
        }

        for (const Json& organization : at(profile, "organizations")) {
            SecureString id = stringAt(organization, "id");
            SecureString wrapped = stringAt(organization, "key");
            if (id.empty() || wrapped.empty()) {
                continue;
            }
            try {
                keys.insert_or_assign(id,
                        SymmetricKey::fromCombined(m_crypto_->rsaDecrypt(wrapped, private_key)));
            } catch (const CryptoError&) {
                Logger::get()->warn("An organisation key failed to decrypt");
            }
        }

        size_t count = keys.size();
        m_session_->setOrganizationKeys(std::move(keys));
        return count;
    }

    std::vector<OrganizationInfo> Organizations::getOrganizations() {
        std::vector<OrganizationInfo> organizations;
        Json profile = m_store_->getProfile(); // keep alive: the loop refers into it
        for (const Json& organization : at(profile, "organizations")) {
            SecureString id = stringAt(organization, "id");
            if (id.empty()) {
                continue;
            }
            const Json& type = at(organization, "type");
            const Json& enabled = at(organization, "enabled");
            organizations.push_back(OrganizationInfo { id, stringAt(organization, "name"),
                    type.is_number_integer() ? static_cast<OrganizationRole>(type.get<int>())
                                             : OrganizationRole::User,
                    !enabled.is_boolean() || enabled.get<bool>(),
                    canManageCollections_(organization),
                    m_session_->getOrganizationKey(id).has_value() });
        }
        return organizations;
    }

    std::vector<CollectionInfo> Organizations::getCollections(std::string_view organization_id) {
        std::vector<CollectionInfo> collections;
        for (Record& record : m_store_->getCollections()) {
            SecureString organization = stringAt(*record, "organizationId");
            if (!organization_id.empty() && organization != organization_id) {
                continue;
            }
            std::optional<SymmetricKey> key = m_session_->getOrganizationKey(organization);
            if (!key) {
                continue;
            }

            SecureString name;
            try {
                name = m_crypto_->decryptText(stringAt(*record, "name"), *key);
            } catch (const CryptoError&) {
                Logger::get()->warn("Skipping a collection whose name failed to decrypt");
                continue;
            }
            collections.push_back(CollectionInfo { stringAt(*record, "id"), organization, name,
                    flag_(*record, "readOnly"), flag_(*record, "hidePasswords"),
                    flag_(*record, "manage") });
        }

        std::sort(collections.begin(), collections.end(),
                [](const CollectionInfo& a, const CollectionInfo& b) {
                    return a.m_name < b.m_name;
                });
        return collections;
    }

    Json Organizations::organizationJson_(std::string_view organization_id) {
        Json profile = m_store_->getProfile(); // keep alive: the loop refers into it
        for (const Json& organization : at(profile, "organizations")) {
            if (stringAt(organization, "id") == organization_id) {
                return organization;
            }
        }
        throw VaultError("not a member of that organisation");
    }

    SymmetricKey Organizations::requireKey_(std::string_view organization_id) {
        std::optional<SymmetricKey> key = m_session_->getOrganizationKey(organization_id);
        if (!key) {
            throw VaultError("organisation key unavailable");
        }
        return *key;
    }

    Json Organizations::collectionJson_(std::string_view collection_id) {
        for (Record& record : m_store_->getCollections()) {
            if (stringAt(*record, "id") == collection_id) {
                return *record;
            }
        }
        throw VaultError("collection not found");
    }

    std::optional<SecureString> Organizations::createCollection(
            std::string_view organization_id, std::string_view name) {
        Json organization = organizationJson_(organization_id);
        if (!canManageCollections_(organization)) {
            throw VaultError("you can't manage collections in that organisation");
        }

        SecureString encrypted = m_crypto_->encryptText(name, requireKey_(organization_id));
        std::optional<Json> created = m_network_->createCollection(
                organization_id, encrypted, stringAt(organization, "organizationUserId"));
        if (!created || stringAt(*created, "id").empty()) {
            return std::nullopt;
        }

        Json collection = *created;
        collection["organizationId"] = SecureString(organization_id);
        collection["manage"] = true;
        m_store_->putCollection(collection);
        return stringAt(collection, "id");
    }

    bool Organizations::renameCollection(std::string_view collection_id, std::string_view name) {
        Json collection = collectionJson_(collection_id);
        SecureString organization_id = stringAt(collection, "organizationId");
        SecureString encrypted = m_crypto_->encryptText(name, requireKey_(organization_id));

        std::optional<Json> updated =
                m_network_->renameCollection(organization_id, collection_id, encrypted);
        if (!updated) {
            return false;
        }
        collection["name"] = encrypted;
        m_store_->putCollection(collection);
        return true;
    }

    bool Organizations::deleteCollection(std::string_view collection_id) {
        Json collection = collectionJson_(collection_id);
        if (!m_network_->deleteCollection(stringAt(collection, "organizationId"), collection_id)) {
            return false;
        }
        m_store_->removeCollection(collection_id);
        return true;
    }

    bool Organizations::canEditIn(const std::vector<SecureString>& collection_ids) {
        for (const SecureString& id : collection_ids) {
            try {
                if (flag_(collectionJson_(id), "readOnly")) {
                    return false;
                }
            } catch (const VaultError&) {
                return false;
            }
        }
        return true;
    }
}
