#include "generic_item.h"

#include <algorithm>

#include "utils/errors/errors.h"
#include "utils/timestamp/timestamp.h"
#include "utils/uuid/uuid.h"
#include "vault/orchestrator/orchestrator.h"

namespace clientwarden {
    namespace {
        constexpr size_t c_max_password_history = 5;

        /**
         * @brief Reads a timestamp member.
         *
         * @param object The JSON object
         * @param key The member name
         * @return Seconds since the epoch, or 0 if absent or not a string
         */
        std::time_t timeOf_(const Json& object, std::string_view key) {
            const Json& value = at(object, key);
            return value.is_string() ? timestamp::parse(value.get_ref<const SecureString&>()) : 0;
        }

        /**
         * @brief Re-encrypts every encrypted string under `node` from one key to another,
         * leaving ids, dates and other plaintext untouched.
         *
         * @param node The JSON subtree to rewrite
         * @param crypto For decrypting and encrypting
         * @param from The key the values are currently under
         * @param to The key to move them to
         */
        void rekey_(Json& node, Crypto& crypto, SymmetricKey from, SymmetricKey to) {
            if (node.is_string()) {
                const SecureString& value = node.get_ref<const SecureString&>();
                if (crypto.isEncString(value)) {
                    node = crypto.encrypt(crypto.decrypt(value, from), to);
                }
            } else if (node.is_structured()) {
                for (Json& child : node) {
                    rekey_(child, crypto, from, to);
                }
            }
        }
    }

    GenericItem::GenericItem(std::shared_ptr<Orchestrator> orchestrator,
            std::shared_ptr<Crypto> crypto, Json cipher, SymmetricKey item_key)
        : m_orchestrator_(std::move(orchestrator)), m_crypto_(std::move(crypto)),
          m_data_(std::move(cipher)), m_key_(std::move(item_key)) {
        if (!m_data_.is_object()) {
            throw VaultError("cipher must be a JSON object");
        }
    }

    Json GenericItem::createJson(CipherType type, std::shared_ptr<Crypto> crypto,
            SymmetricKey user_key, SymmetricKey& item_key) {
        std::optional<TypeSchema> schema = Schema::forType(type);
        if (!schema) {
            throw VaultError("cannot create an item of unknown type");
        }

        item_key = SymmetricKey::generate();

        // clang-format off
        Json cipher = {
            { "id", uuid::generate() },
            { "type", static_cast<int>(type) },
            { "key", crypto->wrapKey(item_key, user_key) },
            { "name", crypto->encryptText("", item_key) },
            { "notes", nullptr },
            { "folderId", nullptr },
            { "organizationId", nullptr },
            { "collectionIds", Json::array() },
            { "favorite", false },
            { "reprompt", 0 },
            { "fields", Json::array() },
            { "passwordHistory", Json::array() },
            { "attachments", nullptr },
            { "creationDate", timestamp::now() },
            { "revisionDate", nullptr },
            { "deletedDate", nullptr },
            { "archivedDate", nullptr },
            { "edit", true },
            { "viewPassword", true },
            { "permissions", { { "delete", true }, { "restore", true } } },
            { "object", "cipherDetails" },
        };
        // clang-format on

        for (const TypeSchema& other : Schema::all()) {
            cipher[SecureString(other.m_section)] = nullptr;
        }

        Json section = Json::object();
        for (const FieldId& field : schema->m_fields) {
            section[SecureString(field.m_key)] =
                    schema->m_initial_value
                            ? Json(crypto->encryptText(*schema->m_initial_value, item_key))
                            : Json();
        }
        if (type == CipherType::Login) {
            section["uris"] = Json::array();
            section["uri"] = nullptr;
            section["passwordRevisionDate"] = nullptr;
            section["fido2Credentials"] = nullptr;
            section["autofillOnPageLoad"] = nullptr;
        } else if (type == CipherType::Note) {
            section["type"] = 0;
        }
        cipher[SecureString(schema->m_section)] = std::move(section);
        return cipher;
    }

    SecureString GenericItem::getId() const {
        return stringAt(m_data_, "id");
    }

    CipherType GenericItem::getType() const {
        return Schema::typeOf(m_data_);
    }

    SecureString GenericItem::getName() const {
        return decrypt_(at(m_data_, "name"));
    }

    SecureString GenericItem::getNotes() const {
        return decrypt_(at(m_data_, "notes"));
    }

    std::optional<SecureString> GenericItem::getFolderId() const {
        const Json& folder = at(m_data_, "folderId");
        if (!folder.is_string() || folder.get_ref<const SecureString&>().empty()) {
            return std::nullopt;
        }
        return folder.get<SecureString>();
    }

    bool GenericItem::getFavorite() const {
        const Json& favorite = at(m_data_, "favorite");
        return favorite.is_boolean() && favorite.get<bool>();
    }

    bool GenericItem::getReprompt() const {
        const Json& reprompt = at(m_data_, "reprompt");
        return reprompt.is_number_integer() && reprompt.get<int>() == 1;
    }

    std::time_t GenericItem::getCreationDate() const {
        return timeOf_(m_data_, "creationDate");
    }

    std::time_t GenericItem::getRevisionDate() const {
        return timeOf_(m_data_, "revisionDate");
    }

    std::time_t GenericItem::getDeletionDate() const {
        return timeOf_(m_data_, "deletedDate");
    }

    std::time_t GenericItem::getArchivedDate() const {
        return timeOf_(m_data_, "archivedDate");
    }

    std::vector<GenericItem::CustomField> GenericItem::getFields() const {
        std::vector<CustomField> out;
        const Json& fields = at(m_data_, "fields");
        if (!fields.is_array()) {
            return out;
        }

        for (const Json& field : fields) {
            const Json& type_value = at(field, "type");
            if (!type_value.is_number_integer()) {
                continue;
            }
            CustomFieldType type = static_cast<CustomFieldType>(type_value.get<int>());
            SecureString value;
            if (type == CustomFieldType::Linked) {
                const Json& linked = at(field, "linkedId");
                if (linked.is_number_integer()) {
                    value = toSecureString(linked.get<std::int64_t>());
                }
            } else {
                value = decrypt_(at(field, "value"));
            }
            out.push_back(CustomField { type, decrypt_(at(field, "name")), std::move(value) });
        }
        return out;
    }

    std::vector<GenericItem::Attachment> GenericItem::getAttachments() const {
        std::vector<Attachment> out;
        const Json& attachments = at(m_data_, "attachments");
        if (!attachments.is_array()) {
            return out;
        }

        for (const Json& attachment : attachments) {
            const Json& id = at(attachment, "id");
            if (!id.is_string()) {
                continue;
            }
            const Json& size = at(attachment, "size");
            SecureString size_text = size.is_string()   ? size.get<SecureString>()
                                     : size.is_number() ? size.dump()
                                                        : SecureString();
            out.push_back(Attachment {
                    id.get<SecureString>(), decrypt_(at(attachment, "fileName")), size_text });
        }
        return out;
    }

    GenericItem& GenericItem::setName(std::string_view name) {
        m_data_["name"] = encrypt_(name);
        return *this;
    }

    GenericItem& GenericItem::setNotes(std::string_view notes) {
        m_data_["notes"] = notes.empty() ? Json() : encrypt_(notes);
        return *this;
    }

    GenericItem& GenericItem::setFolder(std::string_view folder_id) {
        m_data_["folderId"] = folder_id.empty() ? Json() : Json(SecureString(folder_id));
        return *this;
    }

    GenericItem& GenericItem::removeFolder() {
        m_data_["folderId"] = nullptr;
        return *this;
    }

    GenericItem& GenericItem::addField(
            CustomFieldType type, std::string_view name, std::string_view value) {
        // clang-format off
        Json field = {
            { "type", static_cast<int>(type) },
            { "name", encrypt_(name) },
            { "value", nullptr },
            { "linkedId", nullptr }
        };
        // clang-format on
        if (type == CustomFieldType::Linked) {
            std::int64_t linked = 0;
            if (!parseInt(value, linked)) {
                throw VaultError("linked field value must be a numeric id");
            }
            field["linkedId"] = linked;
        } else {
            field["value"] = encrypt_(value);
        }

        Json& fields = m_data_["fields"];
        if (!fields.is_array()) {
            fields = Json::array();
        }
        fields.push_back(std::move(field));
        return *this;
    }

    GenericItem& GenericItem::removeField(std::string_view name) {
        Json& fields = m_data_["fields"];
        if (!fields.is_array()) {
            return *this;
        }
        for (Json::iterator it = fields.begin(); it != fields.end(); ++it) {
            if (decrypt_(at(*it, "name")) == name) {
                fields.erase(it);
                break;
            }
        }
        return *this;
    }

    GenericItem& GenericItem::clearFields() {
        m_data_["fields"] = Json::array();
        return *this;
    }

    GenericItem& GenericItem::setFavorite(bool favorite) {
        m_data_["favorite"] = favorite;
        return *this;
    }

    GenericItem& GenericItem::setReprompt(bool reprompt) {
        m_data_["reprompt"] = reprompt ? 1 : 0;
        return *this;
    }

    namespace {
        /**
         * @brief Throws unless an item has an orchestrator to perform vault operations.
         *
         * @param orchestrator The item's orchestrator
         * @return The orchestrator
         */
        Orchestrator& require_(std::shared_ptr<Orchestrator> orchestrator) {
            if (!orchestrator) {
                throw VaultError("item is not attached to a vault");
            }
            return *orchestrator;
        }
    }

    bool GenericItem::commit() {
        return require_(m_orchestrator_).saveItem(*this);
    }

    bool GenericItem::remove() {
        return require_(m_orchestrator_).deleteItem(*this);
    }

    bool GenericItem::bin() {
        return require_(m_orchestrator_).binItem(*this);
    }

    bool GenericItem::restore() {
        return require_(m_orchestrator_).restoreItem(*this);
    }

    bool GenericItem::archive() {
        return require_(m_orchestrator_).archiveItem(*this);
    }

    bool GenericItem::unarchive() {
        return require_(m_orchestrator_).unarchiveItem(*this);
    }

    SecureString GenericItem::duplicate() {
        return require_(m_orchestrator_).duplicateItem(*this);
    }

    std::optional<SecureString> GenericItem::addAttachment(std::string_view file_name,
            std::span<const uint8_t> content, std::function<void(float)> on_progress) {
        return require_(m_orchestrator_)
                .addAttachment(*this, file_name, content, std::move(on_progress));
    }

    bool GenericItem::removeAttachment(std::string_view attachment_id) {
        return require_(m_orchestrator_).removeAttachment(*this, attachment_id);
    }

    bool GenericItem::downloadAttachment(std::string_view attachment_id,
            std::filesystem::path destination, std::function<void(float)> on_progress) {
        return require_(m_orchestrator_)
                .downloadAttachment(
                        *this, attachment_id, std::move(destination), std::move(on_progress));
    }

    Json GenericItem::getJson() const {
        return m_data_;
    }

    SymmetricKey GenericItem::getKey() const {
        return m_key_;
    }

    void GenericItem::replaceJson(Json cipher) {
        if (!cipher.is_object()) {
            throw VaultError("cipher must be a JSON object");
        }
        m_data_ = std::move(cipher);
    }

    void GenericItem::touch() {
        m_data_["revisionDate"] = timestamp::now();
    }

    void GenericItem::markDeleted(bool deleted) {
        m_data_["deletedDate"] = deleted ? Json(timestamp::now()) : Json();
    }

    void GenericItem::markArchived(bool archived) {
        m_data_["archivedDate"] = archived ? Json(timestamp::now()) : Json();
    }

    Json GenericItem::duplicateJson(SymmetricKey user_key) const {
        SymmetricKey new_key = SymmetricKey::generate();

        Json copy = m_data_;
        copy["id"] = uuid::generate();
        copy["key"] = m_crypto_->wrapKey(new_key, user_key);
        copy["creationDate"] = timestamp::now();
        copy["revisionDate"] = nullptr;
        copy["passwordHistory"] = Json::array();
        copy["attachments"] = nullptr;
        copy["deletedDate"] = nullptr;
        copy["archivedDate"] = nullptr;
        copy.erase("createdOffline");
        copy.erase("data");

        std::optional<TypeSchema> schema = Schema::forType(getType());
        if (schema) {
            SecureString section(schema->m_section);
            if (getType() == CipherType::Login && copy[section].is_object()) {
                copy[section]["fido2Credentials"] = nullptr;
            }
            rekey_(copy[section], *m_crypto_, m_key_, new_key);
        }
        for (std::string_view field : { std::string_view("name"), std::string_view("notes"),
                     std::string_view("fields") }) {
            rekey_(copy[SecureString(field)], *m_crypto_, m_key_, new_key);
        }
        return copy;
    }

    SecureString GenericItem::getField_(FieldId field) const {
        requireType_(field.m_type, field.m_key);
        return decrypt_(at(constSection_(), field.m_key));
    }

    void GenericItem::setField_(FieldId field, std::string_view value) {
        requireType_(field.m_type, field.m_key);
        Json& section = section_();
        SecureString key(field.m_key);

        if (field == fields::login::c_password) {
            /*
             * Remember the previous password, as Bitwarden clients do.
             */
            Json old = at(section, key);
            if (old.is_string() && decrypt_(old) != value) {
                Json& history = m_data_["passwordHistory"];
                if (!history.is_array()) {
                    history = Json::array();
                }
                history.insert(history.begin(), Json::object({ { "lastUsedDate", timestamp::now() },
                                                        { "password", old } }));
                if (history.size() > c_max_password_history) {
                    history.erase(history.begin() + c_max_password_history, history.end());
                }
                section["passwordRevisionDate"] = timestamp::now();
            }
        }

        bool nullable = !Schema::forType(field.m_type)->m_initial_value;
        section[key] = value.empty() && nullable ? Json() : encrypt_(value);
    }

    SecureString GenericItem::decrypt_(const Json& value) const {
        if (!value.is_string()) {
            return SecureString();
        }
        try {
            return m_crypto_->decryptText(value.get_ref<const SecureString&>(), m_key_);
        } catch (const CryptoError&) {
            if (m_orchestrator_) {
                m_orchestrator_->reportIntegrityFailure("item field failed authentication");
            }
            throw;
        }
    }

    Json GenericItem::encrypt_(std::string_view value) const {
        return m_crypto_->encryptText(value, m_key_);
    }

    Json& GenericItem::section_() {
        std::optional<TypeSchema> schema = Schema::forType(getType());
        if (!schema) {
            throw VaultError("item has no type-specific fields");
        }
        Json& section = m_data_[SecureString(schema->m_section)];
        if (!section.is_object()) {
            section = Json::object();
        }
        return section;
    }

    const Json& GenericItem::constSection_() const {
        std::optional<TypeSchema> schema = Schema::forType(getType());
        if (!schema) {
            static const Json c_null;
            return c_null;
        }
        return at(m_data_, schema->m_section);
    }

    void GenericItem::requireType_(CipherType type, std::string_view what) const {
        if (getType() != type) {
            throw VaultError(SecureString(what) + " is not available for this item type");
        }
    }

    std::optional<SecureString> GenericItem::getOrganizationId() const {
        const Json& organization = at(m_data_, "organizationId");
        if (!organization.is_string()) {
            return std::nullopt;
        }
        return organization.get<SecureString>();
    }

    std::vector<SecureString> GenericItem::getCollectionIds() const {
        std::vector<SecureString> ids;
        for (const Json& id : at(m_data_, "collectionIds")) {
            if (id.is_string()) {
                ids.push_back(id.get<SecureString>());
            }
        }
        return ids;
    }

    bool GenericItem::canEdit() const {
        const Json& edit = at(m_data_, "edit");
        return !edit.is_boolean() || edit.get<bool>();
    }

    bool GenericItem::canViewPassword() const {
        const Json& view = at(m_data_, "viewPassword");
        return !view.is_boolean() || view.get<bool>();
    }

    bool GenericItem::shareTo(
            std::string_view organization_id, std::vector<SecureString> collection_ids) {
        if (!m_orchestrator_) {
            throw VaultError("item is not attached to a vault");
        }
        return m_orchestrator_->shareItem(*this, organization_id, std::move(collection_ids));
    }

    bool GenericItem::setCollections(std::vector<SecureString> collection_ids) {
        if (!m_orchestrator_) {
            throw VaultError("item is not attached to a vault");
        }
        return m_orchestrator_->updateItemCollections(*this, std::move(collection_ids));
    }

    Json GenericItem::sharedJson(std::string_view organization_id, SymmetricKey organization_key,
            std::vector<SecureString> collection_ids) const {
        Json shared = m_data_;
        shared.erase("createdOffline");
        shared["organizationId"] = SecureString(organization_id);
        shared["collectionIds"] = collection_ids;

        if (at(m_data_, "key").is_string()) {
            shared["key"] = m_crypto_->wrapKey(m_key_, organization_key);
            return shared;
        }

        /*
         * Legacy item encrypted with the user key: move everything under a new item key.
         */
        SymmetricKey new_key = SymmetricKey::generate();
        shared["key"] = m_crypto_->wrapKey(new_key, organization_key);

        std::optional<TypeSchema> schema = Schema::forType(getType());
        if (schema) {
            rekey_(shared[SecureString(schema->m_section)], *m_crypto_, m_key_, new_key);
        }
        for (std::string_view field : { std::string_view("name"), std::string_view("notes"),
                     std::string_view("fields"), std::string_view("passwordHistory") }) {
            rekey_(shared[SecureString(field)], *m_crypto_, m_key_, new_key);
        }

        Json& attachments = shared["attachments"];
        if (attachments.is_array()) {
            for (Json& attachment : attachments) {
                SecureString wrapped = stringAt(attachment, "key");
                if (wrapped.empty()) {
                    throw VaultError("an attachment is too old to move; re-upload it first");
                }
                attachment["key"] =
                        m_crypto_->wrapKey(m_crypto_->unwrapKey(wrapped, m_key_), new_key);
                rekey_(attachment["fileName"], *m_crypto_, m_key_, new_key);
            }

            /*
             * The share endpoint updates attachment metadata from "attachments2".
             */
            Json updated = Json::object();
            for (const Json& attachment : attachments) {
                updated[stringAt(attachment, "id")] = { { "fileName", at(attachment, "fileName") },
                    { "key", at(attachment, "key") } };
            }
            shared["attachments2"] = updated;
        }
        return shared;
    }
}
