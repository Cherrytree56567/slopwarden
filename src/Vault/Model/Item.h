#pragma once
#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>

#include "Crypto/Crypto.h"
#include "Model/CipherSchema.h"

namespace ClientWarden {
    /*
     * A vault item (Bitwarden "cipher").
     *
     * Item is a self-contained value: it holds the encrypted server JSON
     * plus the item key needed to read and edit it, and never talks to
     * the network or disk. Persisting changes is the Vault's job
     * (Vault::Save, Vault::Delete, ...), which keeps this class pure and
     * unit-testable.
     *
     * Getters decrypt on demand into SecretString; setters encrypt
     * immediately so plaintext is never stored in the model.
    */
    class Item {
    public:
        struct CustomField {
            CustomFieldType type;
            SecretString name;
            SecretString value;     // linked fields hold the linked id
        };

        struct PasswordHistoryEntry {
            std::time_t lastUsed;
            SecretString password;
        };

        struct TotpCode {
            std::string code;
            std::time_t validUntil;
            int period;
        };

        struct Attachment {
            std::string id;
            SecretString fileName;
            std::string size;
        };

        static constexpr size_t MaxPasswordHistory = 5;

        /*
         * New, unsaved item with a freshly generated item key.
        */
        static Item Create(CipherType type, const Crypto::SymmetricKey& userKey);

        /*
         * Wraps an encrypted cipher from the store or server.
        */
        static Item FromJson(nlohmann::json cipher, const Crypto::SymmetricKey& userKey);

        const std::string& Id() const { return id; }
        CipherType Type() const;

        SecretString Name() const;
        void SetName(std::string_view name);
        SecretString Notes() const;
        void SetNotes(std::string_view notes);

        std::optional<std::string> FolderId() const;
        void SetFolderId(std::optional<std::string> folderId);

        bool Favorite() const;
        void SetFavorite(bool favorite);
        bool Reprompt() const;
        void SetReprompt(bool reprompt);

        std::time_t Created() const;
        std::time_t Revised() const;
        std::time_t Deleted() const;    // 0 if not in the bin
        std::time_t Archived() const;   // 0 if not archived

        /*
         * Type-specific fields, e.g. item.Get(Fields::Card::Number).
         * Throws VaultError if the field belongs to another type.
        */
        SecretString Get(FieldId field) const;
        void Set(FieldId field, std::string_view value);

        std::vector<CustomField> CustomFields() const;
        void AddCustomField(CustomFieldType type, std::string_view name, std::string_view value);
        void RemoveCustomField(std::string_view name);
        void ClearCustomFields();

        /*
         * Login only.
        */
        std::vector<SecretString> Uris() const;
        void AddUri(std::string_view uri);
        void RemoveUri(std::string_view uri);
        std::vector<PasswordHistoryEntry> PasswordHistory() const;
        std::optional<TotpCode> Totp(std::time_t now = std::time(nullptr)) const;
        std::vector<std::time_t> PasskeyCreationDates() const;

        std::vector<Attachment> Attachments() const;
        std::optional<Attachment> FindAttachment(std::string_view attachmentId) const;

        /*
         * Copy with a new id and item key, everything re-encrypted, and
         * history, attachments and passkeys dropped (as Bitwarden does).
        */
        Item Duplicate(const Crypto::SymmetricKey& userKey) const;

        /*
         * Body for POST/PUT. includeLegacyData adds the "data" blob that
         * servers older than 2026.6.0 expect.
        */
        nlohmann::json ToWire(bool includeLegacyData) const;
        const nlohmann::json& Json() const { return data; }
        const Crypto::SymmetricKey& Key() const { return key; }

        /*
         * Same as ToWire for a raw stored record; needs no key because the
         * legacy blob is assembled from already-encrypted values.
        */
        static nlohmann::json WireFormat(const nlohmann::json& cipher, bool includeLegacyData);

        /*
         * Used by the Vault after the server assigns an id or returns the
         * canonical record.
        */
        void Replace(nlohmann::json cipher);
        void Touch();
        void MarkDeleted(bool deleted);
        void MarkArchived(bool archived);

    private:
        Item(nlohmann::json cipher, Crypto::SymmetricKey key);

        SecretString Decrypt(const nlohmann::json& value) const;
        nlohmann::json Encrypt(std::string_view value) const;
        nlohmann::json& Section();
        const nlohmann::json* Section() const;
        void RequireType(CipherType type, const char* what) const;

        nlohmann::json data;
        Crypto::SymmetricKey key;
        std::string id;
    };
}
