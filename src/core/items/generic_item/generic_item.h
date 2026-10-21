#pragma once
#include <ctime>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "items/schema/schema.h"
#include "vault/crypto/crypto.h"

namespace clientwarden {
    /*
     * Forward declared to break the cycle Orchestrator -> GenericItem -> Orchestrator: items
     * commit through the orchestrator, which in turn creates items.
     */
    class Orchestrator;

    /**
     * @brief Any vault item (Bitwarden "cipher"): the fields every type shares.
     *
     * Holds the encrypted server JSON and the item key. Getters decrypt on demand; setters
     * encrypt immediately, so plaintext is never stored in the item. Setters only change this
     * object; commit() saves (online if possible, otherwise queued for the next sync).
     *
     * Use a typed subclass (LoginItem, CardItem, ...) for type-specific fields; GenericItem is
     * for code that only needs the shared fields (ADR 5).
     */
    class GenericItem {
    public:
        /**
         * @brief A user-defined field.
         */
        struct CustomField {
            CustomFieldType m_type;
            SecureString m_name;
            SecureString m_value; // for linked fields, the linked field id
        };

        /**
         * @brief Metadata of an attached file.
         */
        struct Attachment {
            SecureString m_id;
            SecureString m_file_name;
            SecureString m_size;
        };

        /**
         * @brief Wraps a stored cipher.
         *
         * @param orchestrator Performs commits and other vault operations
         * @param crypto For decrypting and encrypting fields
         * @param cipher The encrypted cipher JSON
         * @param item_key The cipher's key (already unwrapped)
         */
        GenericItem(std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Crypto> crypto,
                Json cipher, SymmetricKey item_key);

        virtual ~GenericItem() = default;

        /**
         * @brief Builds the JSON for a new, unsaved cipher with a fresh item key.
         *
         * @param type The cipher type
         * @param crypto For generating and wrapping the key
         * @param user_key The account's user key
         * @param item_key Receives the new item key
         * @return The cipher JSON
         * @throws VaultError for Generic/unknown types
         */
        static Json createJson(CipherType type, std::shared_ptr<Crypto> crypto,
                SymmetricKey user_key, SymmetricKey& item_key);

        /**
         * @brief The cipher id.
         *
         * @return The id
         */
        SecureString getId() const;

        /**
         * @brief The cipher type.
         *
         * @return The type, or Generic if unknown
         */
        CipherType getType() const;

        /**
         * @brief The decrypted name.
         *
         * @return The name
         */
        SecureString getName() const;

        /**
         * @brief The decrypted notes.
         *
         * @return The notes, or empty
         */
        SecureString getNotes() const;

        /**
         * @brief The folder the item is filed under.
         *
         * @return The folder id, or nullopt for none
         */
        std::optional<SecureString> getFolderId() const;

        /**
         * @brief Whether the item is a favourite.
         *
         * @return True if favourited
         */
        bool getFavorite() const;

        /**
         * @brief Whether viewing the item requires re-entering the master password.
         *
         * @return True if re-prompt is on
         */
        bool getReprompt() const;

        /**
         * @brief When the item was created.
         *
         * @return Seconds since the epoch, or 0
         */
        std::time_t getCreationDate() const;

        /**
         * @brief When the item was last changed.
         *
         * @return Seconds since the epoch, or 0
         */
        std::time_t getRevisionDate() const;

        /**
         * @brief When the item was moved to the bin.
         *
         * @return Seconds since the epoch, or 0 if not binned
         */
        std::time_t getDeletionDate() const;

        /**
         * @brief When the item was archived.
         *
         * @return Seconds since the epoch, or 0 if not archived
         */
        std::time_t getArchivedDate() const;

        /**
         * @brief The decrypted custom fields.
         *
         * @return The fields in order
         */
        std::vector<CustomField> getFields() const;

        /**
         * @brief The attached files.
         *
         * @return Attachment metadata with decrypted names
         */
        std::vector<Attachment> getAttachments() const;

        /**
         * @brief Sets the name.
         *
         * @param name The new name
         * @return This item, for chaining
         */
        GenericItem& setName(std::string_view name);

        /**
         * @brief Sets the notes (empty clears them).
         *
         * @param notes The new notes
         * @return This item, for chaining
         */
        GenericItem& setNotes(std::string_view notes);

        /**
         * @brief Files the item under a folder (empty for none).
         *
         * @param folder_id The folder id
         * @return This item, for chaining
         */
        GenericItem& setFolder(std::string_view folder_id);

        /**
         * @brief Removes the item from its folder.
         *
         * @return This item, for chaining
         */
        GenericItem& removeFolder();

        /**
         * @brief Appends a custom field.
         *
         * @param type The field kind
         * @param name The field name
         * @param value The value (for linked fields, the numeric linked id)
         * @return This item, for chaining
         * @throws VaultError if a linked value isn't numeric
         */
        GenericItem& addField(CustomFieldType type, std::string_view name, std::string_view value);

        /**
         * @brief Removes the first custom field with this name.
         *
         * @param name The field name
         * @return This item, for chaining
         */
        GenericItem& removeField(std::string_view name);

        /**
         * @brief Removes all custom fields.
         *
         * @return This item, for chaining
         */
        GenericItem& clearFields();

        /**
         * @brief Marks or unmarks as favourite.
         *
         * @param favorite True to favourite
         * @return This item, for chaining
         */
        GenericItem& setFavorite(bool favorite);

        /**
         * @brief Turns master password re-prompt on or off.
         *
         * @param reprompt True to require re-prompt
         * @return This item, for chaining
         */
        GenericItem& setReprompt(bool reprompt);

        /**
         * @brief Saves the item.
         *
         * @return True once the server has it; false if saved locally and queued for sync
         */
        bool commit();

        /**
         * @brief Permanently deletes the item.
         *
         * @return True once the server has deleted it; false if queued
         */
        bool remove();

        /**
         * @brief Moves the item to the bin.
         *
         * @return True once the server has it
         */
        bool bin();

        /**
         * @brief Restores the item from the bin.
         *
         * @return True once the server has it
         */
        bool restore();

        /**
         * @brief Archives the item.
         *
         * @return True once the server has it
         */
        bool archive();

        /**
         * @brief Unarchives the item.
         *
         * @return True once the server has it
         */
        bool unarchive();

        /**
         * @brief Saves a copy under a new id and item key (history, attachments and passkeys
         * are not copied, as in Bitwarden).
         *
         * @return The new item's id
         */
        SecureString duplicate();

        /**
         * @brief Encrypts and uploads a file. The item must already be saved online.
         *
         * @param file_name The file name
         * @param content The file contents
         * @param on_progress Upload progress 0-1, may be null
         * @return The attachment id, or nullopt if the upload failed
         */
        std::optional<SecureString> addAttachment(std::string_view file_name,
                std::span<const uint8_t> content, std::function<void(float)> on_progress);

        /**
         * @brief Deletes an attachment.
         *
         * @param attachment_id The attachment
         * @return True on success
         */
        bool removeAttachment(std::string_view attachment_id);

        /**
         * @brief Downloads and decrypts an attachment to a file.
         *
         * @param attachment_id The attachment
         * @param destination Where to write the decrypted file
         * @param on_progress Download progress 0-1, may be null
         * @return True on success
         */
        bool downloadAttachment(std::string_view attachment_id, std::filesystem::path destination,
                std::function<void(float)> on_progress);

        /**
         * @brief The encrypted cipher JSON (for the orchestrator).
         *
         * @return A copy of the JSON
         */
        Json getJson() const;

        /**
         * @brief The item key (for the orchestrator).
         *
         * @return A copy of the key
         */
        SymmetricKey getKey() const;

        /**
         * @brief Replaces the JSON with the server's canonical copy.
         *
         * @param cipher The new JSON
         */
        void replaceJson(Json cipher);

        /**
         * @brief Sets the revision date to now.
         */
        void touch();

        /**
         * @brief Sets or clears the deletion date.
         *
         * @param deleted True to mark as binned
         */
        void markDeleted(bool deleted);

        /**
         * @brief Sets or clears the archived date.
         *
         * @param archived True to mark as archived
         */
        void markArchived(bool archived);

        /**
         * @brief A re-encrypted copy for duplication: new id and key, history, attachments and
         * passkeys dropped.
         *
         * @param user_key The account's user key (wraps the new item key)
         * @return The copy's JSON
         */
        Json duplicateJson(SymmetricKey user_key) const;

    protected:
        /**
         * @brief Decrypts a type-specific field.
         *
         * @param field The field (must belong to this item's type)
         * @return The plaintext, or empty
         */
        SecureString getField_(FieldId field) const;

        /**
         * @brief Encrypts and sets a type-specific field (password changes record history).
         *
         * @param field The field (must belong to this item's type)
         * @param value The plaintext
         */
        void setField_(FieldId field, std::string_view value);

        /**
         * @brief Decrypts a JSON string value with the item key.
         *
         * @param value An encrypted string, or null
         * @return The plaintext, or empty for null
         */
        SecureString decrypt_(const Json& value) const;

        /**
         * @brief Encrypts with the item key.
         *
         * @param value The plaintext
         * @return The encrypted string as JSON
         */
        Json encrypt_(std::string_view value) const;

        /**
         * @brief The type-specific section (e.g. "login"), created if missing.
         *
         * @return The section object
         */
        Json& section_();

        /**
         * @brief Read-only view of the type-specific section.
         *
         * @return The section, or null
         */
        const Json& constSection_() const;

        /**
         * @brief Throws unless this item has the given type.
         *
         * @param type The required type
         * @param what Describes the operation, for the error
         */
        void requireType_(CipherType type, std::string_view what) const;

        std::shared_ptr<Orchestrator> m_orchestrator_;
        std::shared_ptr<Crypto> m_crypto_;
        Json m_data_;
        SymmetricKey m_key_;
    };
}
