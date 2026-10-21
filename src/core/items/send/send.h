#pragma once
#include <ctime>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

#include "vault/crypto/crypto.h"

namespace clientwarden {
    /*
     * Forward declared to break the cycle Sends -> Send -> Sends: a Send commits through the
     * Sends part, which in turn creates Sends.
     */
    class Sends;

    /**
     * @brief What a Send shares.
     */
    enum class SendType { Text = 0, File = 1 };

    /**
     * @brief A Bitwarden Send: text or a file shared through a link (builder style, like items).
     *
     * Each Send has 16 bytes of key material; its encryption key is HKDF-SHA256 of that material,
     * and the material is stored encrypted with the user key. The share link carries the material
     * in its fragment, so the server never sees it. Sends are online only.
     */
    class Send {
    public:
        static constexpr int c_password_iterations = 100000;

        /**
         * @brief Wraps a stored (or new) Send.
         *
         * @param sends Performs commits and deletes
         * @param crypto For fields and passwords
         * @param send The encrypted Send JSON
         * @param key_material The Send's 16 bytes of key material
         */
        Send(std::shared_ptr<Sends> sends, std::shared_ptr<Crypto> crypto, Json send,
                SecureBytes key_material);

        /**
         * @brief Derives a Send's encryption key from its key material.
         *
         * @param crypto Cryptography
         * @param key_material The 16 bytes of key material
         * @return HKDF-SHA256(material, "bitwarden-send", "send") as an enc/mac key
         */
        static SymmetricKey deriveKey(Crypto& crypto, std::span<const uint8_t> key_material);

        /**
         * @brief The value sent instead of a Send password: base64 PBKDF2-SHA256 of the password,
         * salted with the key material.
         *
         * @param crypto Cryptography
         * @param password The password
         * @param key_material The Send's key material
         * @return The password hash
         */
        static SecureString hashPassword(
                Crypto& crypto, std::string_view password, std::span<const uint8_t> key_material);

        /**
         * @brief The Send id (empty until first saved).
         *
         * @return The id
         */
        SecureString getId() const;

        /**
         * @brief The public id used in share links.
         *
         * @return The access id (empty until first saved)
         */
        SecureString getAccessId() const;

        /**
         * @brief Text or file.
         *
         * @return The type
         */
        SendType getType() const;

        /**
         * @brief The decrypted name.
         *
         * @return The name
         */
        SecureString getName() const;

        /**
         * @brief The decrypted private notes (only the owner sees them).
         *
         * @return The notes
         */
        SecureString getNotes() const;

        /**
         * @brief The decrypted text of a text Send.
         *
         * @return The text
         */
        SecureString getText() const;

        /**
         * @brief Whether recipients must click to reveal the text.
         *
         * @return True if hidden by default
         */
        bool getTextHidden() const;

        /**
         * @brief The decrypted file name of a file Send.
         *
         * @return The file name
         */
        SecureString getFileName() const;

        /**
         * @brief The file size as the server reports it (e.g. "1.2 MB").
         *
         * @return The size
         */
        SecureString getFileSize() const;

        /**
         * @brief How many times it may be opened.
         *
         * @return The limit, or nullopt for unlimited
         */
        std::optional<int> getMaxAccessCount() const;

        /**
         * @brief How many times it has been opened.
         *
         * @return The count
         */
        int getAccessCount() const;

        /**
         * @brief When the link stops working.
         *
         * @return Seconds since the epoch, or 0 for never
         */
        std::time_t getExpirationDate() const;

        /**
         * @brief When the server deletes it.
         *
         * @return Seconds since the epoch
         */
        std::time_t getDeletionDate() const;

        /**
         * @brief Whether it's disabled (the link doesn't work).
         *
         * @return True if disabled
         */
        bool getDisabled() const;

        /**
         * @brief Whether the owner's email is hidden from recipients.
         *
         * @return True if hidden
         */
        bool getHideEmail() const;

        /**
         * @brief Whether recipients need a password.
         *
         * @return True if password protected
         */
        bool hasPassword() const;

        /**
         * @brief The link to share (empty until saved).
         *
         * @return e.g. https://vault.example/#/send/<accessId>/<key>
         */
        SecureString getShareUrl() const;

        /**
         * @brief Sets the name.
         *
         * @param name The new name
         * @return This Send, for chaining
         */
        Send& setName(std::string_view name);

        /**
         * @brief Sets the owner's private notes.
         *
         * @param notes The notes (empty clears them)
         * @return This Send, for chaining
         */
        Send& setNotes(std::string_view notes);

        /**
         * @brief Sets the text of a text Send.
         *
         * @param text The text
         * @param hidden Recipients must click to reveal it
         * @return This Send, for chaining
         * @throws VaultError for file Sends
         */
        Send& setText(std::string_view text, bool hidden);

        /**
         * @brief Chooses the file of a new file Send (uploaded on commit).
         *
         * @param file_name The file name
         * @param content The file contents
         * @return This Send, for chaining
         * @throws VaultError for text Sends or Sends that are already saved
         */
        Send& setFile(std::string_view file_name, std::span<const uint8_t> content);

        /**
         * @brief Limits how many times it may be opened.
         *
         * @param count The limit, or nullopt for unlimited
         * @return This Send, for chaining
         */
        Send& setMaxAccessCount(std::optional<int> count);

        /**
         * @brief Sets when the link stops working.
         *
         * @param when Seconds since the epoch, or 0 for never
         * @return This Send, for chaining
         */
        Send& setExpirationDate(std::time_t when);

        /**
         * @brief Sets when the server deletes it (at most 31 days ahead).
         *
         * @param when Seconds since the epoch
         * @return This Send, for chaining
         * @throws VaultError if it's in the past or more than 31 days ahead
         */
        Send& setDeletionDate(std::time_t when);

        /**
         * @brief Disables or enables the link.
         *
         * @param disabled True to disable
         * @return This Send, for chaining
         */
        Send& setDisabled(bool disabled);

        /**
         * @brief Hides or shows the owner's email to recipients.
         *
         * @param hide True to hide
         * @return This Send, for chaining
         */
        Send& setHideEmail(bool hide);

        /**
         * @brief Requires a password (only its hash is stored).
         *
         * @param password The password; empty leaves any existing password unchanged
         * @return This Send, for chaining
         */
        Send& setPassword(std::string_view password);

        /**
         * @brief Saves the Send (creating it, and uploading its file, if new).
         *
         * @return True once the server has it
         */
        bool commit();

        /**
         * @brief Deletes the Send.
         *
         * @return True once the server has deleted it
         */
        bool remove();

        /**
         * @brief Removes password protection.
         *
         * @return True once the server has it
         */
        bool removePassword();

        /**
         * @brief The encrypted Send JSON (for the Sends part).
         *
         * @return A copy of the JSON
         */
        Json getJson() const;

        /**
         * @brief The derived encryption key (for the Sends part).
         *
         * @return A copy of the key
         */
        SymmetricKey getKey() const;

        /**
         * @brief The file chosen for a new file Send (for the Sends part).
         *
         * @return The contents, or nullopt
         */
        std::optional<SecureBytes> getPendingFile() const;

        /**
         * @brief Replaces the JSON with the server's copy and drops any pending file.
         *
         * @param send The new JSON
         */
        void replaceJson(Json send);

    private:
        SecureString decrypt_(const Json& value) const;

        std::shared_ptr<Sends> m_sends_;
        std::shared_ptr<Crypto> m_crypto_;
        Json m_data_;
        SecureBytes m_key_material_;
        SymmetricKey m_key_;
        std::optional<SecureBytes> m_pending_file_;
    };
}
