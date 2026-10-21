#pragma once
#include <ctime>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "items/send/send.h"
#include "platform/file_store/file_store.h"
#include "vault/crypto/crypto.h"
#include "vault/network/network.h"
#include "vault/session/session.h"
#include "vault/store/store.h"

namespace clientwarden {
    /**
     * @brief The parts of a Send link.
     */
    struct SendLink {
        SecureString m_origin; // API origin, e.g. https://vault.bitwarden.com
        SecureString m_access_id;
        SecureBytes m_key_material; // from the link fragment; never sent to the server
    };

    /**
     * @brief A Send someone shared, opened from its link and decrypted.
     */
    struct ReceivedSend {
        SendLink m_link;
        SecureString m_id;
        SendType m_type;
        SecureString m_name;
        SecureString m_text;
        bool m_text_hidden;
        SecureString m_file_id;
        SecureString m_file_name;
        SecureString m_file_size;
        std::time_t m_expiration_date;
        SecureString m_creator; // the sender's email, unless they hid it
        SecureString m_password_hash;
    };

    /**
     * @brief The outcome of opening a Send link.
     */
    enum class ReceiveResult {
        Success,
        NeedsPassword, // ask the user, then call open() again with it
        WrongPassword,
        NotAvailable, // deleted, expired, disabled or used up
        InvalidLink,
        Offline,
        Failed
    };

    /**
     * @brief Bitwarden Send: the user's own Sends and opening Sends from links.
     */
    class Sends : public std::enable_shared_from_this<Sends> {
    public:
        /**
         * @brief Creates the part.
         *
         * @param crypto Cryptography
         * @param network The API client
         * @param store The vault cache ("sends" from sync)
         * @param session Holds the user key
         * @param files For saving received files
         * @param web_vault Returns the web vault origin used in share links
         */
        Sends(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network,
                std::shared_ptr<Store> store, std::shared_ptr<Session> session,
                std::shared_ptr<FileStore> files, std::function<SecureString()> web_vault);

        /**
         * @brief The user's Sends.
         *
         * @return Every Send from the last sync, newest deletion date last
         * @throws VaultError if locked
         */
        std::vector<std::shared_ptr<Send>> getSends();

        /**
         * @brief One of the user's Sends.
         *
         * @param id The Send id
         * @return The Send
         * @throws VaultError if missing or locked
         */
        std::shared_ptr<Send> getSend(std::string_view id);

        /**
         * @brief Starts a new, unsaved Send that is deleted after 7 days.
         *
         * @param type Text or file
         * @return The Send
         */
        std::shared_ptr<Send> createSend(SendType type);

        /**
         * @brief Saves a Send (Send::commit).
         *
         * @param send The Send
         * @return True once the server has it
         */
        bool saveSend(Send& send);

        /**
         * @brief Deletes a Send (Send::remove).
         *
         * @param send The Send
         * @return True once the server has deleted it
         */
        bool deleteSend(Send& send);

        /**
         * @brief Removes a Send's password (Send::removePassword).
         *
         * @param send The Send
         * @return True once the server has it
         */
        bool removePassword(Send& send);

        /**
         * @brief Builds the share link for a Send.
         *
         * @param access_id The Send's access id
         * @param key_material The Send's key material
         * @return The link
         */
        SecureString shareUrl(std::string_view access_id, std::span<const uint8_t> key_material);

        /**
         * @brief Splits a Send link into its server, access id and key material.
         *
         * Accepts both https://host/#/send/<id>/<key> and https://send.host/#<id>/<key>.
         *
         * @param link The link
         * @return Its parts, or nullopt if it isn't a Send link
         */
        static std::optional<SendLink> parseLink(std::string_view link);

        /**
         * @brief Opens someone's Send from its link.
         *
         * @param link The link
         * @param password The Send password, or empty
         * @param received Receives the decrypted Send on success
         * @return What happened
         */
        ReceiveResult open(
                std::string_view link, std::string_view password, ReceivedSend& received);

        /**
         * @brief Downloads and decrypts the file of a received file Send.
         *
         * @param received From open()
         * @param destination Where to write the file
         * @param on_progress Download progress, may be null
         * @return True on success
         */
        bool downloadReceivedFile(const ReceivedSend& received, std::filesystem::path destination,
                std::function<void(float)> on_progress);

    private:
        std::shared_ptr<Send> wrap_(Json send);
        std::optional<ReceiveResult> accessToken_(
                const SendLink& link, std::string_view password_hash, SecureString& token);

        std::shared_ptr<Crypto> m_crypto_;
        std::shared_ptr<Network> m_network_;
        std::shared_ptr<Store> m_store_;
        std::shared_ptr<Session> m_session_;
        std::shared_ptr<FileStore> m_files_;
        std::function<SecureString()> m_web_vault_;
    };
}
