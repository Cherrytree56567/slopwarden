#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "platform/http/http.h"
#include "vault/crypto/crypto.h"

namespace clientwarden {
    /**
     * @brief How this client identifies itself to the server.
     */
    struct DeviceInfo {
        SecureString m_identifier; // persistent per vault, so the server recognises the device
        SecureString m_type;       // see SPEC.md (e.g. "7" = macOS desktop)
        SecureString m_name;

        /**
         * @brief Device type and name for the platform this binary was built for.
         *
         * @param identifier The persistent device id
         * @return The device info
         */
        static DeviceInfo forThisPlatform(SecureString identifier);
    };

    /**
     * @brief Bitwarden two-factor provider ids.
     */
    enum class TwoFactorProvider { Authenticator = 0, Email = 1, WebAuthn = 7 };

    /**
     * @brief A second factor submitted with a password grant.
     */
    struct TwoFactorToken {
        TwoFactorProvider m_provider;
        SecureString m_token;
    };

    /**
     * @brief The classified result of a token request.
     */
    struct TokenResponse {
        /**
         * @brief What the server said.
         */
        enum class Kind {
            Success,
            TwoFactorRequired,
            NewDeviceVerification,
            InvalidCredentials,
            Failed
        };

        Kind m_kind = Kind::Failed;
        SecureString m_access_token;
        SecureString m_refresh_token;
        int m_expires_in = 0;

        std::vector<TwoFactorProvider> m_providers;
        SecureString m_web_authn_challenge;     // TwoFactorProviders2["7"].challenge
        SecureString m_web_authn_relying_party; // TwoFactorProviders2["7"].rpId, if sent
    };

    /**
     * @brief Supplies bearer tokens to authenticated requests (implemented by Session).
     */
    class AccessTokenSource {
    public:
        virtual ~AccessTokenSource() = default;

        /**
         * @brief A valid access token, refreshing first if it is about to expire.
         *
         * @return The token, or nullopt if logged out or the refresh failed
         */
        virtual std::optional<SecureString> getAccessToken() = 0;

        /**
         * @brief Refreshes after the server rejected a token.
         *
         * @param rejected The token that got a 401; skipped if it has already been replaced
         * @return True if a new token is available
         */
        virtual bool refresh(std::string_view rejected) = 0;
    };

    /**
     * @brief Typed client for the Bitwarden / Vaultwarden REST API.
     *
     * Holds no secrets beyond what each call is given and tracks connectivity as a side effect
     * of every request instead of polling. JSON bodies are always built with the JSON library
     * (never by string concatenation) and server ids are validated before going into paths.
     */
    class Network {
    public:
        /**
         * @brief A downloaded attachment: metadata plus the still-encrypted body.
         */
        struct Download {
            Json m_meta;
            SecureBytes m_content;
        };

        /**
         * @brief Creates the client.
         *
         * @param transport How requests are sent
         * @param device How this client identifies itself
         */
        Network(std::shared_ptr<HttpTransport> transport, DeviceInfo device);

        /**
         * @brief Points the client at a server.
         *
         * @param urls The endpoints
         */
        void configure(ServerUrls urls);

        /**
         * @brief Sets where bearer tokens come from.
         *
         * @param source Usually the vault's Session
         */
        void setTokenSource(std::shared_ptr<AccessTokenSource> source);

        /**
         * @brief The underlying transport (for the notification listener).
         *
         * @return The transport
         */
        std::shared_ptr<HttpTransport> getTransport();

        /**
         * @brief Whether the last request reached the server.
         *
         * @return True if online
         */
        bool isOnline() const;

        /**
         * @brief Pings /alive.
         *
         * @return True if the server answered
         */
        bool checkAlive();

        /**
         * @brief Fetches the KDF settings for an account.
         *
         * @param email The lowercased email
         * @return The settings (unvalidated), or nullopt
         */
        std::optional<KdfParams> preLogin(std::string_view email);

        /**
         * @brief Logs in with the master password hash.
         *
         * @param email The lowercased email
         * @param password_hash From Crypto::hashMasterPassword
         * @param two_factor A second factor, if the server asked for one
         * @param new_device_otp A new-device verification code, if asked for one
         * @return The classified response
         */
        TokenResponse passwordGrant(std::string_view email, std::string_view password_hash,
                std::optional<TwoFactorToken> two_factor,
                std::optional<SecureString> new_device_otp);

        /**
         * @brief Exchanges a refresh token for a new access token.
         *
         * @param refresh_token The refresh token
         * @return The classified response
         */
        TokenResponse refreshGrant(std::string_view refresh_token);

        /**
         * @brief GET /api/config (server version, feature flags).
         *
         * @return The config, or nullopt
         */
        std::optional<Json> getConfig();

        /**
         * @brief GET /api/accounts/profile.
         *
         * @return The profile, or nullopt
         */
        std::optional<Json> getProfile();

        /**
         * @brief GET /api/sync (the whole vault).
         *
         * @return The sync response, or nullopt
         */
        std::optional<Json> getSync();

        /**
         * @brief POST /api/ciphers.
         *
         * @param cipher The encrypted cipher
         * @return The server's copy (with its id and revision date), or nullopt
         */
        std::optional<Json> createCipher(const Json& cipher);

        /**
         * @brief PUT /api/ciphers/{id}.
         *
         * @param cipher The encrypted cipher, including its id
         * @return The server's copy, or nullopt
         */
        std::optional<Json> updateCipher(const Json& cipher);

        /**
         * @brief DELETE /api/ciphers/{id} (permanent).
         *
         * @param id The cipher id
         * @return True on success
         */
        bool deleteCipher(std::string_view id);

        /**
         * @brief PUT /api/ciphers/{id}/delete (move to bin).
         *
         * @param id The cipher id
         * @return True on success
         */
        bool softDeleteCipher(std::string_view id);

        /**
         * @brief PUT /api/ciphers/{id}/restore (out of the bin).
         *
         * @param id The cipher id
         * @return True on success
         */
        bool restoreCipher(std::string_view id);

        /**
         * @brief PUT /api/ciphers/archive.
         *
         * @param ids The cipher ids
         * @return True on success
         */
        bool archiveCiphers(const std::vector<SecureString>& ids);

        /**
         * @brief PUT /api/ciphers/unarchive.
         *
         * @param ids The cipher ids
         * @return True on success
         */
        bool unarchiveCiphers(const std::vector<SecureString>& ids);

        /**
         * @brief POST /api/ciphers/create: creates an item owned by an organisation.
         *
         * @param cipher The cipher, encrypted with its key wrapped by the organisation key
         * @param collection_ids Collections to place it in (at least one)
         * @return The server's copy, or nullopt
         */
        std::optional<Json> createOrganizationCipher(
                const Json& cipher, const std::vector<SecureString>& collection_ids);

        /**
         * @brief PUT /api/ciphers/{id}/share: moves a personal item into an organisation.
         *
         * @param id The cipher id
         * @param cipher The cipher re-keyed for the organisation
         * @param collection_ids Collections to place it in (at least one)
         * @return The server's copy, or nullopt
         */
        std::optional<Json> shareCipher(std::string_view id, const Json& cipher,
                const std::vector<SecureString>& collection_ids);

        /**
         * @brief Replaces the collections an organisation item belongs to.
         *
         * @param id The cipher id
         * @param collection_ids The new collections
         * @return True on success
         */
        bool updateCipherCollections(
                std::string_view id, const std::vector<SecureString>& collection_ids);

        /**
         * @brief POST /api/organizations/{orgId}/collections.
         *
         * @param organization_id The organisation
         * @param encrypted_name The name encrypted with the organisation key
         * @param organization_user_id The caller's membership id, granted manage access
         * @return The server's collection, or nullopt
         */
        std::optional<Json> createCollection(std::string_view organization_id,
                std::string_view encrypted_name, std::string_view organization_user_id);

        /**
         * @brief Renames a collection, keeping its existing group and user access.
         *
         * @param organization_id The organisation
         * @param id The collection id
         * @param encrypted_name The new name encrypted with the organisation key
         * @return The server's collection, or nullopt
         */
        std::optional<Json> renameCollection(std::string_view organization_id, std::string_view id,
                std::string_view encrypted_name);

        /**
         * @brief DELETE /api/organizations/{orgId}/collections/{id}.
         *
         * @param organization_id The organisation
         * @param id The collection id
         * @return True on success
         */
        bool deleteCollection(std::string_view organization_id, std::string_view id);

        /**
         * @brief POST /api/sends: creates a text Send.
         *
         * @param send The encrypted Send
         * @return The server's copy, or nullopt
         */
        std::optional<Json> createSend(const Json& send);

        /**
         * @brief Creates a file Send: registers it, then uploads the encrypted file.
         *
         * @param send The encrypted Send (its file.fileName is encrypted)
         * @param encrypted_content The file from Crypto::encryptBuffer
         * @param on_progress Upload progress, may be null
         * @return The server's copy, or nullopt
         */
        std::optional<Json> createFileSend(const Json& send,
                std::span<const uint8_t> encrypted_content, std::function<void(float)> on_progress);

        /**
         * @brief PUT /api/sends/{id}.
         *
         * @param id The Send id
         * @param send The encrypted Send
         * @return The server's copy, or nullopt
         */
        std::optional<Json> updateSend(std::string_view id, const Json& send);

        /**
         * @brief PUT /api/sends/{id}/remove-password.
         *
         * @param id The Send id
         * @return The server's copy, or nullopt
         */
        std::optional<Json> removeSendPassword(std::string_view id);

        /**
         * @brief DELETE /api/sends/{id}.
         *
         * @param id The Send id
         * @return True on success
         */
        bool deleteSend(std::string_view id);

        /**
         * @brief Opens someone's Send. Unauthenticated, and sent to the link's own server.
         *
         * @param origin The Send server, e.g. https://vault.bitwarden.com
         * @param access_id From the link
         * @param password_hash From Send password protection, or empty
         * @return {status, body}: 200 with the encrypted Send, 401 if a password is needed or
         * wrong, 404 if gone; status 0 if unreachable
         */
        HttpResponse accessSend(std::string_view origin, std::string_view access_id,
                std::string_view password_hash);

        /**
         * @brief Downloads the (encrypted) file of someone's file Send.
         *
         * @param origin The Send server
         * @param send_id The Send id (from accessSend)
         * @param file_id The file id (from accessSend)
         * @param password_hash As for accessSend
         * @param on_progress Download progress, may be null
         * @return The encrypted file, or nullopt
         */
        std::optional<SecureBytes> accessSendFile(std::string_view origin, std::string_view send_id,
                std::string_view file_id, std::string_view password_hash,
                std::function<void(float)> on_progress);

        /**
         * @brief Uploads an attachment (prepare, then upload the body).
         *
         * @param cipher_id The owning cipher
         * @param encrypted_file_name The file name encrypted with the item key
         * @param encrypted_key The attachment key wrapped with the item key
         * @param encrypted_content The body from Crypto::encryptBuffer
         * @param on_progress Upload progress 0-1, may be null
         * @return {attachmentId, cipherResponse}, or nullopt
         */
        std::optional<Json> uploadAttachment(std::string_view cipher_id,
                std::string_view encrypted_file_name, std::string_view encrypted_key,
                std::span<const uint8_t> encrypted_content, std::function<void(float)> on_progress);

        /**
         * @brief DELETE /api/ciphers/{id}/attachment/{attachmentId}.
         *
         * @param cipher_id The owning cipher
         * @param attachment_id The attachment
         * @return True on success
         */
        bool deleteAttachment(std::string_view cipher_id, std::string_view attachment_id);

        /**
         * @brief Fetches attachment metadata and its body. The body URL is pre-signed and may be on
         * another host, so it never receives the bearer token.
         *
         * @param cipher_id The owning cipher
         * @param attachment_id The attachment
         * @param on_progress Download progress 0-1, may be null
         * @return The download, or nullopt
         */
        std::optional<Download> downloadAttachment(std::string_view cipher_id,
                std::string_view attachment_id, std::function<void(float)> on_progress);

        /**
         * @brief POST /api/folders.
         *
         * @param encrypted_name The name encrypted with the user key
         * @return The server's folder, or nullopt
         */
        std::optional<Json> createFolder(std::string_view encrypted_name);

        /**
         * @brief PUT /api/folders/{id}.
         *
         * @param id The folder id
         * @param encrypted_name The new name encrypted with the user key
         * @return The server's folder, or nullopt
         */
        std::optional<Json> updateFolder(std::string_view id, std::string_view encrypted_name);

        /**
         * @brief DELETE /api/folders/{id}.
         *
         * @param id The folder id
         * @return True on success
         */
        bool deleteFolder(std::string_view id);

        /**
         * @brief Fetches a site's favicon from the icon service.
         *
         * @param domain A validated bare hostname
         * @return PNG bytes, or nullopt
         */
        std::optional<SecureBytes> getIcon(std::string_view domain);

    private:
        HttpResponse call_(
                HttpMethod method, Host host, SecureString path, std::optional<Json> body);
        HttpResponse send_(HttpRequest request, bool authenticated);
        TokenResponse token_(std::vector<std::pair<SecureString, SecureString>> form);
        std::optional<Json> jsonOf_(HttpResponse response, std::string_view what);

        std::shared_ptr<HttpTransport> m_transport_;
        DeviceInfo m_device_;
        std::shared_ptr<AccessTokenSource> m_tokens_;
        std::atomic<bool> m_online_ { false };
    };

    /**
     * @brief Push notification types from the Bitwarden hub.
     * https://github.com/bitwarden/server/blob/main/src/Core/Enums/PushType.cs
     */
    enum class PushType {
        SyncCipherUpdate = 0,
        SyncCipherCreate = 1,
        SyncLoginDelete = 2,
        SyncFolderDelete = 3,
        SyncCiphers = 4,
        SyncVault = 5,
        SyncOrgKeys = 6,
        SyncFolderCreate = 7,
        SyncFolderUpdate = 8,
        SyncCipherDelete = 9,
        SyncSettings = 10,
        LogOut = 11,
        SyncSendCreate = 12,
        SyncSendUpdate = 13,
        SyncSendDelete = 14
    };

    /**
     * @brief Decodes one websocket frame of SignalR MessagePack invocations.
     *
     * Frames are server-controlled, so anything malformed is skipped rather than trusted.
     *
     * @param frame The raw frame
     * @return The push types it carried
     */
    std::vector<PushType> parseNotificationFrame(std::span<const uint8_t> frame);
}
