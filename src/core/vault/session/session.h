#pragma once
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string_view>

#include "platform/secret_store/secret_store.h"
#include "vault/crypto/crypto.h"
#include "vault/network/network.h"

namespace clientwarden {
    /**
     * @brief The persisted account record (keychain "account").
     */
    struct Account {
        SecureString m_email;
        KdfParams m_kdf;
        ServerUrls m_urls;
        bool m_biometrics = false;

        /**
         * @brief Serialises for the keychain.
         *
         * @return The account as JSON
         */
        Json toJson() const;

        /**
         * @brief Reads back what toJson wrote.
         *
         * @param json The stored object
         * @return The account, or nullopt if incomplete
         */
        static std::optional<Account> fromJson(const Json& json);
    };

    /**
     * @brief Everything secret about the logged-in user.
     *
     *  - the account record and OAuth tokens: persisted in the keychain, cached in memory so
     *    requests don't hit the keychain
     *  - the master key and user key: memory only, wiped on lock
     *
     * Implements AccessTokenSource so Network refreshes tokens transparently. Refreshes are
     * serialised so a rotated refresh token is never spent twice.
     */
    class Session : public AccessTokenSource {
    public:
        /**
         * @brief Creates the session.
         *
         * @param secrets The vault's (scoped) keychain
         * @param crypto For key comparisons
         */
        Session(std::shared_ptr<SecretStore> secrets, std::shared_ptr<Crypto> crypto);

        /**
         * @brief Sets the API used for refreshes (set after construction to break the cycle
         * Network -> Session -> Network).
         *
         * @param network The vault's network client
         */
        void setNetwork(std::shared_ptr<Network> network);

        /**
         * @brief The persistent device id, created on first use.
         *
         * @param secrets The vault's keychain
         * @return The device id
         */
        static SecureString getDeviceId(std::shared_ptr<SecretStore> secrets);

        /**
         * @brief Loads the account, migrating the pre-rewrite keychain layout if present.
         *
         * @return The account, or nullopt if logged out
         */
        std::optional<Account> loadAccount();

        /**
         * @brief Saves the account.
         *
         * @param account The account
         * @return True on success
         */
        bool saveAccount(Account account);

        /**
         * @brief Loads tokens from the keychain into memory.
         *
         * @return True if a refresh token is available
         */
        bool loadTokens();

        /**
         * @brief Stores tokens from a successful grant.
         *
         * @param token The grant response
         * @return True on success
         */
        bool setTokens(TokenResponse token);

        std::optional<SecureString> getAccessToken() override;
        bool refresh(std::string_view rejected) override;

        /**
         * @brief Called (from whichever thread noticed) when the server revokes the session.
         *
         * @param callback Usually logs the vault out
         */
        void onRevoked(std::function<void()> callback);

        /**
         * @brief Holds the unlocked keys.
         *
         * @param master_key The derived master key (kept for re-prompt checks)
         * @param user_key The decrypted user key
         */
        void setKeys(SecureBytes master_key, SymmetricKey user_key);

        /**
         * @brief Wipes the keys (lock).
         */
        void clearKeys();

        /**
         * @brief Whether the vault is unlocked.
         *
         * @return True if keys are held
         */
        bool hasKeys() const;

        /**
         * @brief The user key.
         *
         * @return A copy of the user key
         * @throws VaultError if locked
         */
        SymmetricKey getUserKey() const;

        /**
         * @brief Holds the decrypted organisation keys (memory only, wiped on lock).
         *
         * @param keys Organisation id -> organisation key
         */
        void setOrganizationKeys(std::map<SecureString, SymmetricKey, std::less<>> keys);

        /**
         * @brief An organisation's key.
         *
         * @param organization_id The organisation id
         * @return The key, or nullopt if locked or not a member
         */
        std::optional<SymmetricKey> getOrganizationKey(std::string_view organization_id) const;

        /**
         * @brief Constant-time check of a candidate master key against the unlocked one.
         *
         * @param candidate A freshly derived master key
         * @return True if equal
         */
        bool masterKeyEquals(std::span<const uint8_t> candidate) const;

        /**
         * @brief Saves the master key behind biometrics / device auth.
         *
         * @return True on success
         */
        bool saveBiometricKey();

        /**
         * @brief Reads the biometric master key (prompts the user).
         *
         * @return The master key, or nullopt
         */
        std::optional<SecureBytes> loadBiometricKey();

        /**
         * @brief Deletes the biometric master key.
         *
         * @return True on success
         */
        bool removeBiometricKey();

        /**
         * @brief Whether biometric unlock is set up (without prompting).
         *
         * @return True if enabled
         */
        bool hasBiometricKey();

        /**
         * @brief Removes every credential except the device id (logout).
         */
        void forget();

    private:
        std::optional<Account> migrateLegacyAccount_();
        bool setBiometricFlag_(bool enabled);

        std::shared_ptr<SecretStore> m_secrets_;
        std::shared_ptr<Crypto> m_crypto_;
        std::weak_ptr<Network> m_network_;

        std::mutex m_refresh_mutex_;
        std::mutex m_token_mutex_;
        SecureString m_access_token_;
        SecureString m_refresh_token_;
        std::time_t m_expires_at_ = 0;
        std::function<void()> m_on_revoked_;

        mutable std::shared_mutex m_key_mutex_;
        SecureBytes m_master_key_;
        SymmetricKey m_user_key_;
        std::map<SecureString, SymmetricKey, std::less<>> m_organization_keys_;
    };
}
