#pragma once
#include <atomic>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>

#include "platform/http/http.h"
#include "utils/secure_string/secure_string.h"
#include "vault/autofill/autofill.h"
#include "vault/crypto/crypto.h"
#include "vault/features/features.h"
#include "vault/generator/generator.h"
#include "vault/network/network.h"
#include "vault/orchestrator/orchestrator.h"
#include "vault/profile/profile.h"
#include "vault/session/session.h"
#include "vault/settings/settings.h"
#include "vault/store/store.h"
#include "vault/sync/sync.h"

namespace clientwarden {
    /**
     * @brief Which password manager API a vault talks to.
     */
    enum class VaultType { Bitwarden };

    /**
     * @brief Where a vault is in its lifecycle.
     */
    enum class VaultState {
        Unknown,
        LoggedOut,
        Unlockable,
        WaitingForTotp,
        WaitingForDeviceVerification,
        WaitingForPasskey,
        Unlocked,
        Failed // tampered or corrupt data; the app must be restarted
    };

    /**
     * @brief The outcome of a login step.
     */
    enum class LoginResult {
        Success,
        NeedsTotp,
        NeedsDeviceVerification,
        NeedsPasskey,
        InvalidCredentials,
        Offline,
        Failed
    };

    /**
     * @brief The outcome of an unlock attempt.
     */
    enum class UnlockResult { Success, InvalidPassword, Failed };

    /**
     * @brief A WebAuthn challenge the UI must answer with the platform authenticator.
     */
    struct PasskeyRequest {
        SecureString m_challenge;
        SecureString m_relying_party;
    };

    /**
     * @brief Base class for one password manager account (ADR 2, ADR 6).
     *
     * Holds the vault's parts (Crypto, Network, Session, Profile, Features, Sync, Store,
     * Settings, AutoFill, Orchestrator, Generator) as shared_ptrs that the derived class (e.g.
     * BitwardenVault) creates. The UI reaches item operations through getOrchestrator() and
     * drives the login/unlock state machine through the virtual functions below.
     *
     * All public functions are thread-safe. Functions that need keys throw VaultError while
     * locked; network failures are reported through return values.
     */
    class Vault {
    public:
        virtual ~Vault() = default;

        /**
         * @brief The vault's id within the VaultManager.
         *
         * @return The id
         */
        SecureString getId() const;

        /**
         * @brief The API this vault talks to.
         *
         * @return The type
         */
        VaultType getType() const;

        /**
         * @brief The current state.
         *
         * @return The state
         */
        VaultState getState() const;

        /**
         * @brief Why the vault entered the Failed state.
         *
         * @return The reason, or empty
         */
        SecureString getFailureReason() const;

        /**
         * @brief Registers a callback for state changes the vault makes on its own (auto-lock,
         * remote logout, failure). Called on a background thread.
         *
         * @param callback Receives the new state
         */
        void onStateChange(std::function<void(VaultState)> callback);

        /**
         * @brief Cryptography.
         *
         * @return The Crypto part
         */
        std::shared_ptr<Crypto> getCrypto() const;

        /**
         * @brief The API client.
         *
         * @return The Network part
         */
        std::shared_ptr<Network> getNetwork() const;

        /**
         * @brief Tokens and keys.
         *
         * @return The Session part
         */
        std::shared_ptr<Session> getSession() const;

        /**
         * @brief The account profile.
         *
         * @return The Profile part
         */
        std::shared_ptr<Profile> getProfile() const;

        /**
         * @brief Server capabilities.
         *
         * @return The Features part
         */
        std::shared_ptr<Features> getFeatures() const;

        /**
         * @brief Synchronisation.
         *
         * @return The Sync part
         */
        std::shared_ptr<Sync> getSync() const;

        /**
         * @brief Preferences.
         *
         * @return The Settings part
         */
        std::shared_ptr<Settings> getSettings() const;

        /**
         * @brief Autofill matching.
         *
         * @return The AutoFill part
         */
        std::shared_ptr<AutoFill> getAutoFill() const;

        /**
         * @brief Item and folder operations.
         *
         * @return The Orchestrator part
         */
        std::shared_ptr<Orchestrator> getOrchestrator() const;

        /**
         * @brief Password generation.
         *
         * @return The Generator part
         */
        std::shared_ptr<Generator> getGenerator() const;

        /**
         * @brief Points the vault at a server before logging in.
         *
         * @param urls The server endpoints
         * @throws VaultError if a URL has no http(s) scheme
         */
        virtual void setServer(ServerUrls urls) = 0;

        /**
         * @brief Logs in with email and master password.
         *
         * @param email The account email (normalised to lowercase)
         * @param password The master password
         * @return The result; Needs* means another step is required
         */
        virtual LoginResult login(std::string_view email, std::string_view password) = 0;

        /**
         * @brief Submits a TOTP or new-device verification code.
         *
         * @param code The code
         * @return The result
         */
        virtual LoginResult submitCode(std::string_view code) = 0;

        /**
         * @brief The WebAuthn challenge while waiting for a passkey.
         *
         * @return The request, or nullopt
         */
        virtual std::optional<PasskeyRequest> getPendingPasskey() const = 0;

        /**
         * @brief Submits the authenticator's raw assertion bytes.
         *
         * @param credential_id Credential id
         * @param authenticator_data Authenticator data
         * @param client_data_json Client data JSON
         * @param signature Signature
         * @return The result
         */
        virtual LoginResult submitPasskey(std::span<const uint8_t> credential_id,
                std::span<const uint8_t> authenticator_data,
                std::span<const uint8_t> client_data_json, std::span<const uint8_t> signature) = 0;

        /**
         * @brief Unlocks with the master password.
         *
         * @param password The master password
         * @return The result
         */
        virtual UnlockResult unlock(std::string_view password) = 0;

        /**
         * @brief Unlocks with the biometric key (the OS prompts the user).
         *
         * @return The result
         */
        virtual UnlockResult unlockWithBiometrics() = 0;

        /**
         * @brief Wipes keys and stops background work.
         */
        virtual void lock() = 0;

        /**
         * @brief Removes credentials and local data for this vault.
         */
        virtual void logout() = 0;

        /**
         * @brief Checks the master password (for re-prompt) without changing state.
         *
         * @param password The candidate password
         * @return True if correct
         */
        virtual bool verifyMasterPassword(std::string_view password) = 0;

        /**
         * @brief Saves the master key behind biometrics.
         *
         * @return True on success (must be unlocked)
         */
        virtual bool enableBiometrics() = 0;

        /**
         * @brief Removes the biometric key.
         *
         * @return True on success
         */
        virtual bool disableBiometrics() = 0;

        /**
         * @brief Whether biometric unlock is set up.
         *
         * @return True if enabled
         */
        virtual bool biometricsEnabled() = 0;

        /**
         * @brief Records user activity for auto-lock.
         *
         * @param when Seconds since the epoch
         */
        virtual void noteActivity(std::time_t when) = 0;

        /**
         * @brief Syncs now on the calling thread.
         *
         * @return True if the server was reached
         */
        virtual bool syncNow() = 0;

        /**
         * @brief Stops background threads (called by the VaultManager on shutdown).
         */
        virtual void shutdown() = 0;

    protected:
        /**
         * @brief Sets identity; called by the derived constructor.
         *
         * @param id The vault id
         * @param type The API type
         */
        Vault(SecureString id, VaultType type);

        /**
         * @brief Changes state and notifies the observer if it changed.
         *
         * @param next The new state
         */
        void setState_(VaultState next);

        /**
         * @brief Records a failure reason and enters the Failed state.
         *
         * @param reason What went wrong (no secrets)
         */
        void setFailed_(std::string_view reason);

        std::shared_ptr<Crypto> m_crypto_;
        std::shared_ptr<Network> m_network_;
        std::shared_ptr<Session> m_session_;
        std::shared_ptr<Profile> m_profile_;
        std::shared_ptr<Features> m_features_;
        std::shared_ptr<Sync> m_sync_;
        std::shared_ptr<Store> m_store_;
        std::shared_ptr<Settings> m_settings_;
        std::shared_ptr<AutoFill> m_autofill_;
        std::shared_ptr<Orchestrator> m_orchestrator_;
        std::shared_ptr<Generator> m_generator_;

    private:
        SecureString m_id_;
        VaultType m_type_;
        std::atomic<VaultState> m_state_ { VaultState::Unknown };
        mutable std::mutex m_observer_mutex_;
        std::function<void(VaultState)> m_observer_;
        SecureString m_failure_reason_;
    };
}
