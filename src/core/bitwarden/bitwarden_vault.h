#pragma once
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <thread>

#include "platform/file_store/file_store.h"
#include "platform/http/http.h"
#include "platform/secret_store/secret_store.h"
#include "vault/vault.h"

namespace clientwarden {
    /**
     * @brief A Bitwarden / Vaultwarden account.
     *
     * Creates the Bitwarden implementations of every vault part and runs the login/unlock
     * state machine. One worker thread runs posted tasks (sync, lock, logout requested from
     * other threads) and a 1 second housekeeping tick (auto-lock, connectivity, server
     * version); the notification listener has its own thread because it blocks on the socket.
     */
    class BitwardenVault : public Vault {
    public:
        /**
         * @brief Creates the vault and loads any saved session.
         *
         * @param id The vault id
         * @param secrets This vault's (scoped) keychain
         * @param files This vault's (scoped) data directory
         * @param resources Bundled resources (word list)
         * @param transport How HTTP requests are sent
         */
        BitwardenVault(SecureString id, std::shared_ptr<SecretStore> secrets,
                std::shared_ptr<FileStore> files, std::shared_ptr<FileStore> resources,
                std::shared_ptr<HttpTransport> transport);

        ~BitwardenVault() override;

        void setServer(ServerUrls urls) override;
        LoginResult login(std::string_view email, std::string_view password) override;
        LoginResult submitCode(std::string_view code) override;
        std::optional<PasskeyRequest> getPendingPasskey() const override;
        LoginResult submitPasskey(std::span<const uint8_t> credential_id,
                std::span<const uint8_t> authenticator_data,
                std::span<const uint8_t> client_data_json,
                std::span<const uint8_t> signature) override;
        UnlockResult unlock(std::string_view password) override;
        UnlockResult unlockWithBiometrics() override;
        void lock() override;
        void logout() override;
        bool verifyMasterPassword(std::string_view password) override;
        bool enableBiometrics() override;
        bool disableBiometrics() override;
        bool biometricsEnabled() override;
        void noteActivity(std::time_t when) override;
        bool syncNow() override;
        void shutdown() override;

    private:
        /**
         * @brief A login waiting on a second factor.
         */
        struct PendingLogin {
            SecureString m_email;
            KdfParams m_kdf;
            SecureBytes m_master_key;
            SecureString m_password_hash;
            std::optional<PasskeyRequest> m_passkey;
        };

        LoginResult handleToken_(TokenResponse token);
        LoginResult completeLogin_(TokenResponse token);
        UnlockResult unlockWithMasterKey_(SecureBytes master_key);
        void onUnlocked_();
        void loadOrganizationKeys_();
        void post_(std::function<void()> task);
        void requestSync_();
        void workerLoop_(std::stop_token stop);
        void housekeeping_();
        void startNotifications_();
        void stopNotifications_();
        void notificationLoop_(std::stop_token stop);

        std::shared_ptr<SecretStore> m_secrets_;
        std::shared_ptr<FileStore> m_files_;

        mutable std::mutex m_auth_mutex_;
        std::optional<PendingLogin> m_pending_;
        std::optional<ServerUrls> m_pending_urls_;

        std::atomic<bool> m_sync_queued_ { false };
        std::atomic<std::time_t> m_last_activity_ { 0 };
        std::time_t m_last_connectivity_check_ = 0;

        std::mutex m_task_mutex_;
        std::condition_variable_any m_task_cv_;
        std::deque<std::function<void()>> m_tasks_;

        std::mutex m_notification_mutex_;
        std::jthread m_notifications_;
        std::jthread m_worker_;
    };
}
