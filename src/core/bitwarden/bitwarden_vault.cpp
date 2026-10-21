#include "bitwarden_vault.h"

#include <algorithm>

#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"
#include "utils/logger/logger.h"

namespace clientwarden {
    namespace {
        constexpr std::chrono::seconds c_tick { 1 };
        constexpr std::time_t c_connectivity_interval = 15;

        /**
         * @brief Loads the passphrase word list, or empty text if the bundle lacks it.
         *
         * @param resources Bundled resources
         * @return The word list
         */
        SecureString loadWordList_(std::shared_ptr<FileStore> resources) {
            std::optional<SecureBytes> words =
                    resources ? resources->read("clientgen.txt") : std::nullopt;
            if (!words) {
                Logger::get()->warn("Passphrase word list unavailable");
                return SecureString();
            }
            return SecureString(words->begin(), words->end());
        }
    }

    BitwardenVault::BitwardenVault(SecureString id, std::shared_ptr<SecretStore> secrets,
            std::shared_ptr<FileStore> files, std::shared_ptr<FileStore> resources,
            std::shared_ptr<HttpTransport> transport)
        : Vault(std::move(id), VaultType::Bitwarden), m_secrets_(secrets), m_files_(files) {
        m_crypto_ = std::make_shared<Crypto>();
        m_store_ = std::make_shared<Store>(files);
        m_features_ = std::make_shared<Features>(m_store_);
        m_settings_ = std::make_shared<Settings>(files);
        m_profile_ = std::make_shared<Profile>(m_store_);
        m_session_ = std::make_shared<Session>(secrets, m_crypto_);
        m_network_ = std::make_shared<Network>(
                std::move(transport), DeviceInfo::forThisPlatform(Session::getDeviceId(secrets)));
        m_network_->setTokenSource(m_session_);
        m_session_->setNetwork(m_network_);
        m_sync_ = std::make_shared<Sync>(m_network_, m_store_, m_features_);
        m_orchestrator_ = std::make_shared<Orchestrator>(
                m_crypto_, m_network_, m_store_, m_session_, m_features_, m_sync_, files);
        m_autofill_ = std::make_shared<AutoFill>(m_orchestrator_, m_store_);
        m_generator_ = std::make_shared<Generator>(m_crypto_, loadWordList_(std::move(resources)));

        m_session_->onRevoked([this]() { post_([this]() { logout(); }); });
        m_sync_->onAccountKeyChanged([this]() { post_([this]() { logout(); }); });
        m_orchestrator_->onSyncRequested([this]() { requestSync_(); });
        m_orchestrator_->onIntegrityFailure([this](std::string_view reason) {
            /*
             * Tampered or corrupt personal data: drop the keys at once and stop trusting the
             * cache until the user restarts (style guide: serious errors enter Failed).
             */
            m_session_->clearKeys();
            setFailed_(reason);
            post_([this]() { stopNotifications_(); });
        });

        m_settings_->load();

        std::optional<Account> account = m_session_->loadAccount();
        if (account && m_session_->loadTokens() && m_store_->load() && !m_store_->empty()) {
            m_network_->configure(account->m_urls);
            setState_(VaultState::Unlockable);
        } else {
            setState_(VaultState::LoggedOut);
        }

        m_worker_ = std::jthread([this](std::stop_token stop) { workerLoop_(stop); });
    }

    BitwardenVault::~BitwardenVault() {
        shutdown();

        /*
         * Items may outlive the vault (the UI can still hold one), so detach the callbacks
         * that point back at this object.
         */
        m_orchestrator_->onIntegrityFailure(nullptr);
        m_orchestrator_->onSyncRequested(nullptr);
        m_session_->onRevoked(nullptr);
        m_sync_->onAccountKeyChanged(nullptr);
        m_session_->clearKeys();
    }

    void BitwardenVault::shutdown() {
        m_worker_.request_stop();
        m_task_cv_.notify_all();
        if (m_worker_.joinable()) {
            m_worker_.join();
        }
        stopNotifications_();
    }

    /*
     * Login
     */
    void BitwardenVault::setServer(ServerUrls urls) {
        if (!urls.valid()) {
            throw VaultError("server URLs must start with http:// or https://");
        }
        std::lock_guard<std::mutex> lock(m_auth_mutex_);
        m_network_->configure(urls);
        m_pending_urls_ = std::move(urls);
    }

    LoginResult BitwardenVault::login(std::string_view raw_email, std::string_view password) {
        SecureString email = toLower(trim(raw_email));
        {
            std::lock_guard<std::mutex> lock(m_auth_mutex_);
            if (!m_pending_urls_) {
                throw VaultError("setServer must be called before login");
            }
        }

        std::optional<KdfParams> kdf = m_network_->preLogin(email);
        if (!kdf) {
            return m_network_->isOnline() ? LoginResult::Failed : LoginResult::Offline;
        }

        PendingLogin pending { email, *kdf };
        try {
            pending.m_master_key = m_crypto_->deriveMasterKey(password, email, *kdf);
        } catch (const CryptoError& e) {
            Logger::get()->error("Refusing server KDF settings: {}", e.what());
            return LoginResult::Failed;
        }
        pending.m_password_hash = m_crypto_->hashMasterPassword(pending.m_master_key, password);

        TokenResponse token = m_network_->passwordGrant(
                email, pending.m_password_hash, std::nullopt, std::nullopt);
        {
            std::lock_guard<std::mutex> lock(m_auth_mutex_);
            m_pending_ = std::move(pending);
        }
        return handleToken_(std::move(token));
    }

    LoginResult BitwardenVault::submitCode(std::string_view code) {
        std::optional<PendingLogin> pending;
        {
            std::lock_guard<std::mutex> lock(m_auth_mutex_);
            pending = m_pending_;
        }
        if (!pending) {
            return LoginResult::Failed;
        }

        TokenResponse token;
        if (getState() == VaultState::WaitingForTotp) {
            token = m_network_->passwordGrant(pending->m_email, pending->m_password_hash,
                    TwoFactorToken { TwoFactorProvider::Authenticator, SecureString(code) },
                    std::nullopt);
        } else if (getState() == VaultState::WaitingForDeviceVerification) {
            token = m_network_->passwordGrant(
                    pending->m_email, pending->m_password_hash, std::nullopt, SecureString(code));
        } else {
            return LoginResult::Failed;
        }
        return handleToken_(std::move(token));
    }

    std::optional<PasskeyRequest> BitwardenVault::getPendingPasskey() const {
        std::lock_guard<std::mutex> lock(m_auth_mutex_);
        return m_pending_ ? m_pending_->m_passkey : std::nullopt;
    }

    LoginResult BitwardenVault::submitPasskey(std::span<const uint8_t> credential_id,
            std::span<const uint8_t> authenticator_data, std::span<const uint8_t> client_data_json,
            std::span<const uint8_t> signature) {
        std::optional<PendingLogin> pending;
        {
            std::lock_guard<std::mutex> lock(m_auth_mutex_);
            pending = m_pending_;
        }
        if (!pending || getState() != VaultState::WaitingForPasskey) {
            return LoginResult::Failed;
        }

        // clang-format off
        Json assertion = {
            { "id", encoding::base64UrlEncode(credential_id) },
            { "rawId", encoding::base64UrlEncode(credential_id) },
            { "type", "public-key" },
            { "extensions", { { "appid", false } } },
            { "response", {
                { "authenticatorData", encoding::base64UrlEncode(authenticator_data) },
                { "clientDataJson", encoding::base64UrlEncode(client_data_json) },
                { "signature", encoding::base64UrlEncode(signature) }
            } }
        };
        // clang-format on
        return handleToken_(m_network_->passwordGrant(pending->m_email, pending->m_password_hash,
                TwoFactorToken { TwoFactorProvider::WebAuthn, assertion.dump() }, std::nullopt));
    }

    LoginResult BitwardenVault::handleToken_(TokenResponse token) {
        switch (token.m_kind) {
        case TokenResponse::Kind::Success: return completeLogin_(std::move(token));

        case TokenResponse::Kind::TwoFactorRequired: {
            bool totp = std::find(token.m_providers.begin(), token.m_providers.end(),
                                TwoFactorProvider::Authenticator) != token.m_providers.end();
            bool web_authn = std::find(token.m_providers.begin(), token.m_providers.end(),
                                     TwoFactorProvider::WebAuthn) != token.m_providers.end();
            if (totp) {
                setState_(VaultState::WaitingForTotp);
                return LoginResult::NeedsTotp;
            }
            if (web_authn && !token.m_web_authn_challenge.empty()) {
                {
                    std::lock_guard<std::mutex> lock(m_auth_mutex_);
                    SecureString relying_party = token.m_web_authn_relying_party;
                    if (relying_party.empty() && m_pending_urls_) {
                        relying_party = Orchestrator::hostName(m_pending_urls_->m_vault)
                                                .value_or(SecureString());
                    }
                    m_pending_->m_passkey =
                            PasskeyRequest { token.m_web_authn_challenge, relying_party };
                }
                setState_(VaultState::WaitingForPasskey);
                return LoginResult::NeedsPasskey;
            }
            Logger::get()->warn("No supported two-factor provider offered");
            return LoginResult::Failed;
        }

        case TokenResponse::Kind::NewDeviceVerification:
            setState_(VaultState::WaitingForDeviceVerification);
            return LoginResult::NeedsDeviceVerification;

        case TokenResponse::Kind::InvalidCredentials: return LoginResult::InvalidCredentials;

        case TokenResponse::Kind::Failed: break;
        }
        return m_network_->isOnline() ? LoginResult::Failed : LoginResult::Offline;
    }

    LoginResult BitwardenVault::completeLogin_(TokenResponse token) {
        PendingLogin pending;
        ServerUrls urls;
        {
            std::lock_guard<std::mutex> lock(m_auth_mutex_);
            if (!m_pending_ || !m_pending_urls_) {
                return LoginResult::Failed;
            }
            pending = std::move(*m_pending_);
            urls = *m_pending_urls_;
            m_pending_.reset();
        }

        m_store_->clear();
        Account account { pending.m_email, pending.m_kdf, urls, false };
        if (!m_session_->setTokens(std::move(token)) ||
                !m_session_->saveAccount(std::move(account)) || !m_sync_->run()) {
            m_session_->forget();
            m_store_->clear();
            setState_(VaultState::LoggedOut);
            return LoginResult::Failed;
        }

        if (unlockWithMasterKey_(std::move(pending.m_master_key)) != UnlockResult::Success) {
            m_session_->forget();
            m_store_->clear();
            setState_(VaultState::LoggedOut);
            return LoginResult::Failed;
        }
        return LoginResult::Success;
    }

    /*
     * Lock / unlock
     */
    UnlockResult BitwardenVault::unlockWithMasterKey_(SecureBytes master_key) {
        std::optional<SecureString> protected_key = m_profile_->getProtectedKey();
        if (!protected_key) {
            return UnlockResult::Failed;
        }

        SymmetricKey user_key;
        try {
            user_key =
                    m_crypto_->unwrapKey(*protected_key, m_crypto_->stretchMasterKey(master_key));
        } catch (const CryptoError&) {
            return UnlockResult::InvalidPassword;
        }

        m_session_->setKeys(std::move(master_key), std::move(user_key));
        onUnlocked_();
        return UnlockResult::Success;
    }

    void BitwardenVault::onUnlocked_() {
        m_last_activity_ = std::time(nullptr);
        setState_(VaultState::Unlocked);
        startNotifications_();
        requestSync_();
    }

    UnlockResult BitwardenVault::unlock(std::string_view password) {
        if (getState() != VaultState::Unlockable) {
            return UnlockResult::Failed;
        }
        std::optional<Account> account = m_session_->loadAccount();
        if (!account) {
            return UnlockResult::Failed;
        }

        SecureBytes master_key;
        try {
            master_key = m_crypto_->deriveMasterKey(password, account->m_email, account->m_kdf);
        } catch (const CryptoError& e) {
            Logger::get()->error("Unlock failed: {}", e.what());
            return UnlockResult::Failed;
        }
        return unlockWithMasterKey_(std::move(master_key));
    }

    UnlockResult BitwardenVault::unlockWithBiometrics() {
        if (getState() != VaultState::Unlockable) {
            return UnlockResult::Failed;
        }
        std::optional<SecureBytes> master_key = m_session_->loadBiometricKey();
        if (!master_key) {
            return UnlockResult::Failed;
        }
        return unlockWithMasterKey_(std::move(*master_key));
    }

    void BitwardenVault::lock() {
        if (getState() != VaultState::Unlocked) {
            return;
        }
        stopNotifications_();
        m_session_->clearKeys();
        m_last_activity_ = 0;
        setState_(VaultState::Unlockable);
    }

    void BitwardenVault::logout() {
        stopNotifications_();
        m_sync_->invalidate();
        m_session_->forget();
        m_store_->clear();
        m_settings_->reset();
        m_files_->removeTree("icons");
        {
            std::lock_guard<std::mutex> lock(m_auth_mutex_);
            m_pending_.reset();
        }
        m_last_activity_ = 0;
        setState_(VaultState::LoggedOut);
    }

    bool BitwardenVault::verifyMasterPassword(std::string_view password) {
        std::optional<Account> account = m_session_->loadAccount();
        if (!account || !m_session_->hasKeys()) {
            return false;
        }
        try {
            return m_session_->masterKeyEquals(
                    m_crypto_->deriveMasterKey(password, account->m_email, account->m_kdf));
        } catch (const CryptoError&) {
            return false;
        }
    }

    bool BitwardenVault::enableBiometrics() {
        return getState() == VaultState::Unlocked && m_session_->saveBiometricKey();
    }

    bool BitwardenVault::disableBiometrics() {
        return m_session_->removeBiometricKey();
    }

    bool BitwardenVault::biometricsEnabled() {
        return m_session_->hasBiometricKey();
    }

    void BitwardenVault::noteActivity(std::time_t when) {
        if (getState() == VaultState::Unlocked) {
            m_last_activity_ = when;
        }
    }

    bool BitwardenVault::syncNow() {
        return m_sync_->run();
    }

    /*
     * Background work
     */
    void BitwardenVault::post_(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(m_task_mutex_);
            m_tasks_.push_back(std::move(task));
        }
        m_task_cv_.notify_one();
    }

    void BitwardenVault::requestSync_() {
        if (!m_sync_queued_.exchange(true)) {
            post_([this]() {
                m_sync_queued_ = false;
                m_sync_->run();
            });
        }
    }

    void BitwardenVault::workerLoop_(std::stop_token stop) {
        std::chrono::steady_clock::time_point next_tick = std::chrono::steady_clock::now() + c_tick;

        while (!stop.stop_requested()) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(m_task_mutex_);
                m_task_cv_.wait_until(
                        lock, stop, next_tick, [this]() { return !m_tasks_.empty(); });
                if (stop.stop_requested()) {
                    return;
                }
                if (!m_tasks_.empty()) {
                    task = std::move(m_tasks_.front());
                    m_tasks_.pop_front();
                }
            }

            try {
                if (task) {
                    task();
                }
                if (std::chrono::steady_clock::now() >= next_tick) {
                    next_tick = std::chrono::steady_clock::now() + c_tick;
                    housekeeping_();
                }
            } catch (const std::exception& e) {
                Logger::get()->error("Background task failed: {}", e.what());
            }
        }
    }

    void BitwardenVault::housekeeping_() {
        std::time_t now = std::time(nullptr);

        if (getState() == VaultState::Unlocked) {
            std::time_t last = m_last_activity_.load();
            if (last != 0 && now - last >= m_settings_->getAutoLockSeconds()) {
                if (m_settings_->getTimeoutAction() == TimeoutAction::Logout) {
                    Logger::get()->info("Logging out after inactivity");
                    logout();
                } else {
                    Logger::get()->info("Auto-locking after inactivity");
                    lock();
                }
                return;
            }
        }

        if (getState() == VaultState::Unlocked || getState() == VaultState::Unlockable) {
            if (!m_network_->isOnline() &&
                    now - m_last_connectivity_check_ >= c_connectivity_interval) {
                m_last_connectivity_check_ = now;
                if (m_network_->checkAlive() && getState() == VaultState::Unlocked) {
                    requestSync_();
                }
            }
            if (m_network_->isOnline() && !m_features_->versionKnown()) {
                std::optional<Json> config = m_network_->getConfig();
                if (config) {
                    m_features_->applyConfig(*config);
                }
            }
        }
    }

    void BitwardenVault::startNotifications_() {
        std::lock_guard<std::mutex> lock(m_notification_mutex_);
        if (!m_notifications_.joinable()) {
            m_notifications_ =
                    std::jthread([this](std::stop_token stop) { notificationLoop_(stop); });
        }
    }

    void BitwardenVault::stopNotifications_() {
        std::jthread listener;
        {
            std::lock_guard<std::mutex> lock(m_notification_mutex_);
            listener = std::move(m_notifications_);
        }
        if (listener.joinable()) {
            listener.request_stop();
            listener.join();
        }
    }

    void BitwardenVault::notificationLoop_(std::stop_token stop) {
        std::mutex wait_mutex;
        std::condition_variable_any wait_cv;
        std::chrono::seconds backoff { 1 };

        while (!stop.stop_requested()) {
            std::optional<SecureString> token = m_session_->getAccessToken();
            bool connected =
                    token && m_network_->getTransport()->listen(
                                     *token,
                                     [this](std::span<const uint8_t> frame) {
                                         for (PushType type : parseNotificationFrame(frame)) {
                                             if (type == PushType::LogOut) {
                                                 post_([this]() { logout(); });
                                             } else if (type != PushType::SyncOrgKeys &&
                                                        type != PushType::SyncSettings) {
                                                 requestSync_();
                                             }
                                         }
                                     },
                                     stop);

            /*
             * Reconnect with exponential backoff, capped at a minute.
             */
            backoff = connected ? std::chrono::seconds(1)
                                : std::min(backoff * 2, std::chrono::seconds(60));
            std::unique_lock<std::mutex> lock(wait_mutex);
            wait_cv.wait_for(lock, stop, backoff, []() { return false; });
        }
    }
}
