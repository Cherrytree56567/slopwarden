#include "session.h"

#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"
#include "utils/logger/logger.h"
#include "utils/timestamp/timestamp.h"
#include "utils/uuid/uuid.h"

namespace clientwarden {
    namespace {
        constexpr std::string_view c_account_key = "account";
        constexpr std::string_view c_tokens_key = "tokens";
        constexpr std::string_view c_device_key = "deviceId";
        constexpr std::string_view c_biometric_key = "internalKey";

        /*
         * Refresh slightly before expiry so a request never goes out with a token that dies
         * in flight.
         */
        constexpr std::time_t c_refresh_margin = 60;

        /*
         * Keychain layout used before the rewrite; read once and migrated.
         */
        // clang-format off
        constexpr std::string_view c_legacy_keys[] = {
            "email", "salt", "kdfType", "kdfIterations", "kdfMemory", "kdfParallelism",
            "vaultURL", "mainURL", "apiURL", "iconURL", "wssURL", "accessString",
            "refreshToken", "expiresIn", "needsRefreshTime", "masterPasswordHash"
        };
        // clang-format on

        /**
         * @brief Reads a keychain entry holding JSON.
         *
         * @param secrets The keychain
         * @param key The entry
         * @return The parsed JSON, or nullopt if absent or malformed
         */
        std::optional<Json> readJson_(std::shared_ptr<SecretStore> secrets, std::string_view key) {
            std::optional<SecureString> value = secrets->get(key);
            if (!value) {
                return std::nullopt;
            }
            Json json = Json::parse(value->begin(), value->end(), nullptr, false);
            if (json.is_discarded() || !json.is_object()) {
                return std::nullopt;
            }
            return json;
        }

        /**
         * @brief Reads a non-negative integer member.
         *
         * @param json The object
         * @param key The member
         * @return The value, or 0
         */
        uint32_t uintAt_(const Json& json, std::string_view key) {
            const Json& value = at(json, key);
            return value.is_number_unsigned() ||
                                   (value.is_number_integer() && value.get<std::int64_t>() >= 0)
                           ? static_cast<uint32_t>(value.get<std::int64_t>())
                           : 0;
        }

        /**
         * @brief Reads a legacy keychain entry holding a decimal number.
         *
         * @param secrets The keychain
         * @param key The entry
         * @return The value, or 0
         */
        uint32_t legacyUint_(std::shared_ptr<SecretStore> secrets, std::string_view key) {
            std::optional<SecureString> value = secrets->get(key);
            std::int64_t parsed = 0;
            return value && parseInt(*value, parsed) && parsed >= 0 ? static_cast<uint32_t>(parsed)
                                                                    : 0;
        }
    }

    Json Account::toJson() const {
        // clang-format off
        return {
            { "email", m_email },
            { "kdf", {
                { "type", static_cast<int>(m_kdf.m_type) },
                { "iterations", m_kdf.m_iterations },
                { "memory", m_kdf.m_memory_mib },
                { "parallelism", m_kdf.m_parallelism }
            } },
            { "urls", m_urls.toJson() },
            { "biometrics", m_biometrics }
        };
        // clang-format on
    }

    std::optional<Account> Account::fromJson(const Json& json) {
        const Json& kdf = at(json, "kdf");
        std::optional<ServerUrls> urls = ServerUrls::fromJson(at(json, "urls"));
        SecureString email = stringAt(json, "email");
        if (!kdf.is_object() || !urls || email.empty()) {
            return std::nullopt;
        }

        Account account;
        account.m_email = std::move(email);
        account.m_kdf.m_type = static_cast<KdfType>(uintAt_(kdf, "type"));
        account.m_kdf.m_iterations = uintAt_(kdf, "iterations");
        account.m_kdf.m_memory_mib = uintAt_(kdf, "memory");
        account.m_kdf.m_parallelism = uintAt_(kdf, "parallelism");
        account.m_urls = std::move(*urls);
        const Json& biometrics = at(json, "biometrics");
        account.m_biometrics = biometrics.is_boolean() && biometrics.get<bool>();
        return account;
    }

    Session::Session(std::shared_ptr<SecretStore> secrets, std::shared_ptr<Crypto> crypto)
        : m_secrets_(std::move(secrets)), m_crypto_(std::move(crypto)) {}

    void Session::setNetwork(std::shared_ptr<Network> network) {
        m_network_ = network;
    }

    SecureString Session::getDeviceId(std::shared_ptr<SecretStore> secrets) {
        std::optional<SecureString> existing = secrets->get(c_device_key);
        if (existing && !existing->empty()) {
            return *existing;
        }
        SecureString id = uuid::generate();
        secrets->set(c_device_key, id, SecretProtection::None);
        return id;
    }

    std::optional<Account> Session::loadAccount() {
        std::optional<Json> json = readJson_(m_secrets_, c_account_key);
        if (json) {
            return Account::fromJson(*json);
        }
        return migrateLegacyAccount_();
    }

    std::optional<Account> Session::migrateLegacyAccount_() {
        std::optional<SecureString> email = m_secrets_->get("email");
        if (!email) {
            return std::nullopt;
        }

        Account account;
        account.m_email = *email;
        account.m_kdf.m_type = static_cast<KdfType>(legacyUint_(m_secrets_, "kdfType"));
        account.m_kdf.m_iterations = legacyUint_(m_secrets_, "kdfIterations");
        account.m_kdf.m_memory_mib = legacyUint_(m_secrets_, "kdfMemory");
        account.m_kdf.m_parallelism = legacyUint_(m_secrets_, "kdfParallelism");
        account.m_urls.m_vault = m_secrets_->get("vaultURL").value_or(SecureString());
        account.m_urls.m_api = m_secrets_->get("apiURL").value_or(SecureString());
        account.m_urls.m_icons = m_secrets_->get("iconURL").value_or(SecureString());
        account.m_urls.m_notifications = m_secrets_->get("wssURL").value_or(SecureString());
        if (!account.m_urls.valid()) {
            return std::nullopt;
        }

        // clang-format off
        Json tokens = {
            { "access", m_secrets_->get("accessString").value_or(SecureString()) },
            { "refresh", m_secrets_->get("refreshToken").value_or(SecureString()) },
            { "expiresAt", static_cast<std::int64_t>(
                timestamp::parse(m_secrets_->get("needsRefreshTime").value_or(SecureString()))) }
        };
        // clang-format on
        if (!saveAccount(account) ||
                !m_secrets_->set(c_tokens_key, tokens.dump(), SecretProtection::None)) {
            return std::nullopt;
        }

        for (std::string_view key : c_legacy_keys) {
            m_secrets_->remove(key);
        }
        Logger::get()->info("Migrated keychain entries to the new layout");
        return account;
    }

    bool Session::saveAccount(Account account) {
        return m_secrets_->set(c_account_key, account.toJson().dump(), SecretProtection::None);
    }

    bool Session::loadTokens() {
        std::optional<Json> json = readJson_(m_secrets_, c_tokens_key);
        if (!json) {
            return false;
        }

        std::lock_guard<std::mutex> lock(m_token_mutex_);
        m_access_token_ = stringAt(*json, "access");
        m_refresh_token_ = stringAt(*json, "refresh");
        const Json& expires = at(*json, "expiresAt");
        m_expires_at_ = expires.is_number_integer()
                                ? static_cast<std::time_t>(expires.get<std::int64_t>())
                                : 0;
        return !m_refresh_token_.empty();
    }

    bool Session::setTokens(TokenResponse token) {
        std::lock_guard<std::mutex> lock(m_token_mutex_);
        m_access_token_ = std::move(token.m_access_token);
        if (!token.m_refresh_token.empty()) {
            m_refresh_token_ = std::move(token.m_refresh_token);
        }
        m_expires_at_ = std::time(nullptr) + token.m_expires_in;

        // clang-format off
        Json json = {
            { "access", m_access_token_ },
            { "refresh", m_refresh_token_ },
            { "expiresAt", static_cast<std::int64_t>(m_expires_at_) }
        };
        // clang-format on
        return m_secrets_->set(c_tokens_key, json.dump(), SecretProtection::None);
    }

    std::optional<SecureString> Session::getAccessToken() {
        SecureString current;
        {
            std::lock_guard<std::mutex> lock(m_token_mutex_);
            if (m_access_token_.empty() && m_refresh_token_.empty()) {
                return std::nullopt;
            }
            if (!m_access_token_.empty() && std::time(nullptr) + c_refresh_margin < m_expires_at_) {
                return m_access_token_;
            }
            current = m_access_token_;
        }

        if (!refresh(current)) {
            return std::nullopt;
        }
        std::lock_guard<std::mutex> lock(m_token_mutex_);
        return m_access_token_;
    }

    bool Session::refresh(std::string_view rejected) {
        std::lock_guard<std::mutex> serial(m_refresh_mutex_);

        SecureString refresh_token;
        {
            std::lock_guard<std::mutex> lock(m_token_mutex_);
            /*
             * Another thread already replaced the token we were about to refresh; use theirs
             * rather than spending the refresh token twice.
             */
            if (!m_access_token_.empty() && std::string_view(m_access_token_) != rejected) {
                return true;
            }
            refresh_token = m_refresh_token_;
        }
        std::shared_ptr<Network> network = m_network_.lock();
        if (refresh_token.empty() || !network) {
            return false;
        }

        TokenResponse response = network->refreshGrant(refresh_token);
        if (response.m_kind == TokenResponse::Kind::Success) {
            return setTokens(std::move(response));
        }

        if (response.m_kind == TokenResponse::Kind::InvalidCredentials) {
            Logger::get()->warn("Refresh token revoked; logging out");
            std::function<void()> callback;
            {
                std::lock_guard<std::mutex> lock(m_token_mutex_);
                m_access_token_.clear();
                m_refresh_token_.clear();
                callback = m_on_revoked_;
            }
            if (callback) {
                callback();
            }
        }
        return false;
    }

    void Session::onRevoked(std::function<void()> callback) {
        std::lock_guard<std::mutex> lock(m_token_mutex_);
        m_on_revoked_ = std::move(callback);
    }

    void Session::setKeys(SecureBytes master_key, SymmetricKey user_key) {
        std::unique_lock<std::shared_mutex> lock(m_key_mutex_);
        m_master_key_ = std::move(master_key);
        m_user_key_ = std::move(user_key);
    }

    void Session::clearKeys() {
        std::unique_lock<std::shared_mutex> lock(m_key_mutex_);
        m_master_key_.clear();
        m_master_key_.shrink_to_fit();
        m_user_key_ = SymmetricKey();
        m_organization_keys_.clear();
    }

    void Session::setOrganizationKeys(std::map<SecureString, SymmetricKey, std::less<>> keys) {
        std::unique_lock<std::shared_mutex> lock(m_key_mutex_);
        m_organization_keys_ = std::move(keys);
    }

    std::optional<SymmetricKey> Session::getOrganizationKey(
            std::string_view organization_id) const {
        std::shared_lock<std::shared_mutex> lock(m_key_mutex_);
        std::map<SecureString, SymmetricKey, std::less<>>::const_iterator it =
                m_organization_keys_.find(organization_id);
        if (it == m_organization_keys_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool Session::hasKeys() const {
        std::shared_lock<std::shared_mutex> lock(m_key_mutex_);
        return m_user_key_.valid();
    }

    SymmetricKey Session::getUserKey() const {
        std::shared_lock<std::shared_mutex> lock(m_key_mutex_);
        if (!m_user_key_.valid()) {
            throw VaultError("vault is locked");
        }
        return m_user_key_;
    }

    bool Session::masterKeyEquals(std::span<const uint8_t> candidate) const {
        std::shared_lock<std::shared_mutex> lock(m_key_mutex_);
        return !m_master_key_.empty() && m_crypto_->constantTimeEquals(m_master_key_, candidate);
    }

    bool Session::saveBiometricKey() {
        SecureString encoded;
        {
            std::shared_lock<std::shared_mutex> lock(m_key_mutex_);
            if (m_master_key_.empty()) {
                return false;
            }
            encoded = encoding::base64Encode(m_master_key_);
        }
        bool saved = m_secrets_->set(c_biometric_key, encoded, SecretProtection::UserAuth);
        return saved && setBiometricFlag_(true);
    }

    bool Session::setBiometricFlag_(bool enabled) {
        std::optional<Account> account = loadAccount();
        if (!account) {
            return false;
        }
        account->m_biometrics = enabled;
        return saveAccount(std::move(*account));
    }

    std::optional<SecureBytes> Session::loadBiometricKey() {
        std::optional<SecureString> value = m_secrets_->get(c_biometric_key);
        if (!value) {
            return std::nullopt;
        }
        try {
            return encoding::base64Decode(*value);
        } catch (const CryptoError&) {
            return std::nullopt;
        }
    }

    bool Session::removeBiometricKey() {
        setBiometricFlag_(false);
        return m_secrets_->remove(c_biometric_key);
    }

    bool Session::hasBiometricKey() {
        /*
         * Reading the key itself would trigger the biometric prompt, so presence is tracked in
         * the account record instead.
         */
        std::optional<Account> account = loadAccount();
        return account && account->m_biometrics;
    }

    void Session::forget() {
        clearKeys();
        {
            std::lock_guard<std::mutex> lock(m_token_mutex_);
            m_access_token_.clear();
            m_refresh_token_.clear();
            m_expires_at_ = 0;
        }
        for (std::string_view key : { c_account_key, c_tokens_key, c_biometric_key }) {
            m_secrets_->remove(key);
        }
        for (std::string_view key : c_legacy_keys) {
            m_secrets_->remove(key);
        }
    }
}
