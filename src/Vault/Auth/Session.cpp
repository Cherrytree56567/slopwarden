#include "Session.h"

#include "Util/Util.h"

namespace ClientWarden {
    namespace {
        constexpr const char* AccountKey = "account";
        constexpr const char* TokensKey = "tokens";
        constexpr const char* DeviceKey = "deviceId";
        constexpr const char* BiometricKey = "internalKey";

        /*
         * Refresh slightly before expiry so a request never goes out with
         * a token that dies in flight.
        */
        constexpr std::time_t RefreshMargin = 60;

        /*
         * Keychain layout used before this rewrite; read once and migrated.
        */
        constexpr const char* LegacyKeys[] = {
            "email", "salt", "kdfType", "kdfIterations", "kdfMemory", "kdfParallelism", "vaultURL", "mainURL",
            "apiURL", "iconURL", "wssURL", "accessString", "refreshToken", "expiresIn", "needsRefreshTime", "masterPasswordHash"
        };

        std::optional<nlohmann::json> ReadJson(SecretStore& secrets, const char* key) {
            auto value = secrets.Get(key);
            if (!value) {
                return std::nullopt;
            }
            nlohmann::json j = nlohmann::json::parse(value->begin(), value->end(), nullptr, false);
            if (j.is_discarded()) {
                return std::nullopt;
            }
            return j;
        }

        std::string Str(const std::optional<SecretString>& s) {
            return s ? std::string(s->begin(), s->end()) : std::string();
        }
    }

    nlohmann::json Account::ToJson() const {
        return {
            { "email", email },
            { "kdf", {
                { "type", static_cast<int>(kdf.type) },
                { "iterations", kdf.iterations },
                { "memory", kdf.memoryMiB },
                { "parallelism", kdf.parallelism }
            } },
            { "urls", urls.ToJson() }
        };
    }

    std::optional<Account> Account::FromJson(const nlohmann::json& j) {
        if (!j.is_object() || !j.contains("kdf") || !j["kdf"].is_object() || !j.contains("urls")) {
            return std::nullopt;
        }
        auto urls = ServerUrls::FromJson(j["urls"]);
        if (!urls) {
            return std::nullopt;
        }
        const auto& kdf = j["kdf"];
        Account a {
            j.value("email", ""),
            Crypto::KdfParams {
                static_cast<Crypto::KdfType>(kdf.value("type", 0)),
                kdf.value("iterations", 0u),
                kdf.value("memory", 0u),
                kdf.value("parallelism", 0u)
            },
            *urls
        };
        if (a.email.empty()) {
            return std::nullopt;
        }
        return a;
    }

    Session::Session(SecretStore& secrets, BitwardenApi& api) : secrets(secrets), api(api) {}

    std::string Session::DeviceId(SecretStore& secrets) {
        if (auto id = secrets.Get(DeviceKey); id && !id->empty()) {
            return std::string(id->begin(), id->end());
        }
        std::string id = NewGuid();
        secrets.Set(DeviceKey, id);
        return id;
    }

    std::optional<Account> Session::LoadAccount() {
        if (auto j = ReadJson(secrets, AccountKey)) {
            return Account::FromJson(*j);
        }
        return MigrateLegacyAccount();
    }

    std::optional<Account> Session::MigrateLegacyAccount() {
        auto email = secrets.Get("email");
        if (!email) {
            return std::nullopt;
        }

        auto toInt = [&](const char* key) -> uint32_t {
            try { return static_cast<uint32_t>(std::stoul(Str(secrets.Get(key)))); } catch (...) { return 0; }
        };

        Account account {
            Str(email),
            Crypto::KdfParams { static_cast<Crypto::KdfType>(toInt("kdfType")), toInt("kdfIterations"), toInt("kdfMemory"), toInt("kdfParallelism") },
            ServerUrls { Str(secrets.Get("vaultURL")), Str(secrets.Get("apiURL")), Str(secrets.Get("iconURL")), Str(secrets.Get("wssURL")) }
        };
        if (!account.urls.Valid()) {
            return std::nullopt;
        }

        std::string access = Str(secrets.Get("accessString"));
        std::string refresh = Str(secrets.Get("refreshToken"));
        std::time_t expiry = ParseTime(Str(secrets.Get("needsRefreshTime")));

        nlohmann::json tokens = { { "access", access }, { "refresh", refresh }, { "expiresAt", expiry } };
        if (!SaveAccount(account) || !secrets.Set(TokensKey, tokens.dump())) {
            return std::nullopt;
        }

        for (const char* key : LegacyKeys) {
            secrets.Remove(key);
        }
        Log()->info("Migrated keychain entries to the new layout");
        return account;
    }

    bool Session::SaveAccount(const Account& account) {
        return secrets.Set(AccountKey, account.ToJson().dump());
    }

    bool Session::LoadTokens() {
        auto j = ReadJson(secrets, TokensKey);
        if (!j || !j->is_object()) {
            return false;
        }

        std::lock_guard lock(tokenMutex);
        accessToken = j->value("access", "");
        refreshToken = j->value("refresh", "");
        expiresAt = j->value("expiresAt", static_cast<std::time_t>(0));
        return !refreshToken.empty();
    }

    bool Session::SetTokens(const TokenResponse& token) {
        std::lock_guard lock(tokenMutex);
        accessToken = token.accessToken;
        if (!token.refreshToken.empty()) {
            refreshToken = token.refreshToken;
        }
        expiresAt = std::time(nullptr) + token.expiresIn;

        nlohmann::json j = { { "access", accessToken }, { "refresh", refreshToken }, { "expiresAt", expiresAt } };
        return secrets.Set(TokensKey, j.dump());
    }

    std::optional<std::string> Session::AccessToken() {
        std::string current;
        {
            std::lock_guard lock(tokenMutex);
            if (accessToken.empty() && refreshToken.empty()) {
                return std::nullopt;
            }
            if (!accessToken.empty() && std::time(nullptr) + RefreshMargin < expiresAt) {
                return accessToken;
            }
            current = accessToken;
        }

        if (!Refresh(current)) {
            return std::nullopt;
        }
        std::lock_guard lock(tokenMutex);
        return accessToken;
    }

    bool Session::Refresh(const std::string& rejected) {
        std::lock_guard serial(refreshMutex);

        std::string refresh;
        {
            std::lock_guard lock(tokenMutex);
            /*
             * Another thread already replaced the token we were about to
             * refresh; use theirs rather than spending the refresh token
             * twice.
            */
            if (!accessToken.empty() && accessToken != rejected) {
                return true;
            }
            refresh = refreshToken;
        }
        if (refresh.empty()) {
            return false;
        }

        TokenResponse res = api.RefreshGrant(refresh);
        if (res.kind == TokenResponse::Kind::Success) {
            return SetTokens(res);
        }

        if (res.kind == TokenResponse::Kind::InvalidCredentials) {
            Log()->warn("Refresh token revoked; logging out");
            std::function<void()> callback;
            {
                std::lock_guard lock(tokenMutex);
                accessToken.clear();
                refreshToken.clear();
                callback = onRevoked;
            }
            if (callback) {
                callback();
            }
        }
        return false;
    }

    void Session::OnRevoked(std::function<void()> callback) {
        std::lock_guard lock(tokenMutex);
        onRevoked = std::move(callback);
    }

    void Session::SetKeys(Bytes master, Crypto::SymmetricKey user) {
        std::unique_lock lock(keyMutex);
        masterKey = std::move(master);
        userKey = std::move(user);
    }

    void Session::ClearKeys() {
        std::unique_lock lock(keyMutex);
        masterKey.clear();
        masterKey.shrink_to_fit();
        userKey = {};
    }

    bool Session::HasKeys() const {
        std::shared_lock lock(keyMutex);
        return userKey.Valid();
    }

    Crypto::SymmetricKey Session::UserKey() const {
        std::shared_lock lock(keyMutex);
        if (!userKey.Valid()) {
            throw VaultError("vault is locked");
        }
        return userKey;
    }

    bool Session::MasterKeyEquals(const Bytes& candidate) const {
        std::shared_lock lock(keyMutex);
        return !masterKey.empty() && Crypto::ConstantTimeEquals(masterKey, candidate);
    }

    bool Session::SaveBiometricKey() {
        std::string encoded;
        {
            std::shared_lock lock(keyMutex);
            if (masterKey.empty()) {
                return false;
            }
            encoded = Crypto::Base64Encode(masterKey);
        }
        bool ok = secrets.Set(BiometricKey, encoded, SecretProtection::UserAuth);
        Wipe(encoded);
        return ok && SetBiometricFlag(true);
    }

    bool Session::SetBiometricFlag(bool enabled) {
        auto j = ReadJson(secrets, AccountKey);
        if (!j || !j->is_object()) {
            return false;
        }
        (*j)["biometrics"] = enabled;
        return secrets.Set(AccountKey, j->dump());
    }

    std::optional<Bytes> Session::LoadBiometricKey() {
        auto value = secrets.Get(BiometricKey);
        if (!value) {
            return std::nullopt;
        }
        return Crypto::Base64Decode(std::string_view(value->data(), value->size()));
    }

    bool Session::RemoveBiometricKey() {
        SetBiometricFlag(false);
        return secrets.Remove(BiometricKey);
    }

    bool Session::HasBiometricKey() {
        /*
         * Reading would trigger the biometric prompt, so presence is
         * tracked in the account record instead.
        */
        auto j = ReadJson(secrets, AccountKey);
        return j && j->value("biometrics", false);
    }

    void Session::Forget() {
        ClearKeys();
        {
            std::lock_guard lock(tokenMutex);
            accessToken.clear();
            refreshToken.clear();
            expiresAt = 0;
        }
        for (const char* key : { AccountKey, TokensKey, BiometricKey }) {
            secrets.Remove(key);
        }
        for (const char* key : LegacyKeys) {
            secrets.Remove(key);
        }
    }
}
