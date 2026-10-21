#pragma once
#include <ctime>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>

#include "Crypto/Crypto.h"
#include "Net/BitwardenApi.h"
#include "Platform/SecretStore.h"

namespace ClientWarden {
    struct Account {
        std::string email;
        Crypto::KdfParams kdf;
        ServerUrls urls;

        nlohmann::json ToJson() const;
        static std::optional<Account> FromJson(const nlohmann::json& j);
    };

    /*
     * Owns everything secret about the logged-in user:
     *
     *  - the account record and OAuth tokens (persisted in the keychain,
     *    cached in memory so requests don't hit the keychain)
     *  - the master key and user key (memory only, wiped on lock)
     *
     * Implements AccessTokenSource so BitwardenApi can refresh tokens
     * transparently.
    */
    class Session : public AccessTokenSource {
    public:
        Session(SecretStore& secrets, BitwardenApi& api);

        static std::string DeviceId(SecretStore& secrets);

        std::optional<Account> LoadAccount();
        bool SaveAccount(const Account& account);

        bool LoadTokens();
        bool SetTokens(const TokenResponse& token);
        std::optional<std::string> AccessToken() override;
        bool Refresh(const std::string& rejected) override;

        /*
         * Called (from whichever thread noticed) when the server revokes
         * the refresh token.
        */
        void OnRevoked(std::function<void()> callback);

        void SetKeys(Bytes masterKey, Crypto::SymmetricKey userKey);
        void ClearKeys();
        bool HasKeys() const;
        Crypto::SymmetricKey UserKey() const;
        bool MasterKeyEquals(const Bytes& candidate) const;

        bool SaveBiometricKey();
        std::optional<Bytes> LoadBiometricKey();
        bool RemoveBiometricKey();
        bool HasBiometricKey();

        /*
         * Removes every credential except the device id.
        */
        void Forget();

    private:
        std::optional<Account> MigrateLegacyAccount();
        bool SetBiometricFlag(bool enabled);

        SecretStore& secrets;
        BitwardenApi& api;

        std::mutex refreshMutex;
        std::mutex tokenMutex;
        std::string accessToken;
        std::string refreshToken;
        std::time_t expiresAt = 0;
        std::function<void()> onRevoked;

        mutable std::shared_mutex keyMutex;
        Bytes masterKey;
        Crypto::SymmetricKey userKey;
    };
}
