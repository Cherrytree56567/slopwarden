#pragma once
#include <atomic>
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

#include "Crypto/Crypto.h"
#include "Net/Http.h"

namespace ClientWarden {
    struct DeviceInfo {
        std::string identifier;
        std::string type;
        std::string name;

        /*
         * Device type/name for the platform this binary was built for.
         * See SPEC.md for the device type table.
        */
        static DeviceInfo ForThisPlatform(std::string identifier);
    };

    enum class TwoFactorProvider {
        Authenticator = 0,
        Email = 1,
        WebAuthn = 7
    };

    struct TwoFactorToken {
        TwoFactorProvider provider;
        std::string token;
    };

    struct TokenResponse {
        enum class Kind {
            Success,
            TwoFactorRequired,
            NewDeviceVerification,
            InvalidCredentials,
            Failed
        };

        Kind kind = Kind::Failed;
        std::string accessToken;
        std::string refreshToken;
        int expiresIn = 0;

        std::vector<TwoFactorProvider> providers;
        std::string webAuthnChallenge;      // TwoFactorProviders2["7"].challenge
        std::string webAuthnRelyingParty;   // TwoFactorProviders2["7"].rpId, if sent
    };

    /*
     * Supplies bearer tokens to authenticated calls. Refresh() is called
     * with the rejected token once when the server answers 401, then the
     * call is retried.
    */
    class AccessTokenSource {
    public:
        virtual ~AccessTokenSource() = default;
        virtual std::optional<std::string> AccessToken() = 0;
        virtual bool Refresh(const std::string& rejected) = 0;
    };

    /*
     * Typed wrapper over the Bitwarden/Vaultwarden REST API.
     *
     * It holds no secrets beyond what each call is given, and tracks
     * connectivity as a side effect of every request instead of polling.
    */
    class BitwardenApi {
    public:
        BitwardenApi(HttpTransport& transport, DeviceInfo device);

        void Configure(const ServerUrls& urls);
        void SetTokenSource(AccessTokenSource* source);
        HttpTransport& Transport() { return transport; }

        bool Online() const { return online.load(); }
        bool CheckAlive();

        /*
         * Identity
        */
        std::optional<Crypto::KdfParams> PreLogin(const std::string& email);
        TokenResponse PasswordGrant(const std::string& email, const std::string& passwordHash,
            const std::optional<TwoFactorToken>& twoFactor = std::nullopt, const std::optional<std::string>& newDeviceOtp = std::nullopt);
        TokenResponse RefreshGrant(const std::string& refreshToken);

        /*
         * Account
        */
        std::optional<nlohmann::json> Config();
        std::optional<nlohmann::json> Profile();
        std::optional<nlohmann::json> Sync();

        /*
         * Ciphers
        */
        std::optional<nlohmann::json> CreateCipher(const nlohmann::json& cipher);
        std::optional<nlohmann::json> UpdateCipher(const nlohmann::json& cipher);
        bool DeleteCipher(const std::string& id);
        bool SoftDeleteCipher(const std::string& id);
        bool RestoreCipher(const std::string& id);
        bool ArchiveCiphers(const std::vector<std::string>& ids);
        bool UnarchiveCiphers(const std::vector<std::string>& ids);

        /*
         * Attachments
        */
        std::optional<nlohmann::json> UploadAttachment(const std::string& cipherId, const std::string& encryptedFileName,
            const std::string& encryptedKey, const std::vector<uint8_t>& encryptedContent, std::function<void(float)> onProgress);
        bool DeleteAttachment(const std::string& cipherId, const std::string& attachmentId);

        struct Download {
            nlohmann::json meta;            // id, fileName, key, url, size
            std::vector<uint8_t> content;   // still encrypted
        };
        std::optional<Download> DownloadAttachment(const std::string& cipherId, const std::string& attachmentId,
            std::function<void(float)> onProgress);

        /*
         * Folders
        */
        std::optional<nlohmann::json> CreateFolder(const std::string& encryptedName);
        std::optional<nlohmann::json> UpdateFolder(const std::string& id, const std::string& encryptedName);
        bool DeleteFolder(const std::string& id);

        std::optional<std::vector<uint8_t>> Icon(const std::string& domain);

    private:
        HttpResponse Call(HttpMethod method, Host host, const std::string& path, const nlohmann::json* body = nullptr);
        HttpResponse Send(HttpRequest request, bool authenticated);
        TokenResponse Token(std::vector<std::pair<std::string, std::string>> form);
        std::optional<nlohmann::json> JsonOf(const HttpResponse& res, std::string_view what);

        HttpTransport& transport;
        DeviceInfo device;
        AccessTokenSource* tokens = nullptr;
        std::atomic<bool> online { false };
    };
}
