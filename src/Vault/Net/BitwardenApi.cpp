#include "BitwardenApi.h"

#include <iomanip>
#include <sstream>

namespace ClientWarden {
    namespace {
        constexpr const char* ClientName = "desktop";
        constexpr const char* ClientVersion = "2026.3.0";

        std::string FormEncode(const std::vector<std::pair<std::string, std::string>>& fields) {
            std::ostringstream out;
            out << std::hex << std::uppercase;
            bool first = true;
            for (const auto& [key, value] : fields) {
                if (!first) out << '&';
                first = false;
                for (const std::string* part : { &key, &value }) {
                    for (unsigned char c : *part) {
                        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                            out << c;
                        } else {
                            out << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(c);
                        }
                    }
                    if (part == &key) out << '=';
                }
            }
            return out.str();
        }

        /*
         * Path segments come from server data (ids), so refuse anything
         * that could escape the intended route.
        */
        std::string Segment(const std::string& id) {
            for (unsigned char c : id) {
                if (!std::isalnum(c) && c != '-') {
                    throw VaultError("invalid id in request path");
                }
            }
            return id;
        }

        std::optional<int> AsInt(const nlohmann::json& j, const char* key) {
            auto it = j.find(key);
            if (it == j.end()) {
                return std::nullopt;
            }
            if (it->is_number_integer()) {
                return it->get<int>();
            }
            if (it->is_string()) {
                try { return std::stoi(it->get<std::string>()); } catch (...) {}
            }
            return std::nullopt;
        }
    }

    DeviceInfo DeviceInfo::ForThisPlatform(std::string identifier) {
        #if defined(__ANDROID__)
            return { std::move(identifier), "0", "android" };
        #elif defined(_WIN32)
            return { std::move(identifier), "6", "windows" };
        #elif defined(__APPLE__)
            return { std::move(identifier), "7", "macos" };
        #else
            return { std::move(identifier), "8", "linux" };
        #endif
    }

    BitwardenApi::BitwardenApi(HttpTransport& transport, DeviceInfo device) : transport(transport), device(std::move(device)) {}

    void BitwardenApi::Configure(const ServerUrls& urls) {
        transport.Configure(urls);
    }

    void BitwardenApi::SetTokenSource(AccessTokenSource* source) {
        tokens = source;
    }

    HttpResponse BitwardenApi::Send(HttpRequest req, bool authenticated) {
        req.headers.emplace_back("Accept", "application/json");
        req.headers.emplace_back("Bitwarden-Client-Name", ClientName);
        req.headers.emplace_back("Bitwarden-Client-Version", ClientVersion);
        req.headers.emplace_back("Device-Type", device.type);

        auto attempt = [&](const std::optional<std::string>& bearer) {
            HttpRequest r = req;
            if (bearer) {
                r.headers.emplace_back("Authorization", "Bearer " + *bearer);
            }
            HttpResponse res = transport.Send(r);
            if (r.host != Host::Icons && !r.path.starts_with("http")) {
                online = res.Reached();
            }
            return res;
        };

        if (!authenticated) {
            return attempt(std::nullopt);
        }
        if (!tokens) {
            return {};
        }

        std::optional<std::string> bearer = tokens->AccessToken();
        if (!bearer) {
            return {};
        }

        HttpResponse res = attempt(bearer);
        if (res.status == 401 && tokens->Refresh(*bearer)) {
            res = attempt(tokens->AccessToken());
        }
        return res;
    }

    HttpResponse BitwardenApi::Call(HttpMethod method, Host host, const std::string& path, const nlohmann::json* body) {
        HttpRequest req { method, host, path };
        if (body) {
            req.body = body->dump();
            req.contentType = "application/json";
        } else if (method == HttpMethod::Put || method == HttpMethod::Post) {
            req.contentType = "application/json";
        }
        return Send(std::move(req), true);
    }

    std::optional<nlohmann::json> BitwardenApi::JsonOf(const HttpResponse& res, std::string_view what) {
        if (!res.Ok()) {
            if (res.Reached()) {
                Log()->warn("{} failed: HTTP {}", what, res.status);
            }
            return std::nullopt;
        }
        auto j = res.Json();
        if (!j) {
            Log()->warn("{} returned malformed JSON", what);
        }
        return j;
    }

    bool BitwardenApi::CheckAlive() {
        return Send({ HttpMethod::Get, Host::Api, "/alive" }, false).Ok();
    }

    std::optional<Crypto::KdfParams> BitwardenApi::PreLogin(const std::string& email) {
        nlohmann::json body = { { "email", email } };
        HttpRequest req { HttpMethod::Post, Host::Vault, "/identity/accounts/prelogin" };
        req.body = body.dump();
        req.contentType = "application/json";

        auto j = JsonOf(Send(std::move(req), false), "PreLogin");
        if (!j) {
            return std::nullopt;
        }

        auto kdf = AsInt(*j, "kdf");
        auto iterations = AsInt(*j, "kdfIterations");
        if (!kdf || !iterations) {
            return std::nullopt;
        }

        return Crypto::KdfParams {
            static_cast<Crypto::KdfType>(*kdf),
            static_cast<uint32_t>(*iterations),
            static_cast<uint32_t>(AsInt(*j, "kdfMemory").value_or(0)),
            static_cast<uint32_t>(AsInt(*j, "kdfParallelism").value_or(0))
        };
    }

    TokenResponse BitwardenApi::Token(std::vector<std::pair<std::string, std::string>> form) {
        HttpRequest req { HttpMethod::Post, Host::Vault, "/identity/connect/token" };
        req.body = FormEncode(form);
        req.contentType = "application/x-www-form-urlencoded; charset=utf-8";

        HttpResponse res = Send(std::move(req), false);
        TokenResponse out;

        auto j = res.Json();
        if (!res.Reached() || !j || !j->is_object()) {
            return out;
        }

        if (res.Ok()) {
            if (j->value("access_token", "").empty() || !AsInt(*j, "expires_in")) {
                return out;
            }
            out.kind = TokenResponse::Kind::Success;
            out.accessToken = j->value("access_token", "");
            out.refreshToken = j->value("refresh_token", "");
            out.expiresIn = *AsInt(*j, "expires_in");
            return out;
        }

        std::string description = j->value("error_description", "");
        if (j->contains("TwoFactorProviders")) {
            out.kind = TokenResponse::Kind::TwoFactorRequired;
            for (const auto& p : (*j)["TwoFactorProviders"]) {
                if (p.is_number_integer()) {
                    out.providers.push_back(static_cast<TwoFactorProvider>(p.get<int>()));
                } else if (p.is_string()) {
                    try { out.providers.push_back(static_cast<TwoFactorProvider>(std::stoi(p.get<std::string>()))); } catch (...) {}
                }
            }
            auto providers2 = j->find("TwoFactorProviders2");
            if (providers2 != j->end() && providers2->is_object() && (*providers2)["7"].is_object()) {
                const auto& webAuthn = (*providers2)["7"];
                const auto& challenge = webAuthn.contains("challenge") ? webAuthn["challenge"] : webAuthn;
                out.webAuthnChallenge = challenge.is_string() ? challenge.get<std::string>() : challenge.dump();
                out.webAuthnRelyingParty = webAuthn.value("rpId", "");
            }
        } else if (description.find("New device verification") != std::string::npos) {
            out.kind = TokenResponse::Kind::NewDeviceVerification;
        } else if (j->value("error", "") == "invalid_grant") {
            out.kind = TokenResponse::Kind::InvalidCredentials;
        } else {
            Log()->warn("Token request rejected: HTTP {}", res.status);
        }
        return out;
    }

    TokenResponse BitwardenApi::PasswordGrant(const std::string& email, const std::string& passwordHash,
        const std::optional<TwoFactorToken>& twoFactor, const std::optional<std::string>& newDeviceOtp) {
        std::vector<std::pair<std::string, std::string>> form = {
            { "grant_type", "password" },
            { "username", email },
            { "password", passwordHash },
            { "scope", "api offline_access" },
            { "client_id", ClientName },
            { "deviceType", device.type },
            { "deviceIdentifier", device.identifier },
            { "deviceName", device.name }
        };
        if (twoFactor) {
            form.emplace_back("twoFactorToken", twoFactor->token);
            form.emplace_back("twoFactorProvider", std::to_string(static_cast<int>(twoFactor->provider)));
            form.emplace_back("twoFactorRemember", "0");
        }
        if (newDeviceOtp) {
            form.emplace_back("newDeviceOtp", *newDeviceOtp);
        }
        return Token(std::move(form));
    }

    TokenResponse BitwardenApi::RefreshGrant(const std::string& refreshToken) {
        return Token({
            { "grant_type", "refresh_token" },
            { "client_id", ClientName },
            { "refresh_token", refreshToken }
        });
    }

    std::optional<nlohmann::json> BitwardenApi::Config() {
        return JsonOf(Send({ HttpMethod::Get, Host::Api, "/api/config" }, false), "Config");
    }

    std::optional<nlohmann::json> BitwardenApi::Profile() {
        return JsonOf(Call(HttpMethod::Get, Host::Api, "/api/accounts/profile"), "Profile");
    }

    std::optional<nlohmann::json> BitwardenApi::Sync() {
        HttpRequest req { HttpMethod::Get, Host::Vault, "/api/sync" };
        req.timeoutSeconds = 120;
        return JsonOf(Send(std::move(req), true), "Sync");
    }

    std::optional<nlohmann::json> BitwardenApi::CreateCipher(const nlohmann::json& cipher) {
        return JsonOf(Call(HttpMethod::Post, Host::Vault, "/api/ciphers", &cipher), "CreateCipher");
    }

    std::optional<nlohmann::json> BitwardenApi::UpdateCipher(const nlohmann::json& cipher) {
        std::string id = cipher.value("id", "");
        return JsonOf(Call(HttpMethod::Put, Host::Vault, "/api/ciphers/" + Segment(id), &cipher), "UpdateCipher");
    }

    bool BitwardenApi::DeleteCipher(const std::string& id) {
        return Call(HttpMethod::Delete, Host::Vault, "/api/ciphers/" + Segment(id)).Ok();
    }

    bool BitwardenApi::SoftDeleteCipher(const std::string& id) {
        return Call(HttpMethod::Put, Host::Vault, "/api/ciphers/" + Segment(id) + "/delete").Ok();
    }

    bool BitwardenApi::RestoreCipher(const std::string& id) {
        return Call(HttpMethod::Put, Host::Vault, "/api/ciphers/" + Segment(id) + "/restore").Ok();
    }

    bool BitwardenApi::ArchiveCiphers(const std::vector<std::string>& ids) {
        nlohmann::json body = { { "ids", ids } };
        return Call(HttpMethod::Put, Host::Vault, "/api/ciphers/archive", &body).Ok();
    }

    bool BitwardenApi::UnarchiveCiphers(const std::vector<std::string>& ids) {
        nlohmann::json body = { { "ids", ids } };
        return Call(HttpMethod::Put, Host::Vault, "/api/ciphers/unarchive", &body).Ok();
    }

    std::optional<nlohmann::json> BitwardenApi::UploadAttachment(const std::string& cipherId, const std::string& encryptedFileName,
        const std::string& encryptedKey, const std::vector<uint8_t>& encryptedContent, std::function<void(float)> onProgress) {
        nlohmann::json meta = {
            { "adminRequest", false },
            { "fileName", encryptedFileName },
            { "fileSize", encryptedContent.size() },
            { "key", encryptedKey }
        };

        auto prepared = JsonOf(Call(HttpMethod::Post, Host::Vault, "/api/ciphers/" + Segment(cipherId) + "/attachment/v2", &meta),
            "PrepareAttachment");
        if (!prepared || !(*prepared)["attachmentId"].is_string() || !prepared->contains("cipherResponse")) {
            return std::nullopt;
        }

        HttpRequest upload { HttpMethod::Post, Host::Vault,
            "/api/ciphers/" + Segment(cipherId) + "/attachment/" + Segment((*prepared)["attachmentId"].get<std::string>()) };
        upload.file = HttpFile { "data", encryptedFileName, std::string(encryptedContent.begin(), encryptedContent.end()) };
        upload.onProgress = std::move(onProgress);
        upload.timeoutSeconds = 600;

        HttpResponse res = Send(std::move(upload), true);
        if (!res.Ok()) {
            Log()->warn("UploadAttachment failed: HTTP {}", res.status);
            return std::nullopt;
        }
        return prepared;
    }

    bool BitwardenApi::DeleteAttachment(const std::string& cipherId, const std::string& attachmentId) {
        return Call(HttpMethod::Delete, Host::Vault, "/api/ciphers/" + Segment(cipherId) + "/attachment/" + Segment(attachmentId)).Ok();
    }

    std::optional<BitwardenApi::Download> BitwardenApi::DownloadAttachment(const std::string& cipherId, const std::string& attachmentId,
        std::function<void(float)> onProgress) {
        auto meta = JsonOf(Call(HttpMethod::Get, Host::Vault, "/api/ciphers/" + Segment(cipherId) + "/attachment/" + Segment(attachmentId)),
            "AttachmentInfo");
        if (!meta || !(*meta)["url"].is_string() || !(*meta)["key"].is_string()) {
            return std::nullopt;
        }

        /*
         * The download URL is pre-signed and may live on a different
         * host (S3/Azure for Bitwarden cloud), so it must not receive
         * the bearer token.
        */
        HttpRequest req { HttpMethod::Get, Host::Vault, (*meta)["url"].get<std::string>() };
        if (!req.path.starts_with("http")) {
            return std::nullopt;
        }
        req.onProgress = std::move(onProgress);
        req.timeoutSeconds = 600;

        HttpResponse res = Send(std::move(req), false);
        if (!res.Ok()) {
            Log()->warn("DownloadAttachment failed: HTTP {}", res.status);
            return std::nullopt;
        }
        return Download { std::move(*meta), std::vector<uint8_t>(res.body.begin(), res.body.end()) };
    }

    std::optional<nlohmann::json> BitwardenApi::CreateFolder(const std::string& encryptedName) {
        nlohmann::json body = { { "name", encryptedName } };
        return JsonOf(Call(HttpMethod::Post, Host::Vault, "/api/folders", &body), "CreateFolder");
    }

    std::optional<nlohmann::json> BitwardenApi::UpdateFolder(const std::string& id, const std::string& encryptedName) {
        nlohmann::json body = { { "name", encryptedName } };
        return JsonOf(Call(HttpMethod::Put, Host::Vault, "/api/folders/" + Segment(id), &body), "UpdateFolder");
    }

    bool BitwardenApi::DeleteFolder(const std::string& id) {
        return Call(HttpMethod::Delete, Host::Vault, "/api/folders/" + Segment(id)).Ok();
    }

    std::optional<std::vector<uint8_t>> BitwardenApi::Icon(const std::string& domain) {
        HttpRequest req { HttpMethod::Get, Host::Icons, "/" + domain + "/icon.png" };
        req.timeoutSeconds = 3;

        HttpResponse res = Send(std::move(req), false);
        if (!res.Ok()) {
            return std::nullopt;
        }
        return std::vector<uint8_t>(res.body.begin(), res.body.end());
    }
}
