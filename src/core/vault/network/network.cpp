#include "network.h"

#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"
#include "utils/logger/logger.h"

namespace clientwarden {
    namespace {
        constexpr std::string_view c_client_name = "desktop";
        constexpr std::string_view c_client_version = "2026.3.0";

        /**
         * @brief Validates a server-supplied id before it goes into a request path.
         *
         * @param id The id
         * @return The id, unchanged
         * @throws VaultError if it contains anything but letters, digits and dashes
         */
        SecureString segment_(std::string_view id) {
            if (id.empty()) {
                throw VaultError("empty id in request path");
            }
            for (char c : id) {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '-';
                if (!ok) {
                    throw VaultError("invalid id in request path");
                }
            }
            return SecureString(id);
        }

        /**
         * @brief Reads an integer that the server may send as a number or a numeric string.
         *
         * @param json The object
         * @param key The member
         * @return The value, or nullopt
         */
        std::optional<std::int64_t> intAt_(const Json& json, std::string_view key) {
            const Json& value = at(json, key);
            if (value.is_number_integer()) {
                return value.get<std::int64_t>();
            }
            if (value.is_string()) {
                std::int64_t parsed = 0;
                if (parseInt(value.get_ref<const SecureString&>(), parsed)) {
                    return parsed;
                }
            }
            return std::nullopt;
        }

        /**
         * @brief Builds a request with a JSON body.
         *
         * @param method The verb
         * @param host The endpoint
         * @param path The path
         * @param body The body
         * @return The request
         */
        HttpRequest jsonRequest_(
                HttpMethod method, Host host, SecureString path, const Json& body) {
            HttpRequest request;
            request.m_method = method;
            request.m_host = host;
            request.m_path = std::move(path);
            request.m_body = body.dump();
            request.m_content_type = "application/json";
            return request;
        }

        /**
         * @brief Builds a body-less request.
         *
         * @param method The verb
         * @param host The endpoint
         * @param path The path
         * @return The request
         */
        HttpRequest plainRequest_(HttpMethod method, Host host, SecureString path) {
            HttpRequest request;
            request.m_method = method;
            request.m_host = host;
            request.m_path = std::move(path);
            return request;
        }

        /*
         * Both Send access calls: the token flow puts the Send in the bearer token, the legacy
         * flow puts it in the path and the password in the body.
         */
        HttpRequest sendAccessRequest_(
                SecureString path, std::string_view password_hash, std::string_view access_token) {
            HttpRequest request;
            request.m_method = HttpMethod::Post;
            request.m_path = std::move(path);
            Json body = Json::object();
            if (!access_token.empty()) {
                request.m_headers.emplace_back(
                        "Authorization", SecureString("Bearer ") + SecureString(access_token));
            } else if (!password_hash.empty()) {
                body["password"] = SecureString(password_hash);
            }
            request.m_body = body.dump();
            request.m_content_type = "application/json";
            return request;
        }
    }

    DeviceInfo DeviceInfo::forThisPlatform(SecureString identifier) {
        DeviceInfo info;
        info.m_identifier = std::move(identifier);
#if defined(__ANDROID__)
        info.m_type = "0";
        info.m_name = "android";
#elif defined(_WIN32)
        info.m_type = "6";
        info.m_name = "windows";
#elif defined(__APPLE__)
        info.m_type = "7";
        info.m_name = "macos";
#elif defined(HW_RVL)
        info.m_type = "8"; // no Wii type; the desktop one matches our client id
        info.m_name = "nintendo wii";
#elif defined(__3DS__)
        info.m_type = "8"; // no 3DS type; the desktop one matches our client id
        info.m_name = "nintendo 3ds";
#else
        info.m_type = "8";
        info.m_name = "linux";
#endif
        return info;
    }

    Network::Network(std::shared_ptr<HttpTransport> transport, DeviceInfo device)
        : m_transport_(std::move(transport)), m_device_(std::move(device)) {}

    void Network::configure(ServerUrls urls) {
        m_transport_->configure(std::move(urls));
    }

    void Network::setTokenSource(std::shared_ptr<AccessTokenSource> source) {
        m_tokens_ = std::move(source);
    }

    std::shared_ptr<HttpTransport> Network::getTransport() {
        return m_transport_;
    }

    bool Network::isOnline() const {
        return m_online_.load();
    }

    HttpResponse Network::send_(HttpRequest request, bool authenticated) {
        request.m_headers.emplace_back("Accept", "application/json");
        request.m_headers.emplace_back("Bitwarden-Client-Name", SecureString(c_client_name));
        request.m_headers.emplace_back("Bitwarden-Client-Version", SecureString(c_client_version));
        request.m_headers.emplace_back("Device-Type", m_device_.m_type);

        /*
         * Icon and blob hosts are third parties; their availability says nothing about
         * whether the vault server is reachable.
         */
        bool tracks_connectivity = request.m_host != Host::Icons && !request.absolute();

        std::function<HttpResponse(std::optional<SecureString>)> attempt =
                [this, &request, tracks_connectivity](std::optional<SecureString> bearer) {
                    HttpRequest copy = request;
                    if (bearer) {
                        copy.m_headers.emplace_back(
                                "Authorization", SecureString("Bearer ") + *bearer);
                    }
                    HttpResponse response = m_transport_->send(std::move(copy));
                    if (tracks_connectivity) {
                        m_online_ = response.reached();
                    }
                    return response;
                };

        if (!authenticated) {
            return attempt(std::nullopt);
        }

        std::shared_ptr<AccessTokenSource> tokens = m_tokens_;
        if (!tokens) {
            return HttpResponse();
        }
        std::optional<SecureString> bearer = tokens->getAccessToken();
        if (!bearer) {
            return HttpResponse();
        }

        HttpResponse response = attempt(bearer);
        if (response.m_status == 401 && tokens->refresh(*bearer)) {
            response = attempt(tokens->getAccessToken());
        }
        return response;
    }

    HttpResponse Network::call_(
            HttpMethod method, Host host, SecureString path, std::optional<Json> body) {
        HttpRequest request = body ? jsonRequest_(method, host, std::move(path), *body)
                                   : plainRequest_(method, host, std::move(path));
        if (!body && (method == HttpMethod::Put || method == HttpMethod::Post)) {
            request.m_content_type = "application/json";
        }
        return send_(std::move(request), true);
    }

    std::optional<Json> Network::jsonOf_(HttpResponse response, std::string_view what) {
        if (!response.ok()) {
            if (response.reached()) {
                Logger::get()->warn("{} failed: HTTP {}", what, response.m_status);
            }
            return std::nullopt;
        }
        std::optional<Json> json = response.json();
        if (!json) {
            Logger::get()->warn("{} returned malformed JSON", what);
        }
        return json;
    }

    bool Network::checkAlive() {
        return send_(plainRequest_(HttpMethod::Get, Host::Api, "/alive"), false).ok();
    }

    std::optional<KdfParams> Network::preLogin(std::string_view email) {
        Json body = { { "email", SecureString(email) } };
        HttpRequest request =
                jsonRequest_(HttpMethod::Post, Host::Vault, "/identity/accounts/prelogin", body);
        std::optional<Json> json = jsonOf_(send_(std::move(request), false), "PreLogin");
        if (!json) {
            return std::nullopt;
        }

        std::optional<std::int64_t> kdf = intAt_(*json, "kdf");
        std::optional<std::int64_t> iterations = intAt_(*json, "kdfIterations");
        if (!kdf || !iterations || *iterations < 0) {
            return std::nullopt;
        }

        KdfParams params;
        params.m_type = static_cast<KdfType>(*kdf);
        params.m_iterations = static_cast<uint32_t>(*iterations);
        std::int64_t memory = intAt_(*json, "kdfMemory").value_or(0);
        std::int64_t parallelism = intAt_(*json, "kdfParallelism").value_or(0);
        params.m_memory_mib = static_cast<uint32_t>(std::max<std::int64_t>(memory, 0));
        params.m_parallelism = static_cast<uint32_t>(std::max<std::int64_t>(parallelism, 0));
        return params;
    }

    TokenResponse Network::token_(std::vector<std::pair<SecureString, SecureString>> form) {
        HttpRequest request =
                plainRequest_(HttpMethod::Post, Host::Vault, "/identity/connect/token");
        request.m_body = encoding::formEncode(form);
        request.m_content_type = "application/x-www-form-urlencoded; charset=utf-8";

        HttpResponse response = send_(std::move(request), false);
        TokenResponse out;

        std::optional<Json> json = response.json();
        if (!response.reached() || !json || !json->is_object()) {
            return out;
        }

        if (response.ok()) {
            std::optional<std::int64_t> expires = intAt_(*json, "expires_in");
            SecureString access = stringAt(*json, "access_token");
            if (access.empty() || !expires) {
                return out;
            }
            out.m_kind = TokenResponse::Kind::Success;
            out.m_access_token = std::move(access);
            out.m_refresh_token = stringAt(*json, "refresh_token");
            out.m_expires_in = static_cast<int>(*expires);
            return out;
        }

        SecureString description = stringAt(*json, "error_description");
        if (json->contains("TwoFactorProviders")) {
            out.m_kind = TokenResponse::Kind::TwoFactorRequired;
            for (const Json& provider : at(*json, "TwoFactorProviders")) {
                std::int64_t id = -1;
                if (provider.is_number_integer()) {
                    id = provider.get<std::int64_t>();
                } else if (provider.is_string() &&
                           !parseInt(provider.get_ref<const SecureString&>(), id)) {
                    id = -1;
                }
                if (id >= 0) {
                    out.m_providers.push_back(static_cast<TwoFactorProvider>(id));
                }
            }
            const Json& web_authn = at(at(*json, "TwoFactorProviders2"), "7");
            if (web_authn.is_object()) {
                const Json& challenge =
                        web_authn.contains("challenge") ? at(web_authn, "challenge") : web_authn;
                out.m_web_authn_challenge =
                        challenge.is_string() ? challenge.get<SecureString>() : challenge.dump();
                out.m_web_authn_relying_party = stringAt(web_authn, "rpId");
            }
        } else if (description.find("New device verification") != SecureString::npos) {
            out.m_kind = TokenResponse::Kind::NewDeviceVerification;
        } else if (stringAt(*json, "error") == "invalid_grant") {
            out.m_kind = TokenResponse::Kind::InvalidCredentials;
        } else {
            Logger::get()->warn("Token request rejected: HTTP {}", response.m_status);
        }
        return out;
    }

    TokenResponse Network::passwordGrant(std::string_view email, std::string_view password_hash,
            std::optional<TwoFactorToken> two_factor, std::optional<SecureString> new_device_otp) {
        // clang-format off
        std::vector<std::pair<SecureString, SecureString>> form = {
            { "grant_type", "password" },
            { "username", SecureString(email) },
            { "password", SecureString(password_hash) },
            { "scope", "api offline_access" },
            { "client_id", SecureString(c_client_name) },
            { "deviceType", m_device_.m_type },
            { "deviceIdentifier", m_device_.m_identifier },
            { "deviceName", m_device_.m_name }
        };
        // clang-format on
        if (two_factor) {
            form.emplace_back("twoFactorToken", two_factor->m_token);
            std::int64_t provider = static_cast<std::int64_t>(two_factor->m_provider);
            form.emplace_back("twoFactorProvider", toSecureString(provider));
            form.emplace_back("twoFactorRemember", "0");
        }
        if (new_device_otp) {
            form.emplace_back("newDeviceOtp", *new_device_otp);
        }
        return token_(std::move(form));
    }

    TokenResponse Network::refreshGrant(std::string_view refresh_token) {
        // clang-format off
        return token_({
            { "grant_type", "refresh_token" },
            { "client_id", SecureString(c_client_name) },
            { "refresh_token", SecureString(refresh_token) }
        });
        // clang-format on
    }

    std::optional<Json> Network::getConfig() {
        return jsonOf_(
                send_(plainRequest_(HttpMethod::Get, Host::Api, "/api/config"), false), "Config");
    }

    std::optional<Json> Network::getProfile() {
        return jsonOf_(call_(HttpMethod::Get, Host::Api, "/api/accounts/profile", std::nullopt),
                "Profile");
    }

    std::optional<Json> Network::getSync() {
        HttpRequest request = plainRequest_(HttpMethod::Get, Host::Vault, "/api/sync");
        request.m_timeout_seconds = 120;
        return jsonOf_(send_(std::move(request), true), "Sync");
    }

    std::optional<Json> Network::createCipher(const Json& cipher) {
        return jsonOf_(
                call_(HttpMethod::Post, Host::Vault, "/api/ciphers", cipher), "CreateCipher");
    }

    std::optional<Json> Network::updateCipher(const Json& cipher) {
        SecureString path = SecureString("/api/ciphers/") + segment_(stringAt(cipher, "id"));
        return jsonOf_(
                call_(HttpMethod::Put, Host::Vault, std::move(path), cipher), "UpdateCipher");
    }

    bool Network::deleteCipher(std::string_view id) {
        SecureString path = SecureString("/api/ciphers/") + segment_(id);
        return call_(HttpMethod::Delete, Host::Vault, std::move(path), std::nullopt).ok();
    }

    bool Network::softDeleteCipher(std::string_view id) {
        SecureString path = SecureString("/api/ciphers/") + segment_(id) + "/delete";
        return call_(HttpMethod::Put, Host::Vault, std::move(path), std::nullopt).ok();
    }

    bool Network::restoreCipher(std::string_view id) {
        SecureString path = SecureString("/api/ciphers/") + segment_(id) + "/restore";
        return call_(HttpMethod::Put, Host::Vault, std::move(path), std::nullopt).ok();
    }

    bool Network::archiveCiphers(const std::vector<SecureString>& ids) {
        Json body = { { "ids", ids } };
        return call_(HttpMethod::Put, Host::Vault, "/api/ciphers/archive", body).ok();
    }

    bool Network::unarchiveCiphers(const std::vector<SecureString>& ids) {
        Json body = { { "ids", ids } };
        return call_(HttpMethod::Put, Host::Vault, "/api/ciphers/unarchive", body).ok();
    }

    std::optional<Json> Network::uploadAttachment(std::string_view cipher_id,
            std::string_view encrypted_file_name, std::string_view encrypted_key,
            std::span<const uint8_t> encrypted_content, std::function<void(float)> on_progress) {
        SecureString base = SecureString("/api/ciphers/") + segment_(cipher_id) + "/attachment/";
        // clang-format off
        Json meta = {
            { "adminRequest", false },
            { "fileName", SecureString(encrypted_file_name) },
            { "fileSize", encrypted_content.size() },
            { "key", SecureString(encrypted_key) }
        };
        // clang-format on

        std::optional<Json> prepared = jsonOf_(
                call_(HttpMethod::Post, Host::Vault, base + "v2", meta), "PrepareAttachment");
        if (!prepared || !at(*prepared, "attachmentId").is_string() ||
                !at(*prepared, "cipherResponse").is_object()) {
            return std::nullopt;
        }

        HttpRequest upload = plainRequest_(HttpMethod::Post, Host::Vault,
                base + segment_(stringAt(*prepared, "attachmentId")));
        upload.m_file = HttpFile { "data", SecureString(encrypted_file_name),
            SecureBytes(encrypted_content.begin(), encrypted_content.end()) };
        upload.m_on_progress = std::move(on_progress);
        upload.m_timeout_seconds = 600;

        HttpResponse response = send_(std::move(upload), true);
        if (!response.ok()) {
            Logger::get()->warn("UploadAttachment failed: HTTP {}", response.m_status);
            return std::nullopt;
        }
        return prepared;
    }

    bool Network::deleteAttachment(std::string_view cipher_id, std::string_view attachment_id) {
        SecureString path = SecureString("/api/ciphers/") + segment_(cipher_id) + "/attachment/" +
                            segment_(attachment_id);
        return call_(HttpMethod::Delete, Host::Vault, std::move(path), std::nullopt).ok();
    }

    std::optional<Network::Download> Network::downloadAttachment(std::string_view cipher_id,
            std::string_view attachment_id, std::function<void(float)> on_progress) {
        SecureString path = SecureString("/api/ciphers/") + segment_(cipher_id) + "/attachment/" +
                            segment_(attachment_id);
        std::optional<Json> meta =
                jsonOf_(call_(HttpMethod::Get, Host::Vault, std::move(path), std::nullopt),
                        "AttachmentInfo");
        if (!meta || !at(*meta, "url").is_string() || !at(*meta, "key").is_string()) {
            return std::nullopt;
        }

        /*
         * The body URL is pre-signed and may live on another host (S3/Azure for Bitwarden
         * cloud), so it never receives the bearer token.
         */
        HttpRequest request = plainRequest_(HttpMethod::Get, Host::Vault, stringAt(*meta, "url"));
        if (!request.absolute()) {
            return std::nullopt;
        }
        request.m_on_progress = std::move(on_progress);
        request.m_timeout_seconds = 600;

        HttpResponse response = send_(std::move(request), false);
        if (!response.ok()) {
            Logger::get()->warn("DownloadAttachment failed: HTTP {}", response.m_status);
            return std::nullopt;
        }
        return Download { std::move(*meta), std::move(response.m_body) };
    }

    std::optional<Json> Network::createFolder(std::string_view encrypted_name) {
        Json body = { { "name", SecureString(encrypted_name) } };
        return jsonOf_(call_(HttpMethod::Post, Host::Vault, "/api/folders", body), "CreateFolder");
    }

    std::optional<Json> Network::updateFolder(
            std::string_view id, std::string_view encrypted_name) {
        Json body = { { "name", SecureString(encrypted_name) } };
        SecureString path = SecureString("/api/folders/") + segment_(id);
        return jsonOf_(call_(HttpMethod::Put, Host::Vault, std::move(path), body), "UpdateFolder");
    }

    bool Network::deleteFolder(std::string_view id) {
        SecureString path = SecureString("/api/folders/") + segment_(id);
        return call_(HttpMethod::Delete, Host::Vault, std::move(path), std::nullopt).ok();
    }

    std::optional<SecureBytes> Network::getIcon(std::string_view domain) {
        HttpRequest request = plainRequest_(HttpMethod::Get, Host::Icons,
                SecureString("/") + SecureString(domain) + "/icon.png");
        request.m_timeout_seconds = 3;

        HttpResponse response = send_(std::move(request), false);
        if (!response.ok()) {
            return std::nullopt;
        }
        return std::move(response.m_body);
    }

    std::optional<Json> Network::createOrganizationCipher(
            const Json& cipher, const std::vector<SecureString>& collection_ids) {
        Json body = { { "cipher", cipher }, { "collectionIds", collection_ids } };
        return jsonOf_(call_(HttpMethod::Post, Host::Vault, "/api/ciphers/create", body),
                "CreateOrganizationCipher");
    }

    std::optional<Json> Network::shareCipher(std::string_view id, const Json& cipher,
            const std::vector<SecureString>& collection_ids) {
        Json body = { { "cipher", cipher }, { "collectionIds", collection_ids } };
        SecureString path = SecureString("/api/ciphers/") + segment_(id) + "/share";
        return jsonOf_(call_(HttpMethod::Put, Host::Vault, std::move(path), body), "ShareCipher");
    }

    bool Network::updateCipherCollections(
            std::string_view id, const std::vector<SecureString>& collection_ids) {
        Json body = { { "collectionIds", collection_ids } };
        SecureString base = SecureString("/api/ciphers/") + segment_(id);

        /*
         * collections_v2 is the current route; older servers (and Vaultwarden before 1.32)
         * only have the original one.
         */
        HttpResponse response = call_(HttpMethod::Put, Host::Vault, base + "/collections_v2", body);
        if (response.m_status == 404 || response.m_status == 405) {
            response = call_(HttpMethod::Put, Host::Vault, base + "/collections", body);
        }
        return response.ok();
    }

    std::optional<Json> Network::createCollection(std::string_view organization_id,
            std::string_view encrypted_name, std::string_view organization_user_id) {
        Json users = Json::array();
        if (!organization_user_id.empty()) {
            users.push_back({ { "id", SecureString(organization_user_id) }, { "readOnly", false },
                    { "hidePasswords", false }, { "manage", true } });
        }
        Json body = { { "name", SecureString(encrypted_name) }, { "externalId", nullptr },
            { "groups", Json::array() }, { "users", users } };
        SecureString path =
                SecureString("/api/organizations/") + segment_(organization_id) + "/collections";
        return jsonOf_(
                call_(HttpMethod::Post, Host::Vault, std::move(path), body), "CreateCollection");
    }

    std::optional<Json> Network::renameCollection(std::string_view organization_id,
            std::string_view id, std::string_view encrypted_name) {
        SecureString path = SecureString("/api/organizations/") + segment_(organization_id) +
                            "/collections/" + segment_(id);

        /*
         * PUT replaces the collection's access lists, so send back the current ones.
         */
        std::optional<Json> details =
                jsonOf_(call_(HttpMethod::Get, Host::Vault, path + "/details", std::nullopt),
                        "CollectionDetails");
        Json body = { { "name", SecureString(encrypted_name) }, { "externalId", nullptr },
            { "groups", details && at(*details, "groups").is_array() ? at(*details, "groups")
                                                                     : Json::array() },
            { "users", details && at(*details, "users").is_array() ? at(*details, "users")
                                                                   : Json::array() } };
        return jsonOf_(
                call_(HttpMethod::Put, Host::Vault, std::move(path), body), "RenameCollection");
    }

    bool Network::deleteCollection(std::string_view organization_id, std::string_view id) {
        SecureString path = SecureString("/api/organizations/") + segment_(organization_id) +
                            "/collections/" + segment_(id);
        return call_(HttpMethod::Delete, Host::Vault, std::move(path), std::nullopt).ok();
    }

    std::optional<Json> Network::createSend(const Json& send) {
        return jsonOf_(call_(HttpMethod::Post, Host::Vault, "/api/sends", send), "CreateSend");
    }

    std::optional<Json> Network::createFileSend(const Json& send,
            std::span<const uint8_t> encrypted_content, std::function<void(float)> on_progress) {
        Json body = send;
        body["fileLength"] = encrypted_content.size();
        std::optional<Json> prepared =
                jsonOf_(call_(HttpMethod::Post, Host::Vault, "/api/sends/file/v2", body),
                        "PrepareFileSend");
        const Json& response = prepared ? at(*prepared, "sendResponse") : at(body, "");
        SecureString send_id = stringAt(response, "id");
        SecureString file_id = stringAt(at(response, "file"), "id");
        if (send_id.empty() || file_id.empty()) {
            return std::nullopt;
        }

        HttpRequest upload;
        upload.m_method = HttpMethod::Post;
        upload.m_host = Host::Vault;
        upload.m_path =
                SecureString("/api/sends/") + segment_(send_id) + "/file/" + segment_(file_id);
        upload.m_file = HttpFile { "data", stringAt(at(send, "file"), "fileName"),
            SecureBytes(encrypted_content.begin(), encrypted_content.end()) };
        upload.m_on_progress = std::move(on_progress);
        upload.m_timeout_seconds = 600;
        if (!send_(std::move(upload), true).ok()) {
            Logger::get()->warn("UploadSendFile failed");
            deleteSend(send_id); // don't leave a Send without its file behind
            return std::nullopt;
        }
        return response;
    }

    std::optional<Json> Network::updateSend(std::string_view id, const Json& send) {
        SecureString path = SecureString("/api/sends/") + segment_(id);
        return jsonOf_(call_(HttpMethod::Put, Host::Vault, std::move(path), send), "UpdateSend");
    }

    std::optional<Json> Network::removeSendPassword(std::string_view id) {
        SecureString path = SecureString("/api/sends/") + segment_(id) + "/remove-password";
        return jsonOf_(call_(HttpMethod::Put, Host::Vault, std::move(path), std::nullopt),
                "RemoveSendPassword");
    }

    bool Network::deleteSend(std::string_view id) {
        SecureString path = SecureString("/api/sends/") + segment_(id);
        return call_(HttpMethod::Delete, Host::Vault, std::move(path), std::nullopt).ok();
    }

    HttpResponse Network::sendAccessToken(
            std::string_view origin, std::string_view access_id, std::string_view password_hash) {
        // clang-format off
        std::vector<std::pair<SecureString, SecureString>> form = {
            { "grant_type", "send_access" },
            { "client_id", "send" },
            { "scope", "api.send.access" },
            { "send_id", SecureString(access_id) }
        };
        // clang-format on
        if (!password_hash.empty()) {
            form.emplace_back("password_hash_b64", SecureString(password_hash));
        }
        HttpRequest request;
        request.m_method = HttpMethod::Post;
        request.m_path = SecureString(origin) + "/identity/connect/token";
        request.m_body = encoding::formEncode(form);
        request.m_content_type = "application/x-www-form-urlencoded; charset=utf-8";
        return send_(std::move(request), false);
    }

    HttpResponse Network::accessSend(std::string_view origin, std::string_view access_id,
            std::string_view password_hash, std::string_view access_token) {
        SecureString path = access_token.empty() ? SecureString(origin) + "/api/sends/access/" +
                                                           segment_(access_id)
                                                 : SecureString(origin) + "/api/sends/access";
        return send_(sendAccessRequest_(std::move(path), password_hash, access_token), false);
    }

    std::optional<SecureBytes> Network::accessSendFile(std::string_view origin,
            std::string_view send_id, std::string_view file_id, std::string_view password_hash,
            std::string_view access_token, std::function<void(float)> on_progress) {
        SecureString path =
                access_token.empty()
                        ? SecureString(origin) + "/api/sends/" + segment_(send_id) +
                                  "/access/file/" + segment_(file_id)
                        : SecureString(origin) + "/api/sends/access/file/" + segment_(file_id);
        HttpRequest request = sendAccessRequest_(std::move(path), password_hash, access_token);
        std::optional<Json> meta = jsonOf_(send_(std::move(request), false), "AccessSendFile");
        SecureString url = meta ? stringAt(*meta, "url") : SecureString();
        if (!url.starts_with("https://") && !url.starts_with("http://")) {
            return std::nullopt;
        }

        HttpRequest download;
        download.m_path = url;
        download.m_on_progress = std::move(on_progress);
        download.m_timeout_seconds = 600;
        HttpResponse response = send_(std::move(download), false);
        if (!response.ok()) {
            return std::nullopt;
        }
        return response.m_body;
    }
}
