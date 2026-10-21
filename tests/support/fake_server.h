#pragma once
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#include "platform/file_store/file_store.h"
#include "platform/http/http.h"
#include "platform/secret_store/secret_store.h"
#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"
#include "utils/timestamp/timestamp.h"
#include "utils/uuid/uuid.h"
#include "vault/crypto/crypto.h"

/**
 * @brief Test doubles: an in-memory Bitwarden server speaking the same HTTP protocol as the
 * real one, plugged in through the HttpTransport seam.
 */
namespace clientwarden::testing {
    /**
     * @brief Decodes an application/x-www-form-urlencoded body.
     *
     * @param body The body
     * @return Field name -> value
     */
    inline std::map<SecureString, SecureString> parseForm(std::string_view body) {
        /**
         * @brief Percent-decodes one component.
         */
        std::function<SecureString(std::string_view)> decode = [](std::string_view s) {
            SecureString out;
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '%' && i + 2 < s.size()) {
                    char hex[3] = { s[i + 1], s[i + 2], 0 };
                    out.push_back(static_cast<char>(std::strtol(hex, nullptr, 16)));
                    i += 2;
                } else {
                    out.push_back(s[i] == '+' ? ' ' : s[i]);
                }
            }
            return out;
        };

        std::map<SecureString, SecureString> out;
        size_t start = 0;
        while (start <= body.size()) {
            size_t end = body.find('&', start);
            std::string_view pair = body.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
            if (!pair.empty()) {
                size_t eq = pair.find('=');
                out[decode(pair.substr(0, eq))] = eq == std::string_view::npos ? SecureString() : decode(pair.substr(eq + 1));
            }
            if (end == std::string_view::npos) {
                break;
            }
            start = end + 1;
        }
        return out;
    }

    /**
     * @brief Reads a request header.
     *
     * @param request The request
     * @param name The header name
     * @return The value, or empty
     */
    inline SecureString headerOf(const HttpRequest& request, std::string_view name) {
        for (const std::pair<SecureString, SecureString>& header : request.m_headers) {
            if (header.first == name) {
                return header.second;
            }
        }
        return SecureString();
    }

    /**
     * @brief An in-memory Bitwarden server with one account.
     */
    class FakeServer {
    public:
        SecureString m_email = "user@example.com";
        SecureString m_password = "correct horse battery staple";
        KdfParams m_kdf { KdfType::Pbkdf2, 100000 };

        Crypto m_crypto;
        SecureBytes m_master_key;
        SymmetricKey m_user_key;
        SecureString m_protected_key;
        SecureString m_password_hash;

        bool m_online = true;
        bool m_require_totp = false;
        bool m_require_passkey = false;
        bool m_require_device_verification = false;
        bool m_revoke_refresh = false;
        SecureString m_version = "2026.9.0";
        SecureString m_last_passkey_assertion;

        SecureString m_access_token = "access-1";
        SecureString m_refresh_token = "refresh-1";
        int m_tokens_issued = 0;
        int m_expires_in = 3600;

        std::map<SecureString, Json> m_ciphers;
        std::map<SecureString, Json> m_folders;
        std::map<SecureString, SecureBytes> m_blobs;
        Json m_domains = Json::object();

        /**
         * @brief An organisation the account belongs to.
         */
        struct FakeOrganization {
            SecureString m_id;
            SecureString m_name;
            SymmetricKey m_key;
            int m_type = 0;
            SecureString m_user_id;
            Json m_permissions = Json::object();
        };

        RsaKeyPair m_rsa;
        SecureString m_encrypted_private_key;
        std::vector<FakeOrganization> m_organizations;
        std::map<SecureString, Json> m_collections;
        bool m_collections_v2 = true;   // false: only the older /collections route exists

        std::mutex m_mutex;
        std::vector<HttpRequest> m_requests;

        /**
         * @brief Creates the account's keys from the default password.
         */
        FakeServer() {
            m_master_key = m_crypto.deriveMasterKey(m_password, m_email, m_kdf);
            m_user_key = SymmetricKey::generate();
            m_protected_key = m_crypto.wrapKey(m_user_key, m_crypto.stretchMasterKey(m_master_key));
            m_password_hash = m_crypto.hashMasterPassword(m_master_key, m_password);
            m_rsa = m_crypto.generateRsaKeyPair();
            m_encrypted_private_key = m_crypto.encrypt(m_rsa.m_private_key, m_user_key);
        }

        /**
         * @brief Makes the current access token invalid so the next request gets a 401.
         */
        void invalidateAccessToken() {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_access_token = "expired";
        }

        /**
         * @brief Counts requests with a method and path prefix.
         *
         * @param method The verb
         * @param prefix Path prefix
         * @return How many were received
         */
        size_t count(HttpMethod method, std::string_view prefix) {
            std::lock_guard<std::mutex> lock(m_mutex);
            return static_cast<size_t>(std::count_if(m_requests.begin(), m_requests.end(),
                [&](const HttpRequest& r) { return r.m_method == method && r.m_path.starts_with(prefix); }));
        }

        /**
         * @brief The most recent request with a method and path prefix.
         *
         * @param method The verb
         * @param prefix Path prefix
         * @return The request, or nullopt
         */
        std::optional<HttpRequest> last(HttpMethod method, std::string_view prefix) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (std::vector<HttpRequest>::reverse_iterator it = m_requests.rbegin(); it != m_requests.rend(); ++it) {
                if (it->m_method == method && it->m_path.starts_with(prefix)) {
                    return *it;
                }
            }
            return std::nullopt;
        }

        /**
         * @brief The account profile as the server reports it.
         *
         * @return The profile JSON
         */
        Json profile() const {
            Json organizations = Json::array();
            for (const FakeOrganization& organization : m_organizations) {
                organizations.push_back({ { "id", organization.m_id }, { "name", organization.m_name },
                    { "key", m_crypto.rsaEncrypt(organization.m_key.combined(), m_rsa.m_public_key) },
                    { "type", organization.m_type }, { "enabled", true }, { "status", 2 },
                    { "organizationUserId", organization.m_user_id }, { "permissions", organization.m_permissions } });
            }
            return { { "id", "user-1" }, { "name", "Test User" }, { "email", m_email }, { "key", m_protected_key },
                { "premium", true }, { "privateKey", m_encrypted_private_key }, { "organizations", organizations } };
        }

        /**
         * @brief Adds an organisation the account belongs to.
         *
         * @param name Its name
         * @param type The member's role (0 owner, 2 user)
         * @return The organisation id
         */
        SecureString addOrganization(std::string_view name, int type) {
            std::lock_guard<std::mutex> lock(m_mutex);
            FakeOrganization organization { SecureString("org-") + uuid::generate(), SecureString(name),
                SymmetricKey::generate(), type, SecureString("orguser-") + uuid::generate() };
            m_organizations.push_back(organization);
            return organization.m_id;
        }

        /**
         * @brief An organisation's key.
         *
         * @param id The organisation id
         * @return Its key
         */
        SymmetricKey organizationKey(std::string_view id) {
            for (FakeOrganization& organization : m_organizations) {
                if (organization.m_id == id) {
                    return organization.m_key;
                }
            }
            throw VaultError("no such organisation");
        }

        /**
         * @brief Adds a collection the account can see.
         *
         * @param organization_id The organisation
         * @param name The plaintext name
         * @param read_only Items in it can't be edited
         * @return The collection id
         */
        SecureString addCollection(std::string_view organization_id, std::string_view name, bool read_only) {
            SymmetricKey key = organizationKey(organization_id);
            std::lock_guard<std::mutex> lock(m_mutex);
            SecureString id = SecureString("col-") + uuid::generate();
            m_collections[id] = { { "id", id }, { "organizationId", SecureString(organization_id) },
                { "name", m_crypto.encryptText(name, key) }, { "readOnly", read_only }, { "hidePasswords", false },
                { "manage", !read_only }, { "object", "collectionDetails" } };
            return id;
        }

        /**
         * @brief Routes one request.
         *
         * @param request The request
         * @return The response
         */
        HttpResponse handle(HttpRequest request) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_requests.push_back(request);

            if (!m_online) {
                return HttpResponse();
            }

            const SecureString& path = request.m_path;
            if (path == "/alive") {
                return respond_(200, Json());
            }
            if (path == "/api/config") {
                return respond_(200, { { "version", m_version } });
            }
            if (path == "/identity/accounts/prelogin") {
                return respond_(200, { { "kdf", static_cast<int>(m_kdf.m_type) }, { "kdfIterations", m_kdf.m_iterations },
                    { "kdfMemory", m_kdf.m_memory_mib }, { "kdfParallelism", m_kdf.m_parallelism } });
            }
            if (path == "/identity/connect/token") {
                return token_(parseForm(request.m_body));
            }
            if (path.starts_with("https://blob.example/")) {
                std::map<SecureString, SecureBytes>::iterator blob = m_blobs.find(path.substr(21));
                if (blob == m_blobs.end()) {
                    return respond_(404, Json());
                }
                HttpResponse response;
                response.m_status = 200;
                response.m_body = blob->second;
                return response;
            }
            if (request.m_host == Host::Icons) {
                HttpResponse response;
                response.m_status = 200;
                response.m_body = SecureBytes { 'P', 'N', 'G' };
                return response;
            }

            if (headerOf(request, "Authorization") != SecureString("Bearer ") + m_access_token) {
                return respond_(401, Json());
            }

            Json body = request.m_body.empty() ? Json() : Json::parse(request.m_body, nullptr, false);

            if (path == "/api/sync") {
                return respond_(200, sync_());
            }
            if (path == "/api/accounts/profile") {
                return respond_(200, profile());
            }
            if (path == "/api/ciphers" && request.m_method == HttpMethod::Post) {
                body["id"] = SecureString("srv-") + uuid::generate();
                body["revisionDate"] = timestamp::now();
                m_ciphers[body["id"].get<SecureString>()] = body;
                return respond_(200, body);
            }
            if (path == "/api/ciphers/archive" || path == "/api/ciphers/unarchive") {
                bool archive = path == "/api/ciphers/archive";
                for (const Json& id : at(body, "ids")) {
                    if (id.is_string() && m_ciphers.contains(id.get<SecureString>())) {
                        m_ciphers[id.get<SecureString>()]["archivedDate"] = archive ? Json(timestamp::now()) : Json();
                    }
                }
                return respond_(200, Json());
            }
            if (path == "/api/ciphers/create" && request.m_method == HttpMethod::Post) {
                Json cipher = at(body, "cipher");
                if (!at(cipher, "organizationId").is_string() || at(body, "collectionIds").empty()) {
                    return respond_(400, { { "message", "organisation and collections required" } });
                }
                cipher["id"] = SecureString("srv-") + uuid::generate();
                cipher["revisionDate"] = timestamp::now();
                cipher["collectionIds"] = at(body, "collectionIds");
                m_ciphers[cipher["id"].get<SecureString>()] = cipher;
                return respond_(200, cipher);
            }
            if (path.starts_with("/api/ciphers/")) {
                return cipher_(request, std::move(body));
            }
            if (path.starts_with("/api/organizations/")) {
                return organization_(request, std::move(body));
            }
            if (path == "/api/folders" && request.m_method == HttpMethod::Post) {
                Json folder = { { "id", SecureString("srv-") + uuid::generate() }, { "name", at(body, "name") },
                    { "revisionDate", timestamp::now() }, { "object", "folder" } };
                m_folders[folder["id"].get<SecureString>()] = folder;
                return respond_(200, folder);
            }
            if (path.starts_with("/api/folders/")) {
                SecureString id = path.substr(13);
                if (!m_folders.contains(id)) {
                    return respond_(404, Json());
                }
                if (request.m_method == HttpMethod::Delete) {
                    m_folders.erase(id);
                    return respond_(200, Json());
                }
                m_folders[id]["name"] = at(body, "name");
                m_folders[id]["revisionDate"] = timestamp::now();
                return respond_(200, m_folders[id]);
            }
            return respond_(404, Json());
        }

    private:
        /**
         * @brief Builds a JSON response.
         */
        HttpResponse respond_(int status, Json body) {
            HttpResponse response;
            response.m_status = status;
            if (!body.is_null()) {
                SecureString text = body.dump();
                response.m_body.assign(text.begin(), text.end());
            }
            return response;
        }

        /**
         * @brief Issues a fresh access token.
         */
        HttpResponse issue_() {
            m_access_token = SecureString("access-") + toSecureString(++m_tokens_issued + 1);
            return respond_(200, { { "access_token", m_access_token }, { "refresh_token", m_refresh_token },
                { "expires_in", m_expires_in } });
        }

        /**
         * @brief Handles /identity/connect/token.
         */
        HttpResponse token_(std::map<SecureString, SecureString> form) {
            if (form["grant_type"] == "refresh_token") {
                if (m_revoke_refresh || form["refresh_token"] != m_refresh_token) {
                    return respond_(400, { { "error", "invalid_grant" } });
                }
                return issue_();
            }

            if (form["username"] != m_email || form["password"] != m_password_hash) {
                return respond_(400, { { "error", "invalid_grant" }, { "error_description", "invalid_username_or_password" } });
            }
            if (m_require_totp) {
                if (!form.contains("twoFactorToken")) {
                    return respond_(400, { { "error", "invalid_grant" }, { "error_description", "Two factor required." },
                        { "TwoFactorProviders", { "0" } } });
                }
                if (form["twoFactorToken"] != "123456" || form["twoFactorProvider"] != "0") {
                    return respond_(400, { { "error", "invalid_grant" }, { "error_description", "Two-step token is invalid." } });
                }
            }
            if (m_require_passkey) {
                if (form["twoFactorProvider"] != "7") {
                    return respond_(400, { { "error", "invalid_grant" }, { "error_description", "Two factor required." },
                        { "TwoFactorProviders", { "7" } },
                        { "TwoFactorProviders2", { { "7", { { "challenge", "chal-123" } } } } } });
                }
                m_last_passkey_assertion = form["twoFactorToken"];
            }
            if (m_require_device_verification && form["newDeviceOtp"] != "654321") {
                return respond_(400, { { "error", "invalid_grant" },
                    { "error_description", "New device verification required" } });
            }
            return issue_();
        }

        /**
         * @brief The whole vault, as /api/sync returns it.
         */
        Json sync_() {
            Json ciphers = Json::array();
            for (std::pair<const SecureString, Json>& cipher : m_ciphers) {
                ciphers.push_back(cipher.second);
            }
            Json folders = Json::array();
            for (std::pair<const SecureString, Json>& folder : m_folders) {
                folders.push_back(folder.second);
            }
            Json collections = Json::array();
            for (std::pair<const SecureString, Json>& collection : m_collections) {
                collections.push_back(collection.second);
            }

            /*
             * Like the real server, an organisation item is read-only when every collection
             * the user reaches it through is read-only.
            */
            for (Json& cipher : ciphers) {
                if (!at(cipher, "organizationId").is_string()) {
                    continue;
                }
                bool editable = false;
                for (const Json& id : at(cipher, "collectionIds")) {
                    std::map<SecureString, Json>::iterator found = m_collections.find(id.get<SecureString>());
                    if (found != m_collections.end() && !found->second["readOnly"].get<bool>()) {
                        editable = true;
                    }
                }
                cipher["edit"] = editable;
            }
            return { { "profile", profile() }, { "ciphers", ciphers }, { "folders", folders },
                { "collections", collections }, { "domains", m_domains } };
        }

        /**
         * @brief Handles /api/ciphers/{id}[/action].
         */
        HttpResponse organization_(HttpRequest request, Json body) {
            SecureString rest = request.m_path.substr(19);   // after /api/organizations/
            SecureString organization_id = rest.substr(0, rest.find('/'));
            SecureString tail = rest.substr(organization_id.size());
            if (!tail.starts_with("/collections")) {
                return respond_(404, Json());
            }
            SecureString collection = tail.size() > 13 ? tail.substr(13) : SecureString();
            bool details = collection.ends_with("/details");
            if (details) {
                collection = collection.substr(0, collection.size() - 8);
            }

            if (collection.empty() && request.m_method == HttpMethod::Post) {
                SecureString id = SecureString("col-") + uuid::generate();
                m_collections[id] = { { "id", id }, { "organizationId", organization_id }, { "name", at(body, "name") },
                    { "readOnly", false }, { "hidePasswords", false }, { "manage", true },
                    { "users", at(body, "users") }, { "groups", at(body, "groups") } };
                return respond_(200, m_collections[id]);
            }
            if (!m_collections.contains(collection)) {
                return respond_(404, Json());
            }
            Json& stored = m_collections[collection];
            if (details) {
                return respond_(200, { { "id", collection }, { "groups", Json::array({ { { "id", "group-1" } } }) },
                    { "users", Json::array({ { { "id", "orguser-x" } } }) } });
            }
            if (request.m_method == HttpMethod::Put) {
                stored["name"] = at(body, "name");
                stored["users"] = at(body, "users");
                stored["groups"] = at(body, "groups");
                return respond_(200, stored);
            }
            if (request.m_method == HttpMethod::Delete) {
                m_collections.erase(collection);
                return respond_(200, Json());
            }
            return respond_(404, Json());
        }

        HttpResponse cipher_(HttpRequest request, Json body) {
            SecureString rest = request.m_path.substr(13);
            SecureString id = rest.substr(0, rest.find('/'));
            SecureString action = rest.size() > id.size() ? rest.substr(id.size() + 1) : SecureString();

            if (!m_ciphers.contains(id)) {
                return respond_(404, Json());
            }
            Json& cipher = m_ciphers[id];

            if (action.empty() && request.m_method == HttpMethod::Put) {
                body["revisionDate"] = timestamp::now();
                cipher = body;
                return respond_(200, cipher);
            }
            if (action.empty() && request.m_method == HttpMethod::Delete) {
                m_ciphers.erase(id);
                return respond_(200, Json());
            }
            if (action == "share" && request.m_method == HttpMethod::Put) {
                Json shared = at(body, "cipher");
                shared["id"] = id;
                shared["revisionDate"] = timestamp::now();
                shared["collectionIds"] = at(body, "collectionIds");
                const Json& updates = at(shared, "attachments2");
                if (updates.is_object() && shared["attachments"].is_array()) {
                    for (Json& attachment : shared["attachments"]) {
                        const Json& update = at(updates, stringAt(attachment, "id"));
                        if (update.is_object()) {
                            attachment["fileName"] = at(update, "fileName");
                            attachment["key"] = at(update, "key");
                        }
                    }
                }
                shared.erase("attachments2");
                cipher = shared;
                return respond_(200, cipher);
            }
            if ((action == "collections_v2" && m_collections_v2) || action == "collections") {
                cipher["collectionIds"] = at(body, "collectionIds");
                cipher["revisionDate"] = timestamp::now();
                return respond_(200, { { "cipher", cipher }, { "unavailable", false } });
            }
            if (action == "delete") {
                cipher["deletedDate"] = timestamp::now();
                return respond_(200, Json());
            }
            if (action == "restore") {
                cipher["deletedDate"] = nullptr;
                return respond_(200, Json());
            }
            if (action == "attachment/v2") {
                Json attachment = { { "id", "att-1" }, { "fileName", at(body, "fileName") }, { "key", at(body, "key") },
                    { "size", toSecureString(at(body, "fileSize").get<std::int64_t>()) } };
                cipher["attachments"] = Json::array({ attachment });
                return respond_(200, { { "attachmentId", "att-1" }, { "cipherResponse", cipher } });
            }
            if (action.starts_with("attachment/")) {
                SecureString attachment_id = action.substr(11);
                if (request.m_method == HttpMethod::Post) {
                    m_blobs[attachment_id] = request.m_file ? request.m_file->m_content : SecureBytes();
                    return respond_(200, Json());
                }
                if (request.m_method == HttpMethod::Delete) {
                    cipher["attachments"] = Json::array();
                    m_blobs.erase(attachment_id);
                    return respond_(200, Json());
                }
                const Json& attachments = at(cipher, "attachments");
                if (!attachments.is_array() || attachments.empty()) {
                    return respond_(404, Json());
                }
                const Json& attachment = attachments[0];
                return respond_(200, { { "id", attachment_id }, { "fileName", at(attachment, "fileName") },
                    { "key", at(attachment, "key") }, { "url", SecureString("https://blob.example/") + attachment_id } });
            }
            return respond_(404, Json());
        }
    };

    /**
     * @brief HttpTransport that forwards to a FakeServer.
     */
    class FakeTransport : public HttpTransport {
    public:
        /**
         * @brief Wraps a server.
         *
         * @param server The server to forward to
         */
        explicit FakeTransport(std::shared_ptr<FakeServer> server) : m_server_(std::move(server)) {}

        /**
         * @brief Ignored; the fake serves every host.
         */
        void configure(ServerUrls) override {}

        /**
         * @brief Forwards to the server.
         *
         * @param request The request
         * @return The server's response
         */
        HttpResponse send(HttpRequest request) override {
            return m_server_->handle(std::move(request));
        }

        /**
         * @brief The fake has no notification hub.
         *
         * @return Always false
         */
        bool listen(std::string_view, std::function<void(std::span<const uint8_t>)>, std::stop_token) override {
            return false;
        }

    private:
        std::shared_ptr<FakeServer> m_server_;
    };

    /**
     * @brief A server plus the device's keychain and disk, which outlive any one Vault so tests
     * can "restart the app" by building a new vault over the same state.
     */
    struct Fixture {
        std::shared_ptr<FakeServer> m_server = std::make_shared<FakeServer>();
        std::shared_ptr<MemorySecretStore> m_secrets = std::make_shared<MemorySecretStore>();
        std::shared_ptr<MemoryFileStore> m_files = std::make_shared<MemoryFileStore>();
        std::shared_ptr<MemoryFileStore> m_resources = std::make_shared<MemoryFileStore>();

        /**
         * @brief A transport talking to this fixture's server.
         *
         * @return The transport
         */
        std::shared_ptr<HttpTransport> transport() {
            return std::make_shared<FakeTransport>(m_server);
        }
    };

    /**
     * @brief The URLs tests configure (all served by the fake).
     *
     * @return The URLs
     */
    inline ServerUrls testUrls() {
        return { "https://vault.example", "https://api.example", "https://icons.example", "wss://notify.example" };
    }
}
