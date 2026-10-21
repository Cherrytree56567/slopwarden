#include <catch2/catch_test_macros.hpp>

#include "support/fake_server.h"
#include "utils/errors/errors.h"
#include "vault/network/network.h"

using namespace clientwarden;
using namespace clientwarden::testing;

namespace {
    /**
     * @brief Token source that hands out a fixed token and "refreshes" by asking the server
     * for whatever token it currently accepts.
     */
    class StaticTokens : public AccessTokenSource {
    public:
        std::shared_ptr<FakeServer> m_server;
        SecureString m_token;
        int m_refreshes = 0;

        /**
         * @brief Starts with the server's current token.
         */
        explicit StaticTokens(std::shared_ptr<FakeServer> server) : m_server(server), m_token(server->m_access_token) {}

        /**
         * @brief The fixed token.
         */
        std::optional<SecureString> getAccessToken() override {
            return m_token;
        }

        /**
         * @brief Adopts a fresh token the server will accept.
         */
        bool refresh(std::string_view) override {
            ++m_refreshes;
            m_server->m_access_token = "access-refreshed";
            m_token = m_server->m_access_token;
            return true;
        }
    };

    /**
     * @brief A network client wired to a fake server, with tokens.
     */
    struct Harness {
        std::shared_ptr<FakeServer> m_server = std::make_shared<FakeServer>();
        std::shared_ptr<Network> m_network =
            std::make_shared<Network>(std::make_shared<FakeTransport>(m_server), DeviceInfo::forThisPlatform("dev-1"));
        std::shared_ptr<StaticTokens> m_tokens = std::make_shared<StaticTokens>(m_server);

        /**
         * @brief Installs the token source.
         */
        Harness() {
            m_network->configure(testUrls());
            m_network->setTokenSource(m_tokens);
        }

        /**
         * @brief Adds a cipher to the server directly.
         */
        SecureString seedCipher(SecureString id) {
            m_server->m_ciphers[id] = { { "id", id }, { "revisionDate", timestamp::now() } };
            return id;
        }
    };

    /**
     * @brief The body of a recorded request as JSON.
     */
    Json bodyOf(std::optional<HttpRequest> request) {
        return Json::parse(request->m_body, nullptr, false);
    }
}

TEST_CASE("DeviceInfo describes this platform") {
    DeviceInfo info = DeviceInfo::forThisPlatform("dev-1");
    REQUIRE(info.m_identifier == "dev-1");
    REQUIRE_FALSE(info.m_type.empty());
    REQUIRE_FALSE(info.m_name.empty());
}

TEST_CASE("checkAlive and isOnline track reachability") {
    Harness h;
    REQUIRE_FALSE(h.m_network->isOnline());
    REQUIRE(h.m_network->checkAlive());
    REQUIRE(h.m_network->isOnline());

    h.m_server->m_online = false;
    REQUIRE_FALSE(h.m_network->checkAlive());
    REQUIRE_FALSE(h.m_network->isOnline());
}

TEST_CASE("Icon requests don't affect connectivity") {
    Harness h;
    h.m_network->checkAlive();
    h.m_server->m_online = false;
    h.m_network->getIcon("github.com");
    REQUIRE(h.m_network->isOnline());
}

TEST_CASE("getTransport returns the configured transport") {
    Harness h;
    REQUIRE(h.m_network->getTransport() != nullptr);
}

TEST_CASE("preLogin builds JSON safely and parses KDF settings") {
    Harness h;
    h.m_server->m_kdf = KdfParams { KdfType::Argon2id, 3, 64, 4 };

    /*
     * Regression: the email used to be spliced into a JSON string.
    */
    std::optional<KdfParams> kdf = h.m_network->preLogin("a\"b@example.com");
    REQUIRE(kdf);
    REQUIRE(kdf->m_type == KdfType::Argon2id);
    REQUIRE(kdf->m_iterations == 3);
    REQUIRE(kdf->m_memory_mib == 64);
    REQUIRE(kdf->m_parallelism == 4);

    std::optional<HttpRequest> request = h.m_server->last(HttpMethod::Post, "/identity/accounts/prelogin");
    REQUIRE(bodyOf(request)["email"] == "a\"b@example.com");
    REQUIRE(headerOf(*request, "Bitwarden-Client-Name") == "desktop");
    REQUIRE_FALSE(headerOf(*request, "Bitwarden-Client-Version").empty());
    REQUIRE_FALSE(headerOf(*request, "Device-Type").empty());
    REQUIRE(headerOf(*request, "Authorization").empty());

    h.m_server->m_online = false;
    REQUIRE_FALSE(h.m_network->preLogin("x@example.com"));
}

TEST_CASE("passwordGrant sends a stable device id and form-encodes values") {
    Harness h;
    TokenResponse response = h.m_network->passwordGrant(h.m_server->m_email, h.m_server->m_password_hash, std::nullopt,
        std::nullopt);
    REQUIRE(response.m_kind == TokenResponse::Kind::Success);
    REQUIRE(response.m_expires_in == 3600);
    REQUIRE_FALSE(response.m_access_token.empty());
    REQUIRE(response.m_refresh_token == "refresh-1");

    std::map<SecureString, SecureString> form = parseForm(h.m_server->last(HttpMethod::Post, "/identity/connect/token")->m_body);
    REQUIRE(form["deviceIdentifier"] == "dev-1");
    REQUIRE(form["password"] == h.m_server->m_password_hash);   // '+', '/' and '=' survive encoding
    REQUIRE(form["grant_type"] == "password");
}

TEST_CASE("Token errors are classified") {
    Harness h;
    std::shared_ptr<Network> n = h.m_network;
    SecureString email = h.m_server->m_email;
    SecureString hash = h.m_server->m_password_hash;

    REQUIRE(n->passwordGrant(email, "wrong", std::nullopt, std::nullopt).m_kind == TokenResponse::Kind::InvalidCredentials);

    h.m_server->m_require_totp = true;
    TokenResponse totp = n->passwordGrant(email, hash, std::nullopt, std::nullopt);
    REQUIRE(totp.m_kind == TokenResponse::Kind::TwoFactorRequired);
    REQUIRE(totp.m_providers == std::vector<TwoFactorProvider> { TwoFactorProvider::Authenticator });

    TwoFactorToken code { TwoFactorProvider::Authenticator, "123456" };
    REQUIRE(n->passwordGrant(email, hash, code, std::nullopt).m_kind == TokenResponse::Kind::Success);

    h.m_server->m_require_totp = false;
    h.m_server->m_require_device_verification = true;
    REQUIRE(n->passwordGrant(email, hash, std::nullopt, std::nullopt).m_kind == TokenResponse::Kind::NewDeviceVerification);
    REQUIRE(n->passwordGrant(email, hash, std::nullopt, SecureString("654321")).m_kind == TokenResponse::Kind::Success);

    h.m_server->m_online = false;
    REQUIRE(n->passwordGrant(email, hash, std::nullopt, std::nullopt).m_kind == TokenResponse::Kind::Failed);
    REQUIRE_FALSE(n->isOnline());
}

TEST_CASE("WebAuthn challenges are parsed and the provider id is sent") {
    Harness h;
    h.m_server->m_require_passkey = true;

    TokenResponse response = h.m_network->passwordGrant(h.m_server->m_email, h.m_server->m_password_hash, std::nullopt,
        std::nullopt);
    REQUIRE(response.m_kind == TokenResponse::Kind::TwoFactorRequired);
    REQUIRE(response.m_providers == std::vector<TwoFactorProvider> { TwoFactorProvider::WebAuthn });
    REQUIRE(response.m_web_authn_challenge == "chal-123");

    TwoFactorToken assertion { TwoFactorProvider::WebAuthn, "{\"id\":\"x\"}" };
    REQUIRE(h.m_network->passwordGrant(h.m_server->m_email, h.m_server->m_password_hash, assertion, std::nullopt).m_kind
        == TokenResponse::Kind::Success);
    REQUIRE(h.m_server->m_last_passkey_assertion == "{\"id\":\"x\"}");
}

TEST_CASE("refreshGrant accepts numeric expires_in and reports revocation") {
    Harness h;

    /*
     * Regression: refresh used to require expires_in to be a string, so every refresh after
     * the first login failed.
    */
    REQUIRE(h.m_network->refreshGrant(h.m_server->m_refresh_token).m_kind == TokenResponse::Kind::Success);
    h.m_server->m_revoke_refresh = true;
    REQUIRE(h.m_network->refreshGrant(h.m_server->m_refresh_token).m_kind == TokenResponse::Kind::InvalidCredentials);
}

TEST_CASE("getConfig is unauthenticated") {
    Harness h;
    std::optional<Json> config = h.m_network->getConfig();
    REQUIRE(config);
    REQUIRE((*config)["version"] == "2026.9.0");
    REQUIRE(headerOf(*h.m_server->last(HttpMethod::Get, "/api/config"), "Authorization").empty());
}

TEST_CASE("getProfile and getSync are authenticated") {
    Harness h;
    std::optional<Json> profile = h.m_network->getProfile();
    REQUIRE(profile);
    REQUIRE((*profile)["name"] == "Test User");

    std::optional<Json> sync = h.m_network->getSync();
    REQUIRE(sync);
    REQUIRE((*sync)["profile"]["key"] == h.m_server->m_protected_key);
    REQUIRE(headerOf(*h.m_server->last(HttpMethod::Get, "/api/sync"), "Authorization") ==
        SecureString("Bearer ") + h.m_server->m_access_token);
}

TEST_CASE("Authenticated calls fail without a token source") {
    std::shared_ptr<FakeServer> server = std::make_shared<FakeServer>();
    Network network(std::make_shared<FakeTransport>(server), DeviceInfo::forThisPlatform("dev-1"));
    REQUIRE_FALSE(network.getSync());
    REQUIRE(server->count(HttpMethod::Get, "/api/sync") == 0);
}

TEST_CASE("A 401 triggers one refresh and a retry") {
    Harness h;
    h.m_server->invalidateAccessToken();
    h.m_tokens->m_token = "stale";

    REQUIRE(h.m_network->getSync());
    REQUIRE(h.m_tokens->m_refreshes == 1);
    REQUIRE(h.m_server->count(HttpMethod::Get, "/api/sync") == 2);
    REQUIRE(h.m_network->isOnline());
}

TEST_CASE("Cipher create, update, bin, restore, archive and delete") {
    Harness h;

    std::optional<Json> created = h.m_network->createCipher({ { "type", 2 }, { "name", "2.x|y|z" } });
    REQUIRE(created);
    SecureString id = stringAt(*created, "id");
    REQUIRE(id.starts_with("srv-"));
    REQUIRE(h.m_server->m_ciphers.contains(id));

    Json edited = *created;
    edited["name"] = "2.a|b|c";
    std::optional<Json> updated = h.m_network->updateCipher(edited);
    REQUIRE(updated);
    REQUIRE(h.m_server->m_ciphers[id]["name"] == "2.a|b|c");

    REQUIRE(h.m_network->softDeleteCipher(id));
    REQUIRE(h.m_server->m_ciphers[id]["deletedDate"].is_string());
    REQUIRE(h.m_network->restoreCipher(id));
    REQUIRE(h.m_server->m_ciphers[id]["deletedDate"].is_null());

    REQUIRE(h.m_network->archiveCiphers({ id }));
    REQUIRE(h.m_server->m_ciphers[id]["archivedDate"].is_string());
    REQUIRE(bodyOf(h.m_server->last(HttpMethod::Put, "/api/ciphers/archive"))["ids"][0] == id);
    REQUIRE(h.m_network->unarchiveCiphers({ id }));
    REQUIRE(h.m_server->m_ciphers[id]["archivedDate"].is_null());

    REQUIRE(h.m_network->deleteCipher(id));
    REQUIRE_FALSE(h.m_server->m_ciphers.contains(id));
    REQUIRE_FALSE(h.m_network->deleteCipher(id));
}

TEST_CASE("Ids that could escape the route are refused") {
    Harness h;
    REQUIRE_THROWS_AS(h.m_network->deleteCipher("../folders/x"), VaultError);
    REQUIRE_THROWS_AS(h.m_network->softDeleteCipher("a/b"), VaultError);
    REQUIRE_THROWS_AS(h.m_network->deleteFolder("a?b"), VaultError);
    REQUIRE_THROWS_AS(h.m_network->updateCipher({ { "id", "x y" } }), VaultError);
    REQUIRE_THROWS_AS(h.m_network->updateCipher({ { "name", "no id" } }), VaultError);
    REQUIRE_THROWS_AS(h.m_network->deleteAttachment("ok", "../x"), VaultError);
}

TEST_CASE("Malformed server JSON is reported as failure, not thrown") {
    std::shared_ptr<FakeServer> server = std::make_shared<FakeServer>();

    /**
     * @brief Transport that answers 200 with garbage.
     */
    class Garbage : public HttpTransport {
    public:
        void configure(ServerUrls) override {}
        HttpResponse send(HttpRequest) override {
            HttpResponse response;
            response.m_status = 200;
            response.m_body = SecureBytes { '{', 'o', 'o', 'p', 's' };
            return response;
        }
        bool listen(std::string_view, std::function<void(std::span<const uint8_t>)>, std::stop_token) override {
            return false;
        }
    };

    Network network(std::make_shared<Garbage>(), DeviceInfo::forThisPlatform("dev-1"));
    network.setTokenSource(std::make_shared<StaticTokens>(server));
    REQUIRE_FALSE(network.getSync());
    REQUIRE_FALSE(network.getConfig());
    REQUIRE_FALSE(network.preLogin("a@b.c"));
    REQUIRE(network.passwordGrant("a@b.c", "h", std::nullopt, std::nullopt).m_kind == TokenResponse::Kind::Failed);
}

TEST_CASE("Attachments upload, download and delete") {
    Harness h;
    SecureString id = h.seedCipher("c1");

    SecureBytes content = { 'b', 'l', 'o', 'b' };
    float progress = -1;
    std::optional<Json> uploaded = h.m_network->uploadAttachment(id, "2.n|a|me", "2.k|e|y", content,
        [&progress](float p) { progress = p; });
    REQUIRE(uploaded);
    REQUIRE((*uploaded)["attachmentId"] == "att-1");
    REQUIRE((*uploaded)["cipherResponse"]["attachments"].size() == 1);
    REQUIRE(h.m_server->m_blobs["att-1"] == content);

    std::optional<HttpRequest> upload = h.m_server->last(HttpMethod::Post, "/api/ciphers/c1/attachment/att-1");
    REQUIRE(upload->m_file);
    REQUIRE(upload->m_file->m_field == "data");

    std::optional<Network::Download> download = h.m_network->downloadAttachment(id, "att-1", nullptr);
    REQUIRE(download);
    REQUIRE(download->m_content == content);
    REQUIRE(download->m_meta["key"] == "2.k|e|y");

    /*
     * The pre-signed blob URL may be on another host, so it must not get the bearer token.
    */
    REQUIRE(headerOf(*h.m_server->last(HttpMethod::Get, "https://blob.example/"), "Authorization").empty());

    REQUIRE(h.m_network->deleteAttachment(id, "att-1"));
    REQUIRE_FALSE(h.m_server->m_blobs.contains("att-1"));
    REQUIRE_FALSE(h.m_network->downloadAttachment(id, "att-1", nullptr));
}

TEST_CASE("Attachment downloads require an absolute blob URL") {
    /**
     * @brief Transport whose attachment metadata points at a relative URL.
     */
    class RelativeUrl : public HttpTransport {
    public:
        void configure(ServerUrls) override {}
        HttpResponse send(HttpRequest) override {
            HttpResponse response;
            response.m_status = 200;
            SecureString text = Json { { "url", "/local/file" }, { "key", "k" } }.dump();
            response.m_body.assign(text.begin(), text.end());
            return response;
        }
        bool listen(std::string_view, std::function<void(std::span<const uint8_t>)>, std::stop_token) override {
            return false;
        }
    };

    std::shared_ptr<FakeServer> server = std::make_shared<FakeServer>();
    Network network(std::make_shared<RelativeUrl>(), DeviceInfo::forThisPlatform("dev-1"));
    network.setTokenSource(std::make_shared<StaticTokens>(server));
    REQUIRE_FALSE(network.downloadAttachment("c1", "a1", nullptr));
}

TEST_CASE("Uploads to a missing cipher fail") {
    Harness h;
    SecureBytes content = { 'x' };
    REQUIRE_FALSE(h.m_network->uploadAttachment("missing", "n", "k", content, nullptr));
}

TEST_CASE("Folders create, update and delete") {
    Harness h;
    std::optional<Json> folder = h.m_network->createFolder("2.f|o|o");
    REQUIRE(folder);
    SecureString id = stringAt(*folder, "id");
    REQUIRE(h.m_server->m_folders[id]["name"] == "2.f|o|o");

    std::optional<Json> renamed = h.m_network->updateFolder(id, "2.b|a|r");
    REQUIRE(renamed);
    REQUIRE((*renamed)["name"] == "2.b|a|r");

    REQUIRE(h.m_network->deleteFolder(id));
    REQUIRE(h.m_server->m_folders.empty());
    REQUIRE_FALSE(h.m_network->updateFolder(id, "2.x|y|z"));
}

TEST_CASE("getIcon fetches from the icon host") {
    Harness h;
    std::optional<SecureBytes> icon = h.m_network->getIcon("github.com");
    REQUIRE(icon);
    REQUIRE(h.m_server->last(HttpMethod::Get, "/github.com")->m_host == Host::Icons);
    REQUIRE(h.m_server->last(HttpMethod::Get, "/github.com")->m_path == "/github.com/icon.png");
}
