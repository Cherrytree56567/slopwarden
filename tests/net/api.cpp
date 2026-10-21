#include <catch2/catch_test_macros.hpp>
#include "Net/BitwardenApi.h"
#include "support/FakeServer.h"

using namespace ClientWarden;
using namespace ClientWarden::Testing;

namespace {
    struct StaticTokens : AccessTokenSource {
        FakeServer& server;
        std::string token;
        int refreshes = 0;

        explicit StaticTokens(FakeServer& s) : server(s), token(s.accessToken) {}
        std::optional<std::string> AccessToken() override { return token; }
        bool Refresh(const std::string&) override {
            ++refreshes;
            token = server.accessToken = "access-refreshed";
            return true;
        }
    };

    std::string Header(const HttpRequest& r, const std::string& name) {
        for (const auto& [k, v] : r.headers) {
            if (k == name) return v;
        }
        return {};
    }
}

TEST_CASE("PreLogin builds JSON safely and parses KDF settings") {
    FakeServer server;
    FakeTransport transport(server);
    BitwardenApi api(transport, DeviceInfo::ForThisPlatform("dev-1"));

    /*
     * Regression: the email used to be spliced into a JSON string.
    */
    auto kdf = api.PreLogin("a\"b@example.com");
    REQUIRE(kdf);
    REQUIRE(kdf->iterations == server.kdf.iterations);

    auto req = server.Last(HttpMethod::Post, "/identity/accounts/prelogin");
    REQUIRE(nlohmann::json::parse(req->body)["email"] == "a\"b@example.com");
    REQUIRE(Header(*req, "Bitwarden-Client-Name") == "desktop");
    REQUIRE_FALSE(Header(*req, "Device-Type").empty());
}

TEST_CASE("Password grant sends a stable device id and form-encodes values") {
    FakeServer server;
    FakeTransport transport(server);
    BitwardenApi api(transport, DeviceInfo::ForThisPlatform("dev-1"));

    TokenResponse res = api.PasswordGrant(server.email, server.passwordHash);
    REQUIRE(res.kind == TokenResponse::Kind::Success);
    REQUIRE(res.expiresIn == 3600);

    auto form = ParseForm(server.Last(HttpMethod::Post, "/identity/connect/token")->body);
    REQUIRE(form["deviceIdentifier"] == "dev-1");
    REQUIRE(form["password"] == server.passwordHash);   // '+', '/' and '=' survive encoding
}

TEST_CASE("Token errors are classified") {
    FakeServer server;
    FakeTransport transport(server);
    BitwardenApi api(transport, DeviceInfo::ForThisPlatform("dev-1"));

    REQUIRE(api.PasswordGrant(server.email, "wrong").kind == TokenResponse::Kind::InvalidCredentials);

    server.requireTotp = true;
    TokenResponse totp = api.PasswordGrant(server.email, server.passwordHash);
    REQUIRE(totp.kind == TokenResponse::Kind::TwoFactorRequired);
    REQUIRE(totp.providers == std::vector<TwoFactorProvider> { TwoFactorProvider::Authenticator });

    server.requireTotp = false;
    server.requireDeviceVerification = true;
    REQUIRE(api.PasswordGrant(server.email, server.passwordHash).kind == TokenResponse::Kind::NewDeviceVerification);

    server.online = false;
    REQUIRE(api.PasswordGrant(server.email, server.passwordHash).kind == TokenResponse::Kind::Failed);
    REQUIRE_FALSE(api.Online());
}

TEST_CASE("Refresh responses with numeric expires_in are accepted") {
    FakeServer server;
    FakeTransport transport(server);
    BitwardenApi api(transport, DeviceInfo::ForThisPlatform("dev-1"));

    /*
     * Regression: refresh used to require expires_in to be a string, so
     * every refresh after the first login failed.
    */
    REQUIRE(api.RefreshGrant(server.refreshToken).kind == TokenResponse::Kind::Success);
    server.revokeRefresh = true;
    REQUIRE(api.RefreshGrant(server.refreshToken).kind == TokenResponse::Kind::InvalidCredentials);
}

TEST_CASE("A 401 triggers one refresh and a retry") {
    FakeServer server;
    FakeTransport transport(server);
    BitwardenApi api(transport, DeviceInfo::ForThisPlatform("dev-1"));
    StaticTokens tokens(server);
    api.SetTokenSource(&tokens);

    server.InvalidateAccessToken();
    tokens.token = "stale";

    REQUIRE(api.Sync());
    REQUIRE(tokens.refreshes == 1);
    REQUIRE(api.Online());
}

TEST_CASE("Ids that could escape the route are refused") {
    FakeServer server;
    FakeTransport transport(server);
    BitwardenApi api(transport, DeviceInfo::ForThisPlatform("dev-1"));
    StaticTokens tokens(server);
    api.SetTokenSource(&tokens);

    REQUIRE_THROWS_AS(api.DeleteCipher("../folders/x"), VaultError);
    REQUIRE_THROWS_AS(api.DeleteFolder("a?b"), VaultError);
}

TEST_CASE("Attachment downloads don't send the bearer token to the blob host") {
    FakeServer server;
    FakeTransport transport(server);
    BitwardenApi api(transport, DeviceInfo::ForThisPlatform("dev-1"));
    StaticTokens tokens(server);
    api.SetTokenSource(&tokens);

    server.ciphers["c1"] = { { "id", "c1" }, { "attachments", { { { "fileName", "n" }, { "key", "k" } } } } };
    server.blobs["att-1"] = "blob";

    auto dl = api.DownloadAttachment("c1", "att-1", nullptr);
    REQUIRE(dl);
    REQUIRE(std::string(dl->content.begin(), dl->content.end()) == "blob");
    REQUIRE(Header(*server.Last(HttpMethod::Get, "https://blob.example/"), "Authorization").empty());
}
