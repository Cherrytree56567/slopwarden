#include <catch2/catch_test_macros.hpp>
#include <thread>

#include "support/fake_server.h"
#include "utils/errors/errors.h"
#include "vault/session/session.h"

using namespace clientwarden;
using namespace clientwarden::testing;

namespace {
    /**
     * @brief A session wired to a fake server through a real Network.
     */
    struct Harness {
        std::shared_ptr<FakeServer> m_server = std::make_shared<FakeServer>();
        std::shared_ptr<MemorySecretStore> m_secrets = std::make_shared<MemorySecretStore>();
        std::shared_ptr<Crypto> m_crypto = std::make_shared<Crypto>();
        std::shared_ptr<Network> m_network =
            std::make_shared<Network>(std::make_shared<FakeTransport>(m_server), DeviceInfo::forThisPlatform("dev-1"));
        std::shared_ptr<Session> m_session = std::make_shared<Session>(m_secrets, m_crypto);

        /**
         * @brief Connects the session and network both ways.
         */
        Harness() {
            m_session->setNetwork(m_network);
            m_network->setTokenSource(m_session);
        }

        /**
         * @brief Logs in against the fake server and stores the tokens.
         */
        void login() {
            TokenResponse token = m_network->passwordGrant(m_server->m_email, m_server->m_password_hash, std::nullopt,
                std::nullopt);
            REQUIRE(m_session->setTokens(token));
        }

        /**
         * @brief A complete account record.
         */
        Account account() {
            Account a;
            a.m_email = m_server->m_email;
            a.m_kdf = m_server->m_kdf;
            a.m_urls = testUrls();
            return a;
        }
    };
}

TEST_CASE("Account serialises round trip") {
    Harness h;
    Account a = h.account();
    a.m_biometrics = true;
    std::optional<Account> back = Account::fromJson(a.toJson());
    REQUIRE(back);
    REQUIRE(back->m_email == a.m_email);
    REQUIRE(back->m_kdf.m_iterations == a.m_kdf.m_iterations);
    REQUIRE(back->m_urls.m_vault == "https://vault.example");
    REQUIRE(back->m_biometrics);

    REQUIRE_FALSE(Account::fromJson(Json::object()));
    REQUIRE_FALSE(Account::fromJson({ { "email", "x" }, { "kdf", Json::object() }, { "urls", { { "vault", "ftp://x" } } } }));
}

TEST_CASE("Account save and load") {
    Harness h;
    REQUIRE_FALSE(h.m_session->loadAccount());
    REQUIRE(h.m_session->saveAccount(h.account()));
    std::optional<Account> loaded = h.m_session->loadAccount();
    REQUIRE(loaded);
    REQUIRE(loaded->m_email == h.m_server->m_email);
}

TEST_CASE("Device id is created once and persists") {
    std::shared_ptr<MemorySecretStore> secrets = std::make_shared<MemorySecretStore>();
    SecureString first = Session::getDeviceId(secrets);
    REQUIRE(first.size() == 36);
    REQUIRE(Session::getDeviceId(secrets) == first);
}

TEST_CASE("Tokens are stored, cached and reloaded") {
    Harness h;
    REQUIRE_FALSE(h.m_session->getAccessToken());
    REQUIRE_FALSE(h.m_session->loadTokens());

    h.login();
    std::optional<SecureString> token = h.m_session->getAccessToken();
    REQUIRE(token == h.m_server->m_access_token);

    Session other(h.m_secrets, h.m_crypto);
    REQUIRE(other.loadTokens());
    REQUIRE(other.getAccessToken() == token);
}

TEST_CASE("An expired access token is refreshed before use") {
    Harness h;
    h.m_server->m_expires_in = 10;   // inside the refresh margin
    h.login();
    SecureString first = h.m_server->m_access_token;

    std::optional<SecureString> token = h.m_session->getAccessToken();
    REQUIRE(token);
    REQUIRE(*token != first);
    REQUIRE(h.m_server->count(HttpMethod::Post, "/identity/connect/token") == 2);
}

TEST_CASE("refresh skips if the rejected token was already replaced") {
    Harness h;
    h.login();
    SecureString current = *h.m_session->getAccessToken();

    REQUIRE(h.m_session->refresh("some-older-token"));
    REQUIRE(h.m_server->count(HttpMethod::Post, "/identity/connect/token") == 1);

    REQUIRE(h.m_session->refresh(current));
    REQUIRE(h.m_server->count(HttpMethod::Post, "/identity/connect/token") == 2);
    REQUIRE(*h.m_session->getAccessToken() != current);
}

TEST_CASE("Concurrent refreshes spend the refresh token once") {
    Harness h;
    h.login();
    SecureString current = *h.m_session->getAccessToken();

    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&h, current]() { h.m_session->refresh(current); });
    }
    for (std::thread& t : threads) {
        t.join();
    }
    REQUIRE(h.m_server->count(HttpMethod::Post, "/identity/connect/token") == 2);
}

TEST_CASE("Network 401s are refreshed through the session") {
    Harness h;
    h.login();
    h.m_server->invalidateAccessToken();
    REQUIRE(h.m_network->getSync());
}

TEST_CASE("A revoked refresh token triggers onRevoked") {
    Harness h;
    h.login();
    bool revoked = false;
    h.m_session->onRevoked([&revoked]() { revoked = true; });
    h.m_server->m_revoke_refresh = true;

    REQUIRE_FALSE(h.m_session->refresh(*h.m_session->getAccessToken()));
    REQUIRE(revoked);
    REQUIRE_FALSE(h.m_session->getAccessToken());
}

TEST_CASE("Refresh fails cleanly without a network") {
    std::shared_ptr<MemorySecretStore> secrets = std::make_shared<MemorySecretStore>();
    Session session(secrets, std::make_shared<Crypto>());
    TokenResponse token;
    token.m_access_token = "a";
    token.m_refresh_token = "r";
    token.m_expires_in = 0;
    session.setTokens(token);
    REQUIRE_FALSE(session.refresh("a"));
}

TEST_CASE("Keys are held until cleared") {
    Harness h;
    REQUIRE_FALSE(h.m_session->hasKeys());
    REQUIRE_THROWS_AS(h.m_session->getUserKey(), VaultError);

    SymmetricKey key = SymmetricKey::generate();
    h.m_session->setKeys(h.m_server->m_master_key, key);
    REQUIRE(h.m_session->hasKeys());
    REQUIRE(h.m_session->getUserKey().m_enc == key.m_enc);
    REQUIRE(h.m_session->masterKeyEquals(h.m_server->m_master_key));

    SecureBytes other = h.m_server->m_master_key;
    other[0] ^= 1;
    REQUIRE_FALSE(h.m_session->masterKeyEquals(other));

    h.m_session->clearKeys();
    REQUIRE_FALSE(h.m_session->hasKeys());
    REQUIRE_FALSE(h.m_session->masterKeyEquals(h.m_server->m_master_key));
    REQUIRE_THROWS_AS(h.m_session->getUserKey(), VaultError);
}

TEST_CASE("Biometric key save, load and remove") {
    Harness h;
    h.m_session->saveAccount(h.account());

    REQUIRE_FALSE(h.m_session->saveBiometricKey());    // locked
    REQUIRE_FALSE(h.m_session->hasBiometricKey());

    h.m_session->setKeys(h.m_server->m_master_key, h.m_server->m_user_key);
    REQUIRE(h.m_session->saveBiometricKey());
    REQUIRE(h.m_session->hasBiometricKey());
    REQUIRE(h.m_session->loadBiometricKey() == h.m_server->m_master_key);

    REQUIRE(h.m_session->removeBiometricKey());
    REQUIRE_FALSE(h.m_session->hasBiometricKey());
    REQUIRE_FALSE(h.m_session->loadBiometricKey());
}

TEST_CASE("The pre-rewrite keychain layout is migrated") {
    Harness h;
    std::shared_ptr<MemorySecretStore> s = h.m_secrets;
    s->set("email", h.m_server->m_email, SecretProtection::None);
    s->set("salt", h.m_server->m_email, SecretProtection::None);
    s->set("kdfType", "0", SecretProtection::None);
    s->set("kdfIterations", "100000", SecretProtection::None);
    s->set("kdfMemory", "0", SecretProtection::None);
    s->set("kdfParallelism", "0", SecretProtection::None);
    s->set("vaultURL", "https://vault.example", SecretProtection::None);
    s->set("mainURL", "https://vault.example", SecretProtection::None);
    s->set("apiURL", "https://api.example", SecretProtection::None);
    s->set("iconURL", "https://icons.example", SecretProtection::None);
    s->set("wssURL", "wss://notify.example", SecretProtection::None);
    s->set("accessString", "old-access", SecretProtection::None);
    s->set("refreshToken", "old-refresh", SecretProtection::None);
    s->set("needsRefreshTime", timestamp::now(3600), SecretProtection::None);
    s->set("masterPasswordHash", "old-hash", SecretProtection::None);

    std::optional<Account> account = h.m_session->loadAccount();
    REQUIRE(account);
    REQUIRE(account->m_email == h.m_server->m_email);
    REQUIRE(account->m_kdf.m_iterations == 100000);
    REQUIRE(account->m_urls.m_notifications == "wss://notify.example");

    for (std::string_view key : { "email", "accessString", "refreshToken", "kdfIterations", "masterPasswordHash" }) {
        REQUIRE_FALSE(s->get(key));
    }
    REQUIRE(s->get("account"));
    REQUIRE(h.m_session->loadTokens());
    REQUIRE(h.m_session->getAccessToken() == "old-access");
}

TEST_CASE("Migration is skipped when the old URLs are incomplete") {
    Harness h;
    h.m_secrets->set("email", "a@b.c", SecretProtection::None);
    REQUIRE_FALSE(h.m_session->loadAccount());
    REQUIRE(h.m_secrets->get("email"));
}

TEST_CASE("forget removes credentials but keeps the device id") {
    Harness h;
    SecureString device = Session::getDeviceId(h.m_secrets);
    h.m_session->saveAccount(h.account());
    h.login();
    h.m_session->setKeys(h.m_server->m_master_key, h.m_server->m_user_key);
    h.m_session->saveBiometricKey();

    h.m_session->forget();

    REQUIRE_FALSE(h.m_session->hasKeys());
    REQUIRE_FALSE(h.m_session->getAccessToken());
    for (std::string_view key : { "account", "tokens", "internalKey" }) {
        REQUIRE_FALSE(h.m_secrets->get(key));
    }
    REQUIRE(Session::getDeviceId(h.m_secrets) == device);
}

TEST_CASE("Sealed tokens are only readable with the user key") {
    std::shared_ptr<MemorySecretStore> secrets = std::make_shared<MemorySecretStore>();
    std::shared_ptr<Crypto> crypto = std::make_shared<Crypto>();
    SymmetricKey user_key = SymmetricKey::generate();
    SecureBytes master_key(32, 7);

    /*
     * Login: tokens arrive before the user key, and nothing is stored until it does.
    */
    {
        Session session(secrets, crypto);
        session.setSealTokens(true);
        TokenResponse token;
        token.m_access_token = "access-secret";
        token.m_refresh_token = "refresh-secret";
        token.m_expires_in = 3600;
        REQUIRE(session.setTokens(token));
        REQUIRE_FALSE(secrets->get("tokens"));

        session.setKeys(master_key, user_key);
        std::optional<SecureString> stored = secrets->get("tokens");
        REQUIRE(stored);
        REQUIRE(stored->find("refresh-secret") == SecureString::npos);
        REQUIRE(stored->find("access-secret") == SecureString::npos);
        REQUIRE(session.getAccessToken() == SecureString("access-secret"));

        session.clearKeys();
        REQUIRE_FALSE(session.getAccessToken());
    }

    /*
     * Next launch: the session counts as present (Unlockable) but holds no tokens until unlock.
    */
    Session restarted(secrets, crypto);
    restarted.setSealTokens(true);
    REQUIRE(restarted.loadTokens());
    REQUIRE_FALSE(restarted.getAccessToken());
    restarted.setKeys(master_key, user_key);
    REQUIRE(restarted.getAccessToken() == SecureString("access-secret"));

    /*
     * The wrong key opens nothing.
    */
    Session wrong(secrets, crypto);
    wrong.setSealTokens(true);
    REQUIRE(wrong.loadTokens());
    wrong.setKeys(master_key, SymmetricKey::generate());
    REQUIRE_FALSE(wrong.getAccessToken());
}
