#include <catch2/catch_test_macros.hpp>
#include <mutex>
#include <vector>

#include "core/support_vault.h"
#include "items/login_item/login_item.h"
#include "items/note_item/note_item.h"

using namespace clientwarden;
using namespace clientwarden::testing;

TEST_CASE("A fresh install starts logged out") {
    Fixture fixture;
    REQUIRE(startVault(fixture)->getState() == VaultState::LoggedOut);
}

TEST_CASE("Login with a password") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    REQUIRE(vault->getState() == VaultState::Unlocked);
    REQUIRE(vault->getProfile()->getName() == "Test User");
    REQUIRE(fixture.m_secrets->get("account"));
    REQUIRE(fixture.m_secrets->get("tokens"));
    REQUIRE(fixture.m_files->exists("vault.json"));
}

TEST_CASE("Login rejects a wrong password") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    vault->setServer(testUrls());

    REQUIRE(vault->login(fixture.m_server->m_email, "wrong") == LoginResult::InvalidCredentials);
    REQUIRE(vault->getState() == VaultState::LoggedOut);
}

TEST_CASE("Login normalises the email") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    vault->setServer(testUrls());
    REQUIRE(vault->login("  USER@Example.com ", fixture.m_server->m_password) == LoginResult::Success);
}

TEST_CASE("Login requires a server") {
    Fixture fixture;
    REQUIRE_THROWS_AS(startVault(fixture)->login("a@b.c", "x"), VaultError);
    REQUIRE_THROWS_AS(startVault(fixture)->setServer(ServerUrls { "ftp://x", "", "", "" }), VaultError);
}

TEST_CASE("Login refuses weak KDF settings from the server") {
    Fixture fixture;
    fixture.m_server->m_kdf.m_iterations = 1;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    vault->setServer(testUrls());

    REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Failed);
    REQUIRE(fixture.m_server->count(HttpMethod::Post, "/identity/connect/token") == 0);
}

TEST_CASE("Login while offline") {
    Fixture fixture;
    fixture.m_server->m_online = false;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    vault->setServer(testUrls());
    REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Offline);
}

TEST_CASE("Login with TOTP") {
    Fixture fixture;
    fixture.m_server->m_require_totp = true;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    vault->setServer(testUrls());

    REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::NeedsTotp);
    REQUIRE(vault->getState() == VaultState::WaitingForTotp);
    REQUIRE(vault->submitCode("000000") == LoginResult::InvalidCredentials);
    REQUIRE(vault->submitCode("123456") == LoginResult::Success);
    REQUIRE(vault->getState() == VaultState::Unlocked);
}

TEST_CASE("Login with a passkey") {
    Fixture fixture;
    fixture.m_server->m_require_passkey = true;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    vault->setServer(testUrls());

    REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::NeedsPasskey);
    std::optional<PasskeyRequest> request = vault->getPendingPasskey();
    REQUIRE(request);
    REQUIRE(request->m_challenge == "chal-123");
    REQUIRE(request->m_relying_party == "vault.example");

    /*
     * Regression: raw authenticator bytes used to go straight into JSON, which throws on
     * anything that isn't valid UTF-8.
    */
    std::vector<uint8_t> binary = { 0xff, 0xfe, 0x00, 0x80 };
    REQUIRE(vault->submitPasskey(binary, binary, binary, binary) == LoginResult::Success);

    Json assertion = Json::parse(fixture.m_server->m_last_passkey_assertion);
    REQUIRE(assertion["id"] == "__4AgA");
    REQUIRE(assertion["response"]["signature"] == "__4AgA");
}

TEST_CASE("Login with new device verification") {
    Fixture fixture;
    fixture.m_server->m_require_device_verification = true;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    vault->setServer(testUrls());

    REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::NeedsDeviceVerification);
    REQUIRE(vault->submitCode("654321") == LoginResult::Success);
}

TEST_CASE("The device id survives logout") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    SecureString first = parseForm(fixture.m_server->last(HttpMethod::Post, "/identity/connect/token")->m_body)["deviceIdentifier"];
    vault->logout();

    vault->setServer(testUrls());
    REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Success);
    REQUIRE(parseForm(fixture.m_server->last(HttpMethod::Post, "/identity/connect/token")->m_body)["deviceIdentifier"] == first);
}

TEST_CASE("Lock and unlock") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<NoteItem> note = vault->getOrchestrator()->createItem<NoteItem>();
    note->setName("Diary").commit();
    SecureString id = note->getId();

    vault->lock();
    REQUIRE(vault->getState() == VaultState::Unlockable);
    REQUIRE_THROWS_AS(vault->getOrchestrator()->getItem<NoteItem>(id), VaultError);
    REQUIRE_THROWS_AS(vault->getOrchestrator()->query(), VaultError);

    REQUIRE(vault->unlock("wrong") == UnlockResult::InvalidPassword);
    REQUIRE(vault->getState() == VaultState::Unlockable);
    REQUIRE(vault->unlock(fixture.m_server->m_password) == UnlockResult::Success);
    REQUIRE(vault->getOrchestrator()->getItem<NoteItem>(id)->getName() == "Diary");
}

TEST_CASE("Restarting keeps the session but requires unlock") {
    Fixture fixture;
    SecureString id;
    {
        std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
        std::shared_ptr<NoteItem> note = vault->getOrchestrator()->createItem<NoteItem>();
        note->commit();
        id = note->getId();
    }

    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    REQUIRE(vault->getState() == VaultState::Unlockable);
    REQUIRE(vault->unlock(fixture.m_server->m_password) == UnlockResult::Success);
    REQUIRE(vault->getOrchestrator()->hasItem(id));
}

TEST_CASE("Unlock works offline") {
    Fixture fixture;
    { loggedInVault(fixture); }
    fixture.m_server->m_online = false;
    REQUIRE(startVault(fixture)->unlock(fixture.m_server->m_password) == UnlockResult::Success);
}

TEST_CASE("Expired access tokens are refreshed transparently") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    fixture.m_server->invalidateAccessToken();
    REQUIRE(vault->getOrchestrator()->createItem<NoteItem>()->commit());
}

TEST_CASE("A revoked refresh token logs out") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    fixture.m_server->invalidateAccessToken();
    fixture.m_server->m_revoke_refresh = true;

    vault->syncNow();
    REQUIRE(eventually([&]() { return vault->getState() == VaultState::LoggedOut; }));
}

TEST_CASE("A remote account key change logs out") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    fixture.m_server->m_protected_key = fixture.m_server->m_crypto.wrapKey(SymmetricKey::generate(),
        fixture.m_server->m_crypto.stretchMasterKey(fixture.m_server->m_master_key));

    REQUIRE_FALSE(vault->syncNow());
    REQUIRE(eventually([&]() { return vault->getState() == VaultState::LoggedOut; }));
}

TEST_CASE("Logout wipes credentials and local data but keeps the device id") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    REQUIRE(vault->enableBiometrics());
    SecureString device = *fixture.m_secrets->get("deviceId");

    std::vector<VaultState> seen;
    vault->onStateChange([&seen](VaultState state) { seen.push_back(state); });
    vault->logout();

    REQUIRE(vault->getState() == VaultState::LoggedOut);
    REQUIRE(seen == std::vector<VaultState> { VaultState::LoggedOut });
    for (std::string_view key : { "account", "tokens", "internalKey" }) {
        CAPTURE(key);
        REQUIRE_FALSE(fixture.m_secrets->get(key));
    }
    REQUIRE(*fixture.m_secrets->get("deviceId") == device);
    REQUIRE_FALSE(fixture.m_files->exists("vault.json"));
    REQUIRE(startVault(fixture)->getState() == VaultState::LoggedOut);
}

TEST_CASE("Biometric unlock") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    REQUIRE_FALSE(vault->biometricsEnabled());
    REQUIRE(vault->enableBiometrics());
    REQUIRE(vault->biometricsEnabled());

    vault->lock();
    REQUIRE(vault->unlockWithBiometrics() == UnlockResult::Success);

    vault->disableBiometrics();
    vault->lock();
    REQUIRE(vault->unlockWithBiometrics() == UnlockResult::Failed);
}

TEST_CASE("Master password re-prompt") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    REQUIRE(vault->verifyMasterPassword(fixture.m_server->m_password));
    REQUIRE_FALSE(vault->verifyMasterPassword("nope"));
}

TEST_CASE("Auto-lock after inactivity") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::mutex mutex;
    std::vector<VaultState> seen;
    vault->onStateChange([&](VaultState state) {
        std::lock_guard<std::mutex> lock(mutex);
        seen.push_back(state);
    });

    vault->noteActivity(std::time(nullptr) - 10000);
    REQUIRE(eventually([&]() { return vault->getState() == VaultState::Unlockable; }));
    std::lock_guard<std::mutex> lock(mutex);
    REQUIRE(seen == std::vector<VaultState> { VaultState::Unlockable });
}

TEST_CASE("Timeout can log out instead of locking") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    vault->getSettings()->setTimeoutAction(TimeoutAction::Logout);

    vault->noteActivity(std::time(nullptr) - 10000);
    REQUIRE(eventually([&]() { return vault->getState() == VaultState::LoggedOut; }));
}

TEST_CASE("Tampered personal data puts the vault in the Failed state") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<LoginItem> login = vault->getOrchestrator()->createItem<LoginItem>();
    login->setName("Bank").commit();
    SecureString id = login->getId();

    /*
     * Swap the cached item key for one encrypted under a different key: the MAC check fails.
    */
    Json tampered = vault->getOrchestrator()->getGenericItem(id)->getJson();
    tampered["key"] = Crypto().wrapKey(SymmetricKey::generate(), SymmetricKey::generate());
    vault.reset();

    std::shared_ptr<Store> store = std::make_shared<Store>(fixture.m_files);
    REQUIRE(store->load());
    store->putCipher(tampered);

    vault = startVault(fixture);
    REQUIRE(vault->unlock(fixture.m_server->m_password) == UnlockResult::Success);
    REQUIRE_THROWS_AS(vault->getOrchestrator()->getItem<LoginItem>(id), CryptoError);
    REQUIRE(vault->getState() == VaultState::Failed);
    REQUIRE_FALSE(vault->getFailureReason().empty());
    REQUIRE_FALSE(vault->getSession()->hasKeys());

    vault->lock();
    REQUIRE(vault->getState() == VaultState::Failed);
    vault->logout();
    REQUIRE(vault->getState() == VaultState::LoggedOut);
}

TEST_CASE("Saves include the legacy data blob only for old servers") {
    Fixture fixture;
    fixture.m_server->m_version = "2026.3.0";
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    REQUIRE(eventually([&]() { return vault->getFeatures()->versionKnown(); }));

    vault->getOrchestrator()->createItem<NoteItem>()->commit();
    REQUIRE(Json::parse(fixture.m_server->last(HttpMethod::Post, "/api/ciphers")->m_body).contains("data"));
}
