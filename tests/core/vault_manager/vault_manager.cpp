#include <catch2/catch_test_macros.hpp>

#include "core/support_vault.h"
#include "vault_manager/vault_manager.h"

using namespace clientwarden;
using namespace clientwarden::testing;

namespace {
    /**
     * @brief A manager over a fixture's shared keychain and disk.
     *
     * @param fixture The device and server
     * @return The manager
     */
    std::shared_ptr<VaultManager> startManager(Fixture& fixture) {
        std::shared_ptr<FakeServer> server = fixture.m_server;
        return std::make_shared<VaultManager>(fixture.m_secrets, fixture.m_files, fixture.m_resources,
            [server]() { return std::shared_ptr<HttpTransport>(std::make_shared<FakeTransport>(server)); });
    }
}

TEST_CASE("A fresh install gets one vault on demand") {
    Fixture fixture;
    std::shared_ptr<VaultManager> manager = startManager(fixture);
    REQUIRE(manager->listVaults().empty());

    std::shared_ptr<Vault> vault = manager->getActiveVault();
    REQUIRE(vault);
    REQUIRE(vault->getState() == VaultState::LoggedOut);
    REQUIRE(manager->listVaults().size() == 1);
    REQUIRE(fixture.m_files->exists("vaults.json"));
}

TEST_CASE("Vaults keep separate keychain entries and files") {
    Fixture fixture;
    std::shared_ptr<VaultManager> manager = startManager(fixture);
    std::shared_ptr<Vault> first = manager->addVault(VaultType::Bitwarden, "Personal");
    std::shared_ptr<Vault> second = manager->addVault(VaultType::Bitwarden, "Work");

    first->setServer(testUrls());
    REQUIRE(first->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Success);
    REQUIRE(second->getState() == VaultState::LoggedOut);

    REQUIRE_FALSE(fixture.m_secrets->get("account"));
    REQUIRE(fixture.m_secrets->get(first->getId() + ".account"));
    REQUIRE(fixture.m_files->exists(std::filesystem::path("vaults") / first->getId().c_str() / "vault.json"));

    REQUIRE(manager->setActiveVault(second->getId()));
    REQUIRE(manager->getActiveVault() == second);
    REQUIRE_FALSE(manager->setActiveVault("nope"));
}

TEST_CASE("The vault list survives a restart") {
    Fixture fixture;
    SecureString id;
    {
        std::shared_ptr<VaultManager> manager = startManager(fixture);
        std::shared_ptr<Vault> vault = manager->addVault(VaultType::Bitwarden, "Personal");
        vault->setServer(testUrls());
        REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Success);
        id = vault->getId();
    }

    std::shared_ptr<VaultManager> manager = startManager(fixture);
    REQUIRE(manager->listVaults().size() == 1);
    REQUIRE(manager->listVaults()[0].m_name == "Personal");
    std::shared_ptr<Vault> vault = manager->getVault(id);
    REQUIRE(vault->getState() == VaultState::Unlockable);
    REQUIRE(vault->unlock(fixture.m_server->m_password) == UnlockResult::Success);
}

TEST_CASE("An account from the single-vault layout is adopted in place") {
    Fixture fixture;
    {
        std::shared_ptr<BitwardenVault> legacy = loggedInVault(fixture);   // unscoped storage
    }

    std::shared_ptr<VaultManager> manager = startManager(fixture);
    REQUIRE(manager->listVaults().size() == 1);
    REQUIRE(manager->listVaults()[0].m_scope.empty());
    std::shared_ptr<Vault> vault = manager->getActiveVault();
    REQUIRE(vault->getState() == VaultState::Unlockable);
    REQUIRE(vault->unlock(fixture.m_server->m_password) == UnlockResult::Success);
}

TEST_CASE("Removing a vault logs it out") {
    Fixture fixture;
    std::shared_ptr<VaultManager> manager = startManager(fixture);
    std::shared_ptr<Vault> vault = manager->addVault(VaultType::Bitwarden, "Personal");
    vault->setServer(testUrls());
    REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Success);
    SecureString id = vault->getId();

    REQUIRE(manager->removeVault(id));
    REQUIRE(manager->listVaults().empty());
    REQUIRE_FALSE(fixture.m_secrets->get(id + ".account"));
    REQUIRE_FALSE(manager->removeVault(id));
}

TEST_CASE("Another vault keeps syncing in the background") {
    Fixture fixture;
    std::shared_ptr<VaultManager> manager = startManager(fixture);
    std::shared_ptr<Vault> first = manager->addVault(VaultType::Bitwarden, "Personal");
    std::shared_ptr<Vault> second = manager->addVault(VaultType::Bitwarden, "Work");
    first->setServer(testUrls());
    REQUIRE(first->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Success);

    REQUIRE(manager->setActiveVault(second->getId()));
    REQUIRE(first->syncNow());
    REQUIRE(first->getState() == VaultState::Unlocked);
}
