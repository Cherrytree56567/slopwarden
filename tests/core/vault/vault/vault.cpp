#include <catch2/catch_test_macros.hpp>

#include "core/support_vault.h"

using namespace clientwarden;
using namespace clientwarden::testing;

TEST_CASE("A vault exposes its identity and every part") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);

    REQUIRE(vault->getId() == "test");
    REQUIRE(vault->getType() == VaultType::Bitwarden);
    REQUIRE(vault->getCrypto());
    REQUIRE(vault->getNetwork());
    REQUIRE(vault->getSession());
    REQUIRE(vault->getProfile());
    REQUIRE(vault->getFeatures());
    REQUIRE(vault->getSync());
    REQUIRE(vault->getSettings());
    REQUIRE(vault->getAutoFill());
    REQUIRE(vault->getOrchestrator());
    REQUIRE(vault->getGenerator());
    REQUIRE(vault->getFailureReason().empty());
}

TEST_CASE("State changes are reported once each") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    std::vector<VaultState> seen;
    vault->onStateChange([&seen](VaultState state) { seen.push_back(state); });

    vault->setServer(testUrls());
    REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Success);
    vault->lock();
    vault->lock();
    vault->onStateChange(nullptr);

    REQUIRE(seen == std::vector<VaultState> { VaultState::Unlocked, VaultState::Unlockable });
}
