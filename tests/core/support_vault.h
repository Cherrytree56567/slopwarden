#pragma once
#include <chrono>
#include <memory>
#include <thread>

#include <catch2/catch_test_macros.hpp>

#include "bitwarden/bitwarden_vault.h"
#include "support/fake_server.h"

namespace clientwarden::testing {
    /**
     * @brief Builds a vault over a fixture (call again to "restart the app").
     *
     * @param fixture The device and server
     * @return The vault
     */
    inline std::shared_ptr<BitwardenVault> startVault(Fixture& fixture) {
        return std::make_shared<BitwardenVault>("test", fixture.m_secrets, fixture.m_files, fixture.m_resources,
            fixture.transport());
    }

    /**
     * @brief Builds a vault and logs in with the fixture's account.
     *
     * @param fixture The device and server
     * @return The unlocked vault
     */
    inline std::shared_ptr<BitwardenVault> loggedInVault(Fixture& fixture) {
        std::shared_ptr<BitwardenVault> vault = startVault(fixture);
        vault->setServer(testUrls());
        REQUIRE(vault->login(fixture.m_server->m_email, fixture.m_server->m_password) == LoginResult::Success);
        return vault;
    }

    /**
     * @brief Polls until a condition holds (for background work) or ~3 seconds pass.
     *
     * @param condition The condition
     * @return Whether it became true
     */
    template <typename Condition>
    bool eventually(Condition condition) {
        for (int i = 0; i < 300; ++i) {
            if (condition()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return condition();
    }
}
