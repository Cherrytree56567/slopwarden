#include <catch2/catch_test_macros.hpp>

#include "vault/profile/profile.h"

using namespace clientwarden;

namespace {
    /**
     * @brief A store whose cache holds `profile`.
     */
    std::shared_ptr<Store> storeWith(Json profile) {
        std::shared_ptr<Store> store = std::make_shared<Store>(std::make_shared<MemoryFileStore>());
        store->applySync(Store::Snapshot(), Json { { "profile", std::move(profile) } }, {}, {});
        return store;
    }
}

TEST_CASE("Profile reads the synced profile") {
    Profile profile(storeWith({ { "id", "u1" }, { "name", "Alice" }, { "email", "a@example.com" },
        { "key", "2.a|b|c" }, { "premium", true } }));
    REQUIRE(profile.getName() == "Alice");
    REQUIRE(profile.getEmail() == "a@example.com");
    REQUIRE(profile.getUserId() == "u1");
    REQUIRE(profile.getPremium());
    REQUIRE(profile.getProtectedKey() == SecureString("2.a|b|c"));
}

TEST_CASE("Profile defaults when nothing is synced") {
    Profile profile(std::make_shared<Store>(std::make_shared<MemoryFileStore>()));
    REQUIRE(profile.getName() == "Unknown");
    REQUIRE(profile.getEmail().empty());
    REQUIRE(profile.getUserId().empty());
    REQUIRE_FALSE(profile.getPremium());
    REQUIRE_FALSE(profile.getProtectedKey());
}

TEST_CASE("Profile premium can come from an organisation") {
    REQUIRE(Profile(storeWith({ { "premium", false }, { "premiumFromOrganization", true } })).getPremium());
    REQUIRE_FALSE(Profile(storeWith({ { "premium", "yes" } })).getPremium());
}
