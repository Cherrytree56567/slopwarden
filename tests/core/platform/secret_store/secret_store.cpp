#include <catch2/catch_test_macros.hpp>

#include "platform/secret_store/secret_store.h"

using namespace clientwarden;

TEST_CASE("MemorySecretStore stores, replaces and removes") {
    MemorySecretStore store;
    REQUIRE_FALSE(store.get("k"));

    REQUIRE(store.set("k", "v1", SecretProtection::None));
    REQUIRE(store.get("k") == SecureString("v1"));

    REQUIRE(store.set("k", "v2", SecretProtection::UserAuth));
    REQUIRE(store.get("k") == SecureString("v2"));

    REQUIRE(store.remove("k"));
    REQUIRE_FALSE(store.get("k"));
    REQUIRE(store.remove("k"));
}

TEST_CASE("ScopedSecretStore prefixes keys") {
    std::shared_ptr<MemorySecretStore> inner = std::make_shared<MemorySecretStore>();
    ScopedSecretStore a(inner, "a.");
    ScopedSecretStore b(inner, "b.");

    a.set("account", "alice", SecretProtection::None);
    b.set("account", "bob", SecretProtection::None);

    REQUIRE(a.get("account") == SecureString("alice"));
    REQUIRE(b.get("account") == SecureString("bob"));
    REQUIRE(inner->get("a.account") == SecureString("alice"));
    REQUIRE_FALSE(inner->get("account"));

    a.remove("account");
    REQUIRE_FALSE(a.get("account"));
    REQUIRE(b.get("account"));

    ScopedSecretStore legacy(inner, "");
    legacy.set("account", "root", SecretProtection::None);
    REQUIRE(inner->get("account") == SecureString("root"));
}
