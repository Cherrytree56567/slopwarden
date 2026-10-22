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

namespace {
    /**
     * @brief A store that refuses values over a size, like Windows Credential Manager.
     */
    class LimitedSecretStore : public MemorySecretStore {
    public:
        explicit LimitedSecretStore(size_t limit) : m_limit(limit) {}

        bool set(std::string_view key, std::string_view value, SecretProtection protection) override {
            return value.size() <= m_limit && MemorySecretStore::set(key, value, protection);
        }

        size_t m_limit;
    };
}

TEST_CASE("ChunkedSecretStore splits values bigger than the store allows") {
    std::shared_ptr<LimitedSecretStore> inner = std::make_shared<LimitedSecretStore>(16);
    ChunkedSecretStore store(inner, 10);

    REQUIRE(store.set("small", "fits", SecretProtection::None));
    REQUIRE(inner->get("small") == SecureString("fits"));
    REQUIRE(store.get("small") == SecureString("fits"));

    SecureString big = "0123456789abcdefghijklmnopqrstuvwxyz";
    REQUIRE(store.set("big", big, SecretProtection::UserAuth));
    REQUIRE(store.get("big") == big);
    REQUIRE(inner->get("big#4"));
    REQUIRE_FALSE(inner->get("big#5"));

    /*
     * Shrinking drops the parts that are no longer needed; a small value replaces the marker.
     */
    REQUIRE(store.set("big", "0123456789abcde", SecretProtection::None));
    REQUIRE(store.get("big") == SecureString("0123456789abcde"));
    REQUIRE_FALSE(inner->get("big#3"));
    REQUIRE(store.set("big", "tiny", SecretProtection::None));
    REQUIRE(store.get("big") == SecureString("tiny"));
    REQUIRE_FALSE(inner->get("big#1"));

    REQUIRE(store.set("big", big, SecretProtection::None));
    REQUIRE(store.remove("big"));
    REQUIRE_FALSE(store.get("big"));
    REQUIRE_FALSE(inner->get("big#1"));
}

TEST_CASE("ChunkedSecretStore treats a missing part as no value") {
    std::shared_ptr<MemorySecretStore> inner = std::make_shared<MemorySecretStore>();
    ChunkedSecretStore store(inner, 4);
    REQUIRE(store.set("k", "abcdefghij", SecretProtection::None));
    inner->remove("k#2");
    REQUIRE_FALSE(store.get("k"));

    /*
     * A value that looks like the marker is stored chunked, so it reads back unchanged.
     */
    SecureString tricky = "\x01" "cw-parts:7";
    REQUIRE(store.set("t", tricky, SecretProtection::None));
    REQUIRE(store.get("t") == tricky);
}
