#include <catch2/catch_test_macros.hpp>

#include "vault/features/features.h"

using namespace clientwarden;

namespace {
    /**
     * @brief Features over a fresh in-memory store.
     */
    struct Fixture {
        std::shared_ptr<Store> m_store = std::make_shared<Store>(std::make_shared<MemoryFileStore>());
        Features m_features { m_store };
    };
}

TEST_CASE("Features::compareVersions compares numerically") {
    REQUIRE(Features::compareVersions("2026.10.0", "2026.9.9") > 0);
    REQUIRE(Features::compareVersions("2026.6", "2026.6.0") == 0);
    REQUIRE(Features::compareVersions("2026.5.1", "2026.6.0") < 0);
    REQUIRE(Features::compareVersions("", "") == 0);
    REQUIRE(Features::compareVersions("1.2.3-beta", "1.2.3") == 0);
}

TEST_CASE("Features before the version is known") {
    Fixture f;
    REQUIRE_FALSE(f.m_features.versionKnown());
    REQUIRE_FALSE(f.m_features.atLeast("1.0.0"));
    REQUIRE(f.m_features.needsLegacyData());
    REQUIRE_FALSE(f.m_features.supportsExtendedItemTypes());
}

TEST_CASE("Features::applyConfig records the server version") {
    Fixture f;
    REQUIRE_FALSE(f.m_features.applyConfig(Json { { "other", 1 } }));
    REQUIRE_FALSE(f.m_features.versionKnown());

    REQUIRE(f.m_features.applyConfig(Json { { "version", "2026.6.0" } }));
    REQUIRE(f.m_features.versionKnown());
    REQUIRE(f.m_store->getServerVersion() == "2026.6.0");
    REQUIRE(f.m_features.atLeast("2026.6.0"));
    REQUIRE_FALSE(f.m_features.atLeast("2026.6.1"));
}

TEST_CASE("Features::needsLegacyData and supportsExtendedItemTypes follow the version") {
    Fixture f;
    f.m_features.applyConfig(Json { { "version", "2026.5.0" } });
    REQUIRE(f.m_features.needsLegacyData());
    REQUIRE_FALSE(f.m_features.supportsExtendedItemTypes());

    f.m_features.applyConfig(Json { { "version", "2026.6.0" } });
    REQUIRE_FALSE(f.m_features.needsLegacyData());
    REQUIRE_FALSE(f.m_features.supportsExtendedItemTypes());

    f.m_features.applyConfig(Json { { "version", "2026.8.1" } });
    REQUIRE(f.m_features.supportsExtendedItemTypes());
}
