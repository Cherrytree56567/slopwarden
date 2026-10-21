#include <catch2/catch_test_macros.hpp>

#include "items/folder/folder.h"
#include "core/items/item_fixture.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("Folder names are encrypted with the user key") {
    Folder folder(nullptr, ItemFixture::crypto(), Json { { "id", "f1" }, { "name", nullptr } }, ItemFixture::userKey());
    REQUIRE(folder.getId() == "f1");
    REQUIRE(folder.getName().empty());

    folder.setName("Work");
    REQUIRE(folder.getName() == "Work");
    REQUIRE(ItemFixture::crypto()->decryptText(folder.getJson()["name"].get<SecureString>(), ItemFixture::userKey())
        == "Work");
}

TEST_CASE("Folder JSON can be replaced") {
    Folder folder(nullptr, ItemFixture::crypto(), Json { { "id", "f1" } }, ItemFixture::userKey());
    folder.replaceJson(Json { { "id", "srv-1" }, { "name", ItemFixture::crypto()->encryptText("x",
        ItemFixture::userKey()) } });
    REQUIRE(folder.getId() == "srv-1");
    REQUIRE(folder.getName() == "x");
    REQUIRE_THROWS_AS(folder.replaceJson(Json(5)), VaultError);
}

TEST_CASE("Folder actions need a vault") {
    Folder folder(nullptr, ItemFixture::crypto(), Json { { "id", "f1" } }, ItemFixture::userKey());
    REQUIRE_THROWS_AS(folder.commit(), VaultError);
    REQUIRE_THROWS_AS(folder.remove(), VaultError);
}

TEST_CASE("Folder rejects tampered names") {
    Folder folder(nullptr, ItemFixture::crypto(), Json { { "id", "f1" } }, SymmetricKey::generate());
    folder.setName("Work");
    Folder other(nullptr, ItemFixture::crypto(), folder.getJson(), ItemFixture::userKey());
    REQUIRE_THROWS_AS(other.getName(), CryptoError);
}
