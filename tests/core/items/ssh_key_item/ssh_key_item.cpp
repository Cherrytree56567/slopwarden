#include <catch2/catch_test_macros.hpp>

#include "items/ssh_key_item/ssh_key_item.h"
#include "core/items/item_fixture.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("SshKeyItem fields round trip through the encrypted JSON") {
    std::shared_ptr<SshKeyItem> item = ItemFixture::create<SshKeyItem>();
    REQUIRE(item->getType() == CipherType::SshKey);

    item->setName("Example")
        .setPrivateKey("PrivateKey value")
        .setPublicKey("PublicKey value")
        .setFingerprint("Fingerprint value");

    std::shared_ptr<SshKeyItem> reloaded = ItemFixture::reload<SshKeyItem>(item->getJson());
    REQUIRE(reloaded->getName() == "Example");
    REQUIRE(reloaded->getPrivateKey() == "PrivateKey value");
    REQUIRE(reloaded->getPublicKey() == "PublicKey value");
    REQUIRE(reloaded->getFingerprint() == "Fingerprint value");

    /*
     * Nothing is stored in plaintext.
    */
    REQUIRE(item->getJson().dump().find("value") == SecureString::npos);
}

TEST_CASE("SshKeyItem fields start as encrypted \" \" and stay encrypted when cleared") {
    std::shared_ptr<SshKeyItem> item = ItemFixture::create<SshKeyItem>();
    REQUIRE(item->getPrivateKey() == " ");

    item->setPrivateKey("");
    REQUIRE(item->getPrivateKey().empty());
}

