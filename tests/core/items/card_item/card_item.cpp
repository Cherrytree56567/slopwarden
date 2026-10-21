#include <catch2/catch_test_macros.hpp>

#include "items/card_item/card_item.h"
#include "core/items/item_fixture.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("CardItem fields round trip through the encrypted JSON") {
    std::shared_ptr<CardItem> item = ItemFixture::create<CardItem>();
    REQUIRE(item->getType() == CipherType::Card);

    item->setName("Example")
        .setCardholderName("CardholderName value")
        .setBrand("Brand value")
        .setNumber("Number value")
        .setExpMonth("ExpMonth value")
        .setExpYear("ExpYear value")
        .setCode("Code value");

    std::shared_ptr<CardItem> reloaded = ItemFixture::reload<CardItem>(item->getJson());
    REQUIRE(reloaded->getName() == "Example");
    REQUIRE(reloaded->getCardholderName() == "CardholderName value");
    REQUIRE(reloaded->getBrand() == "Brand value");
    REQUIRE(reloaded->getNumber() == "Number value");
    REQUIRE(reloaded->getExpMonth() == "ExpMonth value");
    REQUIRE(reloaded->getExpYear() == "ExpYear value");
    REQUIRE(reloaded->getCode() == "Code value");

    /*
     * Nothing is stored in plaintext.
    */
    REQUIRE(item->getJson().dump().find("value") == SecureString::npos);
}

TEST_CASE("CardItem fields start empty and clear to null") {
    std::shared_ptr<CardItem> item = ItemFixture::create<CardItem>();
    REQUIRE(item->getCardholderName().empty());

    item->setCardholderName("x").setCardholderName("");
    REQUIRE(item->getJson()["card"]["cardholderName"].is_null());
    REQUIRE(item->getCardholderName().empty());
}

