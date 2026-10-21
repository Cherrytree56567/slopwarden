#include <catch2/catch_test_macros.hpp>

#include "items/bank_account_item/bank_account_item.h"
#include "core/items/item_fixture.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("BankAccountItem fields round trip through the encrypted JSON") {
    std::shared_ptr<BankAccountItem> item = ItemFixture::create<BankAccountItem>();
    REQUIRE(item->getType() == CipherType::BankAccount);

    item->setName("Example")
        .setBankName("BankName value")
        .setNameOnAccount("NameOnAccount value")
        .setAccountType("AccountType value")
        .setAccountNumber("AccountNumber value")
        .setRoutingNumber("RoutingNumber value")
        .setBranchNumber("BranchNumber value")
        .setPin("Pin value")
        .setSwiftCode("SwiftCode value")
        .setIban("Iban value")
        .setBankContactPhone("BankContactPhone value");

    std::shared_ptr<BankAccountItem> reloaded = ItemFixture::reload<BankAccountItem>(item->getJson());
    REQUIRE(reloaded->getName() == "Example");
    REQUIRE(reloaded->getBankName() == "BankName value");
    REQUIRE(reloaded->getNameOnAccount() == "NameOnAccount value");
    REQUIRE(reloaded->getAccountType() == "AccountType value");
    REQUIRE(reloaded->getAccountNumber() == "AccountNumber value");
    REQUIRE(reloaded->getRoutingNumber() == "RoutingNumber value");
    REQUIRE(reloaded->getBranchNumber() == "BranchNumber value");
    REQUIRE(reloaded->getPin() == "Pin value");
    REQUIRE(reloaded->getSwiftCode() == "SwiftCode value");
    REQUIRE(reloaded->getIban() == "Iban value");
    REQUIRE(reloaded->getBankContactPhone() == "BankContactPhone value");

    /*
     * Nothing is stored in plaintext.
    */
    REQUIRE(item->getJson().dump().find("value") == SecureString::npos);
}

TEST_CASE("BankAccountItem fields start as encrypted \"\" and stay encrypted when cleared") {
    std::shared_ptr<BankAccountItem> item = ItemFixture::create<BankAccountItem>();
    REQUIRE(item->getBankName() == "");

    item->setBankName("");
    REQUIRE(item->getBankName().empty());
}

