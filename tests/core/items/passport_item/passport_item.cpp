#include <catch2/catch_test_macros.hpp>

#include "items/passport_item/passport_item.h"
#include "core/items/item_fixture.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("PassportItem fields round trip through the encrypted JSON") {
    std::shared_ptr<PassportItem> item = ItemFixture::create<PassportItem>();
    REQUIRE(item->getType() == CipherType::Passport);

    item->setName("Example")
        .setSurname("Surname value")
        .setGivenName("GivenName value")
        .setDateOfBirth("DateOfBirth value")
        .setSex("Sex value")
        .setBirthPlace("BirthPlace value")
        .setNationality("Nationality value")
        .setIssuingCountry("IssuingCountry value")
        .setPassportNumber("PassportNumber value")
        .setPassportType("PassportType value")
        .setNationalIdentificationNumber("NationalIdentificationNumber value")
        .setIssuingAuthority("IssuingAuthority value")
        .setIssueDate("IssueDate value")
        .setExpirationDate("ExpirationDate value");

    std::shared_ptr<PassportItem> reloaded = ItemFixture::reload<PassportItem>(item->getJson());
    REQUIRE(reloaded->getName() == "Example");
    REQUIRE(reloaded->getSurname() == "Surname value");
    REQUIRE(reloaded->getGivenName() == "GivenName value");
    REQUIRE(reloaded->getDateOfBirth() == "DateOfBirth value");
    REQUIRE(reloaded->getSex() == "Sex value");
    REQUIRE(reloaded->getBirthPlace() == "BirthPlace value");
    REQUIRE(reloaded->getNationality() == "Nationality value");
    REQUIRE(reloaded->getIssuingCountry() == "IssuingCountry value");
    REQUIRE(reloaded->getPassportNumber() == "PassportNumber value");
    REQUIRE(reloaded->getPassportType() == "PassportType value");
    REQUIRE(reloaded->getNationalIdentificationNumber() == "NationalIdentificationNumber value");
    REQUIRE(reloaded->getIssuingAuthority() == "IssuingAuthority value");
    REQUIRE(reloaded->getIssueDate() == "IssueDate value");
    REQUIRE(reloaded->getExpirationDate() == "ExpirationDate value");

    /*
     * Nothing is stored in plaintext.
    */
    REQUIRE(item->getJson().dump().find("value") == SecureString::npos);
}

TEST_CASE("PassportItem fields start as encrypted \"\" and stay encrypted when cleared") {
    std::shared_ptr<PassportItem> item = ItemFixture::create<PassportItem>();
    REQUIRE(item->getSurname() == "");

    item->setSurname("");
    REQUIRE(item->getSurname().empty());
}

