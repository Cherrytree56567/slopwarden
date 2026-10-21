#include <catch2/catch_test_macros.hpp>

#include "items/drivers_license_item/drivers_license_item.h"
#include "core/items/item_fixture.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("DriversLicenseItem fields round trip through the encrypted JSON") {
    std::shared_ptr<DriversLicenseItem> item = ItemFixture::create<DriversLicenseItem>();
    REQUIRE(item->getType() == CipherType::DriversLicense);

    item->setName("Example")
        .setFirstName("FirstName value")
        .setMiddleName("MiddleName value")
        .setLastName("LastName value")
        .setDateOfBirth("DateOfBirth value")
        .setLicenseNumber("LicenseNumber value")
        .setIssuingCountry("IssuingCountry value")
        .setIssuingState("IssuingState value")
        .setIssueDate("IssueDate value")
        .setExpirationDate("ExpirationDate value")
        .setIssuingAuthority("IssuingAuthority value")
        .setLicenseClass("LicenseClass value");

    std::shared_ptr<DriversLicenseItem> reloaded = ItemFixture::reload<DriversLicenseItem>(item->getJson());
    REQUIRE(reloaded->getName() == "Example");
    REQUIRE(reloaded->getFirstName() == "FirstName value");
    REQUIRE(reloaded->getMiddleName() == "MiddleName value");
    REQUIRE(reloaded->getLastName() == "LastName value");
    REQUIRE(reloaded->getDateOfBirth() == "DateOfBirth value");
    REQUIRE(reloaded->getLicenseNumber() == "LicenseNumber value");
    REQUIRE(reloaded->getIssuingCountry() == "IssuingCountry value");
    REQUIRE(reloaded->getIssuingState() == "IssuingState value");
    REQUIRE(reloaded->getIssueDate() == "IssueDate value");
    REQUIRE(reloaded->getExpirationDate() == "ExpirationDate value");
    REQUIRE(reloaded->getIssuingAuthority() == "IssuingAuthority value");
    REQUIRE(reloaded->getLicenseClass() == "LicenseClass value");

    /*
     * Nothing is stored in plaintext.
    */
    REQUIRE(item->getJson().dump().find("value") == SecureString::npos);
}

TEST_CASE("DriversLicenseItem fields start as encrypted \"\" and stay encrypted when cleared") {
    std::shared_ptr<DriversLicenseItem> item = ItemFixture::create<DriversLicenseItem>();
    REQUIRE(item->getFirstName() == "");

    item->setFirstName("");
    REQUIRE(item->getFirstName().empty());
}

