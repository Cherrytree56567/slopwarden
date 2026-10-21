#include <catch2/catch_test_macros.hpp>

#include "items/identity_item/identity_item.h"
#include "core/items/item_fixture.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("IdentityItem fields round trip through the encrypted JSON") {
    std::shared_ptr<IdentityItem> item = ItemFixture::create<IdentityItem>();
    REQUIRE(item->getType() == CipherType::Identity);

    item->setName("Example")
        .setTitle("Title value")
        .setFirstName("FirstName value")
        .setMiddleName("MiddleName value")
        .setLastName("LastName value")
        .setAddress1("Address1 value")
        .setAddress2("Address2 value")
        .setAddress3("Address3 value")
        .setCity("City value")
        .setState("State value")
        .setPostalCode("PostalCode value")
        .setCountry("Country value")
        .setCompany("Company value")
        .setEmail("Email value")
        .setPhone("Phone value")
        .setSsn("Ssn value")
        .setUsername("Username value")
        .setPassportNumber("PassportNumber value")
        .setLicenseNumber("LicenseNumber value");

    std::shared_ptr<IdentityItem> reloaded = ItemFixture::reload<IdentityItem>(item->getJson());
    REQUIRE(reloaded->getName() == "Example");
    REQUIRE(reloaded->getTitle() == "Title value");
    REQUIRE(reloaded->getFirstName() == "FirstName value");
    REQUIRE(reloaded->getMiddleName() == "MiddleName value");
    REQUIRE(reloaded->getLastName() == "LastName value");
    REQUIRE(reloaded->getAddress1() == "Address1 value");
    REQUIRE(reloaded->getAddress2() == "Address2 value");
    REQUIRE(reloaded->getAddress3() == "Address3 value");
    REQUIRE(reloaded->getCity() == "City value");
    REQUIRE(reloaded->getState() == "State value");
    REQUIRE(reloaded->getPostalCode() == "PostalCode value");
    REQUIRE(reloaded->getCountry() == "Country value");
    REQUIRE(reloaded->getCompany() == "Company value");
    REQUIRE(reloaded->getEmail() == "Email value");
    REQUIRE(reloaded->getPhone() == "Phone value");
    REQUIRE(reloaded->getSsn() == "Ssn value");
    REQUIRE(reloaded->getUsername() == "Username value");
    REQUIRE(reloaded->getPassportNumber() == "PassportNumber value");
    REQUIRE(reloaded->getLicenseNumber() == "LicenseNumber value");

    /*
     * Nothing is stored in plaintext.
    */
    REQUIRE(item->getJson().dump().find("value") == SecureString::npos);
}

TEST_CASE("IdentityItem fields start empty and clear to null") {
    std::shared_ptr<IdentityItem> item = ItemFixture::create<IdentityItem>();
    REQUIRE(item->getTitle().empty());

    item->setTitle("x").setTitle("");
    REQUIRE(item->getJson()["identity"]["title"].is_null());
    REQUIRE(item->getTitle().empty());
}

