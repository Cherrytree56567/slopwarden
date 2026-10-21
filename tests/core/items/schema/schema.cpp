#include <catch2/catch_test_macros.hpp>

#include "items/card_item/card_item.h"
#include "items/identity_item/identity_item.h"
#include "core/items/item_fixture.h"
#include "items/login_item/login_item.h"
#include "items/note_item/note_item.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("Schema covers every concrete type") {
    REQUIRE(Schema::all().size() == 8);
    REQUIRE_FALSE(Schema::forType(CipherType::Generic));
    REQUIRE(Schema::forType(CipherType::Login)->m_section == "login");
    REQUIRE(Schema::forType(CipherType::SshKey)->m_initial_value == std::string_view(" "));
    REQUIRE(Schema::forType(CipherType::Passport)->m_fields.size() == 13);
}

TEST_CASE("Schema legacy keys are PascalCase") {
    REQUIRE(Schema::legacyKey("cardholderName") == "CardholderName");
    REQUIRE(Schema::legacyKey("ssn") == "SSN");
    REQUIRE(Schema::legacyKey("") == "");
}

TEST_CASE("Schema::typeOf reads the cipher type") {
    REQUIRE(Schema::typeOf(Json { { "type", 3 } }) == CipherType::Card);
    REQUIRE(Schema::typeOf(Json { { "type", "3" } }) == CipherType::Generic);
    REQUIRE(Schema::typeOf(Json::array()) == CipherType::Generic);
}

TEST_CASE("Schema legacy data blob mirrors the encrypted fields") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();
    login->setName("Site").setPassword("pw").addWebsite("https://example.com")
        .addField(CustomFieldType::Text, "k", "v").addField(CustomFieldType::Linked, "l", "5");
    login->setPassword("pw2");

    Json stored = login->getJson();
    Json wire = Schema::wireFormat(stored, true, "");
    Json data = Json::parse(wire["data"].get<SecureString>());

    REQUIRE(data["Name"] == stored["name"]);
    REQUIRE(data["Password"] == stored["login"]["password"]);
    REQUIRE(data["Uris"][0]["Uri"] == stored["login"]["uris"][0]["uri"]);
    REQUIRE(data["PasswordHistory"][0]["Password"] == stored["passwordHistory"][0]["password"]);

    /*
     * Regression: the original code renamed type/value to Type/Value and then erased the new
     * keys, silently dropping them.
    */
    REQUIRE(data["Fields"][0]["Type"] == 0);
    REQUIRE(data["Fields"][0]["Value"] == stored["fields"][0]["value"]);
    REQUIRE(data["Fields"][1]["LinkedId"] == 5);

    REQUIRE_FALSE(Schema::wireFormat(stored, false, "").contains("data"));

    std::shared_ptr<IdentityItem> identity = ItemFixture::create<IdentityItem>();
    identity->setSsn("123");
    REQUIRE(Json::parse(Schema::wireFormat(identity->getJson(), true, "")["data"].get<SecureString>()).contains("SSN"));

    std::shared_ptr<NoteItem> note = ItemFixture::create<NoteItem>();
    REQUIRE(Json::parse(Schema::wireFormat(note->getJson(), true, "")["data"].get<SecureString>())["Type"] == 0);
}

TEST_CASE("Schema wire format strips local-only markers") {
    std::shared_ptr<CardItem> card = ItemFixture::create<CardItem>();
    Json json = card->getJson();
    json["createdOffline"] = true;
    REQUIRE_FALSE(Schema::wireFormat(json, false, "").contains("createdOffline"));
}

TEST_CASE("Fields are found by key and secrets are flagged") {
    REQUIRE(Schema::fieldFor(CipherType::Card, "number") == fields::card::c_number);
    REQUIRE_FALSE(Schema::fieldFor(CipherType::Card, "username"));
    REQUIRE_FALSE(Schema::fieldFor(CipherType::Generic, "number"));

    REQUIRE(Schema::isSecret(fields::login::c_password));
    REQUIRE(Schema::isSecret(fields::card::c_code));
    REQUIRE_FALSE(Schema::isSecret(fields::login::c_username));
    REQUIRE_FALSE(Schema::isSecret(fields::card::c_brand));
}
