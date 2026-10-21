#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include "Model/Item.h"

using namespace ClientWarden;

namespace {
    const Crypto::SymmetricKey UserKey = Crypto::SymmetricKey::Generate();

    SecretString S(std::string_view s) {
        return SecretString(s.begin(), s.end());
    }
}

TEST_CASE("Every schema field round trips for every type") {
    for (const auto& schema : AllSchemas()) {
        CAPTURE(schema.section);
        Item item = Item::Create(schema.type, UserKey);

        REQUIRE(item.Type() == schema.type);
        REQUIRE(item.Json()[std::string(schema.section)].is_object());

        for (const auto& field : schema.fields) {
            CAPTURE(field.key);
            item.Set(field, std::string("value of ") + std::string(field.key));
        }

        /*
         * Reload from the encrypted JSON to prove nothing is kept in
         * plaintext on the side.
        */
        Item reloaded = Item::FromJson(item.Json(), UserKey);
        for (const auto& field : schema.fields) {
            REQUIRE(reloaded.Get(field) == S(std::string("value of ") + std::string(field.key)));
        }
    }
}

TEST_CASE("New items start with the schema's initial values") {
    Item ssh = Item::Create(CipherType::SSHKey, UserKey);
    REQUIRE(ssh.Get(Fields::SSHKey::PrivateKey) == " ");

    Item bank = Item::Create(CipherType::BankAccount, UserKey);
    REQUIRE(bank.Json()["bankAccount"]["iban"].is_string());
    REQUIRE(bank.Get(Fields::BankAccount::Iban).empty());

    Item card = Item::Create(CipherType::Card, UserKey);
    REQUIRE(card.Json()["card"]["number"].is_null());

    Item note = Item::Create(CipherType::Note, UserKey);
    REQUIRE(note.Json()["secureNote"]["type"] == 0);
}

TEST_CASE("Fields of another type are refused") {
    Item card = Item::Create(CipherType::Card, UserKey);
    REQUIRE_THROWS_AS(card.Set(Fields::Login::Password, "x"), VaultError);
    REQUIRE_THROWS_AS(card.Get(Fields::Login::Password), VaultError);
    REQUIRE_THROWS_AS(card.Uris(), VaultError);
}

TEST_CASE("Values are stored encrypted with the item key, not the user key") {
    Item login = Item::Create(CipherType::Login, UserKey);
    login.Set(Fields::Login::Password, "hunter2");

    std::string stored = login.Json()["login"]["password"];
    REQUIRE(Crypto::IsEncString(stored));
    REQUIRE(stored.find("hunter2") == std::string::npos);
    REQUIRE(Crypto::DecryptString(stored, login.Key()) == "hunter2");
    REQUIRE_THROWS_AS(Crypto::Decrypt(stored, UserKey), CryptoError);
}

TEST_CASE("Common properties") {
    Item item = Item::Create(CipherType::Login, UserKey);
    item.SetName("GitHub");
    item.SetNotes("work account");
    item.SetFavorite(true);
    item.SetReprompt(true);
    item.SetFolderId("f1");

    REQUIRE(item.Name() == "GitHub");
    REQUIRE(item.Notes() == "work account");
    REQUIRE(item.Favorite());
    REQUIRE(item.Reprompt());
    REQUIRE(item.FolderId() == "f1");

    item.SetFolderId(std::nullopt);
    item.SetNotes("");
    REQUIRE_FALSE(item.FolderId());
    REQUIRE(item.Json()["notes"].is_null());
}

TEST_CASE("Changing a password records history") {
    Item login = Item::Create(CipherType::Login, UserKey);
    login.Set(Fields::Login::Password, "first");
    REQUIRE(login.PasswordHistory().empty());

    login.Set(Fields::Login::Password, "first");    // unchanged: no entry
    REQUIRE(login.PasswordHistory().empty());

    for (int i = 0; i < 8; ++i) {
        login.Set(Fields::Login::Password, "pw" + std::to_string(i));
    }

    auto history = login.PasswordHistory();
    REQUIRE(history.size() == Item::MaxPasswordHistory);
    REQUIRE(history.front().password == "pw6");
    REQUIRE(login.Json()["login"]["passwordRevisionDate"].is_string());
}

TEST_CASE("Custom fields") {
    Item item = Item::Create(CipherType::Note, UserKey);
    item.AddCustomField(CustomFieldType::Text, "pin", "1234");
    item.AddCustomField(CustomFieldType::Hidden, "secret", "s3cr3t");
    item.AddCustomField(CustomFieldType::Checkbox, "flag", "true");
    item.AddCustomField(CustomFieldType::Linked, "link", "100");

    auto fields = item.CustomFields();
    REQUIRE(fields.size() == 4);
    REQUIRE(fields[1].type == CustomFieldType::Hidden);
    REQUIRE(fields[1].name == "secret");
    REQUIRE(fields[1].value == "s3cr3t");
    REQUIRE(fields[3].value == "100");
    REQUIRE(item.Json()["fields"][3]["linkedId"] == 100);

    REQUIRE_THROWS_AS(item.AddCustomField(CustomFieldType::Linked, "bad", "abc"), VaultError);

    item.RemoveCustomField("secret");
    REQUIRE(item.CustomFields().size() == 3);

    item.ClearCustomFields();
    REQUIRE(item.CustomFields().empty());
}

TEST_CASE("Login URIs carry checksums") {
    Item login = Item::Create(CipherType::Login, UserKey);
    login.AddUri("https://github.com");
    login.AddUri("https://gitlab.com");

    REQUIRE(login.Uris() == std::vector<SecretString> { "https://github.com", "https://gitlab.com" });

    const auto& uri = login.Json()["login"]["uris"][0];
    REQUIRE(Crypto::DecryptString(uri["uriChecksum"].get<std::string>(), login.Key()) ==
        Crypto::DecryptString(Crypto::UriChecksum("https://github.com", login.Key()), login.Key()));

    login.RemoveUri("https://github.com");
    REQUIRE(login.Uris() == std::vector<SecretString> { "https://gitlab.com" });
}

TEST_CASE("TOTP matches RFC 6238") {
    Item login = Item::Create(CipherType::Login, UserKey);

    /*
     * RFC 6238 appendix B, SHA-1 secret "12345678901234567890".
    */
    login.Set(Fields::Login::Totp, "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8");
    auto code = login.Totp(59);
    REQUIRE(code);
    REQUIRE(code->code == "94287082");
    REQUIRE(code->validUntil == 60);
    REQUIRE(code->period == 30);

    login.Set(Fields::Login::Totp, "gezd gnbv gy3t qojq gezd gnbv gy3t qojq");
    REQUIRE(login.Totp(59)->code == "287082");

    login.Set(Fields::Login::Totp, "not base32 at all!");
    REQUIRE_FALSE(login.Totp());
}

TEST_CASE("Duplicate re-encrypts under a fresh key") {
    Item original = Item::Create(CipherType::Login, UserKey);
    original.SetName("Original");
    original.Set(Fields::Login::Username, "alice");
    original.Set(Fields::Login::Password, "one");
    original.Set(Fields::Login::Password, "two");
    original.AddUri("https://example.com");
    original.AddCustomField(CustomFieldType::Hidden, "api", "key");

    Item copy = original.Duplicate(UserKey);

    REQUIRE(copy.Id() != original.Id());
    REQUIRE(copy.Key().enc != original.Key().enc);
    REQUIRE(copy.Name() == "Original");
    REQUIRE(copy.Get(Fields::Login::Username) == "alice");
    REQUIRE(copy.Get(Fields::Login::Password) == "two");
    REQUIRE(copy.Uris() == std::vector<SecretString> { "https://example.com" });
    REQUIRE(copy.CustomFields()[0].value == "key");
    REQUIRE(copy.PasswordHistory().empty());

    /*
     * Nothing in the copy may still be readable with the old item key.
    */
    REQUIRE_THROWS_AS(Crypto::Decrypt(copy.Json()["login"]["username"].get<std::string>(), original.Key()), CryptoError);

    Item reloaded = Item::FromJson(copy.Json(), UserKey);
    REQUIRE(reloaded.Get(Fields::Login::Username) == "alice");
}

TEST_CASE("Legacy items without a per-item key use the user key") {
    nlohmann::json legacy = {
        { "id", "legacy" },
        { "type", 2 },
        { "key", nullptr },
        { "name", Crypto::Encrypt("Old note", UserKey) },
        { "secureNote", { { "type", 0 } } }
    };
    REQUIRE(Item::FromJson(legacy, UserKey).Name() == "Old note");
}

TEST_CASE("Missing or odd server fields don't crash") {
    nlohmann::json sparse = { { "id", "x" }, { "type", 1 }, { "fields", { { { "name", 5 } }, nullptr } }, { "attachments", { 1, 2 } } };
    Item item = Item::FromJson(sparse, UserKey);

    REQUIRE(item.Name().empty());
    REQUIRE(item.CustomFields().empty());
    REQUIRE(item.Attachments().empty());
    REQUIRE(item.Uris().empty());
    REQUIRE(item.Get(Fields::Login::Password).empty());
    REQUIRE(item.Deleted() == 0);

    REQUIRE_THROWS_AS(Item::FromJson({ { "type", 1 } }, UserKey), VaultError);
}

TEST_CASE("Legacy data blob mirrors the encrypted fields") {
    Item login = Item::Create(CipherType::Login, UserKey);
    login.SetName("Site");
    login.Set(Fields::Login::Password, "pw");
    login.AddUri("https://example.com");
    login.AddCustomField(CustomFieldType::Text, "k", "v");

    nlohmann::json wire = login.ToWire(true);
    nlohmann::json data = nlohmann::json::parse(wire["data"].get<std::string>());

    REQUIRE(data["Name"] == login.Json()["name"]);
    REQUIRE(data["Password"] == login.Json()["login"]["password"]);
    REQUIRE(data["Uris"][0]["Uri"] == login.Json()["login"]["uris"][0]["uri"]);

    /*
     * Regression: the old code renamed type/value to Type/Value and then
     * erased the new keys, silently dropping them.
    */
    REQUIRE(data["Fields"][0]["Type"] == 0);
    REQUIRE(data["Fields"][0]["Value"] == login.Json()["fields"][0]["value"]);

    REQUIRE_FALSE(login.ToWire(false).contains("data"));

    Item identity = Item::Create(CipherType::Identity, UserKey);
    identity.Set(Fields::Identity::SSN, "123");
    REQUIRE(nlohmann::json::parse(identity.ToWire(true)["data"].get<std::string>()).contains("SSN"));
}

TEST_CASE("Wire format strips local-only markers") {
    Item item = Item::Create(CipherType::Note, UserKey);
    nlohmann::json j = item.Json();
    j["createdOffline"] = true;
    REQUIRE_FALSE(Item::WireFormat(j, false).contains("createdOffline"));
}

TEST_CASE("Attachments are listed with decrypted names") {
    Item item = Item::Create(CipherType::Note, UserKey);
    nlohmann::json j = item.Json();
    j["attachments"] = { { { "id", "a1" }, { "fileName", Crypto::Encrypt("doc.pdf", item.Key()) }, { "size", "1024" } } };
    item.Replace(j);

    auto attachments = item.Attachments();
    REQUIRE(attachments.size() == 1);
    REQUIRE(attachments[0].fileName == "doc.pdf");
    REQUIRE(attachments[0].size == "1024");
    REQUIRE(item.FindAttachment("a1"));
    REQUIRE_FALSE(item.FindAttachment("nope"));
}
