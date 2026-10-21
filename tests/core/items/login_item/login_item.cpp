#include <catch2/catch_test_macros.hpp>

#include "core/items/item_fixture.h"
#include "items/login_item/login_item.h"
#include "utils/timestamp/timestamp.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("LoginItem username and password round trip") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();
    login->setName("GitHub").setUsername("octocat").setPassword("hunter2");

    std::shared_ptr<LoginItem> reloaded = ItemFixture::reload<LoginItem>(login->getJson());
    REQUIRE(reloaded->getUsername() == "octocat");
    REQUIRE(reloaded->getPassword() == "hunter2");
}

TEST_CASE("LoginItem values are encrypted with the item key, not the user key") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();
    login->setPassword("hunter2");

    SecureString stored = login->getJson()["login"]["password"].get<SecureString>();
    REQUIRE(ItemFixture::crypto()->isEncString(stored));
    REQUIRE(stored.find("hunter2") == SecureString::npos);
    REQUIRE(ItemFixture::crypto()->decryptText(stored, login->getKey()) == "hunter2");
    REQUIRE_THROWS_AS(ItemFixture::crypto()->decrypt(stored, ItemFixture::userKey()), CryptoError);
}

TEST_CASE("LoginItem records password history") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();
    login->setPassword("first");
    REQUIRE(login->getPasswordHistory().empty());

    login->setPassword("first");    // unchanged: no entry
    REQUIRE(login->getPasswordHistory().empty());

    for (int i = 0; i < 8; ++i) {
        login->setPassword(SecureString("pw") + toSecureString(i));
    }

    std::vector<PasswordHistoryEntry> history = login->getPasswordHistory();
    REQUIRE(history.size() == 5);
    REQUIRE(history.front().m_password == "pw6");
    REQUIRE(history.front().m_last_used > 0);
    REQUIRE(login->getJson()["login"]["passwordRevisionDate"].is_string());
}

TEST_CASE("LoginItem websites carry checksums") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();
    login->addWebsite("https://github.com").addWebsite("https://gitlab.com");

    REQUIRE(login->getWebsites() == std::vector<SecureString> { "https://github.com", "https://gitlab.com" });

    SecureString checksum = login->getJson()["login"]["uris"][0]["uriChecksum"].get<SecureString>();
    SecureString expected = ItemFixture::crypto()->uriChecksum("https://github.com", login->getKey());
    REQUIRE(ItemFixture::crypto()->decryptText(checksum, login->getKey())
        == ItemFixture::crypto()->decryptText(expected, login->getKey()));

    login->removeWebsite("https://github.com");
    REQUIRE(login->getWebsites() == std::vector<SecureString> { "https://gitlab.com" });
}

TEST_CASE("LoginItem TOTP matches RFC 6238") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();

    /*
     * RFC 6238 appendix B, SHA-1 secret "12345678901234567890".
    */
    login->setTotp("otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8");
    std::optional<TotpCode> code = login->getTotp(59);
    REQUIRE(code);
    REQUIRE(code->m_code == "94287082");
    REQUIRE(code->m_valid_until == 60);
    REQUIRE(code->m_period == 30);

    login->setTotp("gezd gnbv gy3t qojq gezd gnbv gy3t qojq");
    REQUIRE(login->getTotp(59)->m_code == "287082");
    REQUIRE(login->getTotpSecret() == "gezd gnbv gy3t qojq gezd gnbv gy3t qojq");

    login->setTotp("not base32 at all!");
    REQUIRE_FALSE(login->getTotp(59));

    login->setTotp("");
    REQUIRE_FALSE(login->getTotp(59));
}

TEST_CASE("LoginItem TOTP honours algorithm and period") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();

    /*
     * RFC 6238 appendix B, SHA-256 secret "12345678901234567890123456789012".
    */
    login->setTotp("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
        "&algorithm=SHA256&digits=8&period=30");
    REQUIRE(login->getTotp(59)->m_code == "46119246");

    login->setTotp("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=60");
    REQUIRE(login->getTotp(59)->m_valid_until == 60);
    REQUIRE(login->getTotp(59)->m_period == 60);
}

TEST_CASE("LoginItem lists passkey creation dates") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();
    Json json = login->getJson();
    json["login"]["fido2Credentials"] = { { { "creationDate", timestamp::format(1787381631) } } };
    login->replaceJson(json);

    REQUIRE(login->getPasskeyCreationDates() == std::vector<std::time_t> { 1787381631 });
}

TEST_CASE("LoginItem duplicates under a fresh key") {
    std::shared_ptr<LoginItem> original = ItemFixture::create<LoginItem>();
    original->setName("Original").setUsername("alice").setPassword("one");
    original->setPassword("two");
    original->addWebsite("https://example.com").addField(CustomFieldType::Hidden, "api", "key");

    Json copy_json = original->duplicateJson(ItemFixture::userKey());
    std::shared_ptr<LoginItem> copy = ItemFixture::reload<LoginItem>(copy_json);

    REQUIRE(copy->getId() != original->getId());
    REQUIRE(copy->getKey().m_enc != original->getKey().m_enc);
    REQUIRE(copy->getName() == "Original");
    REQUIRE(copy->getUsername() == "alice");
    REQUIRE(copy->getPassword() == "two");
    REQUIRE(copy->getWebsites() == std::vector<SecureString> { "https://example.com" });
    REQUIRE(copy->getFields()[0].m_value == "key");
    REQUIRE(copy->getPasswordHistory().empty());

    /*
     * Nothing in the copy may still be readable with the old item key.
    */
    REQUIRE_THROWS_AS(ItemFixture::crypto()->decrypt(copy_json["login"]["username"].get<SecureString>(),
        original->getKey()), CryptoError);
}

TEST_CASE("LoginItem duplicates drop passkeys") {
    std::shared_ptr<LoginItem> login = ItemFixture::create<LoginItem>();
    Json json = login->getJson();
    json["login"]["fido2Credentials"] = { { { "creationDate", timestamp::now() } } };
    login->replaceJson(json);

    REQUIRE(login->duplicateJson(ItemFixture::userKey())["login"]["fido2Credentials"].is_null());
}
