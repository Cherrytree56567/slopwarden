#include <catch2/catch_test_macros.hpp>

#include "items/card_item/card_item.h"
#include "core/items/item_fixture.h"
#include "items/login_item/login_item.h"
#include "items/note_item/note_item.h"
#include "utils/timestamp/timestamp.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("GenericItem::createJson builds every type's section") {
    for (TypeSchema schema : Schema::all()) {
        CAPTURE(std::string_view(schema.m_section));
        SymmetricKey key;
        Json cipher = GenericItem::createJson(schema.m_type, ItemFixture::crypto(), ItemFixture::userKey(), key);

        REQUIRE(Schema::typeOf(cipher) == schema.m_type);
        REQUIRE(cipher[SecureString(schema.m_section)].is_object());
        REQUIRE(key.valid());
        REQUIRE(ItemFixture::crypto()->unwrapKey(cipher["key"].get<SecureString>(), ItemFixture::userKey()).m_enc
            == key.m_enc);
        for (TypeSchema other : Schema::all()) {
            if (other.m_type != schema.m_type) {
                REQUIRE(cipher[SecureString(other.m_section)].is_null());
            }
        }
    }

    SymmetricKey key;
    REQUIRE_THROWS_AS(GenericItem::createJson(CipherType::Generic, ItemFixture::crypto(), ItemFixture::userKey(), key),
        VaultError);
}

TEST_CASE("GenericItem shared properties") {
    std::shared_ptr<LoginItem> item = ItemFixture::create<LoginItem>();
    item->setName("GitHub").setNotes("work account").setFavorite(true).setReprompt(true).setFolder("f1");

    REQUIRE(item->getName() == "GitHub");
    REQUIRE(item->getNotes() == "work account");
    REQUIRE(item->getFavorite());
    REQUIRE(item->getReprompt());
    REQUIRE(item->getFolderId() == SecureString("f1"));
    REQUIRE(item->getCreationDate() > 0);

    item->removeFolder().setNotes("").setFavorite(false).setReprompt(false);
    REQUIRE_FALSE(item->getFolderId());
    REQUIRE(item->getJson()["notes"].is_null());
    REQUIRE_FALSE(item->getFavorite());
    REQUIRE_FALSE(item->getReprompt());

    item->setFolder("");
    REQUIRE_FALSE(item->getFolderId());
}

TEST_CASE("GenericItem custom fields") {
    std::shared_ptr<NoteItem> item = ItemFixture::create<NoteItem>();
    item->addField(CustomFieldType::Text, "pin", "1234")
        .addField(CustomFieldType::Hidden, "secret", "s3cr3t")
        .addField(CustomFieldType::Checkbox, "flag", "true")
        .addField(CustomFieldType::Linked, "link", "100");

    std::vector<GenericItem::CustomField> fields = item->getFields();
    REQUIRE(fields.size() == 4);
    REQUIRE(fields[1].m_type == CustomFieldType::Hidden);
    REQUIRE(fields[1].m_name == "secret");
    REQUIRE(fields[1].m_value == "s3cr3t");
    REQUIRE(fields[3].m_value == "100");
    REQUIRE(item->getJson()["fields"][3]["linkedId"] == 100);

    REQUIRE_THROWS_AS(item->addField(CustomFieldType::Linked, "bad", "abc"), VaultError);

    item->removeField("secret");
    REQUIRE(item->getFields().size() == 3);

    item->clearFields();
    REQUIRE(item->getFields().empty());
}

TEST_CASE("GenericItem status markers") {
    std::shared_ptr<NoteItem> item = ItemFixture::create<NoteItem>();
    REQUIRE(item->getDeletionDate() == 0);
    REQUIRE(item->getArchivedDate() == 0);
    REQUIRE(item->getRevisionDate() == 0);

    item->markDeleted(true);
    item->markArchived(true);
    item->touch();
    REQUIRE(item->getDeletionDate() > 0);
    REQUIRE(item->getArchivedDate() > 0);
    REQUIRE(item->getRevisionDate() > 0);

    item->markDeleted(false);
    item->markArchived(false);
    REQUIRE(item->getDeletionDate() == 0);
    REQUIRE(item->getArchivedDate() == 0);
}

TEST_CASE("GenericItem refuses another type's fields") {
    std::shared_ptr<CardItem> card = ItemFixture::create<CardItem>();
    std::shared_ptr<GenericItem> generic = card;

    /*
     * A LoginItem view over a card's JSON must not read or write login fields.
    */
    LoginItem wrong(nullptr, ItemFixture::crypto(), card->getJson(), card->getKey());
    REQUIRE_THROWS_AS(wrong.setPassword("x"), VaultError);
    REQUIRE_THROWS_AS(wrong.getPassword(), VaultError);
    REQUIRE_THROWS_AS(wrong.getWebsites(), VaultError);
    REQUIRE(generic->getType() == CipherType::Card);
}

TEST_CASE("GenericItem uses the user key for legacy items without a per-item key") {
    Json legacy = {
        { "id", "legacy" },
        { "type", 2 },
        { "key", nullptr },
        { "name", ItemFixture::crypto()->encryptText("Old note", ItemFixture::userKey()) },
        { "secureNote", { { "type", 0 } } }
    };
    REQUIRE(ItemFixture::reload<NoteItem>(legacy)->getName() == "Old note");
}

TEST_CASE("GenericItem tolerates missing or odd server fields") {
    Json sparse = { { "id", "x" }, { "type", 1 }, { "fields", { { { "name", 5 } }, nullptr } },
        { "attachments", { 1, 2 } } };
    LoginItem item(nullptr, ItemFixture::crypto(), sparse, ItemFixture::userKey());

    REQUIRE(item.getName().empty());
    REQUIRE(item.getFields().empty());
    REQUIRE(item.getAttachments().empty());
    REQUIRE(item.getWebsites().empty());
    REQUIRE(item.getPassword().empty());
    REQUIRE(item.getDeletionDate() == 0);
    REQUIRE_FALSE(item.getFolderId());

    REQUIRE_THROWS_AS(LoginItem(nullptr, ItemFixture::crypto(), Json("not an object"), ItemFixture::userKey()),
        VaultError);
}

TEST_CASE("GenericItem lists attachments with decrypted names") {
    std::shared_ptr<NoteItem> item = ItemFixture::create<NoteItem>();
    Json json = item->getJson();
    json["attachments"] = { { { "id", "a1" }, { "fileName", ItemFixture::crypto()->encryptText("doc.pdf",
        item->getKey()) }, { "size", "1024" } }, { { "id", "a2" }, { "size", 7 } } };
    item->replaceJson(json);

    std::vector<GenericItem::Attachment> attachments = item->getAttachments();
    REQUIRE(attachments.size() == 2);
    REQUIRE(attachments[0].m_id == "a1");
    REQUIRE(attachments[0].m_file_name == "doc.pdf");
    REQUIRE(attachments[0].m_size == "1024");
    REQUIRE(attachments[1].m_size == "7");
}

TEST_CASE("GenericItem actions need a vault") {
    std::shared_ptr<NoteItem> item = ItemFixture::create<NoteItem>();
    REQUIRE_THROWS_AS(item->commit(), VaultError);
    REQUIRE_THROWS_AS(item->remove(), VaultError);
    REQUIRE_THROWS_AS(item->bin(), VaultError);
    REQUIRE_THROWS_AS(item->restore(), VaultError);
    REQUIRE_THROWS_AS(item->archive(), VaultError);
    REQUIRE_THROWS_AS(item->unarchive(), VaultError);
    REQUIRE_THROWS_AS(item->duplicate(), VaultError);
    REQUIRE_THROWS_AS(item->addAttachment("x", std::span<const uint8_t>(), nullptr), VaultError);
    REQUIRE_THROWS_AS(item->removeAttachment("x"), VaultError);
    REQUIRE_THROWS_AS(item->downloadAttachment("x", "/tmp/x", nullptr), VaultError);
}

TEST_CASE("GenericItem rejects tampered fields") {
    std::shared_ptr<NoteItem> item = ItemFixture::create<NoteItem>();
    item->setName("secret");
    Json json = item->getJson();
    SecureString name = json["name"].get<SecureString>();
    name[5] = name[5] == 'A' ? 'B' : 'A';
    json["name"] = name;
    item->replaceJson(json);

    REQUIRE_THROWS_AS(item->getName(), CryptoError);
}

TEST_CASE("GenericItem duplicates every type") {
    std::shared_ptr<CardItem> card = ItemFixture::create<CardItem>();
    card->setName("Visa").setNumber("4111111111111111");

    std::shared_ptr<CardItem> copy = ItemFixture::reload<CardItem>(card->duplicateJson(ItemFixture::userKey()));
    REQUIRE(copy->getNumber() == "4111111111111111");
    REQUIRE(copy->getId() != card->getId());
    REQUIRE(copy->getJson()["revisionDate"].is_null());
    REQUIRE(copy->getJson()["attachments"].is_null());
}
