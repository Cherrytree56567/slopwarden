#include <catch2/catch_test_macros.hpp>

#include "core/items/item_fixture.h"
#include "items/note_item/note_item.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

TEST_CASE("NoteItem starts as a generic secure note") {
    std::shared_ptr<NoteItem> note = ItemFixture::create<NoteItem>();
    REQUIRE(note->getType() == CipherType::Note);
    REQUIRE(note->getJson()["secureNote"]["type"] == 0);
}

TEST_CASE("NoteItem keeps its text in the encrypted notes") {
    std::shared_ptr<NoteItem> note = ItemFixture::create<NoteItem>();
    note->setName("Diary").setNotes("dear diary");

    std::shared_ptr<NoteItem> reloaded = ItemFixture::reload<NoteItem>(note->getJson());
    REQUIRE(reloaded->getName() == "Diary");
    REQUIRE(reloaded->getNotes() == "dear diary");
}
