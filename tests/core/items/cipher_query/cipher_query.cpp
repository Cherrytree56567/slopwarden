#include <catch2/catch_test_macros.hpp>
#include <functional>

#include "items/cipher_query/cipher_query.h"
#include "items/generic_item/generic_item.h"
#include "core/items/item_fixture.h"
#include "utils/timestamp/timestamp.h"

using namespace clientwarden;
using clientwarden::testing::ItemFixture;

namespace {
    /**
     * @brief Builds a stored record with a name, optionally tweaked.
     */
    Record make(CipherType type, std::string_view name, std::function<void(Json&)> tweak = nullptr) {
        SymmetricKey key;
        Json cipher = GenericItem::createJson(type, ItemFixture::crypto(), ItemFixture::userKey(), key);
        cipher["name"] = ItemFixture::crypto()->encryptText(name, key);
        if (tweak) {
            tweak(cipher);
        }
        return std::make_shared<const Json>(std::move(cipher));
    }

    /**
     * @brief The decrypted names of a query's results, in order.
     */
    std::vector<SecureString> names(const CipherQuery& query, const std::vector<Record>& records) {
        std::vector<SecureString> out;
        for (const SecureString& id : query.ids()) {
            for (const Record& record : records) {
                if (record->at("id") == id) {
                    GenericItem item(nullptr, ItemFixture::crypto(), *record, ItemFixture::crypto()->unwrapKey(
                        record->at("key").get<SecureString>(), ItemFixture::userKey()));
                    out.push_back(item.getName());
                }
            }
        }
        return out;
    }

    /**
     * @brief A fresh query over some records.
     */
    CipherQuery query(const std::vector<Record>& records) {
        return CipherQuery(records, ItemFixture::crypto(), ItemFixture::userKey());
    }
}

TEST_CASE("CipherQuery filters") {
    std::vector<Record> records = {
        make(CipherType::Login, "GitHub"),
        make(CipherType::Login, "GitLab", [](Json& j) { j["favorite"] = true; j["folderId"] = "work"; }),
        make(CipherType::Card, "Visa"),
        make(CipherType::Note, "Binned", [](Json& j) { j["deletedDate"] = timestamp::now(); }),
        make(CipherType::Note, "Archived", [](Json& j) { j["archivedDate"] = timestamp::now(); }),
        make(CipherType::Login, "Passkey", [](Json& j) {
            j["login"]["fido2Credentials"] = { { { "creationDate", timestamp::now() } } };
        }),
    };

    REQUIRE(names(query(records).ofType(CipherType::Login).notInBin(), records)
        == std::vector<SecureString> { "GitHub", "GitLab", "Passkey" });
    REQUIRE(names(query(records).inBin(), records) == std::vector<SecureString> { "Binned" });
    REQUIRE(names(query(records).archived(), records) == std::vector<SecureString> { "Archived" });
    REQUIRE(query(records).notInBin().notArchived().ids().size() == 4);
    REQUIRE(names(query(records).favorites(), records) == std::vector<SecureString> { "GitLab" });
    REQUIRE(names(query(records).inFolder("work"), records) == std::vector<SecureString> { "GitLab" });
    REQUIRE(names(query(records).withPasskey(), records) == std::vector<SecureString> { "Passkey" });
}

TEST_CASE("CipherQuery date ranges") {
    std::vector<Record> records = {
        make(CipherType::Note, "Old", [](Json& j) {
            j["creationDate"] = timestamp::format(1000);
            j["revisionDate"] = timestamp::format(2000);
            j["deletedDate"] = timestamp::format(3000);
        }),
        make(CipherType::Note, "New"),
    };

    REQUIRE(names(query(records).createdBetween(0, 1500), records) == std::vector<SecureString> { "Old" });
    REQUIRE(names(query(records).revisedBetween(1500, 2500), records) == std::vector<SecureString> { "Old" });
    REQUIRE(names(query(records).deletedBetween(0, 5000), records) == std::vector<SecureString> { "Old" });
}

TEST_CASE("CipherQuery name search is a case-insensitive substring match") {
    std::vector<Record> records = { make(CipherType::Login, "GitHub"), make(CipherType::Login, "C++ Docs"),
        make(CipherType::Card, "Visa") };

    REQUIRE(names(query(records).nameContains("git"), records) == std::vector<SecureString> { "GitHub" });

    /*
     * Regression: the original regex search threw on text like this.
    */
    REQUIRE(names(query(records).nameContains("c++ ("), records).empty());
    REQUIRE(names(query(records).nameContains("C++"), records) == std::vector<SecureString> { "C++ Docs" });
}

TEST_CASE("CipherQuery summaries report types") {
    std::vector<Record> records = { make(CipherType::Card, "Visa") };
    std::vector<ItemSummary> result = query(records).run();
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].m_type == CipherType::Card);
}

TEST_CASE("CipherQuery skips records it can't decrypt or identify") {
    SymmetricKey other_user = SymmetricKey::generate();
    SymmetricKey key;
    Json foreign = GenericItem::createJson(CipherType::Login, ItemFixture::crypto(), other_user, key);
    foreign["name"] = ItemFixture::crypto()->encryptText("GitHub", key);

    std::vector<Record> records = { std::make_shared<const Json>(foreign),
        std::make_shared<const Json>(Json { { "type", 1 } }) };
    REQUIRE(query(records).nameContains("git").ids().empty());
    REQUIRE(query(records).ids().size() == 1);
}
