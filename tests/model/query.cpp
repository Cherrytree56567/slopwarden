#include <catch2/catch_test_macros.hpp>
#include "Model/Item.h"
#include "Model/ItemQuery.h"
#include "Util/Util.h"

using namespace ClientWarden;

namespace {
    const Crypto::SymmetricKey UserKey = Crypto::SymmetricKey::Generate();

    Record Make(CipherType type, std::string_view name, std::function<void(nlohmann::json&)> tweak = nullptr) {
        Item item = Item::Create(type, UserKey);
        item.SetName(name);
        nlohmann::json j = item.Json();
        if (tweak) {
            tweak(j);
        }
        return std::make_shared<const nlohmann::json>(std::move(j));
    }

    std::vector<std::string> Names(const ItemQuery& q, const std::vector<Record>& records) {
        std::vector<std::string> out;
        for (const auto& id : q.Ids()) {
            for (const auto& r : records) {
                if ((*r)["id"] == id) {
                    SecretString n = Item::FromJson(*r, UserKey).Name();
                    out.emplace_back(n.begin(), n.end());
                }
            }
        }
        return out;
    }
}

TEST_CASE("Query filters") {
    std::vector<Record> records = {
        Make(CipherType::Login, "GitHub"),
        Make(CipherType::Login, "GitLab", [](auto& j) { j["favorite"] = true; j["folderId"] = "work"; }),
        Make(CipherType::Card, "Visa"),
        Make(CipherType::Note, "Binned", [](auto& j) { j["deletedDate"] = NowTime(); }),
        Make(CipherType::Note, "Archived", [](auto& j) { j["archivedDate"] = NowTime(); }),
        Make(CipherType::Login, "Passkey", [](auto& j) { j["login"]["fido2Credentials"] = { { { "creationDate", NowTime() } } }; }),
    };

    auto q = [&] { return ItemQuery(records, UserKey); };

    REQUIRE(Names(q().OfType(CipherType::Login).NotInBin(), records) == std::vector<std::string> { "GitHub", "GitLab", "Passkey" });
    REQUIRE(Names(q().InBin(), records) == std::vector<std::string> { "Binned" });
    REQUIRE(Names(q().Archived(), records) == std::vector<std::string> { "Archived" });
    REQUIRE(q().NotInBin().NotArchived().Ids().size() == 4);
    REQUIRE(Names(q().Favorites(), records) == std::vector<std::string> { "GitLab" });
    REQUIRE(Names(q().InFolder("work"), records) == std::vector<std::string> { "GitLab" });
    REQUIRE(Names(q().WithPasskey(), records) == std::vector<std::string> { "Passkey" });
}

TEST_CASE("Name search is a case-insensitive substring match") {
    std::vector<Record> records = { Make(CipherType::Login, "GitHub"), Make(CipherType::Login, "C++ Docs"), Make(CipherType::Card, "Visa") };

    REQUIRE(Names(ItemQuery(records, UserKey).NameContains("git"), records) == std::vector<std::string> { "GitHub" });

    /*
     * Regression: the old regex search threw on text like this.
    */
    REQUIRE(Names(ItemQuery(records, UserKey).NameContains("c++ ("), records).empty());
    REQUIRE(Names(ItemQuery(records, UserKey).NameContains("C++"), records) == std::vector<std::string> { "C++ Docs" });
}

TEST_CASE("Query summaries report types") {
    std::vector<Record> records = { Make(CipherType::Card, "Visa") };
    auto result = ItemQuery(records, UserKey).Run();
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].type == CipherType::Card);
}

TEST_CASE("Records that can't be decrypted are skipped by name search") {
    Crypto::SymmetricKey other = Crypto::SymmetricKey::Generate();
    Item foreign = Item::Create(CipherType::Login, other);
    foreign.SetName("GitHub");
    std::vector<Record> records = { std::make_shared<const nlohmann::json>(foreign.Json()) };

    REQUIRE(ItemQuery(records, UserKey).NameContains("git").Ids().empty());
}
