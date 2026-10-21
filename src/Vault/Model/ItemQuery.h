#pragma once
#include <ctime>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "Crypto/Crypto.h"
#include "Store/VaultStore.h"

namespace ClientWarden {
    struct ItemSummary {
        std::string id;
        CipherType type;
    };

    /*
     * Composable filter over a snapshot of the vault:
     *
     *   vault.Query().NotInBin().OfType(CipherType::Login).NameContains("git").Run();
     *
     * Filters are applied in one pass when Run() is called, with the
     * name filter (which needs decryption) evaluated last.
    */
    class ItemQuery {
    public:
        ItemQuery(std::vector<Record> records, Crypto::SymmetricKey userKey);

        ItemQuery& OfType(CipherType type);
        ItemQuery& InBin();
        ItemQuery& NotInBin();
        ItemQuery& Archived();
        ItemQuery& NotArchived();
        ItemQuery& Favorites();
        ItemQuery& InFolder(const std::string& folderId);
        ItemQuery& WithPasskey();
        ItemQuery& CreatedBetween(std::time_t start, std::time_t end);
        ItemQuery& RevisedBetween(std::time_t start, std::time_t end);
        ItemQuery& DeletedBetween(std::time_t start, std::time_t end);

        /*
         * Case-insensitive substring match on the decrypted name.
        */
        ItemQuery& NameContains(std::string_view text);

        std::vector<ItemSummary> Run() const;
        std::vector<std::string> Ids() const;

    private:
        using Predicate = std::function<bool(const nlohmann::json&)>;
        ItemQuery& Where(Predicate predicate);

        std::vector<Record> records;
        Crypto::SymmetricKey userKey;
        std::vector<Predicate> predicates;
        std::string needle;
    };
}
