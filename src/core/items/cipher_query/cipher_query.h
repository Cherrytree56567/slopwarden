#pragma once
#include <ctime>
#include <functional>
#include <optional>
#include <memory>
#include <string_view>
#include <vector>

#include "items/schema/schema.h"
#include "vault/crypto/crypto.h"
#include "vault/store/store.h"

namespace clientwarden {
    /**
     * @brief One query result row.
     */
    struct ItemSummary {
        SecureString m_id;
        CipherType m_type;
    };

    /**
     * @brief Composable filter over a snapshot of the vault:
     *
     *     vault->getOrchestrator()->query()
     *         .notInBin().ofType(CipherType::Login).nameContains("git").run();
     *
     * Filters run in one pass when run() is called, with the name filter (which needs
     * decryption) last.
     */
    class CipherQuery {
    public:
        /**
         * @brief Returns the key a cipher's own key is wrapped with: the user key for personal
         * items, the organisation key for organisation items, nullopt if unavailable.
         */
        using KeyResolver = std::function<std::optional<SymmetricKey>(const Json&)>;

        /**
         * @brief Creates a query over some records.
         *
         * @param records The ciphers to filter
         * @param crypto For decrypting names
         * @param user_key The account's user key
         */
        CipherQuery(
                std::vector<Record> records, std::shared_ptr<Crypto> crypto, SymmetricKey user_key);

        /**
         * @brief Creates a query that can also decrypt organisation item names.
         *
         * @param records The ciphers to filter
         * @param crypto For decrypting names
         * @param resolver Finds the wrapping key for each cipher
         */
        CipherQuery(
                std::vector<Record> records, std::shared_ptr<Crypto> crypto, KeyResolver resolver);

        /**
         * @brief Keeps one type.
         *
         * @param type The type to keep
         * @return This query, for chaining
         */
        CipherQuery& ofType(CipherType type);

        /**
         * @brief Keeps items in the bin.
         *
         * @return This query, for chaining
         */
        CipherQuery& inBin();

        /**
         * @brief Keeps items not in the bin.
         *
         * @return This query, for chaining
         */
        CipherQuery& notInBin();

        /**
         * @brief Keeps archived items.
         *
         * @return This query, for chaining
         */
        CipherQuery& archived();

        /**
         * @brief Keeps items that aren't archived.
         *
         * @return This query, for chaining
         */
        CipherQuery& notArchived();

        /**
         * @brief Keeps favourites.
         *
         * @return This query, for chaining
         */
        CipherQuery& favorites();

        /**
         * @brief Keeps items in a folder.
         *
         * @param folder_id The folder id
         * @return This query, for chaining
         */
        CipherQuery& inFolder(std::string_view folder_id);

        /**
         * @brief Keeps items owned by an organisation.
         *
         * @param organization_id The organisation id
         * @return This query, for chaining
         */
        CipherQuery& inOrganization(std::string_view organization_id);

        /**
         * @brief Keeps items in a collection.
         *
         * @param collection_id The collection id
         * @return This query, for chaining
         */
        CipherQuery& inCollection(std::string_view collection_id);

        /**
         * @brief Keeps items the user owns personally (not in any organisation).
         *
         * @return This query, for chaining
         */
        CipherQuery& personal();

        /**
         * @brief Keeps logins with at least one passkey.
         *
         * @return This query, for chaining
         */
        CipherQuery& withPasskey();

        /**
         * @brief Keeps items created within [start, end].
         *
         * @param start Earliest time
         * @param end Latest time
         * @return This query, for chaining
         */
        CipherQuery& createdBetween(std::time_t start, std::time_t end);

        /**
         * @brief Keeps items last changed within [start, end].
         *
         * @param start Earliest time
         * @param end Latest time
         * @return This query, for chaining
         */
        CipherQuery& revisedBetween(std::time_t start, std::time_t end);

        /**
         * @brief Keeps items binned within [start, end].
         *
         * @param start Earliest time
         * @param end Latest time
         * @return This query, for chaining
         */
        CipherQuery& deletedBetween(std::time_t start, std::time_t end);

        /**
         * @brief Keeps items whose decrypted name contains `text` (case-insensitive substring).
         *
         * @param text The search text
         * @return This query, for chaining
         */
        CipherQuery& nameContains(std::string_view text);

        /**
         * @brief Runs the query.
         *
         * @return Matching ids and types, in vault order
         */
        std::vector<ItemSummary> run() const;

        /**
         * @brief Runs the query, returning ids only.
         *
         * @return Matching ids
         */
        std::vector<SecureString> ids() const;

    private:
        CipherQuery& where_(std::function<bool(const Json&)> predicate);

        std::vector<Record> m_records_;
        std::shared_ptr<Crypto> m_crypto_;
        KeyResolver m_resolver_;
        std::vector<std::function<bool(const Json&)>> m_predicates_;
        SecureString m_needle_;
    };
}
