#include "cipher_query.h"

#include <algorithm>

#include "utils/timestamp/timestamp.h"

namespace clientwarden {
    namespace {
        /**
         * @brief Reads a timestamp member.
         *
         * @param record The cipher
         * @param key The member name
         * @return Seconds since the epoch, or 0
         */
        std::time_t timeOf_(const Json& record, std::string_view key) {
            const Json& value = at(record, key);
            return value.is_string() ? timestamp::parse(value.get_ref<const SecureString&>()) : 0;
        }

        /**
         * @brief Whether a member is present and not null.
         *
         * @param record The cipher
         * @param key The member name
         * @return True if set
         */
        bool hasValue_(const Json& record, std::string_view key) {
            return !at(record, key).is_null();
        }
    }

    CipherQuery::CipherQuery(
            std::vector<Record> records, std::shared_ptr<Crypto> crypto, SymmetricKey user_key)
        : m_records_(std::move(records)), m_crypto_(std::move(crypto)),
          m_user_key_(std::move(user_key)) {}

    CipherQuery& CipherQuery::where_(std::function<bool(const Json&)> predicate) {
        m_predicates_.push_back(std::move(predicate));
        return *this;
    }

    CipherQuery& CipherQuery::ofType(CipherType type) {
        return where_([type](const Json& record) { return Schema::typeOf(record) == type; });
    }

    CipherQuery& CipherQuery::inBin() {
        return where_([](const Json& record) { return hasValue_(record, "deletedDate"); });
    }

    CipherQuery& CipherQuery::notInBin() {
        return where_([](const Json& record) { return !hasValue_(record, "deletedDate"); });
    }

    CipherQuery& CipherQuery::archived() {
        return where_([](const Json& record) { return hasValue_(record, "archivedDate"); });
    }

    CipherQuery& CipherQuery::notArchived() {
        return where_([](const Json& record) { return !hasValue_(record, "archivedDate"); });
    }

    CipherQuery& CipherQuery::favorites() {
        return where_([](const Json& record) {
            const Json& favorite = at(record, "favorite");
            return favorite.is_boolean() && favorite.get<bool>();
        });
    }

    CipherQuery& CipherQuery::inFolder(std::string_view folder_id) {
        SecureString wanted(folder_id);
        return where_([wanted](const Json& record) {
            const Json& folder = at(record, "folderId");
            return folder.is_string() && folder.get_ref<const SecureString&>() == wanted;
        });
    }

    CipherQuery& CipherQuery::withPasskey() {
        return where_([](const Json& record) {
            if (Schema::typeOf(record) != CipherType::Login) {
                return false;
            }
            const Json& credentials = at(at(record, "login"), "fido2Credentials");
            return credentials.is_array() && !credentials.empty();
        });
    }

    CipherQuery& CipherQuery::createdBetween(std::time_t start, std::time_t end) {
        return where_([start, end](const Json& record) {
            std::time_t time = timeOf_(record, "creationDate");
            return time >= start && time <= end;
        });
    }

    CipherQuery& CipherQuery::revisedBetween(std::time_t start, std::time_t end) {
        return where_([start, end](const Json& record) {
            std::time_t time = timeOf_(record, "revisionDate");
            return time >= start && time <= end;
        });
    }

    CipherQuery& CipherQuery::deletedBetween(std::time_t start, std::time_t end) {
        return where_([start, end](const Json& record) {
            std::time_t time = timeOf_(record, "deletedDate");
            return time != 0 && time >= start && time <= end;
        });
    }

    CipherQuery& CipherQuery::nameContains(std::string_view text) {
        m_needle_ = toLower(text);
        return *this;
    }

    std::vector<ItemSummary> CipherQuery::run() const {
        std::vector<ItemSummary> out;

        for (const Record& record : m_records_) {
            const Json& cipher = *record;
            const Json& id = at(cipher, "id");
            if (!id.is_string()) {
                continue;
            }

            bool keep = std::all_of(m_predicates_.begin(), m_predicates_.end(),
                    [&cipher](const std::function<bool(const Json&)>& predicate) {
                        return predicate(cipher);
                    });
            if (!keep) {
                continue;
            }

            if (!m_needle_.empty()) {
                const Json& name = at(cipher, "name");
                if (!name.is_string()) {
                    continue;
                }
                try {
                    const Json& key = at(cipher, "key");
                    SymmetricKey item_key =
                            key.is_string()
                                    ? m_crypto_->unwrapKey(
                                              key.get_ref<const SecureString&>(), m_user_key_)
                                    : m_user_key_;
                    SecureString plain = toLower(
                            m_crypto_->decryptText(name.get_ref<const SecureString&>(), item_key));
                    if (plain.find(m_needle_) == SecureString::npos) {
                        continue;
                    }
                } catch (const std::exception&) {
                    continue; // undecryptable record (e.g. an organisation cipher)
                }
            }

            out.push_back(ItemSummary { id.get<SecureString>(), Schema::typeOf(cipher) });
        }
        return out;
    }

    std::vector<SecureString> CipherQuery::ids() const {
        std::vector<SecureString> out;
        for (ItemSummary& summary : run()) {
            out.push_back(std::move(summary.m_id));
        }
        return out;
    }
}
