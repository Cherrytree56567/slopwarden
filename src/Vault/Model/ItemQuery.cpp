#include "ItemQuery.h"

#include <algorithm>

#include "Util/Util.h"

namespace ClientWarden {
    namespace {
        std::time_t TimeOf(const nlohmann::json& r, const char* key) {
            auto it = r.find(key);
            return it != r.end() && it->is_string() ? ParseTime(it->get<std::string>()) : 0;
        }

        bool HasValue(const nlohmann::json& r, const char* key) {
            auto it = r.find(key);
            return it != r.end() && !it->is_null();
        }

        int TypeOf(const nlohmann::json& r) {
            auto it = r.find("type");
            return it != r.end() && it->is_number_integer() ? it->get<int>() : -1;
        }
    }

    ItemQuery::ItemQuery(std::vector<Record> records, Crypto::SymmetricKey userKey)
        : records(std::move(records)), userKey(std::move(userKey)) {}

    ItemQuery& ItemQuery::Where(Predicate predicate) {
        predicates.push_back(std::move(predicate));
        return *this;
    }

    ItemQuery& ItemQuery::OfType(CipherType type) {
        return Where([type](const nlohmann::json& r) { return TypeOf(r) == static_cast<int>(type); });
    }

    ItemQuery& ItemQuery::InBin() {
        return Where([](const nlohmann::json& r) { return HasValue(r, "deletedDate"); });
    }

    ItemQuery& ItemQuery::NotInBin() {
        return Where([](const nlohmann::json& r) { return !HasValue(r, "deletedDate"); });
    }

    ItemQuery& ItemQuery::Archived() {
        return Where([](const nlohmann::json& r) { return HasValue(r, "archivedDate"); });
    }

    ItemQuery& ItemQuery::NotArchived() {
        return Where([](const nlohmann::json& r) { return !HasValue(r, "archivedDate"); });
    }

    ItemQuery& ItemQuery::Favorites() {
        return Where([](const nlohmann::json& r) {
            auto it = r.find("favorite");
            return it != r.end() && it->is_boolean() && it->get<bool>();
        });
    }

    ItemQuery& ItemQuery::InFolder(const std::string& folderId) {
        return Where([folderId](const nlohmann::json& r) {
            auto it = r.find("folderId");
            return it != r.end() && it->is_string() && it->get_ref<const std::string&>() == folderId;
        });
    }

    ItemQuery& ItemQuery::WithPasskey() {
        return Where([](const nlohmann::json& r) {
            auto login = r.find("login");
            if (TypeOf(r) != static_cast<int>(CipherType::Login) || login == r.end() || !login->is_object()) {
                return false;
            }
            auto creds = login->find("fido2Credentials");
            return creds != login->end() && creds->is_array() && !creds->empty();
        });
    }

    ItemQuery& ItemQuery::CreatedBetween(std::time_t start, std::time_t end) {
        return Where([=](const nlohmann::json& r) {
            std::time_t t = TimeOf(r, "creationDate");
            return t >= start && t <= end;
        });
    }

    ItemQuery& ItemQuery::RevisedBetween(std::time_t start, std::time_t end) {
        return Where([=](const nlohmann::json& r) {
            std::time_t t = TimeOf(r, "revisionDate");
            return t >= start && t <= end;
        });
    }

    ItemQuery& ItemQuery::DeletedBetween(std::time_t start, std::time_t end) {
        return Where([=](const nlohmann::json& r) {
            std::time_t t = TimeOf(r, "deletedDate");
            return t != 0 && t >= start && t <= end;
        });
    }

    ItemQuery& ItemQuery::NameContains(std::string_view text) {
        needle = ToLower(text);
        return *this;
    }

    std::vector<ItemSummary> ItemQuery::Run() const {
        std::vector<ItemSummary> out;

        for (const auto& record : records) {
            const nlohmann::json& r = *record;
            auto id = r.find("id");
            if (id == r.end() || !id->is_string()) {
                continue;
            }

            bool keep = true;
            for (const auto& p : predicates) {
                if (!p(r)) {
                    keep = false;
                    break;
                }
            }
            if (!keep) {
                continue;
            }

            if (!needle.empty()) {
                try {
                    auto name_it = r.find("name");
                    if (name_it == r.end() || !name_it->is_string()) {
                        continue;
                    }
                    auto key = r.find("key");
                    SecretString name = key != r.end() && key->is_string()
                        ? Crypto::DecryptString(name_it->get_ref<const std::string&>(), Crypto::UnwrapKey(key->get<std::string>(), userKey))
                        : Crypto::DecryptString(name_it->get_ref<const std::string&>(), userKey);
                    for (char& c : name) {
                        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    }
                    if (name.find(needle.c_str()) == SecretString::npos) {
                        continue;
                    }
                } catch (const std::exception&) {
                    continue;   // undecryptable record (e.g. org cipher)
                }
            }

            out.push_back({ id->get<std::string>(), static_cast<CipherType>(std::max(TypeOf(r), 0)) });
        }
        return out;
    }

    std::vector<std::string> ItemQuery::Ids() const {
        std::vector<std::string> out;
        for (auto& summary : Run()) {
            out.push_back(std::move(summary.id));
        }
        return out;
    }
}
