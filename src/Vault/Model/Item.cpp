#include "Item.h"

#include <algorithm>
#include <chrono>
#include <botan/base32.h>
#include <botan/otp.h>
#include <boost/url/parse.hpp>

#include "Util/Util.h"

namespace ClientWarden {
    namespace {
        /*
         * Missing-key-safe lookup: const operator[] on nlohmann::json is
         * undefined behaviour for absent keys, and server data can omit
         * anything.
        */
        const nlohmann::json& At(const nlohmann::json& obj, std::string_view key) {
            static const nlohmann::json null;
            if (!obj.is_object()) {
                return null;
            }
            auto it = obj.find(key);
            return it == obj.end() ? null : *it;
        }

        std::time_t TimeOf(const nlohmann::json& data, const char* key) {
            auto it = data.find(key);
            return it != data.end() && it->is_string() ? ParseTime(it->get<std::string>()) : 0;
        }

        /*
         * Re-encrypts every encrypted string under `node` from one key to
         * another, leaving ids, dates and other plaintext untouched.
        */
        void Rekey(nlohmann::json& node, const Crypto::SymmetricKey& from, const Crypto::SymmetricKey& to) {
            if (node.is_string()) {
                const std::string& value = node.get_ref<const std::string&>();
                if (Crypto::IsEncString(value)) {
                    node = Crypto::Encrypt(Crypto::Decrypt(value, from), to);
                }
            } else if (node.is_structured()) {
                for (auto& child : node) {
                    Rekey(child, from, to);
                }
            }
        }

        nlohmann::json LegacyData(const nlohmann::json& data) {
            nlohmann::json legacy = {
                { "Name", At(data, "name") },
                { "Notes", At(data, "notes") },
                { "Fields", nlohmann::json::array() }
            };

            for (const auto& f : data.value("fields", nlohmann::json::array())) {
                if (!f.is_object()) continue;
                nlohmann::json lf = { { "Name", At(f, "name") }, { "Type", f.value("type", 0) } };
                if (f.value("type", 0) == static_cast<int>(CustomFieldType::Linked)) {
                    lf["LinkedId"] = At(f, "linkedId");
                } else {
                    lf["Value"] = At(f, "value");
                }
                legacy["Fields"].push_back(std::move(lf));
            }

            auto typeIt = data.find("type");
            CipherType type = typeIt != data.end() && typeIt->is_number_integer() ? static_cast<CipherType>(typeIt->get<int>()) : CipherType::Generic;
            const TypeSchema* schema = SchemaFor(type);
            if (!schema || !At(data, schema->section).is_object()) {
                return legacy;
            }
            const nlohmann::json* section = &At(data, schema->section);

            for (const auto& field : schema->fields) {
                legacy[LegacyKey(field.key)] = At(*section, field.key);
            }

            if (type == CipherType::Login) {
                legacy["Uris"] = nlohmann::json::array();
                for (const auto& u : section->value("uris", nlohmann::json::array())) {
                    if (u.is_object()) {
                        legacy["Uris"].push_back({
                            { "Uri", At(u, "uri") },
                            { "UriChecksum", At(u, "uriChecksum") },
                            { "Match", At(u, "match") }
                        });
                    }
                }
                legacy["PasswordRevisionDate"] = At(*section, "passwordRevisionDate");
                legacy["PasswordHistory"] = nlohmann::json::array();
                for (const auto& h : data.value("passwordHistory", nlohmann::json::array())) {
                    if (h.is_object()) {
                        legacy["PasswordHistory"].push_back({
                            { "LastUsedDate", At(h, "lastUsedDate") },
                            { "Password", At(h, "password") }
                        });
                    }
                }
            } else if (type == CipherType::Note) {
                legacy["Type"] = 0;
            }
            return legacy;
        }

        Bytes DecodeTotpSecret(std::string secret) {
            std::erase_if(secret, [](char c) { return c == ' ' || c == '-' || c == '='; });
            for (char& c : secret) {
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            }
            while (secret.size() % 8 != 0) {
                secret.push_back('=');
            }
            return Botan::base32_decode(secret);
        }
    }

    Item::Item(nlohmann::json cipher, Crypto::SymmetricKey itemKey) : data(std::move(cipher)), key(std::move(itemKey)) {
        id = data.value("id", "");
    }

    Item Item::Create(CipherType type, const Crypto::SymmetricKey& userKey) {
        const TypeSchema* schema = SchemaFor(type);
        if (!schema) {
            throw VaultError("cannot create an item of unknown type");
        }

        Crypto::SymmetricKey itemKey = Crypto::SymmetricKey::Generate();

        nlohmann::json j = {
            { "id", NewGuid() },
            { "type", static_cast<int>(type) },
            { "key", Crypto::WrapKey(itemKey, userKey) },
            { "name", Crypto::Encrypt(std::string_view(), itemKey) },
            { "notes", nullptr },
            { "folderId", nullptr },
            { "organizationId", nullptr },
            { "collectionIds", nlohmann::json::array() },
            { "favorite", false },
            { "reprompt", 0 },
            { "fields", nlohmann::json::array() },
            { "passwordHistory", nlohmann::json::array() },
            { "attachments", nullptr },
            { "creationDate", NowTime() },
            { "revisionDate", nullptr },
            { "deletedDate", nullptr },
            { "archivedDate", nullptr },
            { "edit", true },
            { "viewPassword", true },
            { "permissions", { { "delete", true }, { "restore", true } } },
            { "object", "cipherDetails" },
        };

        for (const auto& other : AllSchemas()) {
            j[std::string(other.section)] = nullptr;
        }

        nlohmann::json section = nlohmann::json::object();
        for (const auto& field : schema->fields) {
            section[std::string(field.key)] = schema->initialValue ? nlohmann::json(Crypto::Encrypt(*schema->initialValue, itemKey)) : nlohmann::json();
        }
        if (type == CipherType::Login) {
            section["uris"] = nlohmann::json::array();
            section["uri"] = nullptr;
            section["passwordRevisionDate"] = nullptr;
            section["fido2Credentials"] = nullptr;
            section["autofillOnPageLoad"] = nullptr;
        } else if (type == CipherType::Note) {
            section["type"] = 0;
        }
        j[std::string(schema->section)] = std::move(section);

        return Item(std::move(j), std::move(itemKey));
    }

    Item Item::FromJson(nlohmann::json cipher, const Crypto::SymmetricKey& userKey) {
        if (!At(cipher, "id").is_string()) {
            throw VaultError("cipher is missing an id");
        }

        /*
         * Older ciphers have no per-item key and are encrypted directly
         * with the user key.
        */
        auto k = cipher.find("key");
        Crypto::SymmetricKey itemKey = (k != cipher.end() && k->is_string()) ? Crypto::UnwrapKey(k->get<std::string>(), userKey) : userKey;
        return Item(std::move(cipher), std::move(itemKey));
    }

    CipherType Item::Type() const {
        auto t = data.find("type");
        return t != data.end() && t->is_number_integer() ? static_cast<CipherType>(t->get<int>()) : CipherType::Generic;
    }

    SecretString Item::Decrypt(const nlohmann::json& value) const {
        if (!value.is_string()) {
            return {};
        }
        return Crypto::DecryptString(value.get_ref<const std::string&>(), key);
    }

    nlohmann::json Item::Encrypt(std::string_view value) const {
        return Crypto::Encrypt(value, key);
    }

    void Item::RequireType(CipherType type, const char* what) const {
        if (Type() != type) {
            throw VaultError(std::string(what) + " is not available for this item type");
        }
    }

    nlohmann::json& Item::Section() {
        const TypeSchema* schema = SchemaFor(Type());
        if (!schema) {
            throw VaultError("item has no type-specific fields");
        }
        nlohmann::json& section = data[std::string(schema->section)];
        if (!section.is_object()) {
            section = nlohmann::json::object();
        }
        return section;
    }

    const nlohmann::json* Item::Section() const {
        const TypeSchema* schema = SchemaFor(Type());
        if (!schema) {
            return nullptr;
        }
        auto it = data.find(schema->section);
        return it != data.end() && it->is_object() ? &*it : nullptr;
    }

    SecretString Item::Name() const {
        return Decrypt(At(data, "name"));
    }

    void Item::SetName(std::string_view name) {
        data["name"] = Encrypt(name);
    }

    SecretString Item::Notes() const {
        return Decrypt(At(data, "notes"));
    }

    void Item::SetNotes(std::string_view notes) {
        data["notes"] = notes.empty() ? nlohmann::json() : Encrypt(notes);
    }

    std::optional<std::string> Item::FolderId() const {
        auto f = data.find("folderId");
        if (f == data.end() || !f->is_string()) {
            return std::nullopt;
        }
        return f->get<std::string>();
    }

    void Item::SetFolderId(std::optional<std::string> folderId) {
        data["folderId"] = folderId && !folderId->empty() ? nlohmann::json(*folderId) : nlohmann::json();
    }

    bool Item::Favorite() const {
        auto f = data.find("favorite");
        return f != data.end() && f->is_boolean() && f->get<bool>();
    }

    void Item::SetFavorite(bool favorite) {
        data["favorite"] = favorite;
    }

    bool Item::Reprompt() const {
        auto r = data.find("reprompt");
        return r != data.end() && r->is_number_integer() && r->get<int>() == 1;
    }

    void Item::SetReprompt(bool reprompt) {
        data["reprompt"] = reprompt ? 1 : 0;
    }

    std::time_t Item::Created() const { return TimeOf(data, "creationDate"); }
    std::time_t Item::Revised() const { return TimeOf(data, "revisionDate"); }
    std::time_t Item::Deleted() const { return TimeOf(data, "deletedDate"); }
    std::time_t Item::Archived() const { return TimeOf(data, "archivedDate"); }

    SecretString Item::Get(FieldId field) const {
        RequireType(field.type, field.key.data());
        const nlohmann::json* section = Section();
        if (!section) {
            return {};
        }
        auto it = section->find(field.key);
        return it == section->end() ? SecretString() : Decrypt(*it);
    }

    void Item::Set(FieldId field, std::string_view value) {
        RequireType(field.type, field.key.data());
        nlohmann::json& section = Section();
        std::string k(field.key);

        if (field == Fields::Login::Password) {
            /*
             * Remember the previous password, as Bitwarden clients do.
            */
            const nlohmann::json& old = section.value(k, nlohmann::json());
            if (old.is_string() && Decrypt(old) != SecretString(value.begin(), value.end())) {
                nlohmann::json& history = data["passwordHistory"];
                if (!history.is_array()) {
                    history = nlohmann::json::array();
                }
                history.insert(history.begin(), nlohmann::json::object({ { "lastUsedDate", NowTime() }, { "password", old } }));
                if (history.size() > MaxPasswordHistory) {
                    history.erase(history.begin() + MaxPasswordHistory, history.end());
                }
                section["passwordRevisionDate"] = NowTime();
            }
        }

        bool nullable = !SchemaFor(field.type)->initialValue;
        section[k] = value.empty() && nullable ? nlohmann::json() : Encrypt(value);
    }

    std::vector<Item::CustomField> Item::CustomFields() const {
        std::vector<CustomField> out;
        auto fields = data.find("fields");
        if (fields == data.end() || !fields->is_array()) {
            return out;
        }

        for (const auto& f : *fields) {
            if (!At(f, "type").is_number_integer()) {
                continue;
            }
            auto type = static_cast<CustomFieldType>(At(f, "type").get<int>());
            SecretString value;
            if (type == CustomFieldType::Linked) {
                if (At(f, "linkedId").is_number_integer()) {
                    std::string linked = std::to_string(At(f, "linkedId").get<int>());
                    value.assign(linked.begin(), linked.end());
                }
            } else {
                value = Decrypt(At(f, "value"));
            }
            out.push_back({ type, Decrypt(At(f, "name")), std::move(value) });
        }
        return out;
    }

    void Item::AddCustomField(CustomFieldType type, std::string_view name, std::string_view value) {
        nlohmann::json f = {
            { "type", static_cast<int>(type) },
            { "name", Encrypt(name) },
            { "value", nullptr },
            { "linkedId", nullptr }
        };
        if (type == CustomFieldType::Linked) {
            try {
                f["linkedId"] = std::stoi(std::string(value));
            } catch (...) {
                throw VaultError("linked field value must be a numeric id");
            }
        } else {
            f["value"] = Encrypt(value);
        }

        nlohmann::json& fields = data["fields"];
        if (!fields.is_array()) {
            fields = nlohmann::json::array();
        }
        fields.push_back(std::move(f));
    }

    void Item::RemoveCustomField(std::string_view name) {
        nlohmann::json& fields = data["fields"];
        if (!fields.is_array()) {
            return;
        }
        SecretString target(name.begin(), name.end());
        auto it = std::find_if(fields.begin(), fields.end(), [&](const nlohmann::json& f) {
            return Decrypt(At(f, "name")) == target;
        });
        if (it != fields.end()) {
            fields.erase(it);
        }
    }

    void Item::ClearCustomFields() {
        data["fields"] = nlohmann::json::array();
    }

    std::vector<SecretString> Item::Uris() const {
        RequireType(CipherType::Login, "URIs");
        std::vector<SecretString> out;
        const nlohmann::json* login = Section();
        if (!login || !At(*login, "uris").is_array()) {
            return out;
        }
        for (const auto& u : At(*login, "uris")) {
            if (u.is_object()) {
                out.push_back(Decrypt(At(u, "uri")));
            }
        }
        return out;
    }

    void Item::AddUri(std::string_view uri) {
        RequireType(CipherType::Login, "URIs");
        nlohmann::json& uris = Section()["uris"];
        if (!uris.is_array()) {
            uris = nlohmann::json::array();
        }
        uris.push_back({ { "uri", Encrypt(uri) }, { "uriChecksum", Crypto::UriChecksum(uri, key) }, { "match", nullptr } });
    }

    void Item::RemoveUri(std::string_view uri) {
        RequireType(CipherType::Login, "URIs");
        nlohmann::json& login = Section();
        SecretString target(uri.begin(), uri.end());

        if (At(login, "uri").is_string() && Decrypt(login["uri"]) == target) {
            login["uri"] = nullptr;
        }

        nlohmann::json& uris = login["uris"];
        if (!uris.is_array()) {
            return;
        }
        auto it = std::find_if(uris.begin(), uris.end(), [&](const nlohmann::json& u) {
            return Decrypt(At(u, "uri")) == target;
        });
        if (it != uris.end()) {
            uris.erase(it);
        }
    }

    std::vector<Item::PasswordHistoryEntry> Item::PasswordHistory() const {
        RequireType(CipherType::Login, "Password history");
        std::vector<PasswordHistoryEntry> out;
        auto history = data.find("passwordHistory");
        if (history == data.end() || !history->is_array()) {
            return out;
        }
        for (const auto& h : *history) {
            if (At(h, "password").is_string()) {
                out.push_back({ TimeOf(h, "lastUsedDate"), Decrypt(At(h, "password")) });
            }
        }
        return out;
    }

    std::optional<Item::TotpCode> Item::Totp(std::time_t now) const {
        SecretString secret = Get(Fields::Login::Totp);
        if (secret.empty()) {
            return std::nullopt;
        }

        std::string raw(secret.begin(), secret.end());
        std::string algorithm = "SHA-1";
        int digits = 6;
        int period = 30;

        try {
            if (raw.starts_with("otpauth://")) {
                auto url = boost::urls::parse_uri(raw);
                if (!url) {
                    return std::nullopt;
                }
                std::string uriSecret;
                for (auto p : url->params()) {
                    std::string k = ToLower(p.key);
                    if (k == "secret") {
                        uriSecret = p.value;
                    } else if (k == "algorithm") {
                        std::string a = ToLower(p.value);
                        algorithm = a == "sha256" ? "SHA-256" : a == "sha512" ? "SHA-512" : "SHA-1";
                    } else if (k == "digits") {
                        digits = std::clamp(std::stoi(p.value), 6, 8);
                    } else if (k == "period") {
                        period = std::clamp(std::stoi(p.value), 1, 300);
                    }
                }
                Wipe(raw);
                raw = std::move(uriSecret);
            }

            Bytes keyBytes = DecodeTotpSecret(raw);
            Wipe(raw);
            if (keyBytes.empty()) {
                return std::nullopt;
            }

            Botan::TOTP totp(keyBytes.data(), keyBytes.size(), algorithm, digits, period);
            uint32_t code = totp.generate_totp(std::chrono::system_clock::from_time_t(now));

            std::string text = std::to_string(code);
            text.insert(0, static_cast<size_t>(digits) - std::min(text.size(), static_cast<size_t>(digits)), '0');
            return TotpCode { text, (now / period + 1) * period, period };
        } catch (const std::exception&) {
            Log()->debug("Invalid TOTP secret");
            return std::nullopt;
        }
    }

    std::vector<std::time_t> Item::PasskeyCreationDates() const {
        RequireType(CipherType::Login, "Passkeys");
        std::vector<std::time_t> out;
        const nlohmann::json* login = Section();
        if (!login || !At(*login, "fido2Credentials").is_array()) {
            return out;
        }
        for (const auto& cred : At(*login, "fido2Credentials")) {
            if (cred.is_object()) {
                out.push_back(TimeOf(cred, "creationDate"));
            }
        }
        return out;
    }

    std::vector<Item::Attachment> Item::Attachments() const {
        std::vector<Attachment> out;
        auto attachments = data.find("attachments");
        if (attachments == data.end() || !attachments->is_array()) {
            return out;
        }
        for (const auto& a : *attachments) {
            const nlohmann::json& size = At(a, "size");
            if (At(a, "id").is_string()) {
                out.push_back({
                    At(a, "id").get<std::string>(),
                    Decrypt(At(a, "fileName")),
                    size.is_string() ? size.get<std::string>() : size.is_number() ? size.dump() : ""
                });
            }
        }
        return out;
    }

    std::optional<Item::Attachment> Item::FindAttachment(std::string_view attachmentId) const {
        for (auto& a : Attachments()) {
            if (a.id == attachmentId) {
                return a;
            }
        }
        return std::nullopt;
    }

    Item Item::Duplicate(const Crypto::SymmetricKey& userKey) const {
        Crypto::SymmetricKey newKey = Crypto::SymmetricKey::Generate();

        nlohmann::json copy = data;
        copy["id"] = NewGuid();
        copy["key"] = Crypto::WrapKey(newKey, userKey);
        copy["creationDate"] = NowTime();
        copy["revisionDate"] = nullptr;
        copy["passwordHistory"] = nlohmann::json::array();
        copy["attachments"] = nullptr;
        copy["deletedDate"] = nullptr;
        copy["archivedDate"] = nullptr;
        copy.erase("createdOffline");
        copy.erase("data");

        if (const TypeSchema* schema = SchemaFor(Type())) {
            std::string section(schema->section);
            if (Type() == CipherType::Login && copy[section].is_object()) {
                copy[section]["fido2Credentials"] = nullptr;
            }
            Rekey(copy[section], key, newKey);
        }
        for (const char* field : { "name", "notes", "fields" }) {
            Rekey(copy[field], key, newKey);
        }

        return Item(std::move(copy), std::move(newKey));
    }

    nlohmann::json Item::WireFormat(const nlohmann::json& cipher, bool includeLegacyData) {
        nlohmann::json wire = cipher;
        wire.erase("createdOffline");
        if (includeLegacyData) {
            wire["data"] = LegacyData(cipher).dump();
        } else {
            wire.erase("data");
        }
        return wire;
    }

    nlohmann::json Item::ToWire(bool includeLegacyData) const {
        return WireFormat(data, includeLegacyData);
    }

    void Item::Replace(nlohmann::json cipher) {
        data = std::move(cipher);
        id = data.value("id", "");
    }

    void Item::Touch() {
        data["revisionDate"] = NowTime();
    }

    void Item::MarkDeleted(bool deleted) {
        data["deletedDate"] = deleted ? nlohmann::json(NowTime()) : nlohmann::json();
    }

    void Item::MarkArchived(bool archived) {
        data["archivedDate"] = archived ? nlohmann::json(NowTime()) : nlohmann::json();
    }
}
