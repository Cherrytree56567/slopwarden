#include "schema.h"

#include <algorithm>

#include <array>

namespace clientwarden {
    namespace {
        namespace f = fields;

        constexpr std::array c_login_fields { f::login::c_username, f::login::c_password,
            f::login::c_totp };

        constexpr std::array c_card_fields { f::card::c_cardholder_name, f::card::c_brand,
            f::card::c_number, f::card::c_exp_month, f::card::c_exp_year, f::card::c_code };

        constexpr std::array c_identity_fields { f::identity::c_title, f::identity::c_first_name,
            f::identity::c_middle_name, f::identity::c_last_name, f::identity::c_address1,
            f::identity::c_address2, f::identity::c_address3, f::identity::c_city,
            f::identity::c_state, f::identity::c_postal_code, f::identity::c_country,
            f::identity::c_company, f::identity::c_email, f::identity::c_phone, f::identity::c_ssn,
            f::identity::c_username, f::identity::c_passport_number,
            f::identity::c_license_number };

        constexpr std::array<FieldId, 0> c_note_fields {};

        constexpr std::array c_ssh_key_fields { f::ssh_key::c_private_key, f::ssh_key::c_public_key,
            f::ssh_key::c_fingerprint };

        constexpr std::array c_bank_account_fields { f::bank_account::c_bank_name,
            f::bank_account::c_name_on_account, f::bank_account::c_account_type,
            f::bank_account::c_account_number, f::bank_account::c_routing_number,
            f::bank_account::c_branch_number, f::bank_account::c_pin, f::bank_account::c_swift_code,
            f::bank_account::c_iban, f::bank_account::c_bank_contact_phone };

        constexpr std::array c_drivers_license_fields { f::drivers_license::c_first_name,
            f::drivers_license::c_middle_name, f::drivers_license::c_last_name,
            f::drivers_license::c_date_of_birth, f::drivers_license::c_license_number,
            f::drivers_license::c_issuing_country, f::drivers_license::c_issuing_state,
            f::drivers_license::c_issue_date, f::drivers_license::c_expiration_date,
            f::drivers_license::c_issuing_authority, f::drivers_license::c_license_class };

        constexpr std::array c_passport_fields { f::passport::c_surname, f::passport::c_given_name,
            f::passport::c_date_of_birth, f::passport::c_sex, f::passport::c_birth_place,
            f::passport::c_nationality, f::passport::c_issuing_country,
            f::passport::c_passport_number, f::passport::c_passport_type,
            f::passport::c_national_identification_number, f::passport::c_issuing_authority,
            f::passport::c_issue_date, f::passport::c_expiration_date };

        const std::array<TypeSchema, 8> c_schemas {
            TypeSchema { CipherType::Login, "login", c_login_fields, std::nullopt },
            TypeSchema { CipherType::Note, "secureNote", c_note_fields, std::nullopt },
            TypeSchema { CipherType::Card, "card", c_card_fields, std::nullopt },
            TypeSchema { CipherType::Identity, "identity", c_identity_fields, std::nullopt },
            TypeSchema { CipherType::SshKey, "sshKey", c_ssh_key_fields, " " },
            TypeSchema { CipherType::BankAccount, "bankAccount", c_bank_account_fields, "" },
            TypeSchema {
                    CipherType::DriversLicense, "driversLicense", c_drivers_license_fields, "" },
            TypeSchema { CipherType::Passport, "passport", c_passport_fields, "" },
        };

        /**
         * @brief Builds the pre-2026.6.0 "data" blob from a cipher's already-encrypted values.
         *
         * @param cipher The stored cipher
         * @return The legacy object (PascalCase keys)
         */
        Json legacyData_(const Json& cipher) {
            // clang-format off
            Json legacy = {
                { "Name", at(cipher, "name") },
                { "Notes", at(cipher, "notes") },
                { "Fields", Json::array() }
            };
            // clang-format on

            const Json& fields = at(cipher, "fields");
            if (fields.is_array()) {
                for (const Json& field : fields) {
                    if (!field.is_object()) {
                        continue;
                    }
                    const Json& type = at(field, "type");
                    Json legacy_field = { { "Name", at(field, "name") }, { "Type", type } };
                    if (type.is_number_integer() &&
                            type.get<int>() == static_cast<int>(CustomFieldType::Linked)) {
                        legacy_field["LinkedId"] = at(field, "linkedId");
                    } else {
                        legacy_field["Value"] = at(field, "value");
                    }
                    legacy["Fields"].push_back(std::move(legacy_field));
                }
            }

            CipherType type = Schema::typeOf(cipher);
            std::optional<TypeSchema> schema = Schema::forType(type);
            if (!schema || !at(cipher, schema->m_section).is_object()) {
                return legacy;
            }
            const Json& section = at(cipher, schema->m_section);

            for (const FieldId& field : schema->m_fields) {
                legacy[Schema::legacyKey(field.m_key)] = at(section, field.m_key);
            }

            if (type == CipherType::Login) {
                legacy["Uris"] = Json::array();
                const Json& uris = at(section, "uris");
                if (uris.is_array()) {
                    for (const Json& uri : uris) {
                        if (uri.is_object()) {
                            // clang-format off
                            legacy["Uris"].push_back({
                                { "Uri", at(uri, "uri") },
                                { "UriChecksum", at(uri, "uriChecksum") },
                                { "Match", at(uri, "match") }
                            });
                            // clang-format on
                        }
                    }
                }
                legacy["PasswordRevisionDate"] = at(section, "passwordRevisionDate");
                legacy["PasswordHistory"] = Json::array();
                const Json& history = at(cipher, "passwordHistory");
                if (history.is_array()) {
                    for (const Json& entry : history) {
                        if (entry.is_object()) {
                            // clang-format off
                            legacy["PasswordHistory"].push_back({
                                { "LastUsedDate", at(entry, "lastUsedDate") },
                                { "Password", at(entry, "password") }
                            });
                            // clang-format on
                        }
                    }
                }
            } else if (type == CipherType::Note) {
                legacy["Type"] = 0;
            }
            return legacy;
        }
    }

    std::optional<TypeSchema> Schema::forType(CipherType type) {
        for (const TypeSchema& schema : c_schemas) {
            if (schema.m_type == type) {
                return schema;
            }
        }
        return std::nullopt;
    }

    std::span<const TypeSchema> Schema::all() {
        return c_schemas;
    }

    SecureString Schema::legacyKey(std::string_view key) {
        if (key == "ssn") {
            return SecureString("SSN");
        }
        SecureString out(key);
        if (!out.empty() && out[0] >= 'a' && out[0] <= 'z') {
            out[0] = static_cast<char>(out[0] - 'a' + 'A');
        }
        return out;
    }

    Json Schema::wireFormat(
            const Json& cipher, bool include_legacy_data, std::string_view encrypted_for) {
        Json wire = cipher;
        wire.erase("createdOffline");
        if (!encrypted_for.empty()) {
            wire["encryptedFor"] = SecureString(encrypted_for);
        }
        if (include_legacy_data) {
            wire["data"] = legacyData_(cipher).dump();
        } else {
            wire.erase("data");
        }
        return wire;
    }

    CipherType Schema::typeOf(const Json& cipher) {
        const Json& type = at(cipher, "type");
        return type.is_number_integer() ? static_cast<CipherType>(type.get<int>())
                                        : CipherType::Generic;
    }

    std::optional<FieldId> Schema::fieldFor(CipherType type, std::string_view key) {
        std::optional<TypeSchema> schema = forType(type);
        if (!schema) {
            return std::nullopt;
        }
        for (FieldId field : schema->m_fields) {
            if (field.m_key == key) {
                return field;
            }
        }
        return std::nullopt;
    }

    bool Schema::isSecret(FieldId field) {
        constexpr std::array<FieldId, 12> c_secrets = { fields::login::c_password, fields::card::c_number,
            fields::card::c_code, fields::identity::c_ssn, fields::identity::c_passport_number,
            fields::ssh_key::c_private_key, fields::bank_account::c_account_number,
            fields::bank_account::c_routing_number, fields::bank_account::c_pin, fields::bank_account::c_iban,
            fields::drivers_license::c_license_number, fields::passport::c_passport_number };
        return std::find(c_secrets.begin(), c_secrets.end(), field) != c_secrets.end();
    }
}
