#pragma once
#include <optional>
#include <span>
#include <string_view>

#include "utils/secure_string/secure_string.h"

namespace clientwarden {
    /**
     * @brief Bitwarden cipher types.
     * See https://github.com/bitwarden/server/blob/main/src/Core/Vault/Enums/CipherType.cs
     */
    enum class CipherType {
        Generic = 0,
        Login = 1,
        Note = 2,
        Card = 3,
        Identity = 4,
        SshKey = 5,
        BankAccount = 6,
        DriversLicense = 7,
        Passport = 8
    };

    /**
     * @brief Custom field kinds.
     */
    enum class CustomFieldType { Text = 0, Hidden = 1, Checkbox = 2, Linked = 3 };

    /**
     * @brief Identifies one encrypted, type-specific field (e.g. a card's number).
     */
    struct FieldId {
        CipherType m_type;
        std::string_view m_key;

        /**
         * @brief Compares type and key.
         *
         * @param other The field to compare with
         * @return True if the same field
         */
        constexpr bool operator==(const FieldId& other) const = default;
    };

    /**
     * @brief Every type-specific field, as named in the Bitwarden JSON.
     */
    namespace fields {
        namespace login {
            inline constexpr FieldId c_username { CipherType::Login, "username" };
            inline constexpr FieldId c_password { CipherType::Login, "password" };
            inline constexpr FieldId c_totp { CipherType::Login, "totp" };
        }

        namespace card {
            inline constexpr FieldId c_cardholder_name { CipherType::Card, "cardholderName" };
            inline constexpr FieldId c_brand { CipherType::Card, "brand" };
            inline constexpr FieldId c_number { CipherType::Card, "number" };
            inline constexpr FieldId c_exp_month { CipherType::Card, "expMonth" };
            inline constexpr FieldId c_exp_year { CipherType::Card, "expYear" };
            inline constexpr FieldId c_code { CipherType::Card, "code" };
        }

        namespace identity {
            inline constexpr FieldId c_title { CipherType::Identity, "title" };
            inline constexpr FieldId c_first_name { CipherType::Identity, "firstName" };
            inline constexpr FieldId c_middle_name { CipherType::Identity, "middleName" };
            inline constexpr FieldId c_last_name { CipherType::Identity, "lastName" };
            inline constexpr FieldId c_address1 { CipherType::Identity, "address1" };
            inline constexpr FieldId c_address2 { CipherType::Identity, "address2" };
            inline constexpr FieldId c_address3 { CipherType::Identity, "address3" };
            inline constexpr FieldId c_city { CipherType::Identity, "city" };
            inline constexpr FieldId c_state { CipherType::Identity, "state" };
            inline constexpr FieldId c_postal_code { CipherType::Identity, "postalCode" };
            inline constexpr FieldId c_country { CipherType::Identity, "country" };
            inline constexpr FieldId c_company { CipherType::Identity, "company" };
            inline constexpr FieldId c_email { CipherType::Identity, "email" };
            inline constexpr FieldId c_phone { CipherType::Identity, "phone" };
            inline constexpr FieldId c_ssn { CipherType::Identity, "ssn" };
            inline constexpr FieldId c_username { CipherType::Identity, "username" };
            inline constexpr FieldId c_passport_number { CipherType::Identity, "passportNumber" };
            inline constexpr FieldId c_license_number { CipherType::Identity, "licenseNumber" };
        }

        namespace ssh_key {
            inline constexpr FieldId c_private_key { CipherType::SshKey, "privateKey" };
            inline constexpr FieldId c_public_key { CipherType::SshKey, "publicKey" };
            inline constexpr FieldId c_fingerprint { CipherType::SshKey, "keyFingerprint" };
        }

        namespace bank_account {
            inline constexpr FieldId c_bank_name { CipherType::BankAccount, "bankName" };
            inline constexpr FieldId c_name_on_account { CipherType::BankAccount, "nameOnAccount" };
            inline constexpr FieldId c_account_type { CipherType::BankAccount, "accountType" };
            inline constexpr FieldId c_account_number { CipherType::BankAccount, "accountNumber" };
            inline constexpr FieldId c_routing_number { CipherType::BankAccount, "routingNumber" };
            inline constexpr FieldId c_branch_number { CipherType::BankAccount, "branchNumber" };
            inline constexpr FieldId c_pin { CipherType::BankAccount, "pin" };
            inline constexpr FieldId c_swift_code { CipherType::BankAccount, "swiftCode" };
            inline constexpr FieldId c_iban { CipherType::BankAccount, "iban" };
            inline constexpr FieldId c_bank_contact_phone { CipherType::BankAccount,
                "bankContactPhone" };
        }

        namespace drivers_license {
            inline constexpr FieldId c_first_name { CipherType::DriversLicense, "firstName" };
            inline constexpr FieldId c_middle_name { CipherType::DriversLicense, "middleName" };
            inline constexpr FieldId c_last_name { CipherType::DriversLicense, "lastName" };
            inline constexpr FieldId c_date_of_birth { CipherType::DriversLicense, "dateOfBirth" };
            inline constexpr FieldId c_license_number { CipherType::DriversLicense,
                "licenseNumber" };
            inline constexpr FieldId c_issuing_country { CipherType::DriversLicense,
                "issuingCountry" };
            inline constexpr FieldId c_issuing_state { CipherType::DriversLicense, "issuingState" };
            inline constexpr FieldId c_issue_date { CipherType::DriversLicense, "issueDate" };
            inline constexpr FieldId c_expiration_date { CipherType::DriversLicense,
                "expirationDate" };
            inline constexpr FieldId c_issuing_authority { CipherType::DriversLicense,
                "issuingAuthority" };
            inline constexpr FieldId c_license_class { CipherType::DriversLicense, "licenseClass" };
        }

        namespace passport {
            inline constexpr FieldId c_surname { CipherType::Passport, "surname" };
            inline constexpr FieldId c_given_name { CipherType::Passport, "givenName" };
            inline constexpr FieldId c_date_of_birth { CipherType::Passport, "dateOfBirth" };
            inline constexpr FieldId c_sex { CipherType::Passport, "sex" };
            inline constexpr FieldId c_birth_place { CipherType::Passport, "birthPlace" };
            inline constexpr FieldId c_nationality { CipherType::Passport, "nationality" };
            inline constexpr FieldId c_issuing_country { CipherType::Passport, "issuingCountry" };
            inline constexpr FieldId c_passport_number { CipherType::Passport, "passportNumber" };
            inline constexpr FieldId c_passport_type { CipherType::Passport, "passportType" };
            inline constexpr FieldId c_national_identification_number { CipherType::Passport,
                "nationalIdentificationNumber" };
            inline constexpr FieldId c_issuing_authority { CipherType::Passport,
                "issuingAuthority" };
            inline constexpr FieldId c_issue_date { CipherType::Passport, "issueDate" };
            inline constexpr FieldId c_expiration_date { CipherType::Passport, "expirationDate" };
        }
    }

    /**
     * @brief Where a type's fields live and how new items of it start out.
     */
    struct TypeSchema {
        CipherType m_type;
        std::string_view m_section;
        std::span<const FieldId> m_fields;

        /**
         * @brief Initial plaintext for every field of a new item; nullopt means null. Some
         * server versions reject null for the newer types, so those start as an encrypted
         * empty (or, for SSH keys, single-space) string.
         */
        std::optional<std::string_view> m_initial_value;
    };

    /**
     * @brief Static description of every cipher type.
     *
     * Items use this to implement field access, defaults, duplication and the legacy "data"
     * blob generically, so adding a field means adding one line here.
     */
    class Schema {
    public:
        /**
         * @brief The schema for a type.
         *
         * @param type The cipher type
         * @return The schema, or nullopt for Generic/unknown types
         */
        static std::optional<TypeSchema> forType(CipherType type);

        /**
         * @brief Every known type schema.
         *
         * @return The schemas
         */
        static std::span<const TypeSchema> all();

        /**
         * @brief Finds a type's field by its JSON key.
         *
         * @param type The cipher type
         * @param key The JSON key
         * @return The field, or nullopt if the type has no such field
         */
        static std::optional<FieldId> fieldFor(CipherType type, std::string_view key);

        /**
         * @brief Whether a field holds a secret the UI should conceal by default (passwords,
         * card numbers and codes, SSNs, account numbers, PINs, private keys, ...).
         *
         * @param field The field
         * @return True to conceal
         */
        static bool isSecret(FieldId field);

        /**
         * @brief The PascalCase key used inside the pre-2026.6.0 "data" blob.
         *
         * @param key The JSON key (e.g. "ssn")
         * @return The legacy key (e.g. "SSN")
         */
        static SecureString legacyKey(std::string_view key);

        /**
         * @brief Builds the POST/PUT body from a stored cipher; needs no key because the legacy
         * blob is assembled from already-encrypted values.
         *
         * @param cipher The stored cipher
         * @param include_legacy_data Add the "data" blob older servers expect
         * @param encrypted_for The id of the user whose key encrypted it (Vaultwarden requires
         * it; empty to leave it out)
         * @return The request body
         */
        static Json wireFormat(
                const Json& cipher, bool include_legacy_data, std::string_view encrypted_for);

        /**
         * @brief The type recorded in a cipher.
         *
         * @param cipher The cipher
         * @return Its type, or Generic if missing
         */
        static CipherType typeOf(const Json& cipher);
    };
}
