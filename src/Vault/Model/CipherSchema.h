#pragma once
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "Clientwarden.h"

/*
 * Declarative description of every cipher type: which JSON section it
 * lives under and which encrypted string fields it has. Item uses this
 * to implement get/set, defaults, duplication and the legacy "data" blob
 * generically instead of hand-writing each type.
*/
namespace ClientWarden {
    struct FieldId {
        CipherType type;
        std::string_view key;

        constexpr bool operator==(const FieldId&) const = default;
    };

    namespace Fields {
        namespace Login {
            inline constexpr FieldId Username { CipherType::Login, "username" };
            inline constexpr FieldId Password { CipherType::Login, "password" };
            inline constexpr FieldId Totp { CipherType::Login, "totp" };
        }

        namespace Card {
            inline constexpr FieldId CardholderName { CipherType::Card, "cardholderName" };
            inline constexpr FieldId Brand { CipherType::Card, "brand" };
            inline constexpr FieldId Number { CipherType::Card, "number" };
            inline constexpr FieldId ExpMonth { CipherType::Card, "expMonth" };
            inline constexpr FieldId ExpYear { CipherType::Card, "expYear" };
            inline constexpr FieldId Code { CipherType::Card, "code" };
        }

        namespace Identity {
            inline constexpr FieldId Title { CipherType::Identity, "title" };
            inline constexpr FieldId FirstName { CipherType::Identity, "firstName" };
            inline constexpr FieldId MiddleName { CipherType::Identity, "middleName" };
            inline constexpr FieldId LastName { CipherType::Identity, "lastName" };
            inline constexpr FieldId Address1 { CipherType::Identity, "address1" };
            inline constexpr FieldId Address2 { CipherType::Identity, "address2" };
            inline constexpr FieldId Address3 { CipherType::Identity, "address3" };
            inline constexpr FieldId City { CipherType::Identity, "city" };
            inline constexpr FieldId State { CipherType::Identity, "state" };
            inline constexpr FieldId PostalCode { CipherType::Identity, "postalCode" };
            inline constexpr FieldId Country { CipherType::Identity, "country" };
            inline constexpr FieldId Company { CipherType::Identity, "company" };
            inline constexpr FieldId Email { CipherType::Identity, "email" };
            inline constexpr FieldId Phone { CipherType::Identity, "phone" };
            inline constexpr FieldId SSN { CipherType::Identity, "ssn" };
            inline constexpr FieldId Username { CipherType::Identity, "username" };
            inline constexpr FieldId PassportNumber { CipherType::Identity, "passportNumber" };
            inline constexpr FieldId LicenseNumber { CipherType::Identity, "licenseNumber" };
        }

        namespace SSHKey {
            inline constexpr FieldId PrivateKey { CipherType::SSHKey, "privateKey" };
            inline constexpr FieldId PublicKey { CipherType::SSHKey, "publicKey" };
            inline constexpr FieldId Fingerprint { CipherType::SSHKey, "keyFingerprint" };
        }

        namespace BankAccount {
            inline constexpr FieldId BankName { CipherType::BankAccount, "bankName" };
            inline constexpr FieldId NameOnAccount { CipherType::BankAccount, "nameOnAccount" };
            inline constexpr FieldId AccountType { CipherType::BankAccount, "accountType" };
            inline constexpr FieldId AccountNumber { CipherType::BankAccount, "accountNumber" };
            inline constexpr FieldId RoutingNumber { CipherType::BankAccount, "routingNumber" };
            inline constexpr FieldId BranchNumber { CipherType::BankAccount, "branchNumber" };
            inline constexpr FieldId Pin { CipherType::BankAccount, "pin" };
            inline constexpr FieldId SwiftCode { CipherType::BankAccount, "swiftCode" };
            inline constexpr FieldId Iban { CipherType::BankAccount, "iban" };
            inline constexpr FieldId BankContactPhone { CipherType::BankAccount, "bankContactPhone" };
        }

        namespace DriversLicense {
            inline constexpr FieldId FirstName { CipherType::DriversLicense, "firstName" };
            inline constexpr FieldId MiddleName { CipherType::DriversLicense, "middleName" };
            inline constexpr FieldId LastName { CipherType::DriversLicense, "lastName" };
            inline constexpr FieldId DateOfBirth { CipherType::DriversLicense, "dateOfBirth" };
            inline constexpr FieldId LicenseNumber { CipherType::DriversLicense, "licenseNumber" };
            inline constexpr FieldId IssuingCountry { CipherType::DriversLicense, "issuingCountry" };
            inline constexpr FieldId IssuingState { CipherType::DriversLicense, "issuingState" };
            inline constexpr FieldId IssueDate { CipherType::DriversLicense, "issueDate" };
            inline constexpr FieldId ExpirationDate { CipherType::DriversLicense, "expirationDate" };
            inline constexpr FieldId IssuingAuthority { CipherType::DriversLicense, "issuingAuthority" };
            inline constexpr FieldId LicenseClass { CipherType::DriversLicense, "licenseClass" };
        }

        namespace Passport {
            inline constexpr FieldId Surname { CipherType::Passport, "surname" };
            inline constexpr FieldId GivenName { CipherType::Passport, "givenName" };
            inline constexpr FieldId DateOfBirth { CipherType::Passport, "dateOfBirth" };
            inline constexpr FieldId Sex { CipherType::Passport, "sex" };
            inline constexpr FieldId BirthPlace { CipherType::Passport, "birthPlace" };
            inline constexpr FieldId Nationality { CipherType::Passport, "nationality" };
            inline constexpr FieldId IssuingCountry { CipherType::Passport, "issuingCountry" };
            inline constexpr FieldId PassportNumber { CipherType::Passport, "passportNumber" };
            inline constexpr FieldId PassportType { CipherType::Passport, "passportType" };
            inline constexpr FieldId NationalIdentificationNumber { CipherType::Passport, "nationalIdentificationNumber" };
            inline constexpr FieldId IssuingAuthority { CipherType::Passport, "issuingAuthority" };
            inline constexpr FieldId IssueDate { CipherType::Passport, "issueDate" };
            inline constexpr FieldId ExpirationDate { CipherType::Passport, "expirationDate" };
        }
    }

    struct TypeSchema {
        CipherType type;
        std::string_view section;
        std::span<const FieldId> fields;

        /*
         * Initial plaintext for every field of a new item. Some server
         * versions reject null for the newer types, so those start as
         * an encrypted empty (or, for SSH keys, single-space) string.
        */
        std::optional<std::string_view> initialValue;
    };

    /*
     * nullptr for Generic and unknown types.
    */
    const TypeSchema* SchemaFor(CipherType type);
    std::span<const TypeSchema> AllSchemas();

    /*
     * Key used inside the pre-2026.6.0 "data" blob (PascalCase).
    */
    std::string LegacyKey(std::string_view key);
}
