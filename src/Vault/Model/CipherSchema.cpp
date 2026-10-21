#include "CipherSchema.h"

#include <array>
#include <cctype>

namespace ClientWarden {
    namespace {
        namespace F = Fields;

        constexpr std::array LoginFields { F::Login::Username, F::Login::Password, F::Login::Totp };

        constexpr std::array CardFields {
            F::Card::CardholderName, F::Card::Brand, F::Card::Number, F::Card::ExpMonth, F::Card::ExpYear, F::Card::Code
        };

        constexpr std::array IdentityFields {
            F::Identity::Title, F::Identity::FirstName, F::Identity::MiddleName, F::Identity::LastName,
            F::Identity::Address1, F::Identity::Address2, F::Identity::Address3, F::Identity::City,
            F::Identity::State, F::Identity::PostalCode, F::Identity::Country, F::Identity::Company,
            F::Identity::Email, F::Identity::Phone, F::Identity::SSN, F::Identity::Username,
            F::Identity::PassportNumber, F::Identity::LicenseNumber
        };

        constexpr std::array<FieldId, 0> NoteFields {};

        constexpr std::array SSHKeyFields { F::SSHKey::PrivateKey, F::SSHKey::PublicKey, F::SSHKey::Fingerprint };

        constexpr std::array BankAccountFields {
            F::BankAccount::BankName, F::BankAccount::NameOnAccount, F::BankAccount::AccountType,
            F::BankAccount::AccountNumber, F::BankAccount::RoutingNumber, F::BankAccount::BranchNumber,
            F::BankAccount::Pin, F::BankAccount::SwiftCode, F::BankAccount::Iban, F::BankAccount::BankContactPhone
        };

        constexpr std::array DriversLicenseFields {
            F::DriversLicense::FirstName, F::DriversLicense::MiddleName, F::DriversLicense::LastName,
            F::DriversLicense::DateOfBirth, F::DriversLicense::LicenseNumber, F::DriversLicense::IssuingCountry,
            F::DriversLicense::IssuingState, F::DriversLicense::IssueDate, F::DriversLicense::ExpirationDate,
            F::DriversLicense::IssuingAuthority, F::DriversLicense::LicenseClass
        };

        constexpr std::array PassportFields {
            F::Passport::Surname, F::Passport::GivenName, F::Passport::DateOfBirth, F::Passport::Sex,
            F::Passport::BirthPlace, F::Passport::Nationality, F::Passport::IssuingCountry,
            F::Passport::PassportNumber, F::Passport::PassportType, F::Passport::NationalIdentificationNumber,
            F::Passport::IssuingAuthority, F::Passport::IssueDate, F::Passport::ExpirationDate
        };

        const std::array Schemas {
            TypeSchema { CipherType::Login, "login", LoginFields, std::nullopt },
            TypeSchema { CipherType::Note, "secureNote", NoteFields, std::nullopt },
            TypeSchema { CipherType::Card, "card", CardFields, std::nullopt },
            TypeSchema { CipherType::Identity, "identity", IdentityFields, std::nullopt },
            TypeSchema { CipherType::SSHKey, "sshKey", SSHKeyFields, " " },
            TypeSchema { CipherType::BankAccount, "bankAccount", BankAccountFields, "" },
            TypeSchema { CipherType::DriversLicense, "driversLicense", DriversLicenseFields, "" },
            TypeSchema { CipherType::Passport, "passport", PassportFields, "" },
        };
    }

    const TypeSchema* SchemaFor(CipherType type) {
        for (const auto& schema : Schemas) {
            if (schema.type == type) {
                return &schema;
            }
        }
        return nullptr;
    }

    std::span<const TypeSchema> AllSchemas() {
        return Schemas;
    }

    std::string LegacyKey(std::string_view key) {
        if (key == "ssn") {
            return "SSN";
        }
        std::string out(key);
        if (!out.empty()) {
            out[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[0])));
        }
        return out;
    }
}
