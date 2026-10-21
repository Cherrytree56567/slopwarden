#pragma once
#include <string_view>

#include "items/generic_item/generic_item_type.h"

namespace clientwarden {
    /**
     * @brief A passport (Bitwarden cipher type Passport).
     */
    class PassportItem : public GenericItemType<PassportItem> {
    public:
        static constexpr CipherType c_type = CipherType::Passport;

        using GenericItemType<PassportItem>::GenericItemType;

        /**
         * @brief Sets the surname.
         *
         * @param value The new surname (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setSurname(std::string_view value);

        /**
         * @brief The decrypted surname.
         *
         * @return The surname, or empty
         */
        SecureString getSurname() const;

        /**
         * @brief Sets the given name.
         *
         * @param value The new given name (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setGivenName(std::string_view value);

        /**
         * @brief The decrypted given name.
         *
         * @return The given name, or empty
         */
        SecureString getGivenName() const;

        /**
         * @brief Sets the date of birth.
         *
         * @param value The new date of birth (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setDateOfBirth(std::string_view value);

        /**
         * @brief The decrypted date of birth.
         *
         * @return The date of birth, or empty
         */
        SecureString getDateOfBirth() const;

        /**
         * @brief Sets the sex.
         *
         * @param value The new sex (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setSex(std::string_view value);

        /**
         * @brief The decrypted sex.
         *
         * @return The sex, or empty
         */
        SecureString getSex() const;

        /**
         * @brief Sets the birth place.
         *
         * @param value The new birth place (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setBirthPlace(std::string_view value);

        /**
         * @brief The decrypted birth place.
         *
         * @return The birth place, or empty
         */
        SecureString getBirthPlace() const;

        /**
         * @brief Sets the nationality.
         *
         * @param value The new nationality (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setNationality(std::string_view value);

        /**
         * @brief The decrypted nationality.
         *
         * @return The nationality, or empty
         */
        SecureString getNationality() const;

        /**
         * @brief Sets the issuing country.
         *
         * @param value The new issuing country (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setIssuingCountry(std::string_view value);

        /**
         * @brief The decrypted issuing country.
         *
         * @return The issuing country, or empty
         */
        SecureString getIssuingCountry() const;

        /**
         * @brief Sets the passport number.
         *
         * @param value The new passport number (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setPassportNumber(std::string_view value);

        /**
         * @brief The decrypted passport number.
         *
         * @return The passport number, or empty
         */
        SecureString getPassportNumber() const;

        /**
         * @brief Sets the passport type.
         *
         * @param value The new passport type (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setPassportType(std::string_view value);

        /**
         * @brief The decrypted passport type.
         *
         * @return The passport type, or empty
         */
        SecureString getPassportType() const;

        /**
         * @brief Sets the national identification number.
         *
         * @param value The new national identification number (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setNationalIdentificationNumber(std::string_view value);

        /**
         * @brief The decrypted national identification number.
         *
         * @return The national identification number, or empty
         */
        SecureString getNationalIdentificationNumber() const;

        /**
         * @brief Sets the issuing authority.
         *
         * @param value The new issuing authority (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setIssuingAuthority(std::string_view value);

        /**
         * @brief The decrypted issuing authority.
         *
         * @return The issuing authority, or empty
         */
        SecureString getIssuingAuthority() const;

        /**
         * @brief Sets the issue date.
         *
         * @param value The new issue date (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setIssueDate(std::string_view value);

        /**
         * @brief The decrypted issue date.
         *
         * @return The issue date, or empty
         */
        SecureString getIssueDate() const;

        /**
         * @brief Sets the expiration date.
         *
         * @param value The new expiration date (empty clears it)
         * @return This item, for chaining
         */
        PassportItem& setExpirationDate(std::string_view value);

        /**
         * @brief The decrypted expiration date.
         *
         * @return The expiration date, or empty
         */
        SecureString getExpirationDate() const;
    };
}
