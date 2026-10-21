#pragma once
#include <string_view>

#include "items/generic_item/generic_item_type.h"

namespace clientwarden {
    /**
     * @brief A driver's licence (Bitwarden cipher type DriversLicense).
     */
    class DriversLicenseItem : public GenericItemType<DriversLicenseItem> {
    public:
        static constexpr CipherType c_type = CipherType::DriversLicense;

        using GenericItemType<DriversLicenseItem>::GenericItemType;

        /**
         * @brief Sets the first name.
         *
         * @param value The new first name (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setFirstName(std::string_view value);

        /**
         * @brief The decrypted first name.
         *
         * @return The first name, or empty
         */
        SecureString getFirstName() const;

        /**
         * @brief Sets the middle name.
         *
         * @param value The new middle name (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setMiddleName(std::string_view value);

        /**
         * @brief The decrypted middle name.
         *
         * @return The middle name, or empty
         */
        SecureString getMiddleName() const;

        /**
         * @brief Sets the last name.
         *
         * @param value The new last name (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setLastName(std::string_view value);

        /**
         * @brief The decrypted last name.
         *
         * @return The last name, or empty
         */
        SecureString getLastName() const;

        /**
         * @brief Sets the date of birth.
         *
         * @param value The new date of birth (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setDateOfBirth(std::string_view value);

        /**
         * @brief The decrypted date of birth.
         *
         * @return The date of birth, or empty
         */
        SecureString getDateOfBirth() const;

        /**
         * @brief Sets the license number.
         *
         * @param value The new license number (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setLicenseNumber(std::string_view value);

        /**
         * @brief The decrypted license number.
         *
         * @return The license number, or empty
         */
        SecureString getLicenseNumber() const;

        /**
         * @brief Sets the issuing country.
         *
         * @param value The new issuing country (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setIssuingCountry(std::string_view value);

        /**
         * @brief The decrypted issuing country.
         *
         * @return The issuing country, or empty
         */
        SecureString getIssuingCountry() const;

        /**
         * @brief Sets the issuing state.
         *
         * @param value The new issuing state (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setIssuingState(std::string_view value);

        /**
         * @brief The decrypted issuing state.
         *
         * @return The issuing state, or empty
         */
        SecureString getIssuingState() const;

        /**
         * @brief Sets the issue date.
         *
         * @param value The new issue date (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setIssueDate(std::string_view value);

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
        DriversLicenseItem& setExpirationDate(std::string_view value);

        /**
         * @brief The decrypted expiration date.
         *
         * @return The expiration date, or empty
         */
        SecureString getExpirationDate() const;

        /**
         * @brief Sets the issuing authority.
         *
         * @param value The new issuing authority (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setIssuingAuthority(std::string_view value);

        /**
         * @brief The decrypted issuing authority.
         *
         * @return The issuing authority, or empty
         */
        SecureString getIssuingAuthority() const;

        /**
         * @brief Sets the license class.
         *
         * @param value The new license class (empty clears it)
         * @return This item, for chaining
         */
        DriversLicenseItem& setLicenseClass(std::string_view value);

        /**
         * @brief The decrypted license class.
         *
         * @return The license class, or empty
         */
        SecureString getLicenseClass() const;
    };
}
