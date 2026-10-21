#pragma once
#include <string_view>

#include "items/generic_item/generic_item_type.h"

namespace clientwarden {
    /**
     * @brief Personal identity details (Bitwarden cipher type Identity).
     */
    class IdentityItem : public GenericItemType<IdentityItem> {
    public:
        static constexpr CipherType c_type = CipherType::Identity;

        using GenericItemType<IdentityItem>::GenericItemType;

        /**
         * @brief Sets the title.
         *
         * @param value The new title (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setTitle(std::string_view value);

        /**
         * @brief The decrypted title.
         *
         * @return The title, or empty
         */
        SecureString getTitle() const;

        /**
         * @brief Sets the first name.
         *
         * @param value The new first name (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setFirstName(std::string_view value);

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
        IdentityItem& setMiddleName(std::string_view value);

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
        IdentityItem& setLastName(std::string_view value);

        /**
         * @brief The decrypted last name.
         *
         * @return The last name, or empty
         */
        SecureString getLastName() const;

        /**
         * @brief Sets the first address line.
         *
         * @param value The new first address line (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setAddress1(std::string_view value);

        /**
         * @brief The decrypted first address line.
         *
         * @return The first address line, or empty
         */
        SecureString getAddress1() const;

        /**
         * @brief Sets the second address line.
         *
         * @param value The new second address line (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setAddress2(std::string_view value);

        /**
         * @brief The decrypted second address line.
         *
         * @return The second address line, or empty
         */
        SecureString getAddress2() const;

        /**
         * @brief Sets the third address line.
         *
         * @param value The new third address line (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setAddress3(std::string_view value);

        /**
         * @brief The decrypted third address line.
         *
         * @return The third address line, or empty
         */
        SecureString getAddress3() const;

        /**
         * @brief Sets the city.
         *
         * @param value The new city (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setCity(std::string_view value);

        /**
         * @brief The decrypted city.
         *
         * @return The city, or empty
         */
        SecureString getCity() const;

        /**
         * @brief Sets the state.
         *
         * @param value The new state (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setState(std::string_view value);

        /**
         * @brief The decrypted state.
         *
         * @return The state, or empty
         */
        SecureString getState() const;

        /**
         * @brief Sets the postal code.
         *
         * @param value The new postal code (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setPostalCode(std::string_view value);

        /**
         * @brief The decrypted postal code.
         *
         * @return The postal code, or empty
         */
        SecureString getPostalCode() const;

        /**
         * @brief Sets the country.
         *
         * @param value The new country (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setCountry(std::string_view value);

        /**
         * @brief The decrypted country.
         *
         * @return The country, or empty
         */
        SecureString getCountry() const;

        /**
         * @brief Sets the company.
         *
         * @param value The new company (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setCompany(std::string_view value);

        /**
         * @brief The decrypted company.
         *
         * @return The company, or empty
         */
        SecureString getCompany() const;

        /**
         * @brief Sets the email.
         *
         * @param value The new email (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setEmail(std::string_view value);

        /**
         * @brief The decrypted email.
         *
         * @return The email, or empty
         */
        SecureString getEmail() const;

        /**
         * @brief Sets the phone.
         *
         * @param value The new phone (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setPhone(std::string_view value);

        /**
         * @brief The decrypted phone.
         *
         * @return The phone, or empty
         */
        SecureString getPhone() const;

        /**
         * @brief Sets the social security number.
         *
         * @param value The new social security number (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setSsn(std::string_view value);

        /**
         * @brief The decrypted social security number.
         *
         * @return The social security number, or empty
         */
        SecureString getSsn() const;

        /**
         * @brief Sets the username.
         *
         * @param value The new username (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setUsername(std::string_view value);

        /**
         * @brief The decrypted username.
         *
         * @return The username, or empty
         */
        SecureString getUsername() const;

        /**
         * @brief Sets the passport number.
         *
         * @param value The new passport number (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setPassportNumber(std::string_view value);

        /**
         * @brief The decrypted passport number.
         *
         * @return The passport number, or empty
         */
        SecureString getPassportNumber() const;

        /**
         * @brief Sets the license number.
         *
         * @param value The new license number (empty clears it)
         * @return This item, for chaining
         */
        IdentityItem& setLicenseNumber(std::string_view value);

        /**
         * @brief The decrypted license number.
         *
         * @return The license number, or empty
         */
        SecureString getLicenseNumber() const;
    };
}
