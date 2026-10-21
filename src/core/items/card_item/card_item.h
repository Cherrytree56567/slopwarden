#pragma once
#include <string_view>

#include "items/generic_item/generic_item_type.h"

namespace clientwarden {
    /**
     * @brief A payment card (Bitwarden cipher type Card).
     */
    class CardItem : public GenericItemType<CardItem> {
    public:
        static constexpr CipherType c_type = CipherType::Card;

        using GenericItemType<CardItem>::GenericItemType;

        /**
         * @brief Sets the cardholder name.
         *
         * @param value The new cardholder name (empty clears it)
         * @return This item, for chaining
         */
        CardItem& setCardholderName(std::string_view value);

        /**
         * @brief The decrypted cardholder name.
         *
         * @return The cardholder name, or empty
         */
        SecureString getCardholderName() const;

        /**
         * @brief Sets the brand.
         *
         * @param value The new brand (empty clears it)
         * @return This item, for chaining
         */
        CardItem& setBrand(std::string_view value);

        /**
         * @brief The decrypted brand.
         *
         * @return The brand, or empty
         */
        SecureString getBrand() const;

        /**
         * @brief Sets the number.
         *
         * @param value The new number (empty clears it)
         * @return This item, for chaining
         */
        CardItem& setNumber(std::string_view value);

        /**
         * @brief The decrypted number.
         *
         * @return The number, or empty
         */
        SecureString getNumber() const;

        /**
         * @brief Sets the exp month.
         *
         * @param value The new exp month (empty clears it)
         * @return This item, for chaining
         */
        CardItem& setExpMonth(std::string_view value);

        /**
         * @brief The decrypted exp month.
         *
         * @return The exp month, or empty
         */
        SecureString getExpMonth() const;

        /**
         * @brief Sets the exp year.
         *
         * @param value The new exp year (empty clears it)
         * @return This item, for chaining
         */
        CardItem& setExpYear(std::string_view value);

        /**
         * @brief The decrypted exp year.
         *
         * @return The exp year, or empty
         */
        SecureString getExpYear() const;

        /**
         * @brief Sets the code.
         *
         * @param value The new code (empty clears it)
         * @return This item, for chaining
         */
        CardItem& setCode(std::string_view value);

        /**
         * @brief The decrypted code.
         *
         * @return The code, or empty
         */
        SecureString getCode() const;
    };
}
