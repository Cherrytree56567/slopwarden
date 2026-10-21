#pragma once
#include <string_view>

#include "items/generic_item/generic_item_type.h"

namespace clientwarden {
    /**
     * @brief A bank account (Bitwarden cipher type BankAccount).
     */
    class BankAccountItem : public GenericItemType<BankAccountItem> {
    public:
        static constexpr CipherType c_type = CipherType::BankAccount;

        using GenericItemType<BankAccountItem>::GenericItemType;

        /**
         * @brief Sets the bank name.
         *
         * @param value The new bank name (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setBankName(std::string_view value);

        /**
         * @brief The decrypted bank name.
         *
         * @return The bank name, or empty
         */
        SecureString getBankName() const;

        /**
         * @brief Sets the name on account.
         *
         * @param value The new name on account (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setNameOnAccount(std::string_view value);

        /**
         * @brief The decrypted name on account.
         *
         * @return The name on account, or empty
         */
        SecureString getNameOnAccount() const;

        /**
         * @brief Sets the account type.
         *
         * @param value The new account type (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setAccountType(std::string_view value);

        /**
         * @brief The decrypted account type.
         *
         * @return The account type, or empty
         */
        SecureString getAccountType() const;

        /**
         * @brief Sets the account number.
         *
         * @param value The new account number (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setAccountNumber(std::string_view value);

        /**
         * @brief The decrypted account number.
         *
         * @return The account number, or empty
         */
        SecureString getAccountNumber() const;

        /**
         * @brief Sets the routing number.
         *
         * @param value The new routing number (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setRoutingNumber(std::string_view value);

        /**
         * @brief The decrypted routing number.
         *
         * @return The routing number, or empty
         */
        SecureString getRoutingNumber() const;

        /**
         * @brief Sets the branch number.
         *
         * @param value The new branch number (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setBranchNumber(std::string_view value);

        /**
         * @brief The decrypted branch number.
         *
         * @return The branch number, or empty
         */
        SecureString getBranchNumber() const;

        /**
         * @brief Sets the PIN.
         *
         * @param value The new PIN (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setPin(std::string_view value);

        /**
         * @brief The decrypted PIN.
         *
         * @return The PIN, or empty
         */
        SecureString getPin() const;

        /**
         * @brief Sets the swift code.
         *
         * @param value The new swift code (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setSwiftCode(std::string_view value);

        /**
         * @brief The decrypted swift code.
         *
         * @return The swift code, or empty
         */
        SecureString getSwiftCode() const;

        /**
         * @brief Sets the IBAN.
         *
         * @param value The new IBAN (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setIban(std::string_view value);

        /**
         * @brief The decrypted IBAN.
         *
         * @return The IBAN, or empty
         */
        SecureString getIban() const;

        /**
         * @brief Sets the bank contact phone.
         *
         * @param value The new bank contact phone (empty clears it)
         * @return This item, for chaining
         */
        BankAccountItem& setBankContactPhone(std::string_view value);

        /**
         * @brief The decrypted bank contact phone.
         *
         * @return The bank contact phone, or empty
         */
        SecureString getBankContactPhone() const;
    };
}
