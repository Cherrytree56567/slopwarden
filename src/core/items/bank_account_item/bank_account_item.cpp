#include "bank_account_item.h"

namespace clientwarden {
    BankAccountItem& BankAccountItem::setBankName(std::string_view value) {
        setField_(fields::bank_account::c_bank_name, value);
        return *this;
    }

    SecureString BankAccountItem::getBankName() const {
        return getField_(fields::bank_account::c_bank_name);
    }

    BankAccountItem& BankAccountItem::setNameOnAccount(std::string_view value) {
        setField_(fields::bank_account::c_name_on_account, value);
        return *this;
    }

    SecureString BankAccountItem::getNameOnAccount() const {
        return getField_(fields::bank_account::c_name_on_account);
    }

    BankAccountItem& BankAccountItem::setAccountType(std::string_view value) {
        setField_(fields::bank_account::c_account_type, value);
        return *this;
    }

    SecureString BankAccountItem::getAccountType() const {
        return getField_(fields::bank_account::c_account_type);
    }

    BankAccountItem& BankAccountItem::setAccountNumber(std::string_view value) {
        setField_(fields::bank_account::c_account_number, value);
        return *this;
    }

    SecureString BankAccountItem::getAccountNumber() const {
        return getField_(fields::bank_account::c_account_number);
    }

    BankAccountItem& BankAccountItem::setRoutingNumber(std::string_view value) {
        setField_(fields::bank_account::c_routing_number, value);
        return *this;
    }

    SecureString BankAccountItem::getRoutingNumber() const {
        return getField_(fields::bank_account::c_routing_number);
    }

    BankAccountItem& BankAccountItem::setBranchNumber(std::string_view value) {
        setField_(fields::bank_account::c_branch_number, value);
        return *this;
    }

    SecureString BankAccountItem::getBranchNumber() const {
        return getField_(fields::bank_account::c_branch_number);
    }

    BankAccountItem& BankAccountItem::setPin(std::string_view value) {
        setField_(fields::bank_account::c_pin, value);
        return *this;
    }

    SecureString BankAccountItem::getPin() const {
        return getField_(fields::bank_account::c_pin);
    }

    BankAccountItem& BankAccountItem::setSwiftCode(std::string_view value) {
        setField_(fields::bank_account::c_swift_code, value);
        return *this;
    }

    SecureString BankAccountItem::getSwiftCode() const {
        return getField_(fields::bank_account::c_swift_code);
    }

    BankAccountItem& BankAccountItem::setIban(std::string_view value) {
        setField_(fields::bank_account::c_iban, value);
        return *this;
    }

    SecureString BankAccountItem::getIban() const {
        return getField_(fields::bank_account::c_iban);
    }

    BankAccountItem& BankAccountItem::setBankContactPhone(std::string_view value) {
        setField_(fields::bank_account::c_bank_contact_phone, value);
        return *this;
    }

    SecureString BankAccountItem::getBankContactPhone() const {
        return getField_(fields::bank_account::c_bank_contact_phone);
    }
}
