#include "card_item.h"

namespace clientwarden {
    CardItem& CardItem::setCardholderName(std::string_view value) {
        setField_(fields::card::c_cardholder_name, value);
        return *this;
    }

    SecureString CardItem::getCardholderName() const {
        return getField_(fields::card::c_cardholder_name);
    }

    CardItem& CardItem::setBrand(std::string_view value) {
        setField_(fields::card::c_brand, value);
        return *this;
    }

    SecureString CardItem::getBrand() const {
        return getField_(fields::card::c_brand);
    }

    CardItem& CardItem::setNumber(std::string_view value) {
        setField_(fields::card::c_number, value);
        return *this;
    }

    SecureString CardItem::getNumber() const {
        return getField_(fields::card::c_number);
    }

    CardItem& CardItem::setExpMonth(std::string_view value) {
        setField_(fields::card::c_exp_month, value);
        return *this;
    }

    SecureString CardItem::getExpMonth() const {
        return getField_(fields::card::c_exp_month);
    }

    CardItem& CardItem::setExpYear(std::string_view value) {
        setField_(fields::card::c_exp_year, value);
        return *this;
    }

    SecureString CardItem::getExpYear() const {
        return getField_(fields::card::c_exp_year);
    }

    CardItem& CardItem::setCode(std::string_view value) {
        setField_(fields::card::c_code, value);
        return *this;
    }

    SecureString CardItem::getCode() const {
        return getField_(fields::card::c_code);
    }
}
