#include "passport_item.h"

namespace clientwarden {
    PassportItem& PassportItem::setSurname(std::string_view value) {
        setField_(fields::passport::c_surname, value);
        return *this;
    }

    SecureString PassportItem::getSurname() const {
        return getField_(fields::passport::c_surname);
    }

    PassportItem& PassportItem::setGivenName(std::string_view value) {
        setField_(fields::passport::c_given_name, value);
        return *this;
    }

    SecureString PassportItem::getGivenName() const {
        return getField_(fields::passport::c_given_name);
    }

    PassportItem& PassportItem::setDateOfBirth(std::string_view value) {
        setField_(fields::passport::c_date_of_birth, value);
        return *this;
    }

    SecureString PassportItem::getDateOfBirth() const {
        return getField_(fields::passport::c_date_of_birth);
    }

    PassportItem& PassportItem::setSex(std::string_view value) {
        setField_(fields::passport::c_sex, value);
        return *this;
    }

    SecureString PassportItem::getSex() const {
        return getField_(fields::passport::c_sex);
    }

    PassportItem& PassportItem::setBirthPlace(std::string_view value) {
        setField_(fields::passport::c_birth_place, value);
        return *this;
    }

    SecureString PassportItem::getBirthPlace() const {
        return getField_(fields::passport::c_birth_place);
    }

    PassportItem& PassportItem::setNationality(std::string_view value) {
        setField_(fields::passport::c_nationality, value);
        return *this;
    }

    SecureString PassportItem::getNationality() const {
        return getField_(fields::passport::c_nationality);
    }

    PassportItem& PassportItem::setIssuingCountry(std::string_view value) {
        setField_(fields::passport::c_issuing_country, value);
        return *this;
    }

    SecureString PassportItem::getIssuingCountry() const {
        return getField_(fields::passport::c_issuing_country);
    }

    PassportItem& PassportItem::setPassportNumber(std::string_view value) {
        setField_(fields::passport::c_passport_number, value);
        return *this;
    }

    SecureString PassportItem::getPassportNumber() const {
        return getField_(fields::passport::c_passport_number);
    }

    PassportItem& PassportItem::setPassportType(std::string_view value) {
        setField_(fields::passport::c_passport_type, value);
        return *this;
    }

    SecureString PassportItem::getPassportType() const {
        return getField_(fields::passport::c_passport_type);
    }

    PassportItem& PassportItem::setNationalIdentificationNumber(std::string_view value) {
        setField_(fields::passport::c_national_identification_number, value);
        return *this;
    }

    SecureString PassportItem::getNationalIdentificationNumber() const {
        return getField_(fields::passport::c_national_identification_number);
    }

    PassportItem& PassportItem::setIssuingAuthority(std::string_view value) {
        setField_(fields::passport::c_issuing_authority, value);
        return *this;
    }

    SecureString PassportItem::getIssuingAuthority() const {
        return getField_(fields::passport::c_issuing_authority);
    }

    PassportItem& PassportItem::setIssueDate(std::string_view value) {
        setField_(fields::passport::c_issue_date, value);
        return *this;
    }

    SecureString PassportItem::getIssueDate() const {
        return getField_(fields::passport::c_issue_date);
    }

    PassportItem& PassportItem::setExpirationDate(std::string_view value) {
        setField_(fields::passport::c_expiration_date, value);
        return *this;
    }

    SecureString PassportItem::getExpirationDate() const {
        return getField_(fields::passport::c_expiration_date);
    }
}
