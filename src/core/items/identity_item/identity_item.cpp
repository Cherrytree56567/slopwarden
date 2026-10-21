#include "identity_item.h"

namespace clientwarden {
    IdentityItem& IdentityItem::setTitle(std::string_view value) {
        setField_(fields::identity::c_title, value);
        return *this;
    }

    SecureString IdentityItem::getTitle() const {
        return getField_(fields::identity::c_title);
    }

    IdentityItem& IdentityItem::setFirstName(std::string_view value) {
        setField_(fields::identity::c_first_name, value);
        return *this;
    }

    SecureString IdentityItem::getFirstName() const {
        return getField_(fields::identity::c_first_name);
    }

    IdentityItem& IdentityItem::setMiddleName(std::string_view value) {
        setField_(fields::identity::c_middle_name, value);
        return *this;
    }

    SecureString IdentityItem::getMiddleName() const {
        return getField_(fields::identity::c_middle_name);
    }

    IdentityItem& IdentityItem::setLastName(std::string_view value) {
        setField_(fields::identity::c_last_name, value);
        return *this;
    }

    SecureString IdentityItem::getLastName() const {
        return getField_(fields::identity::c_last_name);
    }

    IdentityItem& IdentityItem::setAddress1(std::string_view value) {
        setField_(fields::identity::c_address1, value);
        return *this;
    }

    SecureString IdentityItem::getAddress1() const {
        return getField_(fields::identity::c_address1);
    }

    IdentityItem& IdentityItem::setAddress2(std::string_view value) {
        setField_(fields::identity::c_address2, value);
        return *this;
    }

    SecureString IdentityItem::getAddress2() const {
        return getField_(fields::identity::c_address2);
    }

    IdentityItem& IdentityItem::setAddress3(std::string_view value) {
        setField_(fields::identity::c_address3, value);
        return *this;
    }

    SecureString IdentityItem::getAddress3() const {
        return getField_(fields::identity::c_address3);
    }

    IdentityItem& IdentityItem::setCity(std::string_view value) {
        setField_(fields::identity::c_city, value);
        return *this;
    }

    SecureString IdentityItem::getCity() const {
        return getField_(fields::identity::c_city);
    }

    IdentityItem& IdentityItem::setState(std::string_view value) {
        setField_(fields::identity::c_state, value);
        return *this;
    }

    SecureString IdentityItem::getState() const {
        return getField_(fields::identity::c_state);
    }

    IdentityItem& IdentityItem::setPostalCode(std::string_view value) {
        setField_(fields::identity::c_postal_code, value);
        return *this;
    }

    SecureString IdentityItem::getPostalCode() const {
        return getField_(fields::identity::c_postal_code);
    }

    IdentityItem& IdentityItem::setCountry(std::string_view value) {
        setField_(fields::identity::c_country, value);
        return *this;
    }

    SecureString IdentityItem::getCountry() const {
        return getField_(fields::identity::c_country);
    }

    IdentityItem& IdentityItem::setCompany(std::string_view value) {
        setField_(fields::identity::c_company, value);
        return *this;
    }

    SecureString IdentityItem::getCompany() const {
        return getField_(fields::identity::c_company);
    }

    IdentityItem& IdentityItem::setEmail(std::string_view value) {
        setField_(fields::identity::c_email, value);
        return *this;
    }

    SecureString IdentityItem::getEmail() const {
        return getField_(fields::identity::c_email);
    }

    IdentityItem& IdentityItem::setPhone(std::string_view value) {
        setField_(fields::identity::c_phone, value);
        return *this;
    }

    SecureString IdentityItem::getPhone() const {
        return getField_(fields::identity::c_phone);
    }

    IdentityItem& IdentityItem::setSsn(std::string_view value) {
        setField_(fields::identity::c_ssn, value);
        return *this;
    }

    SecureString IdentityItem::getSsn() const {
        return getField_(fields::identity::c_ssn);
    }

    IdentityItem& IdentityItem::setUsername(std::string_view value) {
        setField_(fields::identity::c_username, value);
        return *this;
    }

    SecureString IdentityItem::getUsername() const {
        return getField_(fields::identity::c_username);
    }

    IdentityItem& IdentityItem::setPassportNumber(std::string_view value) {
        setField_(fields::identity::c_passport_number, value);
        return *this;
    }

    SecureString IdentityItem::getPassportNumber() const {
        return getField_(fields::identity::c_passport_number);
    }

    IdentityItem& IdentityItem::setLicenseNumber(std::string_view value) {
        setField_(fields::identity::c_license_number, value);
        return *this;
    }

    SecureString IdentityItem::getLicenseNumber() const {
        return getField_(fields::identity::c_license_number);
    }
}
