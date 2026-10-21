#include "drivers_license_item.h"

namespace clientwarden {
    DriversLicenseItem& DriversLicenseItem::setFirstName(std::string_view value) {
        setField_(fields::drivers_license::c_first_name, value);
        return *this;
    }

    SecureString DriversLicenseItem::getFirstName() const {
        return getField_(fields::drivers_license::c_first_name);
    }

    DriversLicenseItem& DriversLicenseItem::setMiddleName(std::string_view value) {
        setField_(fields::drivers_license::c_middle_name, value);
        return *this;
    }

    SecureString DriversLicenseItem::getMiddleName() const {
        return getField_(fields::drivers_license::c_middle_name);
    }

    DriversLicenseItem& DriversLicenseItem::setLastName(std::string_view value) {
        setField_(fields::drivers_license::c_last_name, value);
        return *this;
    }

    SecureString DriversLicenseItem::getLastName() const {
        return getField_(fields::drivers_license::c_last_name);
    }

    DriversLicenseItem& DriversLicenseItem::setDateOfBirth(std::string_view value) {
        setField_(fields::drivers_license::c_date_of_birth, value);
        return *this;
    }

    SecureString DriversLicenseItem::getDateOfBirth() const {
        return getField_(fields::drivers_license::c_date_of_birth);
    }

    DriversLicenseItem& DriversLicenseItem::setLicenseNumber(std::string_view value) {
        setField_(fields::drivers_license::c_license_number, value);
        return *this;
    }

    SecureString DriversLicenseItem::getLicenseNumber() const {
        return getField_(fields::drivers_license::c_license_number);
    }

    DriversLicenseItem& DriversLicenseItem::setIssuingCountry(std::string_view value) {
        setField_(fields::drivers_license::c_issuing_country, value);
        return *this;
    }

    SecureString DriversLicenseItem::getIssuingCountry() const {
        return getField_(fields::drivers_license::c_issuing_country);
    }

    DriversLicenseItem& DriversLicenseItem::setIssuingState(std::string_view value) {
        setField_(fields::drivers_license::c_issuing_state, value);
        return *this;
    }

    SecureString DriversLicenseItem::getIssuingState() const {
        return getField_(fields::drivers_license::c_issuing_state);
    }

    DriversLicenseItem& DriversLicenseItem::setIssueDate(std::string_view value) {
        setField_(fields::drivers_license::c_issue_date, value);
        return *this;
    }

    SecureString DriversLicenseItem::getIssueDate() const {
        return getField_(fields::drivers_license::c_issue_date);
    }

    DriversLicenseItem& DriversLicenseItem::setExpirationDate(std::string_view value) {
        setField_(fields::drivers_license::c_expiration_date, value);
        return *this;
    }

    SecureString DriversLicenseItem::getExpirationDate() const {
        return getField_(fields::drivers_license::c_expiration_date);
    }

    DriversLicenseItem& DriversLicenseItem::setIssuingAuthority(std::string_view value) {
        setField_(fields::drivers_license::c_issuing_authority, value);
        return *this;
    }

    SecureString DriversLicenseItem::getIssuingAuthority() const {
        return getField_(fields::drivers_license::c_issuing_authority);
    }

    DriversLicenseItem& DriversLicenseItem::setLicenseClass(std::string_view value) {
        setField_(fields::drivers_license::c_license_class, value);
        return *this;
    }

    SecureString DriversLicenseItem::getLicenseClass() const {
        return getField_(fields::drivers_license::c_license_class);
    }
}
