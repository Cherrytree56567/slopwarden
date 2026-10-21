#include "profile.h"

namespace clientwarden {
    namespace {
        /**
         * @brief Reads a boolean member.
         *
         * @param json The object
         * @param key The member name
         * @return The value, or false if missing or not a boolean
         */
        bool boolAt_(const Json& json, std::string_view key) {
            const Json& value = at(json, key);
            return value.is_boolean() && value.get<bool>();
        }
    }

    Profile::Profile(std::shared_ptr<Store> store) : m_store_(std::move(store)) {}

    SecureString Profile::getName() const {
        SecureString name = stringAt(m_store_->getProfile(), "name");
        return name.empty() ? SecureString("Unknown") : name;
    }

    SecureString Profile::getEmail() const {
        return stringAt(m_store_->getProfile(), "email");
    }

    SecureString Profile::getUserId() const {
        return stringAt(m_store_->getProfile(), "id");
    }

    bool Profile::getPremium() const {
        Json profile = m_store_->getProfile();
        return boolAt_(profile, "premium") || boolAt_(profile, "premiumFromOrganization");
    }

    std::optional<SecureString> Profile::getProtectedKey() const {
        SecureString key = stringAt(m_store_->getProfile(), "key");
        if (key.empty()) {
            return std::nullopt;
        }
        return key;
    }
}
