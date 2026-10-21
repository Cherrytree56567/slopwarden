#include "secret_store.h"

#include <keychain/keychain.h>

#include "utils/logger/logger.h"

namespace clientwarden {
    namespace {
        constexpr const char* c_package = "com.ct5.clientwarden";
        constexpr const char* c_service = "clientwarden";

        /*
         * The keychain library only speaks std::string. This is one of the allowlisted
         * boundaries: values are copied into secure memory and the temporaries wiped at once.
         */
        using KeychainString = std::string;

        void wipe_(KeychainString& s) {
            volatile char* p = s.data();
            for (size_t i = 0; i < s.size(); ++i) {
                p[i] = 0;
            }
            s.clear();
        }
    }

    std::optional<SecureString> KeychainSecretStore::get(std::string_view key) {
        keychain::Error err;
        KeychainString value =
                keychain::getPassword(c_package, c_service, KeychainString(key), err);
        SecureString out(value.begin(), value.end());
        wipe_(value);

        if (err.type != keychain::ErrorType::NoError) {
            if (err.type != keychain::ErrorType::NotFound) {
                Logger::get()->warn("Keychain read failed for '{}'", key);
            }
            return std::nullopt;
        }
        return out;
    }

    bool KeychainSecretStore::set(
            std::string_view key, std::string_view value, SecretProtection protection) {
        keychain::Error err;
        keychain::SecurityDetail detail = protection == SecretProtection::UserAuth
                                                  ? keychain::SecurityDetail::Secure
                                                  : keychain::SecurityDetail::NoPassword;

        KeychainString copy(value);
        keychain::setPassword(c_package, c_service, KeychainString(key), copy, err, detail);
        wipe_(copy);

        if (err.type != keychain::ErrorType::NoError) {
            Logger::get()->warn("Keychain write failed for '{}'", key);
            return false;
        }
        return true;
    }

    bool KeychainSecretStore::remove(std::string_view key) {
        keychain::Error err;
        keychain::deletePassword(c_package, c_service, KeychainString(key), err);
        return err.type == keychain::ErrorType::NoError ||
               err.type == keychain::ErrorType::NotFound;
    }

    std::optional<SecureString> MemorySecretStore::get(std::string_view key) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        std::map<SecureString, SecureString, std::less<>>::iterator it = m_values_.find(key);
        if (it == m_values_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool MemorySecretStore::set(std::string_view key, std::string_view value, SecretProtection) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_values_.insert_or_assign(SecureString(key), SecureString(value));
        return true;
    }

    bool MemorySecretStore::remove(std::string_view key) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        std::map<SecureString, SecureString, std::less<>>::iterator it = m_values_.find(key);
        if (it != m_values_.end()) {
            m_values_.erase(it);
        }
        return true;
    }

    ScopedSecretStore::ScopedSecretStore(std::shared_ptr<SecretStore> inner, SecureString prefix)
        : m_inner_(std::move(inner)), m_prefix_(std::move(prefix)) {}

    SecureString ScopedSecretStore::key_(std::string_view key) {
        return m_prefix_ + SecureString(key);
    }

    std::optional<SecureString> ScopedSecretStore::get(std::string_view key) {
        return m_inner_->get(key_(key));
    }

    bool ScopedSecretStore::set(
            std::string_view key, std::string_view value, SecretProtection protection) {
        return m_inner_->set(key_(key), value, protection);
    }

    bool ScopedSecretStore::remove(std::string_view key) {
        return m_inner_->remove(key_(key));
    }
}
