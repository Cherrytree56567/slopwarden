#include "SecretStore.h"

#include <keychain/keychain.h>

namespace ClientWarden {
    namespace {
        constexpr const char* Package = "com.ct5.clientwarden";
        constexpr const char* Service = "clientwarden";
    }

    std::optional<SecretString> KeychainSecretStore::Get(std::string_view key) {
        keychain::Error err;
        std::string value = keychain::getPassword(Package, Service, std::string(key), err);
        SecretString out(value.begin(), value.end());
        Wipe(value);

        if (err.type != keychain::ErrorType::NoError) {
            if (err.type != keychain::ErrorType::NotFound) {
                Log()->warn("Keychain read failed for '{}': {}", key, err.message);
            }
            return std::nullopt;
        }
        return out;
    }

    bool KeychainSecretStore::Set(std::string_view key, std::string_view value, SecretProtection protection) {
        keychain::Error err;
        auto detail = protection == SecretProtection::UserAuth ? keychain::SecurityDetail::Secure : keychain::SecurityDetail::NoPassword;
        keychain::setPassword(Package, Service, std::string(key), std::string(value), err, detail);

        if (err.type != keychain::ErrorType::NoError) {
            Log()->warn("Keychain write failed for '{}': {}", key, err.message);
            return false;
        }
        return true;
    }

    bool KeychainSecretStore::Remove(std::string_view key) {
        keychain::Error err;
        keychain::deletePassword(Package, Service, std::string(key), err);
        return err.type == keychain::ErrorType::NoError || err.type == keychain::ErrorType::NotFound;
    }

    std::optional<SecretString> MemorySecretStore::Get(std::string_view key) {
        std::lock_guard lock(mutex);
        auto it = values.find(key);
        if (it == values.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool MemorySecretStore::Set(std::string_view key, std::string_view value, SecretProtection) {
        std::lock_guard lock(mutex);
        values.insert_or_assign(std::string(key), SecretString(value.begin(), value.end()));
        return true;
    }

    bool MemorySecretStore::Remove(std::string_view key) {
        std::lock_guard lock(mutex);
        if (auto it = values.find(key); it != values.end()) {
            values.erase(it);
        }
        return true;
    }
}
