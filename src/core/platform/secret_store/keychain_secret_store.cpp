#include "secret_store.h"

#include <keychain/keychain.h>

#include "utils/logger/logger.h"

/*
 * Kept apart from the other stores so platforms without the keychain library (the Wii) can
 * leave it out.
 */
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
            Logger::get()->warn("Keychain write failed for '{}': {}", key, err.message);
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
}
