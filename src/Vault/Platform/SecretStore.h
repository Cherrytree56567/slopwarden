#pragma once
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include "Clientwarden.h"

namespace ClientWarden {
    enum class SecretProtection {
        None,      // readable whenever the device is unlocked
        UserAuth   // requires password or biometrics on every read
    };

    /*
     * Key/value store for credentials. Production uses the OS keychain;
     * tests use MemorySecretStore.
    */
    class SecretStore {
    public:
        virtual ~SecretStore() = default;

        virtual std::optional<SecretString> Get(std::string_view key) = 0;
        virtual bool Set(std::string_view key, std::string_view value, SecretProtection protection = SecretProtection::None) = 0;
        virtual bool Remove(std::string_view key) = 0;
    };

    class KeychainSecretStore : public SecretStore {
    public:
        std::optional<SecretString> Get(std::string_view key) override;
        bool Set(std::string_view key, std::string_view value, SecretProtection protection = SecretProtection::None) override;
        bool Remove(std::string_view key) override;
    };

    class MemorySecretStore : public SecretStore {
    public:
        std::optional<SecretString> Get(std::string_view key) override;
        bool Set(std::string_view key, std::string_view value, SecretProtection protection = SecretProtection::None) override;
        bool Remove(std::string_view key) override;

    private:
        std::mutex mutex;
        std::map<std::string, SecretString, std::less<>> values;
    };
}
