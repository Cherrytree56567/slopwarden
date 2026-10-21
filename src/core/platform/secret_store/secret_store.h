#pragma once
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>

#include "utils/secure_string/secure_string.h"

namespace clientwarden {
    /**
     * @brief How strongly a stored secret is protected by the OS.
     */
    enum class SecretProtection {
        None,    // readable whenever the device is unlocked
        UserAuth // requires password or biometrics on every read
    };

    /**
     * @brief Key/value store for credentials (the OS keychain in production).
     */
    class SecretStore {
    public:
        virtual ~SecretStore() = default;

        /**
         * @brief Reads a secret.
         *
         * @param key The entry name
         * @return The value, or nullopt if absent or unreadable
         */
        virtual std::optional<SecureString> get(std::string_view key) = 0;

        /**
         * @brief Creates or replaces a secret.
         *
         * @param key The entry name
         * @param value The secret
         * @param protection How the OS should guard it
         * @return True on success
         */
        virtual bool set(
                std::string_view key, std::string_view value, SecretProtection protection) = 0;

        /**
         * @brief Deletes a secret; succeeds if it didn't exist.
         *
         * @param key The entry name
         * @return True unless the OS refused
         */
        virtual bool remove(std::string_view key) = 0;
    };

    /**
     * @brief The OS keychain (Keychain, Credential Manager, libsecret) via the keychain library.
     */
    class KeychainSecretStore : public SecretStore {
    public:
        std::optional<SecureString> get(std::string_view key) override;
        bool set(
                std::string_view key, std::string_view value, SecretProtection protection) override;
        bool remove(std::string_view key) override;
    };

    /**
     * @brief In-memory store for tests.
     */
    class MemorySecretStore : public SecretStore {
    public:
        std::optional<SecureString> get(std::string_view key) override;
        bool set(
                std::string_view key, std::string_view value, SecretProtection protection) override;
        bool remove(std::string_view key) override;

    private:
        std::mutex m_mutex_;
        std::map<SecureString, SecureString, std::less<>> m_values_;
    };

    /**
     * @brief Namespaces another store with a key prefix, giving each vault its own entries.
     */
    class ScopedSecretStore : public SecretStore {
    public:
        /**
         * @brief Wraps a store.
         *
         * @param inner The shared underlying store
         * @param prefix Prepended to every key (empty for the legacy single-vault layout)
         */
        ScopedSecretStore(std::shared_ptr<SecretStore> inner, SecureString prefix);

        std::optional<SecureString> get(std::string_view key) override;
        bool set(
                std::string_view key, std::string_view value, SecretProtection protection) override;
        bool remove(std::string_view key) override;

    private:
        SecureString key_(std::string_view key);

        std::shared_ptr<SecretStore> m_inner_;
        SecureString m_prefix_;
    };
}
