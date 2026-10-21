#pragma once
#include <stdexcept>
#include <string_view>

#include "utils/secure_string/secure_string.h"

namespace clientwarden {
    /**
     * @brief Base error for everything the vault core throws.
     *
     * Network failures are reported through return values; exceptions are reserved for
     * misuse (e.g. reading items while locked) and corrupt or tampered data.
     */
    class VaultError : public std::runtime_error {
    public:
        /**
         * @brief Creates an error with a human-readable message.
         *
         * @param message What went wrong (never include secrets)
         */
        explicit VaultError(std::string_view message)
            : std::runtime_error(SecureString(message).c_str()) {}
    };

    /**
     * @brief Raised for malformed ciphertext, authentication (MAC) failures and bad keys.
     */
    class CryptoError : public VaultError {
    public:
        /**
         * @brief Creates a crypto error.
         *
         * @param message What went wrong (never include secrets)
         */
        explicit CryptoError(std::string_view message) : VaultError(message) {}
    };
}
