#pragma once
#include <memory>
#include <string_view>
#include <vector>

#include "vault/crypto/crypto.h"

namespace clientwarden {
    /**
     * @brief Options for random passwords.
     */
    struct PasswordOptions {
        int m_length = 16;
        bool m_uppercase = true;
        bool m_numbers = true;
        bool m_symbols = false;
    };

    /**
     * @brief Password, PIN and passphrase generator.
     *
     * Everything is drawn with unbiased rejection sampling from the system CSPRNG.
     */
    class Generator {
    public:
        /**
         * @brief Creates a generator.
         *
         * @param crypto For random numbers
         * @param word_list Passphrase words, one per line (may be empty)
         */
        Generator(std::shared_ptr<Crypto> crypto, std::string_view word_list);

        /**
         * @brief A random password with at least one character of each enabled class.
         *
         * @param options Length and character classes
         * @return The password
         * @throws VaultError if the length can't fit every class or exceeds 1024
         */
        SecureString password(PasswordOptions options) const;

        /**
         * @brief A random numeric PIN.
         *
         * @param digits 4 - 64
         * @return The PIN
         */
        SecureString pin(int digits) const;

        /**
         * @brief A random passphrase from the word list.
         *
         * @param words 3 - 20
         * @param capitalize Capitalise each word
         * @param separator Between words
         * @return The passphrase
         * @throws VaultError if no word list is loaded
         */
        SecureString passphrase(int words, bool capitalize, char separator) const;

    private:
        char pick_(std::string_view set) const;

        std::shared_ptr<Crypto> m_crypto_;
        std::vector<SecureString> m_words_;
    };
}
