#pragma once
#include <string_view>

#include "items/generic_item/generic_item_type.h"
#include <ctime>
#include <optional>
#include <vector>

namespace clientwarden {
    /**
     * @brief A current TOTP code.
     */
    struct TotpCode {
        SecureString m_code;
        std::time_t m_valid_until; // when the next code starts
        int m_period;
    };

    /**
     * @brief A password the login used to have.
     */
    struct PasswordHistoryEntry {
        std::time_t m_last_used;
        SecureString m_password;
    };

    /**
     * @brief A website or app login (Bitwarden cipher type Login).
     */
    class LoginItem : public GenericItemType<LoginItem> {
    public:
        static constexpr CipherType c_type = CipherType::Login;

        using GenericItemType<LoginItem>::GenericItemType;

        /**
         * @brief Sets the username.
         *
         * @param value The new username (empty clears it)
         * @return This item, for chaining
         */
        LoginItem& setUsername(std::string_view value);

        /**
         * @brief The decrypted username.
         *
         * @return The username, or empty
         */
        SecureString getUsername() const;

        /**
         * @brief Sets the password.
         *
         * @param value The new password (empty clears it)
         * @return This item, for chaining
         */
        LoginItem& setPassword(std::string_view value);

        /**
         * @brief The decrypted password.
         *
         * @return The password, or empty
         */
        SecureString getPassword() const;

        /**
         * @brief Sets the TOTP secret (an otpauth:// URI or a bare base32 secret).
         *
         * @param secret The secret
         * @return This item, for chaining
         */
        LoginItem& setTotp(std::string_view secret);

        /**
         * @brief The decrypted TOTP secret.
         *
         * @return The secret, or empty
         */
        SecureString getTotpSecret() const;

        /**
         * @brief The TOTP code for a moment in time.
         *
         * @param now Seconds since the epoch
         * @return The code, or nullopt if there's no valid secret
         */
        std::optional<TotpCode> getTotp(std::time_t now) const;

        /**
         * @brief Adds a website, with the checksum Bitwarden uses to detect tampering.
         *
         * @param uri The URI
         * @return This item, for chaining
         */
        LoginItem& addWebsite(std::string_view uri);

        /**
         * @brief Removes the first matching website.
         *
         * @param uri The URI
         * @return This item, for chaining
         */
        LoginItem& removeWebsite(std::string_view uri);

        /**
         * @brief The decrypted websites.
         *
         * @return The URIs in order
         */
        std::vector<SecureString> getWebsites() const;

        /**
         * @brief Previous passwords, newest first (at most 5).
         *
         * @return The history
         */
        std::vector<PasswordHistoryEntry> getPasswordHistory() const;

        /**
         * @brief When each stored passkey was created.
         *
         * @return Seconds since the epoch per passkey
         */
        std::vector<std::time_t> getPasskeyCreationDates() const;
    };
}
