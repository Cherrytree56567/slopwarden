#pragma once
#include <memory>

#include "vault/store/store.h"

namespace clientwarden {
    /**
     * @brief The account owner's profile from the last sync.
     */
    class Profile {
    public:
        /**
         * @brief Reads the profile from the vault cache.
         *
         * @param store The vault cache
         */
        explicit Profile(std::shared_ptr<Store> store);

        /**
         * @brief The account display name.
         *
         * @return The name, or "Unknown"
         */
        SecureString getName() const;

        /**
         * @brief The account email.
         *
         * @return The email, or empty
         */
        SecureString getEmail() const;

        /**
         * @brief The server-side user id.
         *
         * @return The id, or empty
         */
        SecureString getUserId() const;

        /**
         * @brief Whether the account has premium features.
         *
         * @return True for premium (personal or via an organisation)
         */
        bool getPremium() const;

        /**
         * @brief The user key, wrapped with the stretched master key.
         *
         * @return The protected key, or nullopt before the first sync
         */
        std::optional<SecureString> getProtectedKey() const;

    private:
        std::shared_ptr<Store> m_store_;
    };
}
