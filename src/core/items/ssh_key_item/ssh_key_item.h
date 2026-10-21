#pragma once
#include <string_view>

#include "items/generic_item/generic_item_type.h"

namespace clientwarden {
    /**
     * @brief An SSH key pair (Bitwarden cipher type SshKey).
     */
    class SshKeyItem : public GenericItemType<SshKeyItem> {
    public:
        static constexpr CipherType c_type = CipherType::SshKey;

        using GenericItemType<SshKeyItem>::GenericItemType;

        /**
         * @brief Sets the private key.
         *
         * @param value The new private key (empty clears it)
         * @return This item, for chaining
         */
        SshKeyItem& setPrivateKey(std::string_view value);

        /**
         * @brief The decrypted private key.
         *
         * @return The private key, or empty
         */
        SecureString getPrivateKey() const;

        /**
         * @brief Sets the public key.
         *
         * @param value The new public key (empty clears it)
         * @return This item, for chaining
         */
        SshKeyItem& setPublicKey(std::string_view value);

        /**
         * @brief The decrypted public key.
         *
         * @return The public key, or empty
         */
        SecureString getPublicKey() const;

        /**
         * @brief Sets the fingerprint.
         *
         * @param value The new fingerprint (empty clears it)
         * @return This item, for chaining
         */
        SshKeyItem& setFingerprint(std::string_view value);

        /**
         * @brief The decrypted fingerprint.
         *
         * @return The fingerprint, or empty
         */
        SecureString getFingerprint() const;
    };
}
