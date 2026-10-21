#pragma once
#include <memory>

#include "items/generic_item/generic_item.h"
#include "utils/errors/errors.h"
#include "vault/crypto/crypto.h"

namespace clientwarden::testing {
    /**
     * @brief Shared crypto and user key for item tests, which build items without a vault.
     */
    class ItemFixture {
    public:
        /**
         * @brief The process-wide crypto instance.
         *
         * @return The crypto
         */
        static std::shared_ptr<Crypto> crypto() {
            static std::shared_ptr<Crypto> s_crypto = std::make_shared<Crypto>();
            return s_crypto;
        }

        /**
         * @brief A user key shared by every item test.
         *
         * @return The key
         */
        static SymmetricKey userKey() {
            static SymmetricKey s_key = SymmetricKey::generate();
            return s_key;
        }

        /**
         * @brief A fresh, unattached item of type T.
         *
         * @tparam T LoginItem, CardItem, ...
         * @return The item
         */
        template <typename T>
        static std::shared_ptr<T> create() {
            SymmetricKey key;
            Json cipher = GenericItem::createJson(T::c_type, crypto(), userKey(), key);
            return std::make_shared<T>(nullptr, crypto(), std::move(cipher), std::move(key));
        }

        /**
         * @brief Rebuilds an item from its encrypted JSON, unwrapping the item key with the
         * user key, to prove nothing was kept in plaintext on the side.
         *
         * @tparam T LoginItem, CardItem, ...
         * @param cipher The encrypted cipher
         * @return The reloaded item
         */
        template <typename T>
        static std::shared_ptr<T> reload(Json cipher) {
            const Json& key = at(cipher, "key");
            SymmetricKey item_key = key.is_string()
                ? crypto()->unwrapKey(key.get_ref<const SecureString&>(), userKey())
                : userKey();
            return std::make_shared<T>(nullptr, crypto(), std::move(cipher), std::move(item_key));
        }
    };
}
