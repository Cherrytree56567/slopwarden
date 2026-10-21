#pragma once
#include <memory>
#include <string_view>

#include "vault/store/store.h"

namespace clientwarden {
    /**
     * @brief What the connected server supports, based on its reported version.
     *
     * Version history that matters to the client:
     *  - 2026.6.0 removed the legacy "data" blob from ciphers
     *  - 2026.8.1 added bank account, driver's licence and passport items
     */
    class Features {
    public:
        /**
         * @brief Creates the feature check over a store that persists the version.
         *
         * @param store The vault cache
         */
        explicit Features(std::shared_ptr<Store> store);

        /**
         * @brief Records the version from /api/config.
         *
         * @param config The config response
         * @return True if it contained a version
         */
        bool applyConfig(const Json& config);

        /**
         * @brief Whether the server version has been learned.
         *
         * @return True once known
         */
        bool versionKnown() const;

        /**
         * @brief Whether the server is at least `version`.
         *
         * @param version e.g. "2026.8.1"
         * @return False if the server version is unknown
         */
        bool atLeast(std::string_view version) const;

        /**
         * @brief Whether saves must include the pre-2026.6.0 "data" blob.
         *
         * @return True for old or unknown servers
         */
        bool needsLegacyData() const;

        /**
         * @brief Whether bank account, licence and passport items are available.
         *
         * @return True from 2026.8.1
         */
        bool supportsExtendedItemTypes() const;

        /**
         * @brief Compares dotted version strings numerically.
         *
         * @param a First version
         * @param b Second version
         * @return Negative, zero or positive like strcmp
         */
        static int compareVersions(std::string_view a, std::string_view b);

    private:
        std::shared_ptr<Store> m_store_;
    };
}
