#pragma once
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "vault/orchestrator/orchestrator.h"
#include "vault/store/store.h"

namespace clientwarden {
    /**
     * @brief How a saved URI is compared with the page being filled.
     * See https://bitwarden.com/help/uri-match-detection/
     */
    enum class UriMatch {
        Domain = 0,
        Host = 1,
        StartsWith = 2,
        Exact = 3,
        RegularExpression = 4,
        Never = 5
    };

    /**
     * @brief Finds the logins that should be offered for a page, following Bitwarden's URI
     * match rules and equivalent domains (from the synced "domains" settings).
     */
    class AutoFill {
    public:
        /**
         * @brief Creates the matcher.
         *
         * @param orchestrator For querying and loading logins
         * @param store For the equivalent-domains settings
         */
        AutoFill(std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Store> store);

        /**
         * @brief Ids of usable logins matching a page.
         *
         * @param url The page URL
         * @param passkeys_only Only logins that hold a passkey
         * @return Matching cipher ids
         */
        std::vector<SecureString> matchingLogins(std::string_view url, bool passkeys_only);

        /**
         * @brief Whether one saved URI matches a page.
         *
         * @param saved The saved URI
         * @param page The page URL
         * @param match The rule (Domain if the login doesn't set one)
         * @param equivalent Extra base domains treated as the same site
         * @return True on a match
         */
        static bool uriMatches(std::string_view saved, std::string_view page, UriMatch match,
                const std::vector<SecureString>& equivalent);

        /**
         * @brief The registrable ("base") domain of a host, e.g. accounts.google.co.uk ->
         * google.co.uk.
         *
         * @param host A lowercased hostname
         * @return The base domain
         */
        static SecureString baseDomain(std::string_view host);

    private:
        std::vector<SecureString> equivalentDomains_(std::string_view base);

        std::shared_ptr<Orchestrator> m_orchestrator_;
        std::shared_ptr<Store> m_store_;
    };
}
