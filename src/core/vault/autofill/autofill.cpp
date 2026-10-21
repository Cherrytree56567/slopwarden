#include "autofill.h"

#include <array>
#include <regex>

#include "items/login_item/login_item.h"
#include "utils/logger/logger.h"

namespace clientwarden {
    namespace {
        /*
         * Common multi-label public suffixes. A full Public Suffix List would be exact; this
         * covers the suffixes most sites use so "Domain" matching doesn't treat every
         * example.co.uk site as the same domain.
         */
        // clang-format off
        constexpr std::array<std::string_view, 34> c_two_label_suffixes = {
            "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
            "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
            "co.jp", "ne.jp", "or.jp", "co.in", "net.in", "org.in", "com.br", "net.br",
            "com.cn", "net.cn", "com.mx", "co.za", "com.sg", "com.tr", "com.hk", "com.tw",
            "co.kr", "com.ar"
        };
        // clang-format on

        /**
         * @brief Splits a URL into lowercased "host:port" and host, assuming http:// when the
         * saved URI has no scheme (as Bitwarden does).
         *
         * @param url The URL
         * @param authority Receives host[:port]
         * @param host Receives the host alone
         * @return False if there's no host
         */
        bool split_(std::string_view url, SecureString& authority, SecureString& host) {
            size_t scheme = url.find("://");
            if (scheme != std::string_view::npos) {
                url.remove_prefix(scheme + 3);
            }
            size_t at_sign = url.find('@');
            size_t end = url.find_first_of("/?#");
            if (at_sign != std::string_view::npos && at_sign < end) {
                url.remove_prefix(at_sign + 1); // drop user:pass@
                end = url.find_first_of("/?#");
            }

            authority = toLower(url.substr(0, end));
            host = authority.substr(0, authority.find(':'));
            return !host.empty();
        }

        /**
         * @brief Whether a host is an IPv4 address (no base domain to compute).
         *
         * @param host The host
         * @return True for dotted digits
         */
        bool isIpAddress_(std::string_view host) {
            return !host.empty() && host.find_first_not_of("0123456789.") == std::string_view::npos;
        }
    }

    AutoFill::AutoFill(std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Store> store)
        : m_orchestrator_(std::move(orchestrator)), m_store_(std::move(store)) {}

    SecureString AutoFill::baseDomain(std::string_view host) {
        if (isIpAddress_(host)) {
            return SecureString(host);
        }

        size_t last = host.rfind('.');
        if (last == std::string_view::npos) {
            return SecureString(host);
        }
        size_t second = host.rfind('.', last - 1);
        if (second == std::string_view::npos) {
            return SecureString(host);
        }

        std::string_view suffix = host.substr(second + 1);
        for (std::string_view known : c_two_label_suffixes) {
            if (suffix == known) {
                size_t third = host.rfind('.', second - 1);
                return SecureString(
                        third == std::string_view::npos ? host : host.substr(third + 1));
            }
        }
        return SecureString(suffix);
    }

    bool AutoFill::uriMatches(std::string_view saved, std::string_view page, UriMatch match,
            const std::vector<SecureString>& equivalent) {
        switch (match) {
        case UriMatch::Never: return false;
        case UriMatch::Exact: return saved == page;
        case UriMatch::StartsWith: return page.starts_with(saved);
        case UriMatch::RegularExpression:
            try {
                std::regex pattern(
                        saved.begin(), saved.end(), std::regex::ECMAScript | std::regex::icase);
                return std::regex_search(page.begin(), page.end(), pattern);
            } catch (const std::regex_error&) {
                return false;
            }
        case UriMatch::Host:
        case UriMatch::Domain: break;
        }

        SecureString saved_authority;
        SecureString saved_host;
        SecureString page_authority;
        SecureString page_host;
        if (!split_(saved, saved_authority, saved_host) ||
                !split_(page, page_authority, page_host)) {
            return false;
        }
        if (match == UriMatch::Host) {
            return saved_authority == page_authority;
        }

        SecureString page_base = baseDomain(page_host);
        if (baseDomain(saved_host) == page_base) {
            return true;
        }
        return std::find(equivalent.begin(), equivalent.end(), page_base) != equivalent.end();
    }

    std::vector<SecureString> AutoFill::equivalentDomains_(std::string_view base) {
        std::vector<SecureString> out;
        Json domains = m_store_->getSection("domains");

        std::function<void(const Json&)> consider = [&out, base](const Json& group) {
            if (!group.is_array()) {
                return;
            }
            bool contains = false;
            for (const Json& domain : group) {
                if (domain.is_string() && domain.get<SecureString>() == base) {
                    contains = true;
                }
            }
            if (contains) {
                for (const Json& domain : group) {
                    if (domain.is_string()) {
                        out.push_back(domain.get<SecureString>());
                    }
                }
            }
        };

        for (const Json& group : at(domains, "equivalentDomains")) {
            consider(group);
        }
        for (const Json& global : at(domains, "globalEquivalentDomains")) {
            const Json& excluded = at(global, "excluded");
            if (!(excluded.is_boolean() && excluded.get<bool>())) {
                consider(at(global, "domains"));
            }
        }
        return out;
    }

    std::vector<SecureString> AutoFill::matchingLogins(std::string_view url, bool passkeys_only) {
        CipherQuery query = m_orchestrator_->query();
        query.notInBin().notArchived().ofType(CipherType::Login);
        if (passkeys_only) {
            query.withPasskey();
        }

        std::vector<SecureString> matched;
        for (SecureString& id : query.ids()) {
            try {
                std::shared_ptr<LoginItem> login = m_orchestrator_->getItem<LoginItem>(id);
                std::vector<SecureString> websites = login->getWebsites();
                Json cipher = login->getJson(); // keep alive: uris refers into it
                const Json& uris = at(at(cipher, "login"), "uris");

                for (size_t i = 0; i < websites.size(); ++i) {
                    UriMatch rule = UriMatch::Domain;
                    if (uris.is_array() && i < uris.size() &&
                            at(uris[i], "match").is_number_integer()) {
                        rule = static_cast<UriMatch>(at(uris[i], "match").get<int>());
                    }

                    SecureString authority;
                    SecureString host;
                    std::vector<SecureString> equivalent;
                    if (rule == UriMatch::Domain && split_(websites[i], authority, host)) {
                        equivalent = equivalentDomains_(baseDomain(host));
                    }

                    if (uriMatches(websites[i], url, rule, equivalent)) {
                        matched.push_back(id);
                        break;
                    }
                }
            } catch (const VaultError& e) {
                Logger::get()->warn("Skipping login during autofill matching: {}", e.what());
            }
        }
        return matched;
    }
}
