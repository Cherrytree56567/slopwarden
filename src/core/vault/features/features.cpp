#include "features.h"

namespace clientwarden {
    namespace {
        constexpr std::string_view c_legacy_data_cutoff = "2026.6.0";
        constexpr std::string_view c_extended_types_version = "2026.8.1";

        /**
         * @brief Reads the next dotted component of a version.
         *
         * @param version The remaining version text; consumed up to and including the dot
         * @return The component's numeric value (non-digits are ignored)
         */
        std::int64_t nextPart_(std::string_view& version) {
            size_t dot = version.find('.');
            std::string_view part = version.substr(0, dot);
            version = dot == std::string_view::npos ? std::string_view() : version.substr(dot + 1);

            std::int64_t value = 0;
            for (char c : part) {
                if (c < '0' || c > '9') {
                    break;
                }
                value = value * 10 + (c - '0');
            }
            return value;
        }
    }

    Features::Features(std::shared_ptr<Store> store) : m_store_(std::move(store)) {}

    int Features::compareVersions(std::string_view a, std::string_view b) {
        while (!a.empty() || !b.empty()) {
            std::int64_t x = nextPart_(a);
            std::int64_t y = nextPart_(b);
            if (x != y) {
                return x < y ? -1 : 1;
            }
        }
        return 0;
    }

    bool Features::applyConfig(const Json& config) {
        SecureString version = stringAt(config, "version");
        if (version.empty()) {
            return false;
        }
        m_store_->setServerVersion(version);
        return true;
    }

    bool Features::versionKnown() const {
        return !m_store_->getServerVersion().empty();
    }

    bool Features::atLeast(std::string_view version) const {
        SecureString current = m_store_->getServerVersion();
        return !current.empty() && compareVersions(current, version) >= 0;
    }

    bool Features::needsLegacyData() const {
        return !atLeast(c_legacy_data_cutoff);
    }

    bool Features::supportsExtendedItemTypes() const {
        return atLeast(c_extended_types_version);
    }
}
