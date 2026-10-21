#include "login_item.h"

#include <algorithm>
#include <chrono>
#include <botan/base32.h>
#include <botan/otp.h>
#include <boost/url/parse.hpp>

#include "utils/timestamp/timestamp.h"

namespace clientwarden {
    LoginItem& LoginItem::setUsername(std::string_view value) {
        setField_(fields::login::c_username, value);
        return *this;
    }

    SecureString LoginItem::getUsername() const {
        return getField_(fields::login::c_username);
    }

    LoginItem& LoginItem::setPassword(std::string_view value) {
        setField_(fields::login::c_password, value);
        return *this;
    }

    SecureString LoginItem::getPassword() const {
        return getField_(fields::login::c_password);
    }

    namespace {
        /**
         * @brief Decodes a base32 TOTP secret, tolerating spaces, dashes, lowercase and missing
         * padding.
         *
         * @param secret The secret as entered
         * @return The key bytes
         */
        SecureBytes decodeTotpSecret_(std::string_view secret) {
            SecureString cleaned;
            for (char c : secret) {
                if (c == ' ' || c == '-' || c == '=') {
                    continue;
                }
                cleaned.push_back(c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : c);
            }
            while (cleaned.size() % 8 != 0) {
                cleaned.push_back('=');
            }
            return Botan::base32_decode(std::string_view(cleaned));
        }

        /**
         * @brief Reads a timestamp member.
         *
         * @param object The JSON object
         * @param key The member name
         * @return Seconds since the epoch, or 0
         */
        std::time_t timeOf_(const Json& object, std::string_view key) {
            const Json& value = at(object, key);
            return value.is_string() ? timestamp::parse(value.get_ref<const SecureString&>()) : 0;
        }
    }

    LoginItem& LoginItem::setTotp(std::string_view secret) {
        setField_(fields::login::c_totp, secret);
        return *this;
    }

    SecureString LoginItem::getTotpSecret() const {
        return getField_(fields::login::c_totp);
    }

    std::optional<TotpCode> LoginItem::getTotp(std::time_t now) const {
        SecureString secret = getTotpSecret();
        if (secret.empty()) {
            return std::nullopt;
        }

        std::string_view algorithm = "SHA-1";
        std::int64_t digits = 6;
        std::int64_t period = 30;

        try {
            if (secret.starts_with("otpauth://")) {
                boost::system::result<boost::urls::url_view> url =
                        boost::urls::parse_uri(std::string_view(secret));
                if (!url) {
                    return std::nullopt;
                }
                SecureString uri_secret;
                for (boost::urls::param_pct_view param : url->encoded_params()) {
                    SecureString key =
                            toLower(std::string_view(param.key.data(), param.key.size()));
                    std::string_view value(param.value.data(), param.value.size());
                    if (key == "secret") {
                        uri_secret = SecureString(value);
                    } else if (key == "algorithm") {
                        SecureString name = toLower(value);
                        algorithm = name == "sha256"   ? "SHA-256"
                                    : name == "sha512" ? "SHA-512"
                                                       : "SHA-1";
                    } else if (key == "digits") {
                        std::int64_t parsed = 0;
                        if (parseInt(value, parsed)) {
                            digits = std::clamp<std::int64_t>(parsed, 6, 8);
                        }
                    } else if (key == "period") {
                        std::int64_t parsed = 0;
                        if (parseInt(value, parsed)) {
                            period = std::clamp<std::int64_t>(parsed, 1, 300);
                        }
                    }
                }
                secret = std::move(uri_secret);
            }

            SecureBytes key = decodeTotpSecret_(secret);
            if (key.empty()) {
                return std::nullopt;
            }

            Botan::TOTP totp(key.data(), key.size(), algorithm, static_cast<size_t>(digits),
                    static_cast<size_t>(period));
            uint32_t code = totp.generate_totp(std::chrono::system_clock::from_time_t(now));

            SecureString text = toSecureString(code);
            while (text.size() < static_cast<size_t>(digits)) {
                text.insert(text.begin(), '0');
            }
            return TotpCode { text, (now / period + 1) * period, static_cast<int>(period) };
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    LoginItem& LoginItem::addWebsite(std::string_view uri) {
        requireType_(CipherType::Login, "websites");
        Json& uris = section_()["uris"];
        if (!uris.is_array()) {
            uris = Json::array();
        }
        uris.push_back({ { "uri", encrypt_(uri) },
                { "uriChecksum", m_crypto_->uriChecksum(uri, m_key_) }, { "match", nullptr } });
        return *this;
    }

    LoginItem& LoginItem::removeWebsite(std::string_view uri) {
        requireType_(CipherType::Login, "websites");
        Json& login = section_();

        if (at(login, "uri").is_string() && decrypt_(login["uri"]) == uri) {
            login["uri"] = nullptr;
        }

        Json& uris = login["uris"];
        if (!uris.is_array()) {
            return *this;
        }
        for (Json::iterator it = uris.begin(); it != uris.end(); ++it) {
            if (decrypt_(at(*it, "uri")) == uri) {
                uris.erase(it);
                break;
            }
        }
        return *this;
    }

    std::vector<SecureString> LoginItem::getWebsites() const {
        requireType_(CipherType::Login, "websites");
        std::vector<SecureString> out;
        const Json& uris = at(constSection_(), "uris");
        if (!uris.is_array()) {
            return out;
        }
        for (const Json& uri : uris) {
            if (uri.is_object()) {
                out.push_back(decrypt_(at(uri, "uri")));
            }
        }
        return out;
    }

    std::vector<PasswordHistoryEntry> LoginItem::getPasswordHistory() const {
        requireType_(CipherType::Login, "password history");
        std::vector<PasswordHistoryEntry> out;
        const Json& history = at(m_data_, "passwordHistory");
        if (!history.is_array()) {
            return out;
        }
        for (const Json& entry : history) {
            if (at(entry, "password").is_string()) {
                out.push_back(PasswordHistoryEntry {
                        timeOf_(entry, "lastUsedDate"), decrypt_(at(entry, "password")) });
            }
        }
        return out;
    }

    std::vector<std::time_t> LoginItem::getPasskeyCreationDates() const {
        requireType_(CipherType::Login, "passkeys");
        std::vector<std::time_t> out;
        const Json& credentials = at(constSection_(), "fido2Credentials");
        if (!credentials.is_array()) {
            return out;
        }
        for (const Json& credential : credentials) {
            if (credential.is_object()) {
                out.push_back(timeOf_(credential, "creationDate"));
            }
        }
        return out;
    }
}
