#include "secret_store.h"

#include <keychain/keychain.h>

#include "utils/logger/logger.h"

namespace clientwarden {
    namespace {
        constexpr const char* c_package = "com.ct5.clientwarden";
        constexpr const char* c_service = "clientwarden";

        /*
         * The keychain library only speaks std::string. This is one of the allowlisted
         * boundaries: values are copied into secure memory and the temporaries wiped at once.
         */
        using KeychainString = std::string;

        void wipe_(KeychainString& s) {
            volatile char* p = s.data();
            for (size_t i = 0; i < s.size(); ++i) {
                p[i] = 0;
            }
            s.clear();
        }
    }

    std::optional<SecureString> KeychainSecretStore::get(std::string_view key) {
        keychain::Error err;
        KeychainString value =
                keychain::getPassword(c_package, c_service, KeychainString(key), err);
        SecureString out(value.begin(), value.end());
        wipe_(value);

        if (err.type != keychain::ErrorType::NoError) {
            if (err.type != keychain::ErrorType::NotFound) {
                Logger::get()->warn("Keychain read failed for '{}'", key);
            }
            return std::nullopt;
        }
        return out;
    }

    bool KeychainSecretStore::set(
            std::string_view key, std::string_view value, SecretProtection protection) {
        keychain::Error err;
        keychain::SecurityDetail detail = protection == SecretProtection::UserAuth
                                                  ? keychain::SecurityDetail::Secure
                                                  : keychain::SecurityDetail::NoPassword;

        KeychainString copy(value);
        keychain::setPassword(c_package, c_service, KeychainString(key), copy, err, detail);
        wipe_(copy);

        if (err.type != keychain::ErrorType::NoError) {
            Logger::get()->warn("Keychain write failed for '{}': {}", key, err.message);
            return false;
        }
        return true;
    }

    bool KeychainSecretStore::remove(std::string_view key) {
        keychain::Error err;
        keychain::deletePassword(c_package, c_service, KeychainString(key), err);
        return err.type == keychain::ErrorType::NoError ||
               err.type == keychain::ErrorType::NotFound;
    }

    std::optional<SecureString> MemorySecretStore::get(std::string_view key) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        std::map<SecureString, SecureString, std::less<>>::iterator it = m_values_.find(key);
        if (it == m_values_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool MemorySecretStore::set(std::string_view key, std::string_view value, SecretProtection) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        m_values_.insert_or_assign(SecureString(key), SecureString(value));
        return true;
    }

    bool MemorySecretStore::remove(std::string_view key) {
        std::lock_guard<std::mutex> lock(m_mutex_);
        std::map<SecureString, SecureString, std::less<>>::iterator it = m_values_.find(key);
        if (it != m_values_.end()) {
            m_values_.erase(it);
        }
        return true;
    }

    ScopedSecretStore::ScopedSecretStore(std::shared_ptr<SecretStore> inner, SecureString prefix)
        : m_inner_(std::move(inner)), m_prefix_(std::move(prefix)) {}

    SecureString ScopedSecretStore::key_(std::string_view key) {
        return m_prefix_ + SecureString(key);
    }

    std::optional<SecureString> ScopedSecretStore::get(std::string_view key) {
        return m_inner_->get(key_(key));
    }

    bool ScopedSecretStore::set(
            std::string_view key, std::string_view value, SecretProtection protection) {
        return m_inner_->set(key_(key), value, protection);
    }

    bool ScopedSecretStore::remove(std::string_view key) {
        return m_inner_->remove(key_(key));
    }

    namespace {
        /*
         * Starts the marker stored in place of a chunked value. Stored values are text (JSON or
         * base64), so they never start with \x01; a value that did would be chunked anyway.
         */
        constexpr std::string_view c_chunk_marker = "\x01cw-parts:";

        SecureString partKey_(std::string_view key, size_t part) {
            return SecureString(key) + "#" + toSecureString(static_cast<std::int64_t>(part));
        }
    }

    ChunkedSecretStore::ChunkedSecretStore(std::shared_ptr<SecretStore> inner, size_t max_value)
        : m_inner_(std::move(inner)), m_max_value_(max_value) {}

    size_t ChunkedSecretStore::partsOf_(std::string_view key) {
        std::optional<SecureString> head = m_inner_->get(key);
        if (!head || !head->starts_with(c_chunk_marker)) {
            return 0;
        }
        std::int64_t parts = 0;
        if (!parseInt(std::string_view(*head).substr(c_chunk_marker.size()), parts) || parts < 0) {
            return 0;
        }
        return static_cast<size_t>(parts);
    }

    void ChunkedSecretStore::removeParts_(std::string_view key, size_t from, size_t to) {
        for (size_t part = from; part <= to; ++part) {
            m_inner_->remove(partKey_(key, part));
        }
    }

    std::optional<SecureString> ChunkedSecretStore::get(std::string_view key) {
        std::optional<SecureString> head = m_inner_->get(key);
        if (!head || !head->starts_with(c_chunk_marker)) {
            return head;
        }
        size_t parts = partsOf_(key);
        SecureString value;
        for (size_t part = 1; part <= parts; ++part) {
            std::optional<SecureString> chunk = m_inner_->get(partKey_(key, part));
            if (!chunk) {
                return std::nullopt; // half-written or damaged
            }
            value += *chunk;
        }
        return value;
    }

    bool ChunkedSecretStore::set(
            std::string_view key, std::string_view value, SecretProtection protection) {
        size_t old_parts = partsOf_(key);
        if (value.size() <= m_max_value_ && !value.starts_with(c_chunk_marker)) {
            if (!m_inner_->set(key, value, protection)) {
                return false;
            }
            removeParts_(key, 1, old_parts);
            return true;
        }

        /*
         * Parts first, then the marker, so a reader never finds a marker without its parts.
         */
        size_t parts = (value.size() + m_max_value_ - 1) / m_max_value_;
        for (size_t part = 1; part <= parts; ++part) {
            if (!m_inner_->set(partKey_(key, part), value.substr((part - 1) * m_max_value_, m_max_value_),
                        protection)) {
                return false;
            }
        }
        SecureString marker = SecureString(c_chunk_marker) + toSecureString(static_cast<std::int64_t>(parts));
        if (!m_inner_->set(key, marker, protection)) {
            return false;
        }
        removeParts_(key, parts + 1, old_parts);
        return true;
    }

    bool ChunkedSecretStore::remove(std::string_view key) {
        removeParts_(key, 1, partsOf_(key));
        return m_inner_->remove(key);
    }
}
