#include "generator.h"

#include "utils/errors/errors.h"

namespace clientwarden {
    namespace {
        constexpr std::string_view c_lower = "abcdefghijklmnopqrstuvwxyz";
        constexpr std::string_view c_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        constexpr std::string_view c_digits = "0123456789";
        constexpr std::string_view c_symbols = "!@#$%^&*()-_=+[]{};:,.<>?/~";
    }

    Generator::Generator(std::shared_ptr<Crypto> crypto, std::string_view word_list)
        : m_crypto_(std::move(crypto)) {
        size_t start = 0;
        while (start <= word_list.size()) {
            size_t end = word_list.find('\n', start);
            std::string_view line = word_list.substr(
                    start, end == std::string_view::npos ? std::string_view::npos : end - start);
            if (!line.empty() && line.back() == '\r') {
                line.remove_suffix(1);
            }
            if (!line.empty()) {
                m_words_.push_back(SecureString(line));
            }
            if (end == std::string_view::npos) {
                break;
            }
            start = end + 1;
        }
    }

    char Generator::pick_(std::string_view set) const {
        return set[m_crypto_->randomBelow(static_cast<uint32_t>(set.size()))];
    }

    SecureString Generator::password(PasswordOptions options) const {
        std::vector<std::string_view> sets { c_lower };
        if (options.m_uppercase)
            sets.push_back(c_upper);
        if (options.m_numbers)
            sets.push_back(c_digits);
        if (options.m_symbols)
            sets.push_back(c_symbols);

        if (options.m_length < static_cast<int>(sets.size()) || options.m_length > 1024) {
            throw VaultError("password length must fit every character class and be at most 1024");
        }

        SecureString pool;
        for (std::string_view set : sets) {
            pool += set;
        }

        /*
         * Guarantee one character from every enabled class, fill the rest from the full pool,
         * then Fisher-Yates shuffle so the guaranteed characters don't sit at fixed positions.
         */
        SecureString out;
        out.reserve(static_cast<size_t>(options.m_length));
        for (std::string_view set : sets) {
            out.push_back(pick_(set));
        }
        while (static_cast<int>(out.size()) < options.m_length) {
            out.push_back(pick_(pool));
        }
        for (size_t i = out.size() - 1; i > 0; --i) {
            std::swap(out[i], out[m_crypto_->randomBelow(static_cast<uint32_t>(i + 1))]);
        }
        return out;
    }

    SecureString Generator::pin(int digits) const {
        if (digits < 4 || digits > 64) {
            throw VaultError("pin length must be between 4 and 64");
        }
        SecureString out;
        for (int i = 0; i < digits; ++i) {
            out.push_back(pick_(c_digits));
        }
        return out;
    }

    SecureString Generator::passphrase(int words, bool capitalize, char separator) const {
        if (m_words_.empty()) {
            throw VaultError("passphrase word list not loaded");
        }
        if (words < 3 || words > 20) {
            throw VaultError("passphrase must be between 3 and 20 words");
        }

        SecureString out;
        for (int i = 0; i < words; ++i) {
            if (i > 0) {
                out.push_back(separator);
            }
            const SecureString& word =
                    m_words_[m_crypto_->randomBelow(static_cast<uint32_t>(m_words_.size()))];
            size_t start = out.size();
            out += word;
            if (capitalize && out[start] >= 'a' && out[start] <= 'z') {
                out[start] = static_cast<char>(out[start] - 'a' + 'A');
            }
        }
        return out;
    }
}
