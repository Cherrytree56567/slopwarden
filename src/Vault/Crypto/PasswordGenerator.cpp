#include "PasswordGenerator.h"

#include <sstream>

#include "Crypto/Crypto.h"
#include "Storage/Storage.h"

namespace ClientWarden {
    namespace {
        constexpr std::string_view Lower = "abcdefghijklmnopqrstuvwxyz";
        constexpr std::string_view Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        constexpr std::string_view Digits = "0123456789";
        constexpr std::string_view Symbols = "!@#$%^&*()-_=+[]{};:,.<>?/~";

        char Pick(std::string_view set) {
            return set[Crypto::RandomBelow(static_cast<uint32_t>(set.size()))];
        }
    }

    PasswordGenerator::PasswordGenerator(std::string_view wordList) {
        std::istringstream ss { std::string(wordList) };
        for (std::string line; std::getline(ss, line);) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (!line.empty()) {
                words.push_back(std::move(line));
            }
        }
    }

    PasswordGenerator PasswordGenerator::FromBundle() {
        try {
            return PasswordGenerator(Storage("").read("clientgen.txt"));
        } catch (const std::exception& e) {
            Log()->warn("Passphrase word list unavailable: {}", e.what());
            return PasswordGenerator();
        }
    }

    SecretString PasswordGenerator::Random(const Options& options) {
        std::vector<std::string_view> sets { Lower };
        if (options.uppercase) sets.push_back(Upper);
        if (options.numbers) sets.push_back(Digits);
        if (options.symbols) sets.push_back(Symbols);

        if (options.length < static_cast<int>(sets.size()) || options.length > 1024) {
            throw VaultError("password length must be between " + std::to_string(sets.size()) + " and 1024");
        }

        std::string pool;
        for (auto set : sets) {
            pool += set;
        }

        /*
         * Guarantee one character from every enabled class, fill the rest
         * from the full pool, then Fisher-Yates shuffle so the guaranteed
         * characters don't sit at fixed positions.
        */
        SecretString out;
        out.reserve(options.length);
        for (auto set : sets) {
            out.push_back(Pick(set));
        }
        while (static_cast<int>(out.size()) < options.length) {
            out.push_back(Pick(pool));
        }
        for (size_t i = out.size() - 1; i > 0; --i) {
            std::swap(out[i], out[Crypto::RandomBelow(static_cast<uint32_t>(i + 1))]);
        }
        return out;
    }

    SecretString PasswordGenerator::Pin(int digits) {
        if (digits < 4 || digits > 64) {
            throw VaultError("pin length must be between 4 and 64");
        }

        SecretString out;
        for (int i = 0; i < digits; ++i) {
            out.push_back(Pick(Digits));
        }
        return out;
    }

    SecretString PasswordGenerator::Passphrase(int count, bool capitalize, char separator) const {
        if (words.empty()) {
            throw VaultError("passphrase word list not loaded");
        }
        if (count < 3 || count > 20) {
            throw VaultError("passphrase must be between 3 and 20 words");
        }

        SecretString out;
        for (int i = 0; i < count; ++i) {
            if (i > 0) {
                out.push_back(separator);
            }
            const std::string& word = words[Crypto::RandomBelow(static_cast<uint32_t>(words.size()))];
            out.append(word.begin(), word.end());
            if (capitalize) {
                out[out.size() - word.size()] = static_cast<char>(std::toupper(static_cast<unsigned char>(word[0])));
            }
        }
        return out;
    }
}
