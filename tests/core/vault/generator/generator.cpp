#include <catch2/catch_test_macros.hpp>
#include <algorithm>

#include "utils/errors/errors.h"
#include "vault/generator/generator.h"

using namespace clientwarden;

namespace {
    /**
     * @brief Whether any character satisfies a predicate.
     */
    bool any(const SecureString& s, int (*predicate)(int)) {
        return std::any_of(s.begin(), s.end(), [predicate](char c) {
            return predicate(static_cast<unsigned char>(c)) != 0;
        });
    }

    /**
     * @brief A generator with no word list.
     */
    Generator plain() {
        return Generator(std::make_shared<Crypto>(), "");
    }
}

TEST_CASE("Generator passwords honour length and character classes") {
    Generator generator = plain();
    for (int i = 0; i < 50; ++i) {
        SecureString password = generator.password(PasswordOptions { 12, true, true, true });
        REQUIRE(password.size() == 12);
        REQUIRE(any(password, std::islower));
        REQUIRE(any(password, std::isupper));
        REQUIRE(any(password, std::isdigit));
        REQUIRE(any(password, std::ispunct));
    }

    SecureString lower_only = generator.password(PasswordOptions { 20, false, false, false });
    REQUIRE(std::all_of(lower_only.begin(), lower_only.end(), [](char c) {
        return std::islower(static_cast<unsigned char>(c)) != 0;
    }));
}

TEST_CASE("Generator passwords are not repeated") {
    Generator generator = plain();
    REQUIRE(generator.password(PasswordOptions()) != generator.password(PasswordOptions()));
}

TEST_CASE("Generator refuses invalid password lengths") {
    Generator generator = plain();
    REQUIRE_THROWS_AS(generator.password(PasswordOptions { 0 }), VaultError);
    REQUIRE_THROWS_AS(generator.password(PasswordOptions { 3, true, true, true }), VaultError);
    REQUIRE_THROWS_AS(generator.password(PasswordOptions { 5000 }), VaultError);
}

TEST_CASE("Generator pins are digits only") {
    SecureString pin = plain().pin(6);
    REQUIRE(pin.size() == 6);
    REQUIRE(std::all_of(pin.begin(), pin.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; }));
    REQUIRE_THROWS_AS(plain().pin(2), VaultError);
    REQUIRE_THROWS_AS(plain().pin(65), VaultError);
}

TEST_CASE("Generator passphrases use the word list") {
    Generator generator(std::make_shared<Crypto>(), "apple\r\nbanana\ncherry\n\n");

    SecureString phrase = generator.passphrase(4, true, '-');
    REQUIRE(std::count(phrase.begin(), phrase.end(), '-') == 3);
    REQUIRE(std::isupper(static_cast<unsigned char>(phrase[0])));
    REQUIRE(phrase.find('\r') == SecureString::npos);

    REQUIRE_THROWS_AS(generator.passphrase(2, false, '-'), VaultError);
    REQUIRE_THROWS_AS(plain().passphrase(4, false, '-'), VaultError);
}
