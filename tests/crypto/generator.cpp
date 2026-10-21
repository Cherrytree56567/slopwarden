#include <catch2/catch_test_macros.hpp>
#include <algorithm>
#include "Crypto/PasswordGenerator.h"

using namespace ClientWarden;

namespace {
    bool Any(const SecretString& s, int (*pred)(int)) {
        return std::any_of(s.begin(), s.end(), [&](char c) { return pred(static_cast<unsigned char>(c)); });
    }
}

TEST_CASE("Random passwords honour length and character classes") {
    for (int i = 0; i < 50; ++i) {
        SecretString pw = PasswordGenerator::Random({ 12, true, true, true });
        REQUIRE(pw.size() == 12);
        REQUIRE(Any(pw, std::islower));
        REQUIRE(Any(pw, std::isupper));
        REQUIRE(Any(pw, std::isdigit));
        REQUIRE(Any(pw, std::ispunct));
    }

    SecretString lowerOnly = PasswordGenerator::Random({ 20, false, false, false });
    REQUIRE(std::all_of(lowerOnly.begin(), lowerOnly.end(), [](char c) { return std::islower(static_cast<unsigned char>(c)); }));
}

TEST_CASE("Random passwords are not repeated") {
    REQUIRE(PasswordGenerator::Random({}) != PasswordGenerator::Random({}));
}

TEST_CASE("Invalid password lengths are refused") {
    REQUIRE_THROWS_AS(PasswordGenerator::Random({ 0 }), VaultError);
    REQUIRE_THROWS_AS(PasswordGenerator::Random({ 3, true, true, true }), VaultError);
    REQUIRE_THROWS_AS(PasswordGenerator::Random({ 5000 }), VaultError);
}

TEST_CASE("Pins are digits only") {
    SecretString pin = PasswordGenerator::Pin(6);
    REQUIRE(pin.size() == 6);
    REQUIRE(std::all_of(pin.begin(), pin.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)); }));
    REQUIRE_THROWS_AS(PasswordGenerator::Pin(2), VaultError);
}

TEST_CASE("Passphrases use the word list") {
    PasswordGenerator gen("apple\r\nbanana\ncherry\n\n");

    SecretString phrase = gen.Passphrase(4, true, '-');
    REQUIRE(std::count(phrase.begin(), phrase.end(), '-') == 3);
    REQUIRE(std::isupper(static_cast<unsigned char>(phrase[0])));
    REQUIRE(phrase.find('\r') == SecretString::npos);

    REQUIRE_THROWS_AS(PasswordGenerator().Passphrase(4, false), VaultError);
}
