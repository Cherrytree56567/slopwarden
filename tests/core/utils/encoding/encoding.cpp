#include <catch2/catch_test_macros.hpp>

#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"

using namespace clientwarden;

TEST_CASE("encoding::base64Encode") {
    REQUIRE(encoding::base64Encode(encoding::bytesOf("Cl1entW@r\\en")) == "Q2wxZW50V0ByXGVu");
    REQUIRE(encoding::base64Encode(encoding::bytesOf("")) == "");
    REQUIRE(encoding::base64Encode(encoding::bytesOf("f")) == "Zg==");
    REQUIRE(encoding::base64Encode(encoding::bytesOf("fo")) == "Zm8=");
    REQUIRE(encoding::base64Encode(encoding::bytesOf("foo")) == "Zm9v");
}

TEST_CASE("encoding::base64Decode") {
    REQUIRE(encoding::textOf(encoding::base64Decode("Q2wxZW50V0ByXGVu")) == "Cl1entW@r\\en");
    REQUIRE(encoding::textOf(encoding::base64Decode("Zg==")) == "f");
    REQUIRE(encoding::textOf(encoding::base64Decode("Zg")) == "f");
    REQUIRE(encoding::base64Decode("").empty());
    REQUIRE_THROWS_AS(encoding::base64Decode("not base64!"), CryptoError);
    REQUIRE_THROWS_AS(encoding::base64Decode("A"), CryptoError);
}

TEST_CASE("encoding::base64UrlEncode") {
    std::vector<uint8_t> data = { 0xff, 0xfe, 0x00, 0x80 };
    REQUIRE(encoding::base64UrlEncode(data) == "__4AgA");
}

TEST_CASE("encoding::hexEncode") {
    std::vector<uint8_t> data = { 0x00, 0x0f, 0xab, 0xff };
    REQUIRE(encoding::hexEncode(data) == "000fabff");
}

TEST_CASE("encoding::formEncode") {
    std::vector<std::pair<SecureString, SecureString>> fields = {
        { "grant_type", "password" },
        { "password", "a+b/c=" },
        { "scope", "api offline_access" }
    };
    REQUIRE(encoding::formEncode(fields) == "grant_type=password&password=a%2Bb%2Fc%3D&scope=api%20offline_access");
    REQUIRE(encoding::formEncode({}) == "");
}

TEST_CASE("encoding::bytesOf and textOf view the same memory") {
    std::string_view text = "abc";
    std::span<const uint8_t> view = encoding::bytesOf(text);
    REQUIRE(view.size() == 3);
    REQUIRE(view[0] == 'a');
    REQUIRE(encoding::textOf(view) == text);
}
