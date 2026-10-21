#include <catch2/catch_test_macros.hpp>

#include "utils/secure_string/secure_string.h"

using namespace clientwarden;

TEST_CASE("toSecureString formats integers") {
    REQUIRE(toSecureString(0) == "0");
    REQUIRE(toSecureString(-42) == "-42");
    REQUIRE(toSecureString(600000) == "600000");
}

TEST_CASE("parseInt accepts only whole integers") {
    std::int64_t value = 0;
    REQUIRE(parseInt("123", value));
    REQUIRE(value == 123);
    REQUIRE(parseInt("+7", value));
    REQUIRE(value == 7);
    REQUIRE(parseInt("-3", value));
    REQUIRE(value == -3);
    REQUIRE_FALSE(parseInt("", value));
    REQUIRE_FALSE(parseInt("12a", value));
    REQUIRE_FALSE(parseInt("abc", value));
}

TEST_CASE("toLower lowercases ASCII only") {
    REQUIRE(toLower("User@Example.COM") == "user@example.com");
    REQUIRE(toLower("\xc3\x84" "B") == "\xc3\x84" "b");
}

TEST_CASE("trim strips surrounding whitespace") {
    REQUIRE(trim("  a b \t\n") == "a b");
    REQUIRE(trim("   ") == "");
    REQUIRE(trim("x") == "x");
}

TEST_CASE("at never inserts or reads past missing keys") {
    Json object = { { "a", 1 } };
    const Json& constant = object;
    REQUIRE(at(constant, "a") == 1);
    REQUIRE(at(constant, "missing").is_null());
    REQUIRE(at(Json::array({ 1 }), "a").is_null());
    REQUIRE(object.size() == 1);
}

TEST_CASE("stringAt returns strings and empty otherwise") {
    Json object = { { "s", "text" }, { "n", 5 } };
    REQUIRE(stringAt(object, "s") == "text");
    REQUIRE(stringAt(object, "n").empty());
    REQUIRE(stringAt(object, "missing").empty());
}

TEST_CASE("Json keeps strings in secure memory and round trips") {
    Json parsed = Json::parse(SecureString(R"({"id":"abc","arr":[1,2]})"));
    REQUIRE(parsed["id"].get<SecureString>() == "abc");
    REQUIRE(Json::parse(parsed.dump()) == parsed);
    REQUIRE(Json::parse(SecureString("{oops"), nullptr, false).is_discarded());
}
