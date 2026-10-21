#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "utils/timestamp/timestamp.h"

using namespace clientwarden;

TEST_CASE("timestamp::parse reads Bitwarden timestamps") {
    REQUIRE(timestamp::parse("2026-08-22T06:53:51.78Z") == 1787381631);
    REQUIRE(timestamp::parse("2026-08-22T06:53:51Z") == 1787381631);
    REQUIRE(timestamp::parse("2026-08-22T06:53:51.1234567") == 1787381631);
    REQUIRE(timestamp::parse("1970-01-01T00:00:00Z") == 0);
}

TEST_CASE("timestamp::parse returns 0 for garbage instead of throwing") {
    std::string_view input = GENERATE(std::string_view(""), std::string_view("yesterday"),
        std::string_view("2026-13"), std::string_view("T06:53:51"), std::string_view("2026-13-01T00:00:00Z"));
    REQUIRE(timestamp::parse(input) == 0);
}

TEST_CASE("timestamp::format is UTC ISO-8601") {
    REQUIRE(timestamp::format(1787381631) == "2026-08-22T06:53:51.000Z");
    REQUIRE(timestamp::format(1787381631, 78) == "2026-08-22T06:53:51.078Z");
}

TEST_CASE("timestamp::now round trips through parse") {
    std::time_t before = std::time(nullptr);
    std::time_t parsed = timestamp::parse(timestamp::now());
    REQUIRE(parsed >= before);
    REQUIRE(parsed <= std::time(nullptr));
    REQUIRE(timestamp::parse(timestamp::now(3600)) >= before + 3600);
}

TEST_CASE("timestamp::localString has the display format") {
    SecureString text = timestamp::localString(1787381631);
    REQUIRE(text.size() == 19);
    REQUIRE(text[4] == '-');
    REQUIRE(text[10] == ' ');
    REQUIRE(text[13] == ':');
}
