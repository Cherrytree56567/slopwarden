#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include "Util/Util.h"

using namespace ClientWarden;

TEST_CASE("ParseTime reads Bitwarden timestamps") {
    REQUIRE(ParseTime("2026-08-22T06:53:51.78Z") == 1787381631);
    REQUIRE(ParseTime("2026-08-22T06:53:51Z") == 1787381631);
    REQUIRE(ParseTime("2026-08-22T06:53:51.1234567") == 1787381631);
}

TEST_CASE("ParseTime returns 0 for garbage instead of throwing") {
    auto input = GENERATE("", "yesterday", "2026-13", "T06:53:51");
    REQUIRE(ParseTime(input) == 0);
}

TEST_CASE("NowTime round trips through ParseTime") {
    std::time_t before = std::time(nullptr);
    std::time_t parsed = ParseTime(NowTime());
    REQUIRE(parsed >= before);
    REQUIRE(parsed <= std::time(nullptr));

    REQUIRE(ParseTime(NowTime(3600)) >= before + 3600);
}

TEST_CASE("FormatTime is UTC ISO-8601") {
    REQUIRE(FormatTime(1787381631) == "2026-08-22T06:53:51.000Z");
}

TEST_CASE("NewGuid is unique and well formed") {
    std::string a = NewGuid();
    REQUIRE(a.size() == 36);
    REQUIRE(a != NewGuid());
}
