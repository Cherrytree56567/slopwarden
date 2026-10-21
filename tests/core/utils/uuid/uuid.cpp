#include <catch2/catch_test_macros.hpp>

#include "utils/uuid/uuid.h"

using namespace clientwarden;

TEST_CASE("uuid::generate is a unique lowercase v4 UUID") {
    SecureString a = uuid::generate();
    REQUIRE(a.size() == 36);
    REQUIRE(a[8] == '-');
    REQUIRE(a[13] == '-');
    REQUIRE(a[14] == '4');
    REQUIRE((a[19] == '8' || a[19] == '9' || a[19] == 'a' || a[19] == 'b'));
    REQUIRE(a.find_first_of("ABCDEF") == SecureString::npos);
    REQUIRE(a != uuid::generate());
}
