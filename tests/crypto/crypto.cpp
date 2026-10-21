#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include "Crypto/Crypto.h"

using namespace ClientWarden;
using namespace ClientWarden::Crypto;

namespace {
    SymmetricKey Key(const char* enc, const char* mac) {
        return { Base64Decode(enc), Base64Decode(mac) };
    }

    Bytes Text(std::string_view s) {
        return Bytes(s.begin(), s.end());
    }

    const char* KnownCipher = "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=";
    const SymmetricKey KnownKey = Key("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=", "AtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");
}

/*
 * Known-answer tests. These vectors were produced by the previous
 * OpenSSL implementation, so passing them proves the rewrite reads and
 * writes exactly what existing vaults contain.
*/
TEST_CASE("Decrypt known ciphertext") {
    REQUIRE(Decrypt(KnownCipher, KnownKey) == Text("Tep"));
    REQUIRE(DecryptString(KnownCipher, KnownKey) == "Tep");
}

TEST_CASE("DecryptBuffer known attachment blob") {
    SymmetricKey key = Key("Ay1c+hUhNSwVi9XkYg+WDEG6wV4IvfYA0juwbBrptKA=", "4xkE6NUAROZOl6LhnVHdBh7ydAX4RkxDRAIuuRK86tw=");
    Bytes blob = Base64Decode("AmKtjLq1L7nHSI9mNmdAJMDQ7Gsp21otZstoMlYUrwHBV2eVleasB3JEThlMT3oqgNM6P/tDsLwSflWF6lig1PY=");

    REQUIRE(DecryptBuffer(blob, key) == Text("ClientWarden"));
}

TEST_CASE("PBKDF2 master key") {
    KdfParams params { KdfType::PBKDF2, 600000 };
    REQUIRE(Base64Encode(DeriveMasterKey("Cl1entW@rden!2345", "cwuser@ct5.app", params)) == "ZpUXcWr1drwwXyagHbbYKjkU/jAR6e2MlvAo8WoWmGY=");

    params.iterations = 6000000;
    REQUIRE(Base64Encode(DeriveMasterKey("Cl1entW@rden!2345", "cwuser@ct5.app", params)) == "jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=");
}

TEST_CASE("Argon2id master key") {
    KdfParams params { KdfType::Argon2id, 4, 64, 4 };
    REQUIRE(Base64Encode(DeriveMasterKey("Cl1entW@rden!2345", "cwuser@ct5.app", params)) == "auOZsuNBQ1HNt5CHg3oDaVnLtx92PUI16tlKn/rexuA=");

    params.iterations = 10;
    REQUIRE(Base64Encode(DeriveMasterKey("Cl1entW@rden!2345", "cwuser@ct5.app", params)) == "D91klz4hoik9kPH29gzUGWLItfo+qLfF5cRIODDqtlE=");
}

TEST_CASE("Master password hash") {
    Bytes masterKey = Base64Decode("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=");
    REQUIRE(HashMasterPassword(masterKey, "Cl1entW@rden!2345") == "aBGZrGGJeaxdM4b5D1SPltKeq7levslhTkm1baSmfrk=");
}

TEST_CASE("Stretch master key and unwrap user key") {
    Bytes masterKey = Base64Decode("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=");
    SymmetricKey stretched = StretchMasterKey(masterKey);

    REQUIRE(Base64Encode(stretched.enc) == "RqOoW328Gq5Uweyy1Yxiksruw1kQIQ6K99cLtSaHDbc=");
    REQUIRE(Base64Encode(stretched.mac) == "gi+sZ7dY7mhiyP6xobX6guXXJFYo4AXe21gdqpfKBVs=");

    SymmetricKey user = UnwrapKey(
        "2.jPKn9+J4a8mkl3fIK6yFHA==|VIf3ki2/1N5b/qcXEKV8ZfeLv0ynW8kv4EwRFIhjX7MFz3HFxwb0cbQY5WyeSgye20cT3TA0/tzvxUsbnFNzzKcBpPGIylNBJLT/d6ODS8c=|LqjwPSkrBBVzqFEXGijaelvmXwYJOx0+GAZ3t/YZKZw=",
        stretched);
    REQUIRE(Base64Encode(user.enc) == "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    REQUIRE(Base64Encode(user.mac) == "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=");
}

TEST_CASE("URI checksum") {
    SymmetricKey key = SymmetricKey::Generate();
    REQUIRE(DecryptString(UriChecksum("https://example.com", key), key) == "EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=");
}

/*
 * Round trips
*/
TEST_CASE("Encrypt/decrypt round trip") {
    SymmetricKey key = SymmetricKey::Generate();
    auto length = GENERATE(0, 1, 15, 16, 17, 1000);
    std::string plaintext(length, 'x');

    std::string enc = Encrypt(plaintext, key);
    REQUIRE(IsEncString(enc));
    REQUIRE(DecryptString(enc, key) == SecretString(plaintext.begin(), plaintext.end()));
}

TEST_CASE("Encryption is randomised") {
    SymmetricKey key = SymmetricKey::Generate();
    REQUIRE(Encrypt("ClientWarden", key) != Encrypt("ClientWarden", key));
    REQUIRE(EncryptBuffer(Text("ClientWarden"), key) != EncryptBuffer(Text("ClientWarden"), key));
}

TEST_CASE("Buffer round trip") {
    SymmetricKey key = SymmetricKey::Generate();
    std::vector<uint8_t> blob = EncryptBuffer(Text("attachment body"), key);

    REQUIRE(blob[0] == 0x02);
    REQUIRE(DecryptBuffer(blob, key) == Text("attachment body"));
}

TEST_CASE("Key wrap round trip") {
    SymmetricKey wrapping = SymmetricKey::Generate();
    SymmetricKey key = SymmetricKey::Generate();

    SymmetricKey unwrapped = UnwrapKey(WrapKey(key, wrapping), wrapping);
    REQUIRE(unwrapped.enc == key.enc);
    REQUIRE(unwrapped.mac == key.mac);
}

/*
 * Authentication and malformed input. Everything here must throw
 * CryptoError; none of it may crash or return garbage.
*/
TEST_CASE("Wrong MAC key is rejected") {
    SymmetricKey wrong = KnownKey;
    wrong.mac[0] ^= 0x01;
    REQUIRE_THROWS_AS(Decrypt(KnownCipher, wrong), CryptoError);
}

TEST_CASE("Tampered ciphertext is rejected") {
    SymmetricKey key = SymmetricKey::Generate();
    std::string enc = Encrypt("secret", key);
    enc[5] = enc[5] == 'A' ? 'B' : 'A';
    REQUIRE_THROWS_AS(Decrypt(enc, key), CryptoError);

    std::vector<uint8_t> blob = EncryptBuffer(Text("secret"), key);
    blob.back() ^= 0x01;
    REQUIRE_THROWS_AS(DecryptBuffer(blob, key), CryptoError);
}

TEST_CASE("Malformed encrypted strings are rejected") {
    SymmetricKey key = SymmetricKey::Generate();
    auto input = GENERATE(
        "",
        "2",
        "2.",
        "0.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==",
        "2.bt==|Ocli+ent==|fi/xxx/mejJmBUCPLZV2iog=",
        "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==",
        "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=|extra",
        "2.AAAA|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=",
        "2.mnIBpndY7sS+DSZQDSKsMA==||aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=",
        "2.!!!|???|***");
    CAPTURE(input);
    REQUIRE_THROWS_AS(Decrypt(input, key), CryptoError);
}

TEST_CASE("Truncated buffers are rejected") {
    SymmetricKey key = SymmetricKey::Generate();
    std::vector<uint8_t> blob = EncryptBuffer(Text("secret"), key);

    for (size_t len : { size_t(0), size_t(1), size_t(17), size_t(49), blob.size() - 1 }) {
        CAPTURE(len);
        REQUIRE_THROWS_AS(DecryptBuffer(std::span(blob.data(), len), key), CryptoError);
    }

    blob[0] = 0x00;
    REQUIRE_THROWS_AS(DecryptBuffer(blob, key), CryptoError);
}

TEST_CASE("Keys of the wrong size are rejected") {
    SymmetricKey shortKey { Bytes(16), Bytes(32) };
    REQUIRE_THROWS_AS(Encrypt("x", shortKey), CryptoError);
    REQUIRE_THROWS_AS(Decrypt(KnownCipher, shortKey), CryptoError);
    REQUIRE_THROWS_AS(SymmetricKey::FromCombined(Bytes(63)), CryptoError);
    REQUIRE_THROWS_AS(StretchMasterKey(Bytes(31)), CryptoError);
}

TEST_CASE("Unwrapping something that isn't a 64 byte key fails") {
    SymmetricKey wrapping = SymmetricKey::Generate();
    REQUIRE_THROWS_AS(UnwrapKey(Encrypt("too short", wrapping), wrapping), CryptoError);
}

/*
 * The server picks KDF parameters, so weak or absurd values must be
 * refused rather than used.
*/
TEST_CASE("KDF parameters are bounds-checked") {
    REQUIRE_NOTHROW(KdfParams { KdfType::PBKDF2, 600000 }.Validate());
    REQUIRE_NOTHROW(KdfParams { KdfType::Argon2id, 3, 64, 4 }.Validate());

    REQUIRE_THROWS_AS((KdfParams { KdfType::PBKDF2, 1 }.Validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::PBKDF2, 5000 }.Validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Argon2id, 1, 64, 4 }.Validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Argon2id, 3, 4, 4 }.Validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Argon2id, 3, 64, 0 }.Validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Argon2id, 3, 100000, 4 }.Validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { static_cast<KdfType>(7), 600000 }.Validate()), CryptoError);

    REQUIRE_THROWS_AS(DeriveMasterKey("pw", "a@b.c", KdfParams { KdfType::PBKDF2, 1 }), CryptoError);
}

TEST_CASE("Base64") {
    Bytes data = Text("Cl1entW@r\\en");
    REQUIRE(Base64Encode(data) == "Q2wxZW50V0ByXGVu");
    REQUIRE(Base64Decode("Q2wxZW50V0ByXGVu") == data);
    REQUIRE_THROWS_AS(Base64Decode("not base64!"), CryptoError);
}

TEST_CASE("Constant time comparison") {
    REQUIRE(ConstantTimeEquals(Text("abcd"), Text("abcd")));
    REQUIRE_FALSE(ConstantTimeEquals(Text("abcd"), Text("abce")));
    REQUIRE_FALSE(ConstantTimeEquals(Text("abcd"), Text("abc")));
}

TEST_CASE("RandomBelow stays in range and covers it") {
    std::array<int, 7> seen {};
    for (int i = 0; i < 2000; ++i) {
        uint32_t v = RandomBelow(7);
        REQUIRE(v < 7);
        seen[v]++;
    }
    for (int count : seen) {
        REQUIRE(count > 150);
    }
    REQUIRE_THROWS_AS(RandomBelow(0), CryptoError);
}
