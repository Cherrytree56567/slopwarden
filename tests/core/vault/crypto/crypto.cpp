#include <array>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"
#include "vault/crypto/crypto.h"

using namespace clientwarden;

namespace {
    /**
     * @brief Builds a key pair from base64 halves.
     */
    SymmetricKey keyOf(std::string_view enc, std::string_view mac) {
        SymmetricKey key;
        key.m_enc = encoding::base64Decode(enc);
        key.m_mac = encoding::base64Decode(mac);
        return key;
    }

    /**
     * @brief Text as secure bytes.
     */
    SecureBytes bytes(std::string_view text) {
        return SecureBytes(text.begin(), text.end());
    }

    const std::string_view c_known_cipher =
        "2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=";

    /**
     * @brief The key the known ciphertext was made with.
     */
    SymmetricKey knownKey() {
        return keyOf("HkpT6z8HAIrdUjMlMBcPDprnYFe4e6Lfius7YhNmCkY=", "AtHPCgB/SlDnlEf9WA0JMtl63oDkLpVnPCZJlyOL01s=");
    }

    const Crypto c_crypto;
}

/*
 * Known-answer tests: these vectors come from the original OpenSSL implementation, so passing
 * them proves the rewrite reads and writes exactly what existing vaults contain.
*/
TEST_CASE("Crypto::decrypt known ciphertext") {
    REQUIRE(c_crypto.decrypt(c_known_cipher, knownKey()) == bytes("Tep"));
    REQUIRE(c_crypto.decryptText(c_known_cipher, knownKey()) == "Tep");
}

TEST_CASE("Crypto::decryptBuffer known attachment blob") {
    SymmetricKey key = keyOf("Ay1c+hUhNSwVi9XkYg+WDEG6wV4IvfYA0juwbBrptKA=", "4xkE6NUAROZOl6LhnVHdBh7ydAX4RkxDRAIuuRK86tw=");
    SecureBytes blob = encoding::base64Decode(
        "AmKtjLq1L7nHSI9mNmdAJMDQ7Gsp21otZstoMlYUrwHBV2eVleasB3JEThlMT3oqgNM6P/tDsLwSflWF6lig1PY=");
    REQUIRE(c_crypto.decryptBuffer(blob, key) == bytes("ClientWarden"));
}

TEST_CASE("Crypto::deriveMasterKey PBKDF2") {
    KdfParams params { KdfType::Pbkdf2, 600000 };
    REQUIRE(encoding::base64Encode(c_crypto.deriveMasterKey("Cl1entW@rden!2345", "cwuser@ct5.app", params))
        == "ZpUXcWr1drwwXyagHbbYKjkU/jAR6e2MlvAo8WoWmGY=");

    params.m_iterations = 6000000;
    REQUIRE(encoding::base64Encode(c_crypto.deriveMasterKey("Cl1entW@rden!2345", "cwuser@ct5.app", params))
        == "jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=");
}

TEST_CASE("Crypto::deriveMasterKey Argon2id") {
    KdfParams params { KdfType::Argon2id, 4, 64, 4 };
    REQUIRE(encoding::base64Encode(c_crypto.deriveMasterKey("Cl1entW@rden!2345", "cwuser@ct5.app", params))
        == "auOZsuNBQ1HNt5CHg3oDaVnLtx92PUI16tlKn/rexuA=");

    params.m_iterations = 10;
    REQUIRE(encoding::base64Encode(c_crypto.deriveMasterKey("Cl1entW@rden!2345", "cwuser@ct5.app", params))
        == "D91klz4hoik9kPH29gzUGWLItfo+qLfF5cRIODDqtlE=");
}

TEST_CASE("Crypto::hashMasterPassword") {
    SecureBytes master_key = encoding::base64Decode("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=");
    REQUIRE(c_crypto.hashMasterPassword(master_key, "Cl1entW@rden!2345") == "aBGZrGGJeaxdM4b5D1SPltKeq7levslhTkm1baSmfrk=");
    REQUIRE_THROWS_AS(c_crypto.hashMasterPassword(SecureBytes(31), "x"), CryptoError);
}

TEST_CASE("Crypto::stretchMasterKey and unwrapKey") {
    SecureBytes master_key = encoding::base64Decode("jIYLWmvcnFcr3+WwlsyJtGGoAvd2rrtOG2v5EOoA1C4=");
    SymmetricKey stretched = c_crypto.stretchMasterKey(master_key);

    REQUIRE(encoding::base64Encode(stretched.m_enc) == "RqOoW328Gq5Uweyy1Yxiksruw1kQIQ6K99cLtSaHDbc=");
    REQUIRE(encoding::base64Encode(stretched.m_mac) == "gi+sZ7dY7mhiyP6xobX6guXXJFYo4AXe21gdqpfKBVs=");

    SymmetricKey user = c_crypto.unwrapKey(
        "2.jPKn9+J4a8mkl3fIK6yFHA==|VIf3ki2/1N5b/qcXEKV8ZfeLv0ynW8kv4EwRFIhjX7MFz3HFxwb0cbQY5WyeSgye20cT3TA0/tzvxUsbnFNzzKcBpPGIylNBJLT/d6ODS8c=|LqjwPSkrBBVzqFEXGijaelvmXwYJOx0+GAZ3t/YZKZw=",
        stretched);
    REQUIRE(encoding::base64Encode(user.m_enc) == "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    REQUIRE(encoding::base64Encode(user.m_mac) == "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=");

    REQUIRE_THROWS_AS(c_crypto.stretchMasterKey(SecureBytes(31)), CryptoError);
}

TEST_CASE("Crypto::uriChecksum") {
    SymmetricKey key = SymmetricKey::generate();
    REQUIRE(c_crypto.decryptText(c_crypto.uriChecksum("https://example.com", key), key)
        == "EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk=");
}

TEST_CASE("Crypto::sha256") {
    REQUIRE(encoding::hexEncode(c_crypto.sha256(encoding::bytesOf("abc")))
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("Crypto::encryptText and decryptText round trip") {
    SymmetricKey key = SymmetricKey::generate();
    int length = GENERATE(0, 1, 15, 16, 17, 1000);
    SecureString plaintext(static_cast<size_t>(length), 'x');

    SecureString enc = c_crypto.encryptText(plaintext, key);
    REQUIRE(c_crypto.isEncString(enc));
    REQUIRE(c_crypto.decryptText(enc, key) == plaintext);
}

TEST_CASE("Crypto::encrypt is randomised") {
    SymmetricKey key = SymmetricKey::generate();
    REQUIRE(c_crypto.encrypt(bytes("ClientWarden"), key) != c_crypto.encrypt(bytes("ClientWarden"), key));
    REQUIRE(c_crypto.encryptBuffer(bytes("ClientWarden"), key) != c_crypto.encryptBuffer(bytes("ClientWarden"), key));
}

TEST_CASE("Crypto::encryptBuffer round trip") {
    SymmetricKey key = SymmetricKey::generate();
    SecureBytes blob = c_crypto.encryptBuffer(bytes("attachment body"), key);
    REQUIRE(blob[0] == 0x02);
    REQUIRE(c_crypto.decryptBuffer(blob, key) == bytes("attachment body"));
}

TEST_CASE("Crypto::wrapKey round trip") {
    SymmetricKey wrapping = SymmetricKey::generate();
    SymmetricKey key = SymmetricKey::generate();
    SymmetricKey unwrapped = c_crypto.unwrapKey(c_crypto.wrapKey(key, wrapping), wrapping);
    REQUIRE(unwrapped.m_enc == key.m_enc);
    REQUIRE(unwrapped.m_mac == key.m_mac);
}

TEST_CASE("Crypto::isEncString") {
    REQUIRE(c_crypto.isEncString(c_known_cipher));
    REQUIRE_FALSE(c_crypto.isEncString("2.only|two"));
    REQUIRE_FALSE(c_crypto.isEncString("plain text"));
    REQUIRE_FALSE(c_crypto.isEncString("0.a|b|c"));
}

TEST_CASE("Crypto::decrypt rejects a wrong MAC key") {
    SymmetricKey wrong = knownKey();
    wrong.m_mac[0] ^= 0x01;
    REQUIRE_THROWS_AS(c_crypto.decrypt(c_known_cipher, wrong), CryptoError);
}

TEST_CASE("Crypto::decrypt rejects tampered ciphertext") {
    SymmetricKey key = SymmetricKey::generate();
    SecureString enc = c_crypto.encryptText("secret", key);
    enc[5] = enc[5] == 'A' ? 'B' : 'A';
    REQUIRE_THROWS_AS(c_crypto.decrypt(enc, key), CryptoError);

    SecureBytes blob = c_crypto.encryptBuffer(bytes("secret"), key);
    blob.back() ^= 0x01;
    REQUIRE_THROWS_AS(c_crypto.decryptBuffer(blob, key), CryptoError);
}

TEST_CASE("Crypto::decrypt rejects malformed strings") {
    SymmetricKey key = SymmetricKey::generate();
    std::string_view input = GENERATE(
        std::string_view(""),
        std::string_view("2"),
        std::string_view("2."),
        std::string_view("0.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q=="),
        std::string_view("2.bt==|Ocli+ent==|fi/xxx/mejJmBUCPLZV2iog="),
        std::string_view("2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q=="),
        std::string_view("2.mnIBpndY7sS+DSZQDSKsMA==|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog=|x"),
        std::string_view("2.AAAA|OdC0I2BW6Po3UdfDFGTJ+Q==|aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog="),
        std::string_view("2.mnIBpndY7sS+DSZQDSKsMA==||aDj5gC/9iM5/AwjJmBUCSoE185XDREZM69XGGNV2iog="),
        std::string_view("2.!!!|???|***"));
    CAPTURE(input);
    REQUIRE_THROWS_AS(c_crypto.decrypt(input, key), CryptoError);
}

TEST_CASE("Crypto::decryptBuffer rejects truncated buffers") {
    SymmetricKey key = SymmetricKey::generate();
    SecureBytes blob = c_crypto.encryptBuffer(bytes("secret"), key);

    for (size_t length : { size_t(0), size_t(1), size_t(17), size_t(49), blob.size() - 1 }) {
        CAPTURE(length);
        REQUIRE_THROWS_AS(c_crypto.decryptBuffer(std::span<const uint8_t>(blob.data(), length), key), CryptoError);
    }

    blob[0] = 0x00;
    REQUIRE_THROWS_AS(c_crypto.decryptBuffer(blob, key), CryptoError);
}

TEST_CASE("Crypto rejects keys of the wrong size") {
    SymmetricKey short_key;
    short_key.m_enc = SecureBytes(16);
    short_key.m_mac = SecureBytes(32);
    REQUIRE_THROWS_AS(c_crypto.encryptText("x", short_key), CryptoError);
    REQUIRE_THROWS_AS(c_crypto.decrypt(c_known_cipher, short_key), CryptoError);
    REQUIRE_THROWS_AS(c_crypto.wrapKey(short_key, SymmetricKey::generate()), CryptoError);
}

TEST_CASE("Crypto::unwrapKey rejects something that isn't a 64 byte key") {
    SymmetricKey wrapping = SymmetricKey::generate();
    REQUIRE_THROWS_AS(c_crypto.unwrapKey(c_crypto.encryptText("too short", wrapping), wrapping), CryptoError);
}

TEST_CASE("SymmetricKey helpers") {
    SymmetricKey key = SymmetricKey::generate();
    REQUIRE(key.valid());
    REQUIRE(key.combined().size() == 64);

    SymmetricKey split = SymmetricKey::fromCombined(key.combined());
    REQUIRE(split.m_enc == key.m_enc);
    REQUIRE(split.m_mac == key.m_mac);
    REQUIRE_THROWS_AS(SymmetricKey::fromCombined(SecureBytes(63)), CryptoError);
    REQUIRE_FALSE(SymmetricKey().valid());
}

/*
 * The server picks KDF parameters, so weak or absurd values must be refused.
*/
TEST_CASE("KdfParams::validate") {
    REQUIRE_NOTHROW(KdfParams { KdfType::Pbkdf2, 600000 }.validate());
    REQUIRE_NOTHROW(KdfParams { KdfType::Argon2id, 3, 64, 4 }.validate());

    REQUIRE_THROWS_AS((KdfParams { KdfType::Pbkdf2, 1 }.validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Pbkdf2, 5000 }.validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Argon2id, 1, 64, 4 }.validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Argon2id, 3, 4, 4 }.validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Argon2id, 3, 64, 0 }.validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { KdfType::Argon2id, 3, 100000, 4 }.validate()), CryptoError);
    REQUIRE_THROWS_AS((KdfParams { static_cast<KdfType>(7), 600000 }.validate()), CryptoError);

    REQUIRE_THROWS_AS(c_crypto.deriveMasterKey("pw", "a@b.c", KdfParams { KdfType::Pbkdf2, 1 }), CryptoError);
}

TEST_CASE("Crypto::constantTimeEquals") {
    REQUIRE(c_crypto.constantTimeEquals(bytes("abcd"), bytes("abcd")));
    REQUIRE_FALSE(c_crypto.constantTimeEquals(bytes("abcd"), bytes("abce")));
    REQUIRE_FALSE(c_crypto.constantTimeEquals(bytes("abcd"), bytes("abc")));
}

TEST_CASE("Crypto::randomBytes fills the buffer") {
    std::array<uint8_t, 32> a = {};
    std::array<uint8_t, 32> b = {};
    c_crypto.randomBytes(a);
    c_crypto.randomBytes(b);
    REQUIRE(a != b);
}

TEST_CASE("Crypto::randomBelow stays in range and covers it") {
    std::array<int, 7> seen = {};
    for (int i = 0; i < 2000; ++i) {
        uint32_t value = c_crypto.randomBelow(7);
        REQUIRE(value < 7);
        seen[value]++;
    }
    for (int count : seen) {
        REQUIRE(count > 150);
    }
    REQUIRE_THROWS_AS(c_crypto.randomBelow(0), CryptoError);
}

TEST_CASE("RSA-OAEP round trip as Bitwarden type 4") {
    Crypto crypto;
    RsaKeyPair pair = crypto.generateRsaKeyPair();
    SymmetricKey organization_key = SymmetricKey::generate();

    SecureString wrapped = crypto.rsaEncrypt(organization_key.combined(), pair.m_public_key);
    REQUIRE(wrapped.starts_with("4."));
    REQUIRE(crypto.rsaDecrypt(wrapped, pair.m_private_key) == organization_key.combined());
}

TEST_CASE("RSA decryption rejects other keys, types and garbage") {
    Crypto crypto;
    RsaKeyPair pair = crypto.generateRsaKeyPair();
    RsaKeyPair other = crypto.generateRsaKeyPair();
    SecureString wrapped = crypto.rsaEncrypt(encoding::bytesOf("secret"), pair.m_public_key);

    REQUIRE_THROWS_AS(crypto.rsaDecrypt(wrapped, other.m_private_key), CryptoError);
    REQUIRE_THROWS_AS(crypto.rsaDecrypt(SecureString("2.") + wrapped.substr(2), pair.m_private_key), CryptoError);
    REQUIRE_THROWS_AS(crypto.rsaDecrypt("4.AAAA", pair.m_private_key), CryptoError);
    REQUIRE_THROWS_AS(crypto.rsaDecrypt(wrapped, SecureBytes { 1, 2, 3 }), CryptoError);
    REQUIRE_THROWS_AS(crypto.rsaEncrypt(encoding::bytesOf("x"), SecureBytes { 1, 2, 3 }), CryptoError);
}

TEST_CASE("HKDF matches RFC 5869 test case 1") {
    Crypto crypto;
    SecureBytes ikm(22, 0x0b);
    std::string_view salt("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c", 13);
    std::string_view info("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9", 10);

    REQUIRE(encoding::hexEncode(crypto.hkdf(ikm, salt, info, 42)) ==
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    REQUIRE_THROWS_AS(crypto.hkdf(ikm, salt, info, 0), CryptoError);
}

TEST_CASE("PBKDF2 matches a known SHA-256 vector") {
    Crypto crypto;
    REQUIRE(encoding::hexEncode(crypto.pbkdf2("password", encoding::bytesOf("salt"), 1, 32)) ==
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    REQUIRE_THROWS_AS(crypto.pbkdf2("password", encoding::bytesOf("salt"), 0, 32), CryptoError);
}
