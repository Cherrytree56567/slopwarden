#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "Clientwarden.h"

/*
 * Bitwarden's client-side crypto, built on Botan.
 *
 * Every function validates its inputs and throws CryptoError on
 * malformed data or authentication failure; nothing returns a
 * half-initialised key or silently falls back.
 *
 * See https://bitwarden.com/help/bitwarden-security-white-paper/
*/
namespace ClientWarden::Crypto {
    inline constexpr size_t KeySize = 32;
    inline constexpr size_t IvSize = 16;
    inline constexpr size_t MacSize = 32;

    /*
     * An AES-256 key paired with its HMAC-SHA256 key. Bitwarden wraps
     * user keys, item keys and attachment keys as the 64 byte
     * concatenation enc || mac.
    */
    struct SymmetricKey {
        Bytes enc;
        Bytes mac;

        static SymmetricKey Generate();
        static SymmetricKey FromCombined(std::span<const uint8_t> combined);

        Bytes Combined() const;
        bool Valid() const;
    };

    enum class KdfType {
        PBKDF2 = 0,
        Argon2id = 1
    };

    struct KdfParams {
        KdfType type = KdfType::PBKDF2;
        uint32_t iterations = 600000;
        uint32_t memoryMiB = 0;
        uint32_t parallelism = 0;

        /*
         * The server chooses these, so a hostile server could weaken
         * them to make the password hash it receives cheap to crack, or
         * inflate them to hang the client. Throws outside sane bounds.
        */
        void Validate() const;
    };

    Bytes DeriveMasterKey(std::string_view password, std::string_view email, const KdfParams& params);
    std::string HashMasterPassword(const Bytes& masterKey, std::string_view password);
    SymmetricKey StretchMasterKey(const Bytes& masterKey);

    /*
     * Type 2 encrypted strings: "2.<iv>|<ciphertext>|<mac>"
     * (AES-256-CBC, HMAC-SHA256 over iv || ciphertext, all base64).
    */
    std::string Encrypt(std::span<const uint8_t> plaintext, const SymmetricKey& key);
    std::string Encrypt(std::string_view plaintext, const SymmetricKey& key);
    Bytes Decrypt(std::string_view encString, const SymmetricKey& key);
    SecretString DecryptString(std::string_view encString, const SymmetricKey& key);
    bool IsEncString(std::string_view value);

    std::string WrapKey(const SymmetricKey& key, const SymmetricKey& wrappingKey);
    SymmetricKey UnwrapKey(std::string_view encString, const SymmetricKey& wrappingKey);

    /*
     * Binary attachment format: 0x02 || iv || mac || ciphertext
    */
    std::vector<uint8_t> EncryptBuffer(std::span<const uint8_t> plaintext, const SymmetricKey& key);
    Bytes DecryptBuffer(std::span<const uint8_t> buffer, const SymmetricKey& key);

    /*
     * Login URIs carry an encrypted base64 SHA-256 of the plaintext URI
     * so the server can detect tampering.
    */
    std::string UriChecksum(std::string_view uri, const SymmetricKey& itemKey);

    bool ConstantTimeEquals(std::span<const uint8_t> a, std::span<const uint8_t> b);
    void RandomBytes(std::span<uint8_t> out);
    uint32_t RandomBelow(uint32_t bound);

    std::string Base64Encode(std::span<const uint8_t> data);
    Bytes Base64Decode(std::string_view data);
}
