#pragma once
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "utils/secure_string/secure_string.h"

namespace clientwarden {
    /**
     * @brief An AES-256 key paired with its HMAC-SHA256 key.
     *
     * Bitwarden wraps user, item and attachment keys as the 64 byte concatenation enc || mac.
     */
    struct SymmetricKey {
        SecureBytes m_enc;
        SecureBytes m_mac;

        /**
         * @brief Generates a fresh random key pair.
         *
         * @return 32 random bytes each for encryption and authentication
         */
        static SymmetricKey generate();

        /**
         * @brief Splits a 64 byte wrapped key into its halves.
         *
         * @param combined enc || mac
         * @return The key pair
         * @throws CryptoError if combined isn't exactly 64 bytes
         */
        static SymmetricKey fromCombined(std::span<const uint8_t> combined);

        /**
         * @brief Joins the halves for wrapping.
         *
         * @return enc || mac
         */
        SecureBytes combined() const;

        /**
         * @brief Whether both halves are 32 bytes.
         *
         * @return True for a usable key
         */
        bool valid() const;
    };

    /**
     * @brief An RSA-2048 key pair as Bitwarden stores it.
     */
    struct RsaKeyPair {
        SecureBytes m_private_key; // PKCS#8 DER
        SecureBytes m_public_key;  // SubjectPublicKeyInfo DER
    };

    /**
     * @brief Key derivation function chosen by the account.
     */
    enum class KdfType { Pbkdf2 = 0, Argon2id = 1 };

    /**
     * @brief Server-chosen KDF settings for deriving the master key.
     */
    struct KdfParams {
        KdfType m_type = KdfType::Pbkdf2;
        uint32_t m_iterations = 600000;
        uint32_t m_memory_mib = 0;
        uint32_t m_parallelism = 0;

        /**
         * @brief Rejects parameters outside safe bounds.
         *
         * The server picks these, so a hostile server could weaken them to make the password
         * hash it receives cheap to crack, or inflate them to hang the client.
         *
         * @throws CryptoError if any parameter is out of range
         */
        void validate() const;
    };

    /**
     * @brief Bitwarden client-side cryptography (built on Botan).
     *
     * Stateless: keys are always passed in. Every function validates its input and throws
     * CryptoError on malformed data or authentication failure; nothing ever returns a
     * half-initialised key or falls back silently.
     * See https://bitwarden.com/help/bitwarden-security-white-paper/
     */
    class Crypto {
    public:
        /**
         * @brief Derives the master key from the master password.
         *
         * @param password The master password
         * @param email The lowercased account email (the salt)
         * @param params KDF settings; validated first
         * @return The 32 byte master key
         */
        SecureBytes deriveMasterKey(
                std::string_view password, std::string_view email, KdfParams params) const;

        /**
         * @brief The master password hash sent to the server to authenticate.
         *
         * @param master_key The derived master key
         * @param password The master password
         * @return base64(PBKDF2-SHA256(master_key, password, 1 iteration))
         */
        SecureString hashMasterPassword(
                std::span<const uint8_t> master_key, std::string_view password) const;

        /**
         * @brief Expands the master key into the key pair that wraps the user key.
         *
         * @param master_key The derived master key
         * @return HKDF-Expand(master_key, "enc") and HKDF-Expand(master_key, "mac")
         */
        SymmetricKey stretchMasterKey(std::span<const uint8_t> master_key) const;

        /**
         * @brief Encrypts into a type 2 encrypted string: "2.<iv>|<ciphertext>|<mac>".
         *
         * @param plaintext The data to encrypt
         * @param key The key to encrypt under
         * @return The encrypted string
         */
        SecureString encrypt(std::span<const uint8_t> plaintext, SymmetricKey key) const;

        /**
         * @brief Encrypts text into a type 2 encrypted string.
         *
         * @param plaintext The text to encrypt
         * @param key The key to encrypt under
         * @return The encrypted string
         */
        SecureString encryptText(std::string_view plaintext, SymmetricKey key) const;

        /**
         * @brief Authenticates and decrypts a type 2 encrypted string.
         *
         * @param enc_string The encrypted string
         * @param key The key it was encrypted under
         * @return The plaintext
         * @throws CryptoError on bad format, wrong key or tampering
         */
        SecureBytes decrypt(std::string_view enc_string, SymmetricKey key) const;

        /**
         * @brief Decrypts a type 2 encrypted string to text.
         *
         * @param enc_string The encrypted string
         * @param key The key it was encrypted under
         * @return The plaintext
         */
        SecureString decryptText(std::string_view enc_string, SymmetricKey key) const;

        /**
         * @brief Whether a value looks like a type 2 encrypted string.
         *
         * @param value The value to check
         * @return True if it has the "2." prefix and three parts
         */
        bool isEncString(std::string_view value) const;

        /**
         * @brief Encrypts a key under another key.
         *
         * @param key The key to wrap
         * @param wrapping_key The key to wrap it with
         * @return The wrapped key as an encrypted string
         */
        SecureString wrapKey(SymmetricKey key, SymmetricKey wrapping_key) const;

        /**
         * @brief Decrypts a wrapped key.
         *
         * @param enc_string The wrapped key
         * @param wrapping_key The key it was wrapped with
         * @return The unwrapped key
         * @throws CryptoError if it doesn't decrypt to exactly 64 bytes
         */
        SymmetricKey unwrapKey(std::string_view enc_string, SymmetricKey wrapping_key) const;

        /**
         * @brief Encrypts an attachment body: 0x02 || iv || mac || ciphertext.
         *
         * @param plaintext The file contents
         * @param key The attachment key
         * @return The encrypted blob
         */
        SecureBytes encryptBuffer(std::span<const uint8_t> plaintext, SymmetricKey key) const;

        /**
         * @brief Authenticates and decrypts an attachment body.
         *
         * @param buffer The encrypted blob
         * @param key The attachment key
         * @return The file contents
         * @throws CryptoError on truncation, wrong key or tampering
         */
        SecureBytes decryptBuffer(std::span<const uint8_t> buffer, SymmetricKey key) const;

        /**
         * @brief The encrypted base64 SHA-256 Bitwarden stores beside each login URI.
         *
         * @param uri The plaintext URI
         * @param item_key The item's key
         * @return The encrypted checksum
         */
        SecureString uriChecksum(std::string_view uri, SymmetricKey item_key) const;

        /**
         * @brief Compares two buffers in constant time.
         *
         * @param a First buffer
         * @param b Second buffer
         * @return True if equal (length differences return early)
         */
        bool constantTimeEquals(std::span<const uint8_t> a, std::span<const uint8_t> b) const;

        /**
         * @brief Fills a buffer from the system CSPRNG.
         *
         * @param out The buffer to fill
         */
        void randomBytes(std::span<uint8_t> out) const;

        /**
         * @brief An unbiased random integer in [0, bound).
         *
         * @param bound The exclusive upper bound; must be positive
         * @return The random value
         */
        uint32_t randomBelow(uint32_t bound) const;

        /**
         * @brief Generates an RSA-2048 key pair (account and organisation sharing keys).
         *
         * @return The key pair
         */
        RsaKeyPair generateRsaKeyPair() const;

        /**
         * @brief Encrypts to an RSA public key as a type 4 encrypted string
         * ("4.<b64 RSA-OAEP-SHA1 ciphertext>"), the format used to share organisation keys.
         *
         * @param plaintext The data (at most 214 bytes for RSA-2048)
         * @param public_key The recipient's SubjectPublicKeyInfo DER
         * @return The encrypted string
         * @throws CryptoError if the key is malformed
         */
        SecureString rsaEncrypt(
                std::span<const uint8_t> plaintext, std::span<const uint8_t> public_key) const;

        /**
         * @brief Decrypts a type 3 (RSA-OAEP-SHA256) or type 4 (RSA-OAEP-SHA1) encrypted string.
         *
         * @param enc_string The encrypted string
         * @param private_key The PKCS#8 DER private key
         * @return The plaintext
         * @throws CryptoError on any other type, a malformed key, or a decryption failure
         */
        SecureBytes rsaDecrypt(
                std::string_view enc_string, std::span<const uint8_t> private_key) const;

        /**
         * @brief HKDF-SHA256 (extract and expand), as used to derive Send keys.
         *
         * @param input_key The input key material
         * @param salt The extract salt
         * @param info The expand context
         * @param length Bytes of output (at most 8160)
         * @return The derived key material
         */
        SecureBytes hkdf(std::span<const uint8_t> input_key, std::string_view salt,
                std::string_view info, size_t length) const;

        /**
         * @brief PBKDF2-HMAC-SHA256.
         *
         * @param password The password
         * @param salt The salt
         * @param iterations Iteration count (at least 1)
         * @param length Bytes of output
         * @return The derived key
         */
        SecureBytes pbkdf2(std::string_view password, std::span<const uint8_t> salt,
                uint32_t iterations, size_t length) const;

        /**
         * @brief SHA-256 of some data.
         *
         * @param data The data to hash
         * @return The 32 byte digest
         */
        SecureBytes sha256(std::span<const uint8_t> data) const;
    };
}
