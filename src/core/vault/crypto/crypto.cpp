#include "crypto.h"

#include <algorithm>
#include <array>
#include <botan/cipher_mode.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/data_src.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/pwdhash.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>
#include "platform/random/random.h"

#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"

namespace clientwarden {
    namespace {
        constexpr size_t c_key_size = 32;
        constexpr size_t c_iv_size = 16;
        constexpr size_t c_mac_size = 32;
        constexpr std::string_view c_type_prefix = "2.";
        constexpr uint8_t c_buffer_type = 0x02;

        /**
         * @brief Ciphertext with its IV and MAC, before serialisation.
         */
        struct Sealed {
            SecureBytes m_iv;
            SecureBytes m_ct;
            SecureBytes m_mac;
        };

        void requireKey_(SymmetricKey key) {
            if (!key.valid()) {
                throw CryptoError("key must be 32 byte enc + 32 byte mac");
            }
        }

        SecureBytes hmac_(std::span<const uint8_t> key, std::span<const uint8_t> iv,
                std::span<const uint8_t> ct) {
            std::shared_ptr<Botan::MessageAuthenticationCode> mac =
                    Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
            mac->set_key(key.data(), key.size());
            mac->update(iv.data(), iv.size());
            mac->update(ct.data(), ct.size());
            return mac->final();
        }

        SecureBytes aesCbc_(Botan::Cipher_Dir dir, std::span<const uint8_t> key,
                std::span<const uint8_t> iv, std::span<const uint8_t> input) {
            std::shared_ptr<Botan::Cipher_Mode> cbc =
                    Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", dir);
            cbc->set_key(key.data(), key.size());
            cbc->start(iv.data(), iv.size());

            SecureBytes buffer(input.begin(), input.end());
            try {
                cbc->finish(buffer);
            } catch (const Botan::Exception&) {
                throw CryptoError("decryption failed");
            }
            return buffer;
        }

        Sealed seal_(std::span<const uint8_t> plaintext, SymmetricKey key) {
            requireKey_(key);

            Sealed out;
            out.m_iv.resize(c_iv_size);
            random::secure().randomize(out.m_iv.data(), out.m_iv.size());
            out.m_ct = aesCbc_(Botan::Cipher_Dir::Encryption, key.m_enc, out.m_iv, plaintext);
            out.m_mac = hmac_(key.m_mac, out.m_iv, out.m_ct);
            return out;
        }

        SecureBytes open_(std::span<const uint8_t> iv, std::span<const uint8_t> ct,
                std::span<const uint8_t> mac, SymmetricKey key, Crypto crypto) {
            requireKey_(key);

            if (iv.size() != c_iv_size || mac.size() != c_mac_size || ct.empty() ||
                    ct.size() % c_iv_size != 0) {
                throw CryptoError("malformed ciphertext");
            }

            /*
             * Authenticate before touching the ciphertext so a tampered payload never reaches
             * the padding check.
             */
            SecureBytes expected = hmac_(key.m_mac, iv, ct);
            if (!crypto.constantTimeEquals(expected, mac)) {
                throw CryptoError("invalid mac");
            }
            return aesCbc_(Botan::Cipher_Dir::Decryption, key.m_enc, iv, ct);
        }
    }

    SymmetricKey SymmetricKey::generate() {
        SymmetricKey key;
        key.m_enc.resize(c_key_size);
        key.m_mac.resize(c_key_size);
        random::secure().randomize(key.m_enc.data(), key.m_enc.size());
        random::secure().randomize(key.m_mac.data(), key.m_mac.size());
        return key;
    }

    SymmetricKey SymmetricKey::fromCombined(std::span<const uint8_t> combined) {
        if (combined.size() != c_key_size * 2) {
            throw CryptoError("wrapped key must be 64 bytes");
        }
        SymmetricKey key;
        key.m_enc.assign(combined.begin(), combined.begin() + c_key_size);
        key.m_mac.assign(combined.begin() + c_key_size, combined.end());
        return key;
    }

    SecureBytes SymmetricKey::combined() const {
        SecureBytes out(m_enc);
        out.insert(out.end(), m_mac.begin(), m_mac.end());
        return out;
    }

    bool SymmetricKey::valid() const {
        return m_enc.size() == c_key_size && m_mac.size() == c_key_size;
    }

    void KdfParams::validate() const {
        switch (m_type) {
        case KdfType::Pbkdf2:
            if (m_iterations < 100000 || m_iterations > 10000000) {
                throw CryptoError("PBKDF2 iterations out of range");
            }
            return;
        case KdfType::Argon2id:
            if (m_iterations < 2 || m_iterations > 10 || m_memory_mib < 16 || m_memory_mib > 1024 ||
                    m_parallelism < 1 || m_parallelism > 16) {
                throw CryptoError("Argon2id parameters out of range");
            }
            return;
        }
        throw CryptoError("unsupported KDF type");
    }

    SecureBytes Crypto::deriveMasterKey(
            std::string_view password, std::string_view email, KdfParams params) const {
        params.validate();

        SecureBytes key(c_key_size);
        if (params.m_type == KdfType::Pbkdf2) {
            std::shared_ptr<Botan::PasswordHash> pbkdf2 =
                    Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)")
                            ->from_params(params.m_iterations);
            pbkdf2->derive_key(key.data(), key.size(), password.data(), password.size(),
                    reinterpret_cast<const uint8_t*>(email.data()), email.size());
            return key;
        }

        /*
         * Bitwarden salts Argon2id with SHA-256(email) rather than the raw email.
         */
        SecureBytes salt = sha256(encoding::bytesOf(email));
        std::shared_ptr<Botan::PasswordHash> argon =
                Botan::PasswordHashFamily::create_or_throw("Argon2id")
                        ->from_params(params.m_memory_mib * 1024, params.m_iterations,
                                params.m_parallelism);
        argon->derive_key(
                key.data(), key.size(), password.data(), password.size(), salt.data(), salt.size());
        return key;
    }

    SecureString Crypto::hashMasterPassword(
            std::span<const uint8_t> master_key, std::string_view password) const {
        if (master_key.size() != c_key_size) {
            throw CryptoError("master key must be 32 bytes");
        }

        SecureBytes hash(c_key_size);
        std::shared_ptr<Botan::PasswordHash> pbkdf2 =
                Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)")->from_params(1);
        pbkdf2->derive_key(hash.data(), hash.size(),
                reinterpret_cast<const char*>(master_key.data()), master_key.size(),
                reinterpret_cast<const uint8_t*>(password.data()), password.size());
        return encoding::base64Encode(hash);
    }

    SymmetricKey Crypto::stretchMasterKey(std::span<const uint8_t> master_key) const {
        if (master_key.size() != c_key_size) {
            throw CryptoError("master key must be 32 bytes");
        }

        /*
         * HKDF-Expand with one output block: T(1) = HMAC(prk, info || 0x01)
         */
        std::array<std::string_view, 2> labels = { "enc", "mac" };
        std::array<SecureBytes, 2> halves;
        for (size_t i = 0; i < labels.size(); ++i) {
            std::shared_ptr<Botan::MessageAuthenticationCode> mac =
                    Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
            mac->set_key(master_key.data(), master_key.size());
            mac->update(reinterpret_cast<const uint8_t*>(labels[i].data()), labels[i].size());
            mac->update(0x01);
            halves[i] = mac->final();
        }

        SymmetricKey key;
        key.m_enc = std::move(halves[0]);
        key.m_mac = std::move(halves[1]);
        return key;
    }

    SecureString Crypto::encrypt(std::span<const uint8_t> plaintext, SymmetricKey key) const {
        Sealed sealed = seal_(plaintext, std::move(key));

        SecureString out(c_type_prefix);
        out += encoding::base64Encode(sealed.m_iv);
        out += '|';
        out += encoding::base64Encode(sealed.m_ct);
        out += '|';
        out += encoding::base64Encode(sealed.m_mac);
        return out;
    }

    SecureString Crypto::encryptText(std::string_view plaintext, SymmetricKey key) const {
        return encrypt(encoding::bytesOf(plaintext), std::move(key));
    }

    SecureBytes Crypto::decrypt(std::string_view enc_string, SymmetricKey key) const {
        if (!enc_string.starts_with(c_type_prefix)) {
            /*
             * Types 0/1 are unauthenticated or deprecated and 3+ are RSA (organisation keys),
             * none of which are handled here.
             */
            throw CryptoError("unsupported encryption type");
        }

        std::string_view rest = enc_string.substr(c_type_prefix.size());
        size_t first = rest.find('|');
        size_t second = first == std::string_view::npos ? first : rest.find('|', first + 1);
        if (second == std::string_view::npos ||
                rest.find('|', second + 1) != std::string_view::npos) {
            throw CryptoError("invalid encrypted string format");
        }

        SecureBytes iv = encoding::base64Decode(rest.substr(0, first));
        SecureBytes ct = encoding::base64Decode(rest.substr(first + 1, second - first - 1));
        SecureBytes mac = encoding::base64Decode(rest.substr(second + 1));
        return open_(iv, ct, mac, std::move(key), *this);
    }

    SecureString Crypto::decryptText(std::string_view enc_string, SymmetricKey key) const {
        SecureBytes plaintext = decrypt(enc_string, std::move(key));
        return SecureString(plaintext.begin(), plaintext.end());
    }

    bool Crypto::isEncString(std::string_view value) const {
        return value.starts_with(c_type_prefix) && std::count(value.begin(), value.end(), '|') == 2;
    }

    SecureString Crypto::wrapKey(SymmetricKey key, SymmetricKey wrapping_key) const {
        requireKey_(key);
        return encrypt(key.combined(), std::move(wrapping_key));
    }

    SymmetricKey Crypto::unwrapKey(std::string_view enc_string, SymmetricKey wrapping_key) const {
        return SymmetricKey::fromCombined(decrypt(enc_string, std::move(wrapping_key)));
    }

    SecureBytes Crypto::encryptBuffer(std::span<const uint8_t> plaintext, SymmetricKey key) const {
        Sealed sealed = seal_(plaintext, std::move(key));

        SecureBytes out;
        out.reserve(1 + c_iv_size + c_mac_size + sealed.m_ct.size());
        out.push_back(c_buffer_type);
        out.insert(out.end(), sealed.m_iv.begin(), sealed.m_iv.end());
        out.insert(out.end(), sealed.m_mac.begin(), sealed.m_mac.end());
        out.insert(out.end(), sealed.m_ct.begin(), sealed.m_ct.end());
        return out;
    }

    SecureBytes Crypto::decryptBuffer(std::span<const uint8_t> buffer, SymmetricKey key) const {
        constexpr size_t c_header = 1 + c_iv_size + c_mac_size;
        if (buffer.size() <= c_header || buffer[0] != c_buffer_type) {
            throw CryptoError("malformed encrypted buffer");
        }
        return open_(buffer.subspan(1, c_iv_size), buffer.subspan(c_header),
                buffer.subspan(1 + c_iv_size, c_mac_size), std::move(key), *this);
    }

    SecureString Crypto::uriChecksum(std::string_view uri, SymmetricKey item_key) const {
        return encryptText(
                encoding::base64Encode(sha256(encoding::bytesOf(uri))), std::move(item_key));
    }

    bool Crypto::constantTimeEquals(std::span<const uint8_t> a, std::span<const uint8_t> b) const {
        if (a.size() != b.size()) {
            return false;
        }
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff = diff | (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    void Crypto::randomBytes(std::span<uint8_t> out) const {
        random::secure().randomize(out.data(), out.size());
    }

    uint32_t Crypto::randomBelow(uint32_t bound) const {
        if (bound == 0) {
            throw CryptoError("randomBelow bound must be positive");
        }

        /*
         * Rejection sampling: discard draws from the final partial bucket so every result is
         * equally likely.
         */
        const uint32_t c_limit = UINT32_MAX - (UINT32_MAX % bound);
        uint32_t value = 0;
        do {
            randomBytes(std::span<uint8_t>(reinterpret_cast<uint8_t*>(&value), sizeof(value)));
        } while (value >= c_limit);
        return value % bound;
    }

    SecureBytes Crypto::sha256(std::span<const uint8_t> data) const {
        std::shared_ptr<Botan::HashFunction> hash = Botan::HashFunction::create_or_throw("SHA-256");
        hash->update(data.data(), data.size());
        return hash->final();
    }

    RsaKeyPair Crypto::generateRsaKeyPair() const {
        Botan::RSA_PrivateKey key(random::secure(), 2048);
        RsaKeyPair pair;
        pair.m_private_key = Botan::PKCS8::BER_encode(key);
        std::vector<uint8_t> public_key = key.subject_public_key();
        pair.m_public_key.assign(public_key.begin(), public_key.end());
        return pair;
    }

    SecureString Crypto::rsaEncrypt(
            std::span<const uint8_t> plaintext, std::span<const uint8_t> public_key) const {
        try {
            std::shared_ptr<Botan::Public_Key> key = Botan::X509::load_key(public_key);
            Botan::PK_Encryptor_EME encryptor(*key, random::secure(), "OAEP(SHA-1)");
            std::vector<uint8_t> ciphertext =
                    encryptor.encrypt(plaintext.data(), plaintext.size(), random::secure());
            return SecureString("4.") + encoding::base64Encode(ciphertext);
        } catch (const Botan::Exception&) {
            throw CryptoError("invalid RSA public key");
        }
    }

    SecureBytes Crypto::rsaDecrypt(
            std::string_view enc_string, std::span<const uint8_t> private_key) const {
        std::string_view padding;
        if (enc_string.starts_with("3.")) {
            padding = "OAEP(SHA-256)";
        } else if (enc_string.starts_with("4.")) {
            padding = "OAEP(SHA-1)";
        } else {
            throw CryptoError("unsupported RSA encryption type");
        }

        SecureBytes ciphertext = encoding::base64Decode(enc_string.substr(2));
        try {
            Botan::DataSource_Memory source(private_key.data(), private_key.size());
            std::shared_ptr<Botan::Private_Key> key = Botan::PKCS8::load_key(source);
            Botan::PK_Decryptor_EME decryptor(*key, random::secure(), padding);
            return decryptor.decrypt(ciphertext.data(), ciphertext.size());
        } catch (const Botan::Exception&) {
            throw CryptoError("RSA decryption failed");
        }
    }

    SecureBytes Crypto::hkdf(std::span<const uint8_t> input_key, std::string_view salt,
            std::string_view info, size_t length) const {
        if (length == 0 || length > 255 * 32) {
            throw CryptoError("invalid HKDF output length");
        }

        /*
         * RFC 5869: PRK = HMAC(salt, IKM); T(n) = HMAC(PRK, T(n-1) || info || n)
         */
        std::shared_ptr<Botan::MessageAuthenticationCode> mac =
                Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
        mac->set_key(reinterpret_cast<const uint8_t*>(salt.data()), salt.size());
        mac->update(input_key.data(), input_key.size());
        SecureBytes prk = mac->final();

        SecureBytes out;
        SecureBytes block;
        for (uint8_t counter = 1; out.size() < length; ++counter) {
            mac->set_key(prk);
            mac->update(block);
            mac->update(reinterpret_cast<const uint8_t*>(info.data()), info.size());
            mac->update(counter);
            block = mac->final();
            out.insert(out.end(), block.begin(), block.end());
        }
        out.resize(length);
        return out;
    }

    SecureBytes Crypto::pbkdf2(std::string_view password, std::span<const uint8_t> salt,
            uint32_t iterations, size_t length) const {
        if (iterations == 0) {
            throw CryptoError("PBKDF2 needs at least one iteration");
        }
        SecureBytes out(length);
        std::shared_ptr<Botan::PasswordHash> hash =
                Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)")
                        ->from_params(iterations);
        hash->derive_key(
                out.data(), out.size(), password.data(), password.size(), salt.data(), salt.size());
        return out;
    }
}
