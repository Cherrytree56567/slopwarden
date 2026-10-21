#include "Crypto.h"

#include <algorithm>

#include <botan/base64.h>
#include <botan/cipher_mode.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pwdhash.h>
#include <botan/system_rng.h>

namespace ClientWarden::Crypto {
    namespace {
        constexpr std::string_view TypePrefix = "2.";
        constexpr uint8_t BufferType = 0x02;

        std::span<const uint8_t> AsBytes(std::string_view str) {
            return { reinterpret_cast<const uint8_t*>(str.data()), str.size() };
        }

        void RequireKey(const SymmetricKey& key) {
            if (!key.Valid()) {
                throw CryptoError("key must be 32 byte enc + 32 byte mac");
            }
        }

        Bytes Hmac(const Bytes& macKey, std::span<const uint8_t> iv, std::span<const uint8_t> ct) {
            auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
            hmac->set_key(macKey);
            hmac->update(iv.data(), iv.size());
            hmac->update(ct.data(), ct.size());
            return hmac->final();
        }

        Bytes AesCbc(Botan::Cipher_Dir dir, const Bytes& encKey, std::span<const uint8_t> iv, std::span<const uint8_t> input) {
            auto cbc = Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", dir);
            cbc->set_key(encKey);
            cbc->start(iv.data(), iv.size());

            Bytes buf(input.begin(), input.end());
            try {
                cbc->finish(buf);
            } catch (const Botan::Exception&) {
                throw CryptoError("decryption failed");
            }
            return buf;
        }

        struct Sealed {
            Bytes iv;
            Bytes ct;
            Bytes mac;
        };

        Sealed Seal(std::span<const uint8_t> plaintext, const SymmetricKey& key) {
            RequireKey(key);

            Sealed out;
            out.iv.resize(IvSize);
            RandomBytes(out.iv);
            out.ct = AesCbc(Botan::Cipher_Dir::Encryption, key.enc, out.iv, plaintext);
            out.mac = Hmac(key.mac, out.iv, out.ct);
            return out;
        }

        Bytes Open(std::span<const uint8_t> iv, std::span<const uint8_t> ct, std::span<const uint8_t> mac, const SymmetricKey& key) {
            RequireKey(key);

            if (iv.size() != IvSize || mac.size() != MacSize || ct.empty() || ct.size() % IvSize != 0) {
                throw CryptoError("malformed ciphertext");
            }

            /*
             * Authenticate before touching the ciphertext so a tampered
             * payload never reaches the padding check.
            */
            Bytes expected = Hmac(key.mac, iv, ct);
            if (!ConstantTimeEquals(expected, mac)) {
                throw CryptoError("invalid mac");
            }

            return AesCbc(Botan::Cipher_Dir::Decryption, key.enc, iv, ct);
        }
    }

    SymmetricKey SymmetricKey::Generate() {
        SymmetricKey key;
        key.enc.resize(KeySize);
        key.mac.resize(KeySize);
        RandomBytes(key.enc);
        RandomBytes(key.mac);
        return key;
    }

    SymmetricKey SymmetricKey::FromCombined(std::span<const uint8_t> combined) {
        if (combined.size() != KeySize * 2) {
            throw CryptoError("wrapped key must be 64 bytes, got " + std::to_string(combined.size()));
        }
        return SymmetricKey {
            Bytes(combined.begin(), combined.begin() + KeySize),
            Bytes(combined.begin() + KeySize, combined.end())
        };
    }

    Bytes SymmetricKey::Combined() const {
        Bytes out(enc);
        out.insert(out.end(), mac.begin(), mac.end());
        return out;
    }

    bool SymmetricKey::Valid() const {
        return enc.size() == KeySize && mac.size() == KeySize;
    }

    void KdfParams::Validate() const {
        auto inRange = [](uint32_t v, uint32_t lo, uint32_t hi) { return v >= lo && v <= hi; };

        switch (type) {
            case KdfType::PBKDF2:
                if (!inRange(iterations, 100000, 10000000)) {
                    throw CryptoError("PBKDF2 iterations out of range: " + std::to_string(iterations));
                }
                return;
            case KdfType::Argon2id:
                if (!inRange(iterations, 2, 10) || !inRange(memoryMiB, 16, 1024) || !inRange(parallelism, 1, 16)) {
                    throw CryptoError("Argon2id parameters out of range");
                }
                return;
        }
        throw CryptoError("unsupported KDF type " + std::to_string(static_cast<int>(type)));
    }

    Bytes DeriveMasterKey(std::string_view password, std::string_view email, const KdfParams& params) {
        params.Validate();

        Bytes key(KeySize);

        if (params.type == KdfType::PBKDF2) {
            auto pbkdf2 = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)")->from_params(params.iterations);
            pbkdf2->derive_key(key.data(), key.size(), password.data(), password.size(),
                reinterpret_cast<const uint8_t*>(email.data()), email.size());
            return key;
        }

        /*
         * Bitwarden salts Argon2id with SHA-256(email) rather than the
         * raw email.
        */
        Bytes salt = Botan::HashFunction::create_or_throw("SHA-256")->process(AsBytes(email).data(), email.size());
        auto argon = Botan::PasswordHashFamily::create_or_throw("Argon2id")
            ->from_params(params.memoryMiB * 1024, params.iterations, params.parallelism);
        argon->derive_key(key.data(), key.size(), password.data(), password.size(), salt.data(), salt.size());
        return key;
    }

    std::string HashMasterPassword(const Bytes& masterKey, std::string_view password) {
        if (masterKey.size() != KeySize) {
            throw CryptoError("master key must be 32 bytes");
        }

        Bytes hash(KeySize);
        auto pbkdf2 = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)")->from_params(1);
        pbkdf2->derive_key(hash.data(), hash.size(), reinterpret_cast<const char*>(masterKey.data()), masterKey.size(),
            reinterpret_cast<const uint8_t*>(password.data()), password.size());
        return Base64Encode(hash);
    }

    SymmetricKey StretchMasterKey(const Bytes& masterKey) {
        if (masterKey.size() != KeySize) {
            throw CryptoError("master key must be 32 bytes");
        }

        /*
         * HKDF-Expand with a single output block: T(1) = HMAC(prk, info || 0x01)
        */
        auto expand = [&](std::string_view info) {
            auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
            hmac->set_key(masterKey);
            hmac->update(AsBytes(info).data(), info.size());
            hmac->update(0x01);
            return hmac->final();
        };

        return SymmetricKey { expand("enc"), expand("mac") };
    }

    std::string Encrypt(std::span<const uint8_t> plaintext, const SymmetricKey& key) {
        Sealed s = Seal(plaintext, key);

        std::string out(TypePrefix);
        out += Base64Encode(s.iv);
        out += '|';
        out += Base64Encode(s.ct);
        out += '|';
        out += Base64Encode(s.mac);
        return out;
    }

    std::string Encrypt(std::string_view plaintext, const SymmetricKey& key) {
        return Encrypt(AsBytes(plaintext), key);
    }

    Bytes Decrypt(std::string_view encString, const SymmetricKey& key) {
        if (!encString.starts_with(TypePrefix)) {
            /*
             * Types 0/1 are unauthenticated or deprecated and types 3+
             * are RSA (org keys), none of which are supported.
            */
            throw CryptoError("unsupported encryption type");
        }

        std::string_view rest = encString.substr(TypePrefix.size());
        size_t first = rest.find('|');
        size_t second = first == std::string_view::npos ? first : rest.find('|', first + 1);
        if (second == std::string_view::npos || rest.find('|', second + 1) != std::string_view::npos) {
            throw CryptoError("invalid encrypted string format");
        }

        Bytes iv = Base64Decode(rest.substr(0, first));
        Bytes ct = Base64Decode(rest.substr(first + 1, second - first - 1));
        Bytes mac = Base64Decode(rest.substr(second + 1));

        return Open(iv, ct, mac, key);
    }

    SecretString DecryptString(std::string_view encString, const SymmetricKey& key) {
        Bytes pt = Decrypt(encString, key);
        return SecretString(pt.begin(), pt.end());
    }

    bool IsEncString(std::string_view value) {
        return value.starts_with(TypePrefix) && std::count(value.begin(), value.end(), '|') == 2;
    }

    std::string WrapKey(const SymmetricKey& key, const SymmetricKey& wrappingKey) {
        RequireKey(key);
        return Encrypt(key.Combined(), wrappingKey);
    }

    SymmetricKey UnwrapKey(std::string_view encString, const SymmetricKey& wrappingKey) {
        return SymmetricKey::FromCombined(Decrypt(encString, wrappingKey));
    }

    std::vector<uint8_t> EncryptBuffer(std::span<const uint8_t> plaintext, const SymmetricKey& key) {
        Sealed s = Seal(plaintext, key);

        std::vector<uint8_t> out;
        out.reserve(1 + IvSize + MacSize + s.ct.size());
        out.push_back(BufferType);
        out.insert(out.end(), s.iv.begin(), s.iv.end());
        out.insert(out.end(), s.mac.begin(), s.mac.end());
        out.insert(out.end(), s.ct.begin(), s.ct.end());
        return out;
    }

    Bytes DecryptBuffer(std::span<const uint8_t> buffer, const SymmetricKey& key) {
        constexpr size_t header = 1 + IvSize + MacSize;
        if (buffer.size() <= header || buffer[0] != BufferType) {
            throw CryptoError("malformed encrypted buffer");
        }

        return Open(buffer.subspan(1, IvSize), buffer.subspan(header), buffer.subspan(1 + IvSize, MacSize), key);
    }

    std::string UriChecksum(std::string_view uri, const SymmetricKey& itemKey) {
        Bytes hash = Botan::HashFunction::create_or_throw("SHA-256")->process(AsBytes(uri).data(), uri.size());
        return Encrypt(Base64Encode(hash), itemKey);
    }

    bool ConstantTimeEquals(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        if (a.size() != b.size()) {
            return false;
        }
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff = diff | (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    void RandomBytes(std::span<uint8_t> out) {
        Botan::system_rng().randomize(out.data(), out.size());
    }

    uint32_t RandomBelow(uint32_t bound) {
        if (bound == 0) {
            throw CryptoError("RandomBelow bound must be positive");
        }

        /*
         * Rejection sampling: discard draws from the final partial
         * bucket so every result is equally likely.
        */
        const uint32_t limit = UINT32_MAX - (UINT32_MAX % bound);
        uint32_t value = 0;
        do {
            RandomBytes({ reinterpret_cast<uint8_t*>(&value), sizeof(value) });
        } while (value >= limit);
        return value % bound;
    }

    std::string Base64Encode(std::span<const uint8_t> data) {
        return Botan::base64_encode(data.data(), data.size());
    }

    Bytes Base64Decode(std::string_view data) {
        try {
            return Botan::base64_decode(data);
        } catch (const Botan::Exception&) {
            throw CryptoError("invalid base64");
        }
    }
}
