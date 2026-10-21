#pragma once
#include <algorithm>   // botan/secmem.h uses std::fill without including it
#include <memory>
#include <stdexcept>
#include <string>
#include <botan/secmem.h>
#include <spdlog/spdlog.h>

namespace ClientWarden {
    /*
     * Key material and decrypted payloads live in secure_vector, which
     * zeroes its buffer when freed. SecretString does the same for text
     * handed to the UI, so callers never need to scrub manually.
    */
    using Bytes = Botan::secure_vector<uint8_t>;
    using SecretString = std::basic_string<char, std::char_traits<char>, Botan::secure_allocator<char>>;

    class VaultError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class CryptoError : public VaultError {
    public:
        using VaultError::VaultError;
    };

    enum class CustomFieldType {
        Text = 0,
        Hidden = 1,
        Checkbox = 2,
        Linked = 3
    };

    /*
     * From Vault Warden
     * https://github.com/dani-garcia/vaultwarden/blob/eb212e23fad88e6136723f43e5b73543fa7026d3/src/db/models/cipher.rs#L51
     * See (v2026.7.0): https://github.com/bitwarden/server/blob/5d4461aa42cadbacfef8fe2166c5453a5c52773a/src/Core/Vault/Enums/CipherType.cs
    */
    enum class CipherType {
        Generic = 0,
        Login = 1,
        Note = 2,
        Card = 3,
        Identity = 4,
        SSHKey = 5,
        BankAccount = 6,
        DriversLicense = 7,
        Passport = 8
    };

    enum class AuthState {
        Unknown,
        LoggedOut,
        Unlockable,
        WaitingForTOTP,
        WaitingForDeviceVerif,
        WaitingForPasskey,
        Unlocked
    };

    /*
     * Zeroes a buffer in a way the optimiser can't elide; for the few
     * places where a secret has to pass through a plain std::string.
    */
    inline void Wipe(std::string& s) {
        volatile char* p = s.data();
        for (size_t i = 0; i < s.size(); ++i) {
            p[i] = 0;
        }
        s.clear();
    }

    inline std::shared_ptr<spdlog::logger> logger = nullptr;

    /*
     * Returns the shared logger, creating a console-only one if the
     * host app hasn't installed its own.
    */
    std::shared_ptr<spdlog::logger> Log();
}
