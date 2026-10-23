#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>

#include "platform/paths/paths.h"
#include "platform/secret_store/platform_secret_store.h"
#include "utils/errors/errors.h"
#include "utils/secure_string/secure_string.h"

/*
 * The Wii has no keychain, so the session lives in data/session.json on the SD card. Nothing in
 * it opens the vault: the user key is only ever derived from the master password, which is asked
 * for every launch, and the session's tokens are sealed under that user key by the core (see
 * Session::setSealTokens) before they're written here. What's left in the clear is the email,
 * server URLs, KDF settings and a device id.
 */
namespace {
    using clientwarden::Json;
    using clientwarden::SecretProtection;
    using clientwarden::SecureString;

    class FileSecretStore : public clientwarden::SecretStore {
    public:
        std::optional<SecureString> get(std::string_view key) override {
            std::lock_guard<std::mutex> lock(m_mutex);
            load_();
            const Json& value = clientwarden::at(m_values, key);
            if (!value.is_string()) {
                return std::nullopt;
            }
            return value.get<SecureString>();
        }

        bool set(std::string_view key, std::string_view value, SecretProtection protection) override {
            if (protection == SecretProtection::UserAuth) {
                return false; // no biometrics or device credential to guard it with
            }
            std::lock_guard<std::mutex> lock(m_mutex);
            load_();
            m_values[SecureString(key)] = SecureString(value);
            return save_();
        }

        bool remove(std::string_view key) override {
            std::lock_guard<std::mutex> lock(m_mutex);
            load_();
            if (m_values.erase(SecureString(key)) == 0) {
                return true;
            }
            return save_();
        }

        bool protectedByOs() const override {
            return false; // a file on the SD card
        }

    private:
        std::filesystem::path file_() const {
            return clientwarden::paths::dataDirectory() / "session.json";
        }

        void load_() {
            if (m_loaded) {
                return;
            }
            m_loaded = true;
            m_values = Json::object();
            std::ifstream in(file_(), std::ios::binary);
            if (!in) {
                return;
            }
            SecureString text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            Json parsed = Json::parse(text, nullptr, false);
            if (parsed.is_object()) {
                m_values = std::move(parsed);
            }
        }

        /*
         * Write a temporary file, then swap it in, so a power cut mid-write can't leave half a
         * session. FAT can't rename over an existing file, hence the remove first.
         */
        bool save_() {
            std::filesystem::path target = file_();
            std::filesystem::path temporary = target;
            temporary += ".tmp";
            {
                std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
                if (!out) {
                    return false;
                }
                SecureString text = m_values.dump();
                out.write(text.data(), static_cast<std::streamsize>(text.size()));
                if (!out) {
                    return false;
                }
            }
            std::error_code error;
            std::filesystem::remove(target, error);
            std::filesystem::rename(temporary, target, error);
            return !error;
        }

        std::mutex m_mutex;
        bool m_loaded = false;
        Json m_values = Json::object();
    };
}

namespace clientwarden {
    std::shared_ptr<SecretStore> createPlatformSecretStore() {
        return std::make_shared<FileSecretStore>();
    }
}
