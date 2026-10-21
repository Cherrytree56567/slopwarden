#include "sends.h"

#include <algorithm>

#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"
#include "utils/logger/logger.h"
#include "utils/timestamp/timestamp.h"

namespace clientwarden {
    namespace {
        constexpr std::string_view c_section = "sends";
        constexpr size_t c_key_material_size = 16;
        constexpr std::time_t c_default_lifetime = 7 * 86400;

        /**
         * @brief Bitwarden cloud serves Send links from send.* but the API from vault.*.
         *
         * @param origin The link's origin
         * @return The origin to call the API on
         */
        SecureString apiOrigin_(std::string_view origin) {
            if (origin == "https://send.bitwarden.com") {
                return "https://vault.bitwarden.com";
            }
            if (origin == "https://send.bitwarden.eu") {
                return "https://vault.bitwarden.eu";
            }
            return SecureString(origin);
        }
    }

    Sends::Sends(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network,
            std::shared_ptr<Store> store, std::shared_ptr<Session> session,
            std::shared_ptr<FileStore> files, std::function<SecureString()> web_vault)
        : m_crypto_(std::move(crypto)), m_network_(std::move(network)), m_store_(std::move(store)),
          m_session_(std::move(session)), m_files_(std::move(files)),
          m_web_vault_(std::move(web_vault)) {}

    std::shared_ptr<Send> Sends::wrap_(Json send) {
        SecureBytes material;
        try {
            material = m_crypto_->decrypt(stringAt(send, "key"), m_session_->getUserKey());
        } catch (const CryptoError&) {
            throw VaultError("a Send's key failed to decrypt");
        }
        return std::make_shared<Send>(
                shared_from_this(), m_crypto_, std::move(send), std::move(material));
    }

    std::vector<std::shared_ptr<Send>> Sends::getSends() {
        m_session_->getUserKey(); // throws if locked
        std::vector<std::shared_ptr<Send>> sends;
        for (Record& record : m_store_->getSectionRecords(c_section)) {
            try {
                sends.push_back(wrap_(*record));
            } catch (const VaultError& e) {
                Logger::get()->warn("Skipping a Send: {}", e.what());
            }
        }
        std::sort(sends.begin(), sends.end(),
                [](const std::shared_ptr<Send>& a, const std::shared_ptr<Send>& b) {
                    return a->getDeletionDate() < b->getDeletionDate();
                });
        return sends;
    }

    std::shared_ptr<Send> Sends::getSend(std::string_view id) {
        for (Record& record : m_store_->getSectionRecords(c_section)) {
            if (stringAt(*record, "id") == id) {
                return wrap_(*record);
            }
        }
        throw VaultError("Send not found");
    }

    std::shared_ptr<Send> Sends::createSend(SendType type) {
        SecureBytes material(c_key_material_size);
        m_crypto_->randomBytes(material);
        SecureString wrapped = m_crypto_->encrypt(material, m_session_->getUserKey());

        // clang-format off
        Json send = {
            { "type", static_cast<int>(type) },
            { "key", wrapped },
            { "name", nullptr },
            { "notes", nullptr },
            { "text", nullptr },
            { "file", nullptr },
            { "maxAccessCount", nullptr },
            { "expirationDate", nullptr },
            { "deletionDate", timestamp::format(std::time(nullptr) + c_default_lifetime) },
            { "password", nullptr },
            { "disabled", false },
            { "hideEmail", false }
        };
        // clang-format on

        std::shared_ptr<Send> created = std::make_shared<Send>(
                shared_from_this(), m_crypto_, std::move(send), std::move(material));
        created->setName("");
        if (type == SendType::Text) {
            created->setText("", false);
        }
        return created;
    }

    bool Sends::saveSend(Send& send) {
        m_session_->getUserKey(); // throws if locked
        Json body = send.getJson();
        body.erase("accessId");
        body.erase("accessCount");
        body.erase("revisionDate");

        std::optional<Json> result;
        if (send.getId().empty()) {
            if (send.getType() == SendType::File) {
                std::optional<SecureBytes> file = send.getPendingFile();
                if (!file) {
                    throw VaultError("choose a file before saving a file Send");
                }
                result = m_network_->createFileSend(
                        body, m_crypto_->encryptBuffer(*file, send.getKey()), nullptr);
            } else {
                result = m_network_->createSend(body);
            }
        } else {
            body.erase("file"); // a file Send's file is fixed once uploaded
            result = m_network_->updateSend(send.getId(), body);
        }

        if (!result || stringAt(*result, "id").empty()) {
            return false;
        }
        send.replaceJson(*result);
        m_store_->putSectionRecord(c_section, *result);
        return true;
    }

    bool Sends::deleteSend(Send& send) {
        if (send.getId().empty()) {
            return true;
        }
        if (!m_network_->deleteSend(send.getId())) {
            return false;
        }
        m_store_->removeSectionRecord(c_section, send.getId());
        return true;
    }

    bool Sends::removePassword(Send& send) {
        if (send.getId().empty()) {
            Json updated = send.getJson();
            updated["password"] = nullptr;
            send.replaceJson(updated);
            return true;
        }
        std::optional<Json> result = m_network_->removeSendPassword(send.getId());
        if (!result) {
            return false;
        }
        send.replaceJson(*result);
        m_store_->putSectionRecord(c_section, *result);
        return true;
    }

    SecureString Sends::shareUrl(
            std::string_view access_id, std::span<const uint8_t> key_material) {
        SecureString base = m_web_vault_ ? m_web_vault_() : SecureString();
        while (!base.empty() && base.back() == '/') {
            base.pop_back();
        }
        return base + "/#/send/" + SecureString(access_id) + "/" +
               encoding::base64UrlEncode(key_material);
    }

    std::optional<SendLink> Sends::parseLink(std::string_view link) {
        if (!link.starts_with("https://") && !link.starts_with("http://")) {
            return std::nullopt;
        }
        size_t scheme_end = link.find("://") + 3;
        size_t hash = link.find('#');
        if (hash == std::string_view::npos) {
            return std::nullopt;
        }
        size_t origin_end = std::min(link.find('/', scheme_end), hash);
        SecureString origin(link.substr(0, origin_end));

        /*
         * Fragment: "/send/<id>/<key>", "send/<id>/<key>", "/<id>/<key>" or "<id>/<key>".
         */
        std::string_view fragment = link.substr(hash + 1);
        if (fragment.starts_with("/")) {
            fragment.remove_prefix(1);
        }
        if (fragment.starts_with("send/")) {
            fragment.remove_prefix(5);
        }
        size_t slash = fragment.find('/');
        if (slash == std::string_view::npos || slash == 0) {
            return std::nullopt;
        }
        std::string_view access_id = fragment.substr(0, slash);
        std::string_view key = fragment.substr(slash + 1);
        key = key.substr(0, key.find_first_of("/?"));

        SecureBytes material;
        try {
            material = encoding::base64Decode(key);
        } catch (const CryptoError&) {
            return std::nullopt;
        }
        if (material.size() != c_key_material_size || access_id.empty()) {
            return std::nullopt;
        }
        for (char c : access_id) {
            bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!allowed) {
                return std::nullopt;
            }
        }
        return SendLink { apiOrigin_(origin), SecureString(access_id), std::move(material) };
    }

    ReceiveResult Sends::open(
            std::string_view link, std::string_view password, ReceivedSend& received) {
        std::optional<SendLink> parsed = parseLink(link);
        if (!parsed) {
            return ReceiveResult::InvalidLink;
        }

        SecureString password_hash =
                password.empty() ? SecureString()
                                 : Send::hashPassword(*m_crypto_, password, parsed->m_key_material);
        HttpResponse response =
                m_network_->accessSend(parsed->m_origin, parsed->m_access_id, password_hash);
        if (!response.reached()) {
            return ReceiveResult::Offline;
        }
        if (response.m_status == 401) {
            return password.empty() ? ReceiveResult::NeedsPassword : ReceiveResult::WrongPassword;
        }
        if (response.m_status == 404 || response.m_status == 400) {
            return ReceiveResult::NotAvailable;
        }
        std::optional<Json> send = response.ok() ? response.json() : std::nullopt;
        if (!send) {
            return ReceiveResult::Failed;
        }

        SymmetricKey key = Send::deriveKey(*m_crypto_, parsed->m_key_material);
        try {
            const Json& type = at(*send, "type");
            received.m_link = *parsed;
            received.m_id = stringAt(*send, "id");
            received.m_type = type.is_number_integer() && type.get<int>() == 1 ? SendType::File
                                                                               : SendType::Text;
            received.m_name = m_crypto_->decryptText(stringAt(*send, "name"), key);
            received.m_text_hidden = false;
            if (received.m_type == SendType::Text) {
                const Json& text = at(*send, "text");
                received.m_text = m_crypto_->decryptText(stringAt(text, "text"), key);
                received.m_text_hidden =
                        at(text, "hidden").is_boolean() && at(text, "hidden").get<bool>();
            } else {
                const Json& file = at(*send, "file");
                received.m_file_id = stringAt(file, "id");
                received.m_file_name = m_crypto_->decryptText(stringAt(file, "fileName"), key);
                received.m_file_size = stringAt(file, "sizeName");
            }
            received.m_expiration_date = timestamp::parse(stringAt(*send, "expirationDate"));
            received.m_creator = stringAt(*send, "creatorIdentifier");
            received.m_password_hash = password_hash;
        } catch (const CryptoError&) {
            /*
             * Wrong key in the link, or tampered content.
             */
            return ReceiveResult::Failed;
        }
        return ReceiveResult::Success;
    }

    bool Sends::downloadReceivedFile(const ReceivedSend& received,
            std::filesystem::path destination, std::function<void(float)> on_progress) {
        if (received.m_type != SendType::File) {
            throw VaultError("not a file Send");
        }
        std::optional<SecureBytes> encrypted =
                m_network_->accessSendFile(received.m_link.m_origin, received.m_id,
                        received.m_file_id, received.m_password_hash, std::move(on_progress));
        if (!encrypted) {
            return false;
        }
        SecureBytes plaintext = m_crypto_->decryptBuffer(
                *encrypted, Send::deriveKey(*m_crypto_, received.m_link.m_key_material));
        m_files_->write(std::move(destination), plaintext);
        return true;
    }
}
