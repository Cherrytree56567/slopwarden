#include "orchestrator.h"

#include <algorithm>

#include "utils/encoding/encoding.h"
#include "utils/logger/logger.h"
#include "utils/timestamp/timestamp.h"
#include "utils/uuid/uuid.h"

namespace clientwarden {
    namespace {
        /**
         * @brief Whether a stored record was created offline and never uploaded.
         *
         * @param record The cipher or folder
         * @return True if it carries createdOffline: true
         */
        bool createdOffline_(const Json& record) {
            const Json& flag = at(record, "createdOffline");
            return flag.is_boolean() && flag.get<bool>();
        }

        /**
         * @brief Whether a cipher belongs to an organisation (encrypted with an org key).
         *
         * @param cipher The cipher
         * @return True if it has an organizationId
         */
        bool organisationCipher_(const Json& cipher) {
            return at(cipher, "organizationId").is_string();
        }
    }

    Orchestrator::Orchestrator(std::shared_ptr<Crypto> crypto, std::shared_ptr<Network> network,
            std::shared_ptr<Store> store, std::shared_ptr<Session> session,
            std::shared_ptr<Features> features, std::shared_ptr<Sync> sync,
            std::shared_ptr<FileStore> files)
        : m_crypto_(std::move(crypto)), m_network_(std::move(network)), m_store_(std::move(store)),
          m_session_(std::move(session)), m_features_(std::move(features)),
          m_sync_(std::move(sync)), m_files_(std::move(files)) {}

    void Orchestrator::onIntegrityFailure(std::function<void(std::string_view)> handler) {
        m_on_integrity_failure_ = std::move(handler);
    }

    void Orchestrator::reportIntegrityFailure(std::string_view reason) {
        Logger::get()->error("Vault integrity failure: {}", reason);
        if (m_on_integrity_failure_) {
            m_on_integrity_failure_(reason);
        }
    }

    void Orchestrator::onSyncRequested(std::function<void()> handler) {
        m_on_sync_requested_ = std::move(handler);
    }

    Json Orchestrator::getCipherJson_(std::string_view id) {
        Record record = m_store_->getCipher(id);
        if (!record) {
            throw VaultError("item not found");
        }
        return *record;
    }

    SymmetricKey Orchestrator::itemKeyFor_(const Json& cipher) {
        SymmetricKey user_key = m_session_->getUserKey();
        SecureString wrapped = stringAt(cipher, "key");
        if (wrapped.empty()) {
            return user_key; // older ciphers are encrypted directly with the user key
        }

        if (organisationCipher_(cipher)) {
            throw VaultError("organisation items are not supported yet");
        }
        try {
            return m_crypto_->unwrapKey(wrapped, user_key);
        } catch (const CryptoError&) {
            reportIntegrityFailure("an item key failed authentication");
            throw;
        }
    }

    std::shared_ptr<GenericItem> Orchestrator::getGenericItem(std::string_view id) {
        Json cipher = getCipherJson_(id);
        SymmetricKey key = itemKeyFor_(cipher);
        return std::make_shared<GenericItem>(
                shared_from_this(), m_crypto_, std::move(cipher), std::move(key));
    }

    std::optional<CipherType> Orchestrator::getItemType(std::string_view id) {
        Record record = m_store_->getCipher(id);
        if (!record) {
            return std::nullopt;
        }
        return Schema::typeOf(*record);
    }

    bool Orchestrator::hasItem(std::string_view id) {
        return m_store_->getCipher(id) != nullptr;
    }

    CipherQuery Orchestrator::query() {
        return CipherQuery(m_store_->getCiphers(), m_crypto_, m_session_->getUserKey());
    }

    bool Orchestrator::saveItem(GenericItem& item) {
        m_session_->getUserKey(); // throws if locked
        item.touch();

        SecureString id = item.getId();
        Record existing = m_store_->getCipher(id);
        bool is_new = !existing || createdOffline_(*existing);
        Json wire = Schema::wireFormat(item.getJson(), m_features_->needsLegacyData());

        std::optional<Json> result =
                is_new ? m_network_->createCipher(wire) : m_network_->updateCipher(wire);
        if (result && !stringAt(*result, "id").empty()) {
            if (is_new && existing && stringAt(*result, "id") != id) {
                m_store_->removeCipher(id, false);
            }
            item.replaceJson(*result);
            m_store_->putCipher(item.getJson());
            return true;
        }

        /*
         * Offline (or rejected): keep the change locally. A newer revision date makes the next
         * sync upload it; createdOffline makes it upload as a new item.
         */
        Json local = item.getJson();
        if (is_new) {
            local["createdOffline"] = true;
        }
        item.replaceJson(local);
        m_store_->putCipher(std::move(local));
        return false;
    }

    bool Orchestrator::deleteItem(GenericItem& item) {
        SecureString id = item.getId();
        Record existing = m_store_->getCipher(id);
        if (!existing) {
            return true;
        }
        if (createdOffline_(*existing)) {
            m_store_->removeCipher(id, false);
            return true;
        }

        bool ok = m_network_->deleteCipher(id);
        m_store_->removeCipher(id, !ok);
        return ok;
    }

    bool Orchestrator::commitStatus_(GenericItem& item, bool ok) {
        item.touch();
        m_store_->putCipher(item.getJson());
        if (ok && m_on_sync_requested_) {
            m_on_sync_requested_(); // pick up the server's revision date
        }
        return ok;
    }

    bool Orchestrator::binItem(GenericItem& item) {
        item.markDeleted(true);
        return commitStatus_(item, m_network_->softDeleteCipher(item.getId()));
    }

    bool Orchestrator::restoreItem(GenericItem& item) {
        item.markDeleted(false);
        return commitStatus_(item, m_network_->restoreCipher(item.getId()));
    }

    bool Orchestrator::archiveItem(GenericItem& item) {
        item.markArchived(true);
        return commitStatus_(item, m_network_->archiveCiphers({ item.getId() }));
    }

    bool Orchestrator::unarchiveItem(GenericItem& item) {
        item.markArchived(false);
        return commitStatus_(item, m_network_->unarchiveCiphers({ item.getId() }));
    }

    SecureString Orchestrator::duplicateItem(GenericItem& item) {
        Json copy = item.duplicateJson(m_session_->getUserKey());
        SymmetricKey key = itemKeyFor_(copy);
        GenericItem duplicate(shared_from_this(), m_crypto_, std::move(copy), std::move(key));
        saveItem(duplicate);
        return duplicate.getId();
    }

    std::optional<SecureString> Orchestrator::addAttachment(GenericItem& item,
            std::string_view file_name, std::span<const uint8_t> content,
            std::function<void(float)> on_progress) {
        Record existing = m_store_->getCipher(item.getId());
        if (!existing || createdOffline_(*existing)) {
            throw VaultError("save the item online before adding attachments");
        }

        SymmetricKey attachment_key = SymmetricKey::generate();
        SecureString wrapped_key = m_crypto_->wrapKey(attachment_key, item.getKey());
        SecureString encrypted_name = m_crypto_->encryptText(file_name, item.getKey());
        SecureBytes encrypted = m_crypto_->encryptBuffer(content, attachment_key);

        std::optional<Json> result = m_network_->uploadAttachment(
                item.getId(), encrypted_name, wrapped_key, encrypted, std::move(on_progress));
        if (!result) {
            return std::nullopt;
        }

        const Json& cipher = at(*result, "cipherResponse");
        if (cipher.is_object()) {
            item.replaceJson(cipher);
            m_store_->putCipher(item.getJson());
        }
        return stringAt(*result, "attachmentId");
    }

    bool Orchestrator::removeAttachment(GenericItem& item, std::string_view attachment_id) {
        if (!m_network_->deleteAttachment(item.getId(), attachment_id)) {
            return false;
        }

        Json updated = item.getJson();
        Json& list = updated["attachments"];
        if (list.is_array()) {
            list.erase(std::remove_if(list.begin(), list.end(),
                               [attachment_id](const Json& attachment) {
                                   return stringAt(attachment, "id") == attachment_id;
                               }),
                    list.end());
        }
        item.replaceJson(std::move(updated));
        m_store_->putCipher(item.getJson());
        return true;
    }

    bool Orchestrator::downloadAttachment(GenericItem& item, std::string_view attachment_id,
            std::filesystem::path destination, std::function<void(float)> on_progress) {
        std::optional<Network::Download> download =
                m_network_->downloadAttachment(item.getId(), attachment_id, std::move(on_progress));
        if (!download) {
            return false;
        }

        try {
            SymmetricKey attachment_key =
                    m_crypto_->unwrapKey(stringAt(download->m_meta, "key"), item.getKey());
            SecureBytes plaintext = m_crypto_->decryptBuffer(download->m_content, attachment_key);
            m_files_->write(std::move(destination), plaintext);
        } catch (const CryptoError&) {
            reportIntegrityFailure("an attachment failed authentication");
            throw;
        }
        return true;
    }

    std::vector<std::shared_ptr<Folder>> Orchestrator::getFolders() {
        SymmetricKey user_key = m_session_->getUserKey();
        std::vector<std::shared_ptr<Folder>> folders;
        for (Record& record : m_store_->getFolders()) {
            folders.push_back(
                    std::make_shared<Folder>(shared_from_this(), m_crypto_, *record, user_key));
        }
        return folders;
    }

    std::shared_ptr<Folder> Orchestrator::getFolder(std::string_view id) {
        Record record = m_store_->getFolder(id);
        if (!record) {
            throw VaultError("folder not found");
        }
        return std::make_shared<Folder>(
                shared_from_this(), m_crypto_, *record, m_session_->getUserKey());
    }

    std::shared_ptr<Folder> Orchestrator::createFolder() {
        SymmetricKey user_key = m_session_->getUserKey();
        // clang-format off
        Json folder = {
            { "id", uuid::generate() },
            { "name", m_crypto_->encryptText("", user_key) },
            { "object", "folder" },
            { "revisionDate", nullptr }
        };
        // clang-format on
        return std::make_shared<Folder>(shared_from_this(), m_crypto_, std::move(folder), user_key);
    }

    bool Orchestrator::saveFolder(Folder& folder) {
        Json data = folder.getJson();
        SecureString id = stringAt(data, "id");
        SecureString name = stringAt(data, "name");
        Record existing = m_store_->getFolder(id);
        bool is_new = !existing || createdOffline_(*existing);

        std::optional<Json> result =
                is_new ? m_network_->createFolder(name) : m_network_->updateFolder(id, name);
        if (result && !stringAt(*result, "id").empty()) {
            if (is_new && existing && stringAt(*result, "id") != id) {
                m_store_->removeFolder(id, false);
            }
            folder.replaceJson(*result);
            m_store_->putFolder(*result);
            return true;
        }

        data["revisionDate"] = timestamp::now();
        if (is_new) {
            data["createdOffline"] = true;
        }
        folder.replaceJson(data);
        m_store_->putFolder(std::move(data));
        return false;
    }

    bool Orchestrator::deleteFolder(Folder& folder) {
        SecureString id = folder.getId();
        Record existing = m_store_->getFolder(id);
        if (!existing) {
            return true;
        }

        bool ok = createdOffline_(*existing) || m_network_->deleteFolder(id);
        m_store_->removeFolder(id, !ok);

        /*
         * The server moves a deleted folder's items to "no folder"; mirror that locally so
         * they don't point at a missing folder.
         */
        for (Record& cipher : m_store_->getCiphers()) {
            if (stringAt(*cipher, "folderId") == id) {
                Json copy = *cipher;
                copy["folderId"] = nullptr;
                m_store_->putCipher(std::move(copy));
            }
        }
        return ok;
    }

    std::optional<SecureString> Orchestrator::hostName(std::string_view url) {
        size_t scheme = url.find("://");
        if (scheme != std::string_view::npos) {
            SecureString name = toLower(url.substr(0, scheme));
            if (name != "http" && name != "https") {
                return std::nullopt;
            }
            url.remove_prefix(scheme + 3);
        } else {
            size_t colon = url.find(':');
            bool port = colon != std::string_view::npos && colon + 1 < url.size() &&
                        url[colon + 1] >= '0' && url[colon + 1] <= '9';
            if (colon != std::string_view::npos && colon < url.find('/') && !port) {
                return std::nullopt; // mailto:, javascript:, ...
            }
        }

        url = url.substr(0, url.find_first_of("/?#:"));
        if (url.empty() || url.size() > 253 || url.find('.') == std::string_view::npos) {
            return std::nullopt;
        }
        for (char c : url) {
            bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') || c == '.' || c == '-';
            if (!allowed) {
                return std::nullopt;
            }
        }
        return toLower(url);
    }

    std::optional<std::filesystem::path> Orchestrator::getIcon(std::string_view url) {
        std::optional<SecureString> host = hostName(url);
        if (!host) {
            return std::nullopt;
        }

        /*
         * Name the cache file after a hash of the domain so paths are never built from
         * (attacker-influenced) URL text.
         */
        SecureBytes digest = m_crypto_->sha256(encoding::bytesOf(*host));
        SecureString name = encoding::hexEncode(std::span<const uint8_t>(digest.data(), 16));
        std::filesystem::path icon =
                std::filesystem::path("icons") / std::filesystem::path((name + ".png").c_str());
        std::filesystem::path failed =
                std::filesystem::path("icons") / std::filesystem::path((name + ".failed").c_str());

        if (m_files_->exists(icon)) {
            return m_files_->root() / icon;
        }
        if (m_files_->exists(failed) || !m_network_->isOnline()) {
            return std::nullopt;
        }

        std::optional<SecureBytes> png = m_network_->getIcon(*host);
        if (!png) {
            m_files_->write(failed, std::span<const uint8_t>());
            return std::nullopt;
        }
        m_files_->write(icon, *png);
        return m_files_->root() / icon;
    }
}
