#include "folder.h"

#include "utils/errors/errors.h"
#include "vault/orchestrator/orchestrator.h"

namespace clientwarden {
    namespace {
        /**
         * @brief Throws unless a folder has an orchestrator to perform vault operations.
         *
         * @param orchestrator The folder's orchestrator
         * @return The orchestrator
         */
        Orchestrator& require_(std::shared_ptr<Orchestrator> orchestrator) {
            if (!orchestrator) {
                throw VaultError("folder is not attached to a vault");
            }
            return *orchestrator;
        }
    }

    Folder::Folder(std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Crypto> crypto,
            Json folder, SymmetricKey user_key)
        : m_orchestrator_(std::move(orchestrator)), m_crypto_(std::move(crypto)),
          m_data_(std::move(folder)), m_key_(std::move(user_key)) {
        if (!m_data_.is_object()) {
            throw VaultError("folder must be a JSON object");
        }
    }

    SecureString Folder::getId() const {
        return stringAt(m_data_, "id");
    }

    SecureString Folder::getName() const {
        const Json& name = at(m_data_, "name");
        if (!name.is_string()) {
            return SecureString();
        }
        try {
            return m_crypto_->decryptText(name.get_ref<const SecureString&>(), m_key_);
        } catch (const CryptoError&) {
            if (m_orchestrator_) {
                m_orchestrator_->reportIntegrityFailure("folder name failed authentication");
            }
            throw;
        }
    }

    Folder& Folder::setName(std::string_view name) {
        m_data_["name"] = m_crypto_->encryptText(name, m_key_);
        return *this;
    }

    bool Folder::commit() {
        return require_(m_orchestrator_).saveFolder(*this);
    }

    bool Folder::remove() {
        return require_(m_orchestrator_).deleteFolder(*this);
    }

    Json Folder::getJson() const {
        return m_data_;
    }

    void Folder::replaceJson(Json folder) {
        if (!folder.is_object()) {
            throw VaultError("folder must be a JSON object");
        }
        m_data_ = std::move(folder);
    }
}
