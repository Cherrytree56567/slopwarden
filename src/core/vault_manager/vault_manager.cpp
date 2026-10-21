#include "vault_manager.h"

#include <algorithm>

#include "bitwarden/bitwarden_vault.h"
#include "utils/encoding/encoding.h"
#include "utils/logger/logger.h"
#include "utils/uuid/uuid.h"

namespace clientwarden {
    namespace {
        constexpr std::string_view c_vaults_file = "vaults.json";
        constexpr std::string_view c_legacy_id = "default";

        /**
         * @brief The stored name of a vault type.
         *
         * @param type The type
         * @return e.g. "bitwarden"
         */
        SecureString typeName_(VaultType type) {
            switch (type) {
            case VaultType::Bitwarden: return "bitwarden";
            }
            return "bitwarden";
        }
    }

    VaultManager::VaultManager(std::shared_ptr<SecretStore> secrets,
            std::shared_ptr<FileStore> files, std::shared_ptr<FileStore> resources,
            std::function<std::shared_ptr<HttpTransport>()> transport_factory)
        : m_secrets_(std::move(secrets)), m_files_(std::move(files)),
          m_resources_(std::move(resources)), m_transport_factory_(std::move(transport_factory)) {
        load_();
    }

    VaultManager::~VaultManager() {
        shutdown();
    }

    void VaultManager::load_() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex_);
        std::optional<SecureBytes> stored = m_files_->read(std::filesystem::path(c_vaults_file));
        Json document =
                stored ? Json::parse(stored->begin(), stored->end(), nullptr, false) : Json();

        if (document.is_object()) {
            for (const Json& entry : at(document, "vaults")) {
                VaultInfo info { stringAt(entry, "id"), VaultType::Bitwarden,
                    stringAt(entry, "name"), stringAt(entry, "scope") };
                if (!info.m_id.empty()) {
                    m_infos_.push_back(std::move(info));
                }
            }
            m_active_id_ = stringAt(document, "active");
        } else {
            /*
             * First run of this version: adopt an account from the single-vault layout in
             * place (unscoped storage), so upgrading doesn't log anyone out.
             */
            bool legacy = m_secrets_->get("account") || m_secrets_->get("email") ||
                          m_files_->exists("vault.json");
            if (legacy) {
                m_infos_.push_back(VaultInfo { SecureString(c_legacy_id), VaultType::Bitwarden,
                        "Bitwarden", SecureString() });
                m_active_id_ = SecureString(c_legacy_id);
                persist_();
            }
        }

        for (VaultInfo& info : m_infos_) {
            try {
                m_vaults_.push_back(create_(info));
            } catch (const std::exception& e) {
                Logger::get()->error("Failed to load a vault: {}", e.what());
                m_vaults_.push_back(nullptr);
            }
        }
    }

    void VaultManager::persist_() {
        Json document = { { "active", m_active_id_ }, { "vaults", Json::array() } };
        for (VaultInfo& info : m_infos_) {
            // clang-format off
            document["vaults"].push_back({
                { "id", info.m_id },
                { "type", typeName_(info.m_type) },
                { "name", info.m_name },
                { "scope", info.m_scope }
            });
            // clang-format on
        }
        SecureString text = document.dump(2);
        m_files_->write(std::filesystem::path(c_vaults_file), encoding::bytesOf(text));
    }

    std::shared_ptr<Vault> VaultManager::create_(VaultInfo info) {
        std::shared_ptr<SecretStore> secrets = m_secrets_;
        std::shared_ptr<FileStore> files = m_files_;
        if (!info.m_scope.empty()) {
            secrets = std::make_shared<ScopedSecretStore>(m_secrets_, info.m_scope + ".");
            files = std::make_shared<ScopedFileStore>(m_files_,
                    std::filesystem::path("vaults") / std::filesystem::path(info.m_scope.c_str()));
        }
        return std::make_shared<BitwardenVault>(
                info.m_id, secrets, files, m_resources_, m_transport_factory_());
    }

    std::vector<VaultInfo> VaultManager::listVaults() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex_);
        return m_infos_;
    }

    std::shared_ptr<Vault> VaultManager::getVault(std::string_view id) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex_);
        for (size_t i = 0; i < m_infos_.size(); ++i) {
            if (m_infos_[i].m_id == id) {
                return m_vaults_[i];
            }
        }
        return nullptr;
    }

    std::shared_ptr<Vault> VaultManager::getActiveVault() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex_);
        if (m_infos_.empty()) {
            return addVault(VaultType::Bitwarden, "Bitwarden");
        }
        std::shared_ptr<Vault> active = getVault(m_active_id_);
        return active ? active : m_vaults_.front();
    }

    bool VaultManager::setActiveVault(std::string_view id) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex_);
        if (!getVault(id)) {
            return false;
        }
        m_active_id_ = SecureString(id);
        persist_();
        return true;
    }

    std::shared_ptr<Vault> VaultManager::addVault(VaultType type, std::string_view name) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex_);
        SecureString id = uuid::generate();
        VaultInfo info { id, type, SecureString(name), id };
        std::shared_ptr<Vault> vault = create_(info);

        m_infos_.push_back(std::move(info));
        m_vaults_.push_back(vault);
        if (m_active_id_.empty() || !getVault(m_active_id_)) {
            m_active_id_ = id;
        }
        persist_();
        return vault;
    }

    bool VaultManager::removeVault(std::string_view id) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex_);
        for (size_t i = 0; i < m_infos_.size(); ++i) {
            if (m_infos_[i].m_id != id) {
                continue;
            }
            if (m_vaults_[i]) {
                m_vaults_[i]->logout();
                m_vaults_[i]->shutdown();
            }
            m_infos_.erase(m_infos_.begin() + static_cast<std::ptrdiff_t>(i));
            m_vaults_.erase(m_vaults_.begin() + static_cast<std::ptrdiff_t>(i));
            if (m_active_id_ == id) {
                m_active_id_ = m_infos_.empty() ? SecureString() : m_infos_.front().m_id;
            }
            persist_();
            return true;
        }
        return false;
    }

    void VaultManager::shutdown() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex_);
        for (std::shared_ptr<Vault>& vault : m_vaults_) {
            if (vault) {
                vault->shutdown();
            }
        }
    }
}
