#pragma once
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string_view>
#include <vector>

#include "platform/file_store/file_store.h"
#include "platform/http/http.h"
#include "platform/secret_store/secret_store.h"
#include "vault/vault.h"

namespace clientwarden {
    /**
     * @brief A registered vault, as listed in vaults.json.
     */
    struct VaultInfo {
        SecureString m_id;
        VaultType m_type;
        SecureString m_name;

        /**
         * @brief Storage scope: keychain keys are prefixed with it and files live under it.
         * Empty for the vault migrated from the single-account layout.
         */
        SecureString m_scope;
    };

    /**
     * @brief Owns every vault (ADR 2).
     *
     * Loads the vault list from vaults.json in shared storage, creates each vault with its own
     * scoped keychain and data directory, and tracks which one the UI is showing. Vaults keep
     * running in the background when another one is active (e.g. to finish a sync).
     */
    class VaultManager {
    public:
        /**
         * @brief Creates a manager over explicit dependencies (used by tests).
         *
         * @param secrets The shared keychain
         * @param files The shared data directory
         * @param resources Bundled resources
         * @param transport_factory Creates one HTTP transport per vault
         */
        VaultManager(std::shared_ptr<SecretStore> secrets, std::shared_ptr<FileStore> files,
                std::shared_ptr<FileStore> resources,
                std::function<std::shared_ptr<HttpTransport>()> transport_factory);

        ~VaultManager();

        /**
         * @brief The process-wide manager, built on first use with the real keychain, the
         * platform's data directory and the httplib transport.
         *
         * @return The manager
         */
        static VaultManager& instance();

        /**
         * @brief Shuts down and destroys the process-wide manager.
         */
        static void destroyInstance();

        /**
         * @brief The registered vaults.
         *
         * @return Their descriptions
         */
        std::vector<VaultInfo> listVaults();

        /**
         * @brief A vault by id.
         *
         * @param id The vault id
         * @return The vault, or nullptr
         */
        std::shared_ptr<Vault> getVault(std::string_view id);

        /**
         * @brief The vault the UI is showing, creating a first one if none exist.
         *
         * @return The active vault
         */
        std::shared_ptr<Vault> getActiveVault();

        /**
         * @brief Switches the UI to another vault.
         *
         * @param id The vault id
         * @return False if no such vault
         */
        bool setActiveVault(std::string_view id);

        /**
         * @brief Registers a new, logged-out vault.
         *
         * @param type The API type
         * @param name A display name
         * @return The new vault
         */
        std::shared_ptr<Vault> addVault(VaultType type, std::string_view name);

        /**
         * @brief Logs a vault out and unregisters it.
         *
         * @param id The vault id
         * @return False if no such vault
         */
        bool removeVault(std::string_view id);

        /**
         * @brief Stops every vault's background work.
         */
        void shutdown();

    private:
        std::shared_ptr<Vault> create_(VaultInfo info);
        void load_();
        void persist_();

        std::shared_ptr<SecretStore> m_secrets_;
        std::shared_ptr<FileStore> m_files_;
        std::shared_ptr<FileStore> m_resources_;
        std::function<std::shared_ptr<HttpTransport>()> m_transport_factory_;

        std::recursive_mutex m_mutex_;
        std::vector<VaultInfo> m_infos_;
        std::vector<std::shared_ptr<Vault>> m_vaults_;
        SecureString m_active_id_;
    };
}
