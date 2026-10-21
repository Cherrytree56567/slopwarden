#include "vault_manager.h"

#include "platform/paths/paths.h"
#include "utils/logger/logger.h"

/*
 * Production wiring, kept out of clientwarden_core so tests never touch the real keychain,
 * filesystem or network.
 */
namespace clientwarden {
    namespace {
        std::mutex g_instance_mutex;
        std::shared_ptr<VaultManager> g_vault_manager;
    }

    VaultManager& VaultManager::instance() {
        std::lock_guard<std::mutex> lock(g_instance_mutex);
        if (!g_vault_manager) {
            std::filesystem::path data = paths::dataDirectory();
            Logger::installFileLogger(data);

            g_vault_manager = std::make_shared<VaultManager>(
                    std::make_shared<KeychainSecretStore>(), std::make_shared<DiskFileStore>(data),
                    std::make_shared<DiskFileStore>(paths::resourceDirectory()), []() {
                        return std::shared_ptr<HttpTransport>(std::make_shared<HttplibTransport>());
                    });
        }
        return *g_vault_manager;
    }

    void VaultManager::destroyInstance() {
        std::shared_ptr<VaultManager> manager;
        {
            std::lock_guard<std::mutex> lock(g_instance_mutex);
            manager = std::move(g_vault_manager);
        }
        if (manager) {
            manager->shutdown();
        }
    }
}
