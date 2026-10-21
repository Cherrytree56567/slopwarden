#include "JsonBridge.h"

#include "vault_manager/vault_manager.h"

/*
 * Kept apart from JsonBridge.cpp so tests can use the bridge without the production
 * VaultManager (real keychain, disk and network).
 */
namespace clientwarden::bridge {
    JsonBridge& JsonBridge::shared() {
        static JsonBridge bridge([]() { return VaultManager::instance().getActiveVault(); });
        return bridge;
    }
}
