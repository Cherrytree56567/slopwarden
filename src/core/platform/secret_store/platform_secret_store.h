#pragma once
#include <memory>

#include "secret_store.h"

namespace clientwarden {
    /**
     * @brief The secret store for the platform this binary was built for.
     *
     * Desktop platforms get the OS keychain (keychain_factory.cpp, part of the runtime library);
     * platforms without one the keychain library supports (Android, Wii) define this themselves.
     *
     * @return The store
     */
    std::shared_ptr<SecretStore> createPlatformSecretStore();
}
