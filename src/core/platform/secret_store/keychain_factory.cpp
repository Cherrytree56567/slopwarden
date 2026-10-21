#include "platform_secret_store.h"

/*
 * Desktop default: the OS keychain. Not built for Android or the Wii, whose platform code
 * provides its own store (the keychain library's Android backend is a stub).
*/
namespace clientwarden {
    std::shared_ptr<SecretStore> createPlatformSecretStore() {
        return std::make_shared<KeychainSecretStore>();
    }
}
