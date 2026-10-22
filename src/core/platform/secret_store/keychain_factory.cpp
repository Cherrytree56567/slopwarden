#include "platform_secret_store.h"

/*
 * Desktop default: the OS keychain. Not built for Android or the Wii, whose platform code
 * provides its own store (the keychain library's Android backend is a stub).
 */
namespace clientwarden {
    std::shared_ptr<SecretStore> createPlatformSecretStore() {
#ifdef _WIN32
        /*
         * Credential Manager refuses secrets over 2560 bytes, and the keychain library checks
         * against CRED_MAX_CREDENTIAL_BLOB_SIZE, which MinGW's headers still define as 512. A
         * session's tokens are bigger than either.
         */
        return std::make_shared<ChunkedSecretStore>(std::make_shared<KeychainSecretStore>(), 512);
#else
        return std::make_shared<KeychainSecretStore>();
#endif
    }
}
