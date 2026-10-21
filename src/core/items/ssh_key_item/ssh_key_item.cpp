#include "ssh_key_item.h"

namespace clientwarden {
    SshKeyItem& SshKeyItem::setPrivateKey(std::string_view value) {
        setField_(fields::ssh_key::c_private_key, value);
        return *this;
    }

    SecureString SshKeyItem::getPrivateKey() const {
        return getField_(fields::ssh_key::c_private_key);
    }

    SshKeyItem& SshKeyItem::setPublicKey(std::string_view value) {
        setField_(fields::ssh_key::c_public_key, value);
        return *this;
    }

    SecureString SshKeyItem::getPublicKey() const {
        return getField_(fields::ssh_key::c_public_key);
    }

    SshKeyItem& SshKeyItem::setFingerprint(std::string_view value) {
        setField_(fields::ssh_key::c_fingerprint, value);
        return *this;
    }

    SecureString SshKeyItem::getFingerprint() const {
        return getField_(fields::ssh_key::c_fingerprint);
    }
}
