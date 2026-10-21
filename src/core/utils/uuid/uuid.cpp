#include "uuid.h"

#include <array>
#include <botan/system_rng.h>

#include "utils/encoding/encoding.h"

namespace clientwarden::uuid {
    SecureString generate() {
        std::array<uint8_t, 16> bytes = {};
        Botan::system_rng().randomize(bytes.data(), bytes.size());
        bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0f) | 0x40);
        bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3f) | 0x80);

        SecureString hex = encoding::hexEncode(bytes);
        return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" +
               hex.substr(16, 4) + "-" + hex.substr(20);
    }
}
