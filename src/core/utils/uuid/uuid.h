#pragma once
#include "utils/secure_string/secure_string.h"

namespace clientwarden::uuid {
    /**
     * @brief A random (version 4) UUID in lowercase canonical form.
     *
     * @return e.g. 3fa85f64-5717-4562-b3fc-2c963f66afa6
     */
    SecureString generate();
}
