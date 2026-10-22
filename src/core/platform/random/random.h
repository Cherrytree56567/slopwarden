#pragma once
#include <algorithm> // Botan's secmem.h uses std::fill without it

#include <botan/rng.h>

namespace clientwarden::random {
    /**
     * @brief The cryptographically secure random generator everything in the core draws from.
     *
     * The OS generator (random.cpp) everywhere except platforms without one, which define this
     * themselves (the Wii seeds its own from Wiimote sensor noise and timing jitter).
     *
     * @return The generator; safe to use from any thread
     */
    Botan::RandomNumberGenerator& secure();
}
