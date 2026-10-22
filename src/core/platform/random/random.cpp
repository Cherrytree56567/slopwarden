#include "random.h"

#include <botan/system_rng.h>

/*
 * Not built for the Wii, whose platform code provides its own generator.
 */
namespace clientwarden::random {
    Botan::RandomNumberGenerator& secure() {
        return Botan::system_rng();
    }
}
