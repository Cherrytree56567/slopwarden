#pragma once
#include <memory>

#include "http.h"

namespace clientwarden {
    /**
     * @brief A new HTTP transport for the platform this binary was built for.
     *
     * cpp-httplib (httplib_transport.cpp) everywhere except the Wii, whose platform code
     * provides one over mbedTLS and libogc sockets.
     *
     * @return The transport
     */
    std::shared_ptr<HttpTransport> createPlatformTransport();
}
