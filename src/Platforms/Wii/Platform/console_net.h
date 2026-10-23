#pragma once
#include <cstdint>
#include <cstring>

#include <network.h>
#include <ogc/lwp_watchdog.h>

/*
 * libogc's sockets, for the shared HTTPS transport.
 */
namespace clientwarden::console::net {
    /**
     * @brief Resolves a host and connects to it.
     *
     * @return The socket, or -1
     */
    inline int connect(const char* host_name, int port) {
        hostent* host = net_gethostbyname(host_name);
        if (!host || host->h_addrtype != AF_INET || !host->h_addr_list[0]) {
            return -1;
        }
        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<u16>(port));
        std::memcpy(&address.sin_addr, host->h_addr_list[0], sizeof(address.sin_addr));
        s32 socket = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (socket >= 0 && net_connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
            net_close(socket);
            return -1;
        }
        return socket;
    }

    inline int send(int socket, const void* data, size_t size, int flags) {
        return net_send(socket, data, size, flags);
    }

    inline int receive(int socket, void* data, size_t size, int flags) {
        return net_recv(socket, data, size, flags);
    }

    inline void close(int socket) {
        net_close(socket);
    }

    inline uint64_t milliseconds() {
        return ticks_to_millisecs(gettime());
    }
}
