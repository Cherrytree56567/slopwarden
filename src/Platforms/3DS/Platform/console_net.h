#pragma once
#include <cstdint>
#include <cstring>

#include <3ds.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * The 3DS's BSD sockets (the soc service), for the shared HTTPS transport.
 */
namespace clientwarden::console::net {
    /**
     * @brief Resolves a host and connects to it.
     *
     * @return The socket, or -1
     */
    inline int connect(const char* host_name, int port) {
        hostent* host = gethostbyname(host_name);
        if (!host || host->h_addrtype != AF_INET || !host->h_addr_list[0]) {
            return -1;
        }
        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<uint16_t>(port));
        std::memcpy(&address.sin_addr, host->h_addr_list[0], sizeof(address.sin_addr));
        int socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (socket >= 0 && ::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
            ::close(socket);
            return -1;
        }
        return socket;
    }

    inline int send(int socket, const void* data, size_t size, int flags) {
        return static_cast<int>(::send(socket, data, size, flags));
    }

    inline int receive(int socket, void* data, size_t size, int flags) {
        return static_cast<int>(::recv(socket, data, size, flags));
    }

    inline void close(int socket) {
        ::close(socket);
    }

    inline uint64_t milliseconds() {
        return svcGetSystemTick() / CPU_TICKS_PER_MSEC;
    }
}
