#include "System.h"

#include <atomic>
#include <cstdio>
#include <ctime>
#include <fat.h>
#include <network.h>
#include <sys/time.h>

#include "utc.h"
#include "platform/paths/paths.h"

namespace clientwarden::wii {
    namespace {
        std::atomic<bool> g_network_ready = false;
    }

    bool initStorage() {
        if (!fatInitDefault()) {
            return false;
        }
        std::error_code error;
        std::filesystem::create_directories(paths::dataDirectory(), error);
        return !error;
    }

    bool initNetwork() {
        char ip[16] = {};
        char netmask[16] = {};
        char gateway[16] = {};
        bool ok = if_config(ip, netmask, gateway, true, 20) >= 0;
        g_network_ready = ok;
        return ok;
    }

    bool networkReady() {
        return g_network_ready;
    }

    std::filesystem::path appDirectory() {
        return "sd:/apps/clientwarden";
    }

    void initPaths() {
        console::utc::load();
    }
}

std::filesystem::path clientwarden::paths::dataDirectory() {
    return clientwarden::wii::appDirectory() / "data";
}

std::filesystem::path clientwarden::paths::resourceDirectory() {
    return clientwarden::wii::appDirectory();
}
