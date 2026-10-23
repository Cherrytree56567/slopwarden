#pragma once
#include <filesystem>

/*
 * Wii start-up and where things live. ClientWarden runs from the Homebrew Channel out of
 * sd:/apps/clientwarden; its data (vaults.json, the encrypted cache, the secret store) lives in
 * sd:/apps/clientwarden/data.
 */
namespace clientwarden::wii {
    /**
     * @brief Mounts the SD card.
     *
     * @return False if there's no usable card (the app can't run without one)
     */
    bool initStorage();

    /**
     * @brief Brings up Wi-Fi/LAN with the console's saved connection. Slow (a few seconds), so
     * call it from a background thread.
     *
     * @return False if the console couldn't connect
     */
    bool initNetwork();

    /**
     * @brief Whether initNetwork() succeeded.
     */
    bool networkReady();

    /**
     * @brief The app's folder, e.g. sd:/apps/clientwarden.
     */
    std::filesystem::path appDirectory();

    /**
     * @brief Points the core at the app's folders (paths::dataDirectory/resourceDirectory).
     * Call once after initStorage().
     */
    void initPaths();
}
