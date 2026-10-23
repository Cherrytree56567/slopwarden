#pragma once
#include <filesystem>

/*
 * 3DS start-up and where things live. ClientWarden runs from the Homebrew Launcher out of
 * sdmc:/3ds/clientwarden; its data (vaults.json, the encrypted cache, the session) lives in
 * sdmc:/3ds/clientwarden/data.
 */
namespace clientwarden::n3ds {
    /**
     * @brief Starts the hardware random generator and the data folder.
     *
     * @return False if the random generator isn't available (the app can't run without it)
     */
    bool initSystem();

    /**
     * @brief Starts the socket service and waits for Wi-Fi. Slow; call it from a thread.
     */
    bool initNetwork();

    /**
     * @brief Stops the services before exiting.
     */
    void exitSystem();

    bool networkReady();

    /**
     * @brief The app's folder, sdmc:/3ds/clientwarden.
     */
    std::filesystem::path appDirectory();
}
