#pragma once
#include <filesystem>

namespace clientwarden::paths {
    /**
     * @brief Where the app keeps its data (vaults.json, per-vault caches, logs).
     *
     * Implemented per platform outside the core (e.g. ~/Library/Application Support/ClientWarden
     * on macOS), since only the platform knows its conventions.
     *
     * @return The data directory
     */
    std::filesystem::path dataDirectory();

    /**
     * @brief Where bundled read-only resources (the passphrase word list) live.
     *
     * Implemented per platform outside the core.
     *
     * @return The resource directory
     */
    std::filesystem::path resourceDirectory();
}
