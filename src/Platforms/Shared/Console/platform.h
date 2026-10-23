#pragma once
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string_view>

#include "utils/secure_string/secure_string.h"

/*
 * What the shared console UI (Wii, 3DS) needs from the console it runs on. Each platform
 * implements these in its own Platform/ folder, and provides console_metrics.h (screen size and
 * layout scale) on its include path.
 */
namespace clientwarden::console::platform {
    /**
     * @brief The app's folder on the SD card (fonts, CA bundle, word list, data/).
     */
    std::filesystem::path appDirectory();

    /**
     * @brief Whether the console is online.
     */
    bool networkReady();

    /**
     * @brief A short name for messages, e.g. "the Wii".
     */
    std::string_view consoleName();

    /**
     * @brief Randomness gathered so far, and how much is needed before the vault may start.
     * Consoles with a hardware generator report ready straight away.
     */
    size_t entropyBits();
    size_t entropyRequired();
    bool entropyReady();

    /**
     * @brief Whether text is entered with the console's own keyboard applet (3DS) rather than
     * the UI's on-screen keyboard (Wii).
     */
    bool hasSystemKeyboard();

    /**
     * @brief Shows the system keyboard and waits for the user.
     *
     * @param label Shown as the hint
     * @param value The current text
     * @param masked Hide what's typed
     * @return The text, or nullopt if cancelled
     */
    std::optional<SecureString> systemKeyboard(std::string_view label, std::string_view value, bool masked);

#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    /**
     * @brief Test builds only: satisfies the randomness gate without input.
     */
    void creditEntropyForTesting();
#endif
}
