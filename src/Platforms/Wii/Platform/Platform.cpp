#include "Entropy.h"
#include "System.h"
#include "platform.h"

/*
 * The shared console UI's view of the Wii.
 */
namespace clientwarden::console::platform {
    std::filesystem::path appDirectory() {
        return wii::appDirectory();
    }

    bool networkReady() {
        return wii::networkReady();
    }

    std::string_view consoleName() {
        return "the Wii";
    }

    size_t entropyBits() {
        return wii::entropy::creditedBits();
    }

    size_t entropyRequired() {
        return wii::entropy::c_required_bits;
    }

    bool entropyReady() {
        return wii::entropy::ready();
    }

    bool hasSystemKeyboard() {
        return false;
    }

    std::optional<SecureString> systemKeyboard(std::string_view, std::string_view, bool) {
        return std::nullopt;
    }

#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    void creditEntropyForTesting() {
        wii::entropy::creditForTesting();
    }
#endif
}
