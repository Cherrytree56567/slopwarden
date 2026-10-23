#include "System.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <string>

#include <3ds.h>
#include <botan/exceptn.h>
#include <botan/rng.h>

#include "platform.h"
#include "platform/paths/paths.h"
#include "platform/random/random.h"
#include "utc.h"

namespace clientwarden::n3ds {
    namespace {
        constexpr u32 c_soc_buffer_size = 0x100000;

        std::atomic<bool> g_network_ready = false;
        std::atomic<bool> g_random_ready = false;
        u32* g_soc_buffer = nullptr;

        /*
         * random::secure(): the 3DS's hardware generator (the ps service), which also backs the
         * system's own TLS and save-data encryption. Nothing is produced if it can't be reached.
         */
        class HardwareRng final : public Botan::RandomNumberGenerator {
        public:
            bool accepts_input() const override { return false; }
            bool is_seeded() const override { return g_random_ready; }
            std::string name() const override { return "3DS ps:ps hardware RNG"; }
            void clear() override {}

        private:
            void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t>) override {
                if (!g_random_ready) {
                    throw Botan::PRNG_Unseeded("the 3DS random generator isn't available");
                }
                /*
                 * The service returns at most a page or so per call.
                 */
                size_t done = 0;
                while (done < output.size()) {
                    size_t chunk = std::min<size_t>(output.size() - done, 0x1000);
                    if (R_FAILED(PS_GenerateRandomBytes(output.data() + done, chunk))) {
                        throw Botan::PRNG_Unseeded("the 3DS random generator failed");
                    }
                    done += chunk;
                }
            }
        };
    }

    bool initSystem() {
        g_random_ready = R_SUCCEEDED(psInit());
        std::error_code error;
        std::filesystem::create_directories(paths::dataDirectory(), error);
        console::utc::load();
        return g_random_ready && !error;
    }

    bool initNetwork() {
        g_soc_buffer = static_cast<u32*>(memalign(0x1000, c_soc_buffer_size));
        if (!g_soc_buffer || R_FAILED(socInit(g_soc_buffer, c_soc_buffer_size))) {
            return false;
        }
        /*
         * Wait for Wi-Fi (up to 20 s): the console connects by itself with its saved settings.
         */
        if (R_SUCCEEDED(acInit())) {
            u32 status = 0;
            for (int i = 0; i < 40; ++i) {
                if (R_SUCCEEDED(ACU_GetWifiStatus(&status)) && status != 0) {
                    break;
                }
                svcSleepThread(500'000'000LL);
            }
            acExit();
        }
        g_network_ready = true;
        return true;
    }

    void exitSystem() {
        if (g_soc_buffer) {
            socExit();
        }
        psExit();
    }

    bool networkReady() {
        return g_network_ready;
    }

    std::filesystem::path appDirectory() {
        return "sdmc:/3ds/clientwarden";
    }
}

std::filesystem::path clientwarden::paths::dataDirectory() {
    return clientwarden::n3ds::appDirectory() / "data";
}

std::filesystem::path clientwarden::paths::resourceDirectory() {
    return clientwarden::n3ds::appDirectory();
}

namespace clientwarden::random {
    Botan::RandomNumberGenerator& secure() {
        static n3ds::HardwareRng rng;
        return rng;
    }
}

/*
 * The shared console UI's view of the 3DS.
 */
namespace clientwarden::console::platform {
    std::filesystem::path appDirectory() {
        return n3ds::appDirectory();
    }

    bool networkReady() {
        return n3ds::networkReady();
    }

    std::string_view consoleName() {
        return "the 3DS";
    }

    /*
     * The hardware generator needs no gathering.
     */
    size_t entropyBits() {
        return 256;
    }

    size_t entropyRequired() {
        return 256;
    }

    bool entropyReady() {
        return n3ds::g_random_ready;
    }

    bool hasSystemKeyboard() {
        return true;
    }

    std::optional<SecureString> systemKeyboard(std::string_view label, std::string_view value, bool masked) {
        constexpr size_t c_max = 1024;
        SwkbdState keyboard;
        swkbdInit(&keyboard, SWKBD_TYPE_NORMAL, 2, static_cast<int>(c_max - 1));
        SecureString hint(label.substr(0, 64));
        swkbdSetHintText(&keyboard, hint.c_str());
        SecureString initial(value);
        swkbdSetInitialText(&keyboard, initial.c_str());
        if (masked) {
            swkbdSetPasswordMode(&keyboard, SWKBD_PASSWORD_HIDE_DELAY); // and no predictive text
        } else {
            swkbdSetFeatures(&keyboard, SWKBD_PREDICTIVE_INPUT);
        }
        swkbdSetValidation(&keyboard, SWKBD_ANYTHING, 0, 0);

        SecureString buffer(c_max, '\0');
        SwkbdButton button = swkbdInputText(&keyboard, buffer.data(), buffer.size());
        if (button != SWKBD_BUTTON_RIGHT) {
            return std::nullopt;
        }
        buffer.resize(std::strlen(buffer.c_str()));
        return buffer;
    }

#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    void creditEntropyForTesting() {}
#endif
}
