#include <3ds.h>

#include <algorithm>
#include <cstdio>
#include <exception>
#include <memory>
#include <thread>

#include "Platform/System.h"
#include "app.h"
#include "gfx.h"
#include "test_script.h"
#include "vault_manager/vault_manager.h"

/*
 * ClientWarden for the 3DS, launched from the Homebrew Launcher. The UI is on the touch screen:
 * tap things, or move with the D-pad and press A; B goes back, L/R scroll, START opens the menu.
 */
namespace {
    using namespace clientwarden::n3ds;
    using namespace clientwarden::console::ui;

    /**
     * @brief Reads the buttons and touch screen into one frame's input, in logical coordinates.
     */
    Input readInput_() {
        hidScanInput();
        u32 down = hidKeysDown();
        u32 held = hidKeysHeld();

        Input input;
        input.m_a = down & KEY_A;
        input.m_b = down & KEY_B;
        input.m_up = down & (KEY_DUP | KEY_CPAD_UP);
        input.m_down = down & (KEY_DDOWN | KEY_CPAD_DOWN);
        input.m_left = down & (KEY_DLEFT | KEY_CPAD_LEFT);
        input.m_right = down & (KEY_DRIGHT | KEY_CPAD_RIGHT);
        input.m_plus = down & (KEY_R | KEY_ZR);
        input.m_minus = down & (KEY_L | KEY_ZL);
        input.m_home = down & KEY_START;

        /*
         * A touch is a click where it lands; the pointer only exists while touching.
         */
        if (held & KEY_TOUCH) {
            touchPosition touch;
            hidTouchRead(&touch);
            input.m_pointer_valid = true;
            input.m_pointer_x = std::clamp(touch.px * c_screen_w / 320, 0, c_screen_w - 1);
            input.m_pointer_y = std::clamp(touch.py * c_screen_h / 240, 0, c_screen_h - 1);
            input.m_a = input.m_a || (down & KEY_TOUCH);
        }
        return input;
    }

#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    void boot_(const char* step) {
        if (FILE* f = std::fopen((appDirectory() / "boot-log.txt").c_str(), "a")) {
            std::fprintf(f, "%s\n", step);
            std::fclose(f);
        }
    }
#else
    void boot_(const char*) {}
#endif

    /**
     * @brief Shows a message on the console's own text screen when the UI can't start.
     */
    void fatal_(const char* message) {
        gfxInitDefault();
        consoleInit(GFX_TOP, nullptr);
        std::printf("\n  ClientWarden can't start:\n\n  %s\n\n  Press START to exit.\n", message);
        while (aptMainLoop()) {
            hidScanInput();
            if (hidKeysDown() & KEY_START) {
                break;
            }
            gspWaitForVBlank();
        }
        gfxExit();
    }
}

int main(int, char**) {
    /*
     * The New 3DS's faster clock and extra cache: key derivation is slow on this CPU.
     */
    osSetSpeedupEnable(true);

    if (!initSystem()) {
        fatal_("The 3DS's random number generator or the SD card isn't available.");
        return 1;
    }
    boot_("system");

    std::thread network([]() {
        initNetwork();
        markNetworkSettled();
    });
    network.detach();

    std::unique_ptr<Gfx> gfx = std::make_unique<Gfx>();
    if (!gfx->init(appDirectory())) {
        gfx.reset();
        fatal_("Its files are missing: copy the whole 3ds/clientwarden folder to the SD card.");
        exitSystem();
        return 1;
    }
    boot_("gfx");

    App app(*gfx);
#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    TestScript script;
    script.load(appDirectory());
    app.onError([&script](std::string_view method, std::string_view error) {
        script.log(std::string("error ") + std::string(method) + ": " + std::string(error));
    });
#endif

    while (aptMainLoop()) {
        Input input = readInput_();
#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
        if (!script.step(app, input)) {
            break;
        }
#endif
        if (!app.frame(input)) {
            break;
        }
    }

    clientwarden::VaultManager::destroyInstance();
    gfx.reset();
    exitSystem();
    return 0;
}
