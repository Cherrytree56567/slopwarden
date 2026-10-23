#include <SDL.h>
#include <ogc/lwp.h>
#include <ogc/lwp_watchdog.h>
#include <wiiuse/wpad.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>
#include <thread>

#include "Platform/Entropy.h"
#include "Platform/System.h"
#include "app.h"
#include "gfx.h"
#include "test_script.h"
#include "vault_manager/vault_manager.h"

/*
 * ClientWarden for the Wii. SDL's Wii main() has already set up the Wii Remotes (with IR),
 * the USB keyboard and the SD card driver before this runs.
 */
namespace {
    using namespace clientwarden::wii;
    using namespace clientwarden::console::ui;

    /**
     * @brief Reads the Wii Remote and USB keyboard into one frame's input, and feeds the
     * remote's sensors to the entropy pool.
     */
    Input readInput_(bool& quit) {
        Input input;
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_QUIT) {
                quit = true;
            } else if (event.type == SDL_TEXTINPUT) {
                input.m_text += event.text.text;
            } else if (event.type == SDL_KEYDOWN) {
                switch (event.key.keysym.sym) {
                    case SDLK_BACKSPACE: input.m_backspace = true; break;
                    case SDLK_RETURN: case SDLK_KP_ENTER: input.m_enter = true; break;
                    case SDLK_ESCAPE: input.m_b = true; break;
                    case SDLK_UP: input.m_up = true; break;
                    case SDLK_DOWN: input.m_down = true; break;
                    case SDLK_LEFT: input.m_left = true; break;
                    case SDLK_RIGHT: input.m_right = true; break;
                    case SDLK_TAB: input.m_down = true; break;
                    case SDLK_PAGEDOWN: input.m_plus = true; break;
                    case SDLK_PAGEUP: input.m_minus = true; break;
                    default: break;
                }
            }
        }

        /*
         * SDL's event pump reads the remotes; take channel 1's state from it.
         */
        WPADData* data = WPAD_Data(WPAD_CHAN_0);
        if (data && data->err == WPAD_ERR_NONE) {
            std::uint32_t pressed = data->btns_d;
            input.m_a = input.m_a || (pressed & WPAD_BUTTON_A);
            input.m_b = input.m_b || (pressed & WPAD_BUTTON_B);
            input.m_up = input.m_up || (pressed & WPAD_BUTTON_UP);
            input.m_down = input.m_down || (pressed & WPAD_BUTTON_DOWN);
            input.m_left = input.m_left || (pressed & WPAD_BUTTON_LEFT);
            input.m_right = input.m_right || (pressed & WPAD_BUTTON_RIGHT);
            input.m_plus = input.m_plus || (pressed & WPAD_BUTTON_PLUS);
            input.m_minus = input.m_minus || (pressed & WPAD_BUTTON_MINUS);
            input.m_home = input.m_home || (pressed & WPAD_BUTTON_HOME);
            if (data->ir.valid) {
                input.m_pointer_valid = true;
                input.m_pointer_x = std::clamp(static_cast<int>(data->ir.x), 0, c_screen_w - 1);
                input.m_pointer_y = std::clamp(static_cast<int>(data->ir.y), 0, c_screen_h - 1);
            }
            entropy::addWiimoteSample(data->accel.x, data->accel.y, data->accel.z,
                    data->ir.valid ? static_cast<int>(data->ir.x * 16) : -1,
                    data->ir.valid ? static_cast<int>(data->ir.y * 16) : -1);
        }
        std::uint64_t ticks = gettime();
        entropy::addUncredited(&ticks, sizeof ticks);
        return input;
    }

    /**
     * @brief A full-screen message for before the app can run (no SD card, no font).
     */
#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    void boot_(const char* step) {
        FILE* f = std::fopen((appDirectory() / "boot-log.txt").c_str(), "a");
        if (f) {
            std::fprintf(f, "%s\n", step);
            std::fclose(f);
        }
    }
#else
    void boot_(const char*) {}
#endif

    void message_(Gfx* gfx, const char* text) {
        if (!gfx) {
            return;
        }
        gfx->clear(colors::c_background);
        gfx->textWrapped(40, 200, text, Font::Title, colors::c_text, c_screen_w - 80);
        gfx->present();
    }
}

int main(int, char**) {
#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    std::set_terminate([]() {
        std::exception_ptr error = std::current_exception();
        try {
            if (error) {
                std::rethrow_exception(error);
            }
            boot_("terminate without an exception");
        } catch (const std::exception& e) {
            boot_("terminate: ");
            boot_(e.what());
        } catch (...) {
            boot_("terminate: unknown exception");
        }
        std::abort();
    });
#endif
    WPAD_SetDataFormat(WPAD_CHAN_ALL, WPAD_FMT_BTNS_ACC_IR);
    WPAD_SetVRes(WPAD_CHAN_ALL, c_screen_w, c_screen_h);

    while (!initStorage()) {
        /*
         * Nothing to draw with yet (the font is on the card); retry until a card appears.
         */
        SDL_Delay(1000);
    }
    boot_("storage");
    initPaths();
    boot_("paths");
    boot_("starting network");
    static lwp_t network_thread;
    LWP_CreateThread(&network_thread, [](void*) -> void* {
                initNetwork();
                markNetworkSettled();
                return nullptr;
            }, nullptr, nullptr,
            256 * 1024, 40);
    boot_("network started");

    std::unique_ptr<Gfx> gfx = std::make_unique<Gfx>();
    boot_("gfx init");
    if (!gfx->init(appDirectory())) {
        boot_("gfx FAILED");
        SDL_Delay(5000);
        return 1;
    }
    SDL_StartTextInput();

    boot_("gfx ok");
    App app(*gfx);
    boot_("app");
#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
    TestScript script;
    script.load(appDirectory());
    app.onError([&script](std::string_view method, std::string_view error) {
        script.log(std::string("error ") + std::string(method) + ": " + std::string(error));
    });
#endif

    bool quit = false;
    while (!quit) {
        Input input = readInput_(quit);
#ifdef CLIENTWARDEN_CONSOLE_TEST_BUILD
        if (!script.step(app, input)) {
            break;
        }
#endif
        if (!app.frame(input)) {
            break;
        }
    }

    message_(gfx.get(), "Closing…");
    clientwarden::VaultManager::destroyInstance();
    gfx.reset();
    SDL_Quit();
    std::exit(0);
}
