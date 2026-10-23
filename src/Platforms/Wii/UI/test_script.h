#pragma once
#ifdef CLIENTWARDEN_WII_TEST_BUILD
#include <deque>
#include <filesystem>
#include <fstream>

#include "app.h"

/*
 * Test builds only: drives the app from sd:/apps/clientwarden/test-script.txt so it can be
 * exercised in Dolphin, whose emulated Wii Remote can't be moved from a script. Commands:
 * wait <ms>, entropy, click <x> <y>, focus <label>, press, type <text>, key <name>,
 * shot <name>, log <text>, quit.
 */
namespace clientwarden::wii::ui {
    class TestScript {
    public:
        /**
         * @brief Loads the script, if there is one.
         */
        bool load(std::filesystem::path app_dir);

        /**
         * @brief Runs commands due this frame, adding any input they make.
         *
         * @return False after "quit"
         */
        bool step(App& app, Input& input);

        /**
         * @brief Appends a line to test-log.txt.
         */
        void log(std::string_view line);

    private:
        std::filesystem::path m_dir_;
        std::deque<std::string> m_lines_;
        std::uint32_t m_wait_until_ = 0;
        bool m_loaded_ = false;
        bool m_pending_type_ = false;
        std::string m_type_text_;
        int m_pointer_x_ = -1;
        int m_pointer_y_ = -1;
    };
}
#endif
