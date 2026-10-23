#ifdef CLIENTWARDEN_WII_TEST_BUILD
#include "test_script.h"

#include <SDL.h>

#include "Platform/Entropy.h"

namespace clientwarden::wii::ui {
    bool TestScript::load(std::filesystem::path app_dir) {
        m_dir_ = app_dir;
        std::ifstream in(app_dir / "test-script.txt");
        if (!in) {
            return false;
        }
        std::string line;
        while (std::getline(in, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
                line.pop_back();
            }
            if (!line.empty() && line[0] != '#') {
                m_lines_.push_back(line);
            }
        }
        std::error_code error;
        std::filesystem::create_directories(app_dir / "shots", error);
        std::filesystem::remove(app_dir / "test-log.txt", error);
        m_loaded_ = true;
        log("script loaded");
        return true;
    }

    void TestScript::log(std::string_view line) {
        if (m_dir_.empty()) {
            return;
        }
        std::ofstream out(m_dir_ / "test-log.txt", std::ios::app);
        out << SDL_GetTicks() << " " << line << "\n";
    }

    bool TestScript::step(App& app, Input& input) {
        if (!m_loaded_) {
            return true;
        }
        if (m_pointer_x_ >= 0) {
            input.m_pointer_valid = true;
            input.m_pointer_x = m_pointer_x_;
            input.m_pointer_y = m_pointer_y_;
        }
        if (m_pending_type_) {
            if (app.keyboard().isOpen()) {
                app.keyboard().submit(m_type_text_);
                m_pending_type_ = false;
            }
            return true;
        }
        if (SDL_GetTicks() < m_wait_until_ || m_lines_.empty()) {
            return true;
        }
        std::string line = m_lines_.front();
        m_lines_.pop_front();
        size_t space = line.find(' ');
        std::string command = line.substr(0, space);
        std::string rest = space == std::string::npos ? "" : line.substr(space + 1);

        if (command == "wait") {
            m_wait_until_ = SDL_GetTicks() + static_cast<std::uint32_t>(std::atoi(rest.c_str()));
        } else if (command == "entropy") {
            entropy::creditForTesting();
        } else if (command == "click") {
            int x = 0;
            int y = 0;
            std::sscanf(rest.c_str(), "%d %d", &x, &y);
            m_pointer_x_ = x;
            m_pointer_y_ = y;
            input.m_pointer_valid = true;
            input.m_pointer_x = x;
            input.m_pointer_y = y;
            input.m_a = true;
        } else if (command == "pointer") {
            std::sscanf(rest.c_str(), "%d %d", &m_pointer_x_, &m_pointer_y_);
        } else if (command == "nopointer") {
            m_pointer_x_ = -1;
            input.m_pointer_valid = false;
        } else if (command == "focus") {
            m_pointer_x_ = -1;
            input.m_pointer_valid = false;
            app.ui().focusLabel(rest);
        } else if (command == "press") {
            app.ui().pressFocused();
        } else if (command == "type") {
            if (app.keyboard().isOpen()) {
                app.keyboard().submit(rest);
            } else {
                app.ui().pressFocused();
                m_pending_type_ = true;
                m_type_text_ = rest;
            }
        } else if (command == "key") {
            if (rest == "a") input.m_a = true;
            else if (rest == "b") input.m_b = true;
            else if (rest == "up") input.m_up = true;
            else if (rest == "down") input.m_down = true;
            else if (rest == "left") input.m_left = true;
            else if (rest == "right") input.m_right = true;
            else if (rest == "plus") input.m_plus = true;
            else if (rest == "minus") input.m_minus = true;
            else if (rest == "home") input.m_home = true;
        } else if (command == "shot") {
            bool ok = app.gfx().saveBmp(m_dir_ / "shots" / (rest + ".bmp"));
            log("shot " + rest + (ok ? " saved" : " FAILED"));
        } else if (command == "log") {
            log(rest);
        } else if (command == "state") {
            log("screen " + std::to_string(static_cast<int>(app.screen())) + " focus=" +
                    std::string(app.ui().focusedLabel()));
        } else if (command == "quit") {
            log("quit");
            return false;
        } else {
            log("unknown command: " + line);
        }
        return true;
    }
}
#endif
