#include "keyboard.h"

#include <algorithm>

namespace clientwarden::console::ui {
    namespace {
        constexpr const char* c_letters[] = { "1234567890", "qwertyuiop", "asdfghjkl@", "zxcvbnm.-_" };
        constexpr const char* c_symbols[] = { "!\"#$%&'()*", "+,/:;<=>?[", "\\]^`{|}~ .", "-_@0123456" };

        /**
         * @brief Removes the last UTF-8 character.
         */
        void backspace_(SecureString& s) {
            while (!s.empty() && (static_cast<unsigned char>(s.back()) & 0xC0) == 0x80) {
                s.pop_back();
            }
            if (!s.empty()) {
                s.pop_back();
            }
        }
    }

    void Keyboard::open(std::string_view title, std::string_view value, bool masked, Done done) {
        m_open_ = true;
        m_fresh_ = true;
        m_title_ = SecureString(title);
        m_value_ = SecureString(value);
        m_masked_ = masked;
        m_reveal_ = false;
        m_shift_ = false;
        m_symbols_ = false;
        m_done_ = std::move(done);
    }

    void Keyboard::close() {
        m_open_ = false;
        m_value_.clear();
        m_value_.shrink_to_fit();
        m_done_ = nullptr;
    }

    void Keyboard::submit(std::string_view text) {
        if (!m_open_) {
            return;
        }
        Done done = std::move(m_done_);
        SecureString value(text);
        close();
        if (done) {
            done(std::move(value));
        }
    }

    void Keyboard::frame(Ui& ui, const Input& given) {
        if (!m_open_) {
            return;
        }
        /*
         * The tap or A that opened the keyboard would otherwise press the key under it.
         */
        bool fresh = m_fresh_;
        m_fresh_ = false;
        Input input = fresh ? Input() : given;
        if (fresh) {
            ui.setEnabled(false);
        }
        Gfx& g = ui.m_gfx;
        g.fill({ 0, 0, c_screen_w, c_screen_h }, 0x0b0b12);

        /*
         * USB keyboard typing goes straight in.
         */
        if (!input.m_text.empty()) {
            m_value_ += input.m_text;
        }
        if (input.m_backspace) {
            backspace_(m_value_);
        }
        if (input.m_enter) {
            submit(SecureString(m_value_));
            return;
        }
        if (input.m_b) {
            close();
            return;
        }

        g.text(24, 20, m_title_, Font::BodyBold, colors::c_subtext);
        Rect box { 24, 48, c_screen_w - 48, 48 };
        g.fill(box, colors::c_surface);
        g.outline(box, colors::c_accent);
        SecureString shown = m_masked_ && !m_reveal_ ? SecureString(m_value_.size(), '*') : m_value_;
        int width = g.measure(shown, Font::Body);
        /*
         * Show the end of long text, where the cursor is.
         */
        g.setClip({ box.x + 8, box.y, box.w - 16, box.h });
        int x = width > box.w - 24 ? box.x + box.w - 16 - width : box.x + 10;
        g.text(x, box.y + (box.h - g.lineHeight(Font::Body)) / 2, shown + "|", Font::Body, colors::c_text);
        g.clearClip();

        const char* const* rows = m_symbols_ ? c_symbols : c_letters;
        /*
         * Ten keys across whatever the screen's width (56 px on the Wii's 640).
         */
        int key_w = std::min(56, (c_screen_w - 24 - 9 * 4) / 10);
        int key_h = 46;
        int left = (c_screen_w - 10 * key_w - 9 * 4) / 2;
        int top = 116;
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 10; ++c) {
                char ch = rows[r][c];
                if (m_shift_ && ch >= 'a' && ch <= 'z') {
                    ch = static_cast<char>(ch - 'a' + 'A');
                }
                char label[2] = { ch, 0 };
                Rect key { left + c * (key_w + 4), top + r * (key_h + 4), key_w, key_h };
                if (ui.button(key, label)) {
                    m_value_.push_back(ch);
                    if (m_shift_ && !m_symbols_) {
                        m_shift_ = false;    // one capital, like a phone
                    }
                }
            }
        }

        int bottom = top + 4 * (key_h + 4) + 6;
        int w = (c_screen_w - 48 - 5 * 6) / 6;
        /*
         * The word where it fits (the Wii), a symbol where it doesn't (the 3DS).
         */
        auto label = [&g, w](const char* word, const char* symbol) {
            return g.measure(word, Font::BodyBold) <= w - 16 ? word : symbol;
        };
        int bx = 24;
        if (ui.button({ bx, bottom, w, key_h }, label("Shift", "⇧"), m_shift_ ? Style::Primary : Style::Normal)) {
            m_shift_ = !m_shift_;
        }
        bx += w + 6;
        if (ui.button({ bx, bottom, w, key_h }, "#+=", m_symbols_ ? Style::Primary : Style::Normal)) {
            m_symbols_ = !m_symbols_;
        }
        bx += w + 6;
        if (ui.button({ bx, bottom, w, key_h }, label("Space", "␣"))) {
            m_value_.push_back(' ');
        }
        bx += w + 6;
        if (ui.button({ bx, bottom, w, key_h }, label("Delete", "⌫"))) {
            backspace_(m_value_);
        }
        bx += w + 6;
        if (m_masked_) {
            if (ui.button({ bx, bottom, w, key_h }, label("Show", "◐"), m_reveal_ ? Style::Primary : Style::Normal)) {
                m_reveal_ = !m_reveal_;
            }
        } else if (ui.button({ bx, bottom, w, key_h }, label("Clear", "✕"))) {
            m_value_.clear();
        }
        bx += w + 6;
        if (ui.button({ bx, bottom, w, key_h }, label("Done", "✓"), Style::Primary)) {
            submit(SecureString(m_value_));
            return;
        }
        g.text(24, bottom + key_h + 14, "B: cancel   USB keyboards work too", Font::Small, colors::c_subtext);
    }
}
