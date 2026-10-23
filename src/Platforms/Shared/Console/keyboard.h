#pragma once
#include <functional>

#include "ui.h"

/*
 * The on-screen keyboard every text field opens: QWERTY with shift and a symbols page, driven
 * by the pointer or the D-pad. A USB keyboard types into it too (Enter finishes).
 */
namespace clientwarden::console::ui {
    class Keyboard {
    public:
        using Done = std::function<void(SecureString)>;

        /**
         * @brief Opens the keyboard over the current screen.
         *
         * @param title What's being entered
         * @param value The starting text
         * @param masked Show dots instead of the text (passwords)
         * @param done Gets the text when the user presses Done (not called on cancel)
         */
        void open(std::string_view title, std::string_view value, bool masked, Done done);
        bool isOpen() const { return m_open_; }

        /**
         * @brief Draws it and handles its input. Call after the screen underneath.
         */
        void frame(Ui& ui, const Input& input);

        /**
         * @brief Replaces the text and finishes (test scripts).
         */
        void submit(std::string_view text);

        void close();

    private:
        bool m_open_ = false;
        bool m_masked_ = false;
        bool m_shift_ = false;
        bool m_symbols_ = false;
        bool m_reveal_ = false;
        SecureString m_title_;
        SecureString m_value_;
        Done m_done_;
    };
}
