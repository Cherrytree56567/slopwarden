#pragma once
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "gfx.h"

/*
 * An immediate-mode toolkit: each frame the screen code calls button()/field()/... with where
 * they go, and they draw themselves and report whether they were activated. Works with the Wii
 * Remote pointer (A clicks what it points at) and without it (the D-pad moves a focus
 * highlight through the controls in the order they were drawn, A activates).
 */
namespace clientwarden::wii::ui {
    /**
     * @brief One frame's input.
     */
    struct Input {
        bool m_pointer_valid = false;
        int m_pointer_x = 0;
        int m_pointer_y = 0;
        bool m_a = false;
        bool m_b = false;
        bool m_up = false;
        bool m_down = false;
        bool m_left = false;
        bool m_right = false;
        bool m_plus = false;
        bool m_minus = false;
        bool m_home = false;
        bool m_backspace = false;
        bool m_enter = false;
        SecureString m_text;    // typed on a USB keyboard

        bool any() const {
            return m_a || m_b || m_up || m_down || m_left || m_right || m_plus || m_minus || m_home ||
                   m_backspace || m_enter || !m_text.empty();
        }
    };

    enum class Style { Normal, Primary, Danger, Flat };

    class Ui {
    public:
        explicit Ui(Gfx& gfx) : m_gfx(gfx) {}

        /**
         * @brief Starts a frame. While disabled (a modal is open over this layer) controls draw
         * but ignore input and can't take focus.
         */
        void begin(const Input& input);
        void setEnabled(bool enabled) { m_enabled_ = enabled; }

        /**
         * @brief Finishes a frame: moves focus for the D-pad.
         */
        void end();

        /**
         * @brief A push button.
         */
        bool button(Rect rect, std::string_view label, Style style = Style::Normal);

        /**
         * @brief A row in a list: a title and an optional subtitle, activated as one.
         */
        bool row(Rect rect, std::string_view title, std::string_view subtitle, bool selected = false,
                std::string_view badge = "");

        /**
         * @brief A text field showing its value (masked if asked); activating it means "edit me".
         */
        bool field(Rect rect, std::string_view label, std::string_view value, bool masked);

        /**
         * @brief An on/off switch; flips value when activated.
         */
        bool toggle(Rect rect, std::string_view label, bool& value);

        /**
         * @brief Starts a scrolling column (the content area of a screen). Rows are laid out
         * top to bottom with next(); the column scrolls to keep the focused control in view, and
         * +/- page it.
         */
        void beginColumn(std::string_view id, Rect area);
        Rect next(int height, int gap = 6);
        void endColumn();

        /**
         * @brief Focuses the control with this label (test scripts and "first field" focus).
         */
        void focusLabel(std::string_view label) { m_focus_request_ = SecureString(label); }

        /**
         * @brief Activates the focused control next frame (test scripts).
         */
        void pressFocused() { m_press_focused_ = true; }

        /**
         * @brief The label of the focused control.
         */
        SecureString focusedLabel() const;

        /**
         * @brief Forgets scroll positions and focus (moving to another screen).
         */
        void resetLayout();

        bool pointerOverControl() const { return m_pointer_over_; }

        Gfx& m_gfx;

    private:
        struct Control {
            SecureString m_id;
            SecureString m_label;
            Rect m_rect;
            bool m_hit;
        };

        bool interact_(Rect rect, std::string_view label, bool& focused);

        Input m_input_;
        bool m_enabled_ = true;
        std::vector<Control> m_controls_;
        std::map<SecureString, int> m_label_counts_;
        SecureString m_focus_;
        SecureString m_focus_request_;
        bool m_press_focused_ = false;
        bool m_activated_this_frame_ = false;
        bool m_pointer_over_ = false;

        // the current column
        bool m_in_column_ = false;
        SecureString m_column_id_;
        Rect m_column_;
        int m_column_y_ = 0;
        std::map<SecureString, int> m_scroll_;
        std::map<SecureString, int> m_content_height_;
        Rect m_focused_rect_in_column_;
        bool m_focus_in_column_ = false;
    };
}
