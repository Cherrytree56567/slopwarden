#include "ui.h"

#include <algorithm>

namespace clientwarden::wii::ui {
    void Ui::begin(const Input& input) {
        m_input_ = input;
        m_controls_.clear();
        m_label_counts_.clear();
        m_activated_this_frame_ = false;
        m_pointer_over_ = false;
        m_enabled_ = true;
    }

    SecureString Ui::focusedLabel() const {
        for (const Control& control : m_controls_) {
            if (control.m_id == m_focus_) {
                return control.m_label;
            }
        }
        return SecureString();
    }

    void Ui::resetLayout() {
        m_scroll_.clear();
        m_focus_.clear();
    }

    bool Ui::interact_(Rect rect, std::string_view label, bool& focused) {
        focused = false;
        if (!m_enabled_) {
            return false;
        }
        int& count = m_label_counts_[SecureString(label)];
        SecureString id = SecureString(label) + "#" + toSecureString(count++);

        bool visible = !m_in_column_ || rect.intersects(m_column_);
        bool hit = visible && m_input_.m_pointer_valid && rect.contains(m_input_.m_pointer_x, m_input_.m_pointer_y);
        if (m_in_column_ && hit && !m_column_.contains(m_input_.m_pointer_x, m_input_.m_pointer_y)) {
            hit = false;
        }
        m_controls_.push_back({ id, SecureString(label), rect, hit });

        if (!m_focus_request_.empty() && m_focus_request_ == label) {
            m_focus_ = id;
            m_focus_request_.clear();
        }
        if (m_focus_.empty()) {
            m_focus_ = id;    // something is always focused
        }

        bool activated = false;
        if (hit) {
            m_pointer_over_ = true;
            if (m_input_.m_a && !m_activated_this_frame_) {
                m_focus_ = id;
                activated = true;
            }
        }
        focused = m_focus_ == id;
        if (focused && !activated && !m_activated_this_frame_) {
            /*
             * A without pointing at the screen activates the focused control.
             */
            bool by_pad = m_input_.m_a && !m_input_.m_pointer_valid;
            if (m_press_focused_ || by_pad || m_input_.m_enter) {
                activated = true;
                m_press_focused_ = false;
            }
        }
        if (focused && m_in_column_) {
            m_focus_in_column_ = true;
            m_focused_rect_in_column_ = rect;
        }
        if (activated) {
            m_activated_this_frame_ = true;
        }
        return activated;
    }

    bool Ui::button(Rect rect, std::string_view label, Style style) {
        bool focused = false;
        bool activated = interact_(rect, label, focused);
        bool hot = !m_controls_.empty() && m_controls_.back().m_hit;
        std::uint32_t bg = colors::c_surface2;
        std::uint32_t fg = colors::c_text;
        if (style == Style::Primary) {
            bg = colors::c_accent;
            fg = colors::c_on_accent;
        } else if (style == Style::Danger) {
            bg = 0x3b2232;
            fg = colors::c_red;
        } else if (style == Style::Flat) {
            bg = colors::c_background;
        }
        if (hot && style != Style::Primary) {
            bg = colors::c_overlay;
        }
        m_gfx.fill(rect, bg);
        if (focused && m_enabled_) {
            m_gfx.outline(rect, style == Style::Primary ? colors::c_text : colors::c_accent);
        }
        int w = m_gfx.measure(label, Font::BodyBold);
        int lh = m_gfx.lineHeight(Font::BodyBold);
        int x = rect.x + std::max(6, (rect.w - w) / 2);
        m_gfx.textFit(x, rect.y + (rect.h - lh) / 2, label, Font::BodyBold, fg, rect.w - 12);
        return activated;
    }

    bool Ui::row(Rect rect, std::string_view title, std::string_view subtitle, bool selected, std::string_view badge) {
        bool focused = false;
        bool activated = interact_(rect, title, focused);
        bool hot = !m_controls_.empty() && m_controls_.back().m_hit;
        m_gfx.fill(rect, selected ? colors::c_overlay : hot ? colors::c_surface2 : colors::c_surface);
        if (focused && m_enabled_) {
            m_gfx.outline(rect, colors::c_accent);
        }
        int badge_w = badge.empty() ? 0 : m_gfx.measure(badge, Font::Small) + 16;
        if (subtitle.empty()) {
            m_gfx.textFit(rect.x + 12, rect.y + (rect.h - m_gfx.lineHeight(Font::Body)) / 2, title, Font::Body,
                    colors::c_text, rect.w - 24 - badge_w);
        } else {
            int top = rect.y + (rect.h - m_gfx.lineHeight(Font::Body) - m_gfx.lineHeight(Font::Small)) / 2;
            m_gfx.textFit(rect.x + 12, top, title, Font::Body, colors::c_text, rect.w - 24 - badge_w);
            m_gfx.textFit(rect.x + 12, top + m_gfx.lineHeight(Font::Body), subtitle, Font::Small, colors::c_subtext,
                    rect.w - 24 - badge_w);
        }
        if (!badge.empty()) {
            m_gfx.text(rect.x + rect.w - badge_w, rect.y + (rect.h - m_gfx.lineHeight(Font::Small)) / 2, badge,
                    Font::Small, colors::c_accent);
        }
        return activated;
    }

    bool Ui::field(Rect rect, std::string_view label, std::string_view value, bool masked) {
        bool focused = false;
        bool activated = interact_(rect, label, focused);
        bool hot = !m_controls_.empty() && m_controls_.back().m_hit;
        int label_h = m_gfx.lineHeight(Font::Small);
        m_gfx.text(rect.x + 2, rect.y, label, Font::Small, colors::c_subtext);
        Rect box { rect.x, rect.y + label_h + 2, rect.w, rect.h - label_h - 2 };
        m_gfx.fill(box, hot ? colors::c_surface2 : colors::c_surface);
        m_gfx.outline(box, focused && m_enabled_ ? colors::c_accent : colors::c_surface2);
        SecureString shown = masked ? SecureString(std::min<size_t>(value.size(), 24), '*') : SecureString(value);
        m_gfx.textFit(box.x + 10, box.y + (box.h - m_gfx.lineHeight(Font::Body)) / 2, shown, Font::Body,
                colors::c_text, box.w - 20);
        return activated;
    }

    bool Ui::toggle(Rect rect, std::string_view label, bool& value) {
        bool focused = false;
        bool activated = interact_(rect, label, focused);
        m_gfx.fill(rect, colors::c_surface);
        if (focused && m_enabled_) {
            m_gfx.outline(rect, colors::c_accent);
        }
        m_gfx.textFit(rect.x + 12, rect.y + (rect.h - m_gfx.lineHeight(Font::Body)) / 2, label, Font::Body,
                colors::c_text, rect.w - 90);
        Rect knob { rect.x + rect.w - 64, rect.y + (rect.h - 24) / 2, 48, 24 };
        m_gfx.fill(knob, value ? colors::c_accent : colors::c_overlay);
        m_gfx.fill({ value ? knob.x + 26 : knob.x + 2, knob.y + 2, 20, 20 }, colors::c_text);
        if (activated) {
            value = !value;
        }
        return activated;
    }

    void Ui::beginColumn(std::string_view id, Rect area) {
        m_in_column_ = true;
        m_column_id_ = SecureString(id);
        m_column_ = area;
        m_column_y_ = 0;
        m_focus_in_column_ = false;

        int& scroll = m_scroll_[m_column_id_];
        int content = m_content_height_[m_column_id_];
        int page = area.h * 3 / 4;
        if (m_enabled_ && m_input_.m_plus) scroll += page;
        if (m_enabled_ && m_input_.m_minus) scroll -= page;
        scroll = std::max(0, std::min(scroll, std::max(0, content - area.h)));
        m_gfx.setClip(area);
    }

    Rect Ui::next(int height, int gap) {
        int scroll = m_scroll_[m_column_id_];
        Rect r { m_column_.x, m_column_.y + m_column_y_ - scroll, m_column_.w, height };
        m_column_y_ += height + gap;
        return r;
    }

    void Ui::endColumn() {
        m_gfx.clearClip();
        m_content_height_[m_column_id_] = m_column_y_;
        int& scroll = m_scroll_[m_column_id_];
        /*
         * Keep the focused control in view (for D-pad users).
         */
        if (m_focus_in_column_ && !m_input_.m_pointer_valid) {
            Rect f = m_focused_rect_in_column_;
            if (f.y < m_column_.y) {
                scroll -= m_column_.y - f.y + 8;
            } else if (f.y + f.h > m_column_.y + m_column_.h) {
                scroll += f.y + f.h - (m_column_.y + m_column_.h) + 8;
            }
            scroll = std::max(0, scroll);
        }
        /*
         * A scroll bar when the content doesn't fit.
         */
        if (m_column_y_ > m_column_.h) {
            int track_h = m_column_.h;
            int thumb_h = std::max(20, track_h * m_column_.h / m_column_y_);
            int thumb_y = m_column_.y + (track_h - thumb_h) * scroll / std::max(1, m_column_y_ - m_column_.h);
            m_gfx.fill({ m_column_.x + m_column_.w + 4, m_column_.y, 4, track_h }, colors::c_surface);
            m_gfx.fill({ m_column_.x + m_column_.w + 4, thumb_y, 4, thumb_h }, colors::c_overlay);
        }
        m_in_column_ = false;
    }

    void Ui::end() {
        if (!m_controls_.empty()) {
            std::vector<Control>::iterator it = std::find_if(m_controls_.begin(), m_controls_.end(),
                    [&](const Control& c) { return c.m_id == m_focus_; });
            if (it == m_controls_.end()) {
                m_focus_ = m_controls_.front().m_id;
                it = m_controls_.begin();
            }
            size_t index = static_cast<size_t>(it - m_controls_.begin());
            if (m_enabled_ && (m_input_.m_down || m_input_.m_right)) {
                index = (index + 1) % m_controls_.size();
                m_focus_ = m_controls_[index].m_id;
            } else if (m_enabled_ && (m_input_.m_up || m_input_.m_left)) {
                index = (index + m_controls_.size() - 1) % m_controls_.size();
                m_focus_ = m_controls_[index].m_id;
            }
        }
        m_press_focused_ = false;
    }
}
