#include "gfx.h"

/*
 * The parts of drawing every backend shares, built on fill(), text() and measure().
 */
namespace clientwarden::console::ui {
    void Gfx::outline(Rect rect, std::uint32_t rgb, int t) {
        fill({ rect.x, rect.y, rect.w, t }, rgb);
        fill({ rect.x, rect.y + rect.h - t, rect.w, t }, rgb);
        fill({ rect.x, rect.y, t, rect.h }, rgb);
        fill({ rect.x + rect.w - t, rect.y, t, rect.h }, rgb);
    }

    void Gfx::textFit(int x, int y, std::string_view s, Font font, std::uint32_t rgb, int max_width) {
        if (measure(s, font) <= max_width) {
            text(x, y, s, font, rgb);
            return;
        }
        /*
         * Cut on UTF-8 character boundaries until it fits with the ellipsis.
         */
        SecureString cut(s);
        while (!cut.empty()) {
            do {
                cut.pop_back();
            } while (!cut.empty() && (static_cast<unsigned char>(cut.back()) & 0xC0) == 0x80);
            if (!cut.empty() && (static_cast<unsigned char>(cut.back()) & 0x80)) {
                cut.pop_back();
            }
            if (measure(cut + "…", font) <= max_width) {
                break;
            }
        }
        text(x, y, cut + "…", font, rgb);
    }

    int Gfx::textWrapped(int x, int y, std::string_view s, Font font, std::uint32_t rgb, int max_width) {
        int line_h = lineHeight(font);
        int dy = 0;
        size_t start = 0;
        while (start <= s.size()) {
            size_t newline = s.find('\n', start);
            std::string_view paragraph =
                    s.substr(start, newline == std::string_view::npos ? std::string_view::npos : newline - start);
            SecureString line;
            size_t i = 0;
            while (i <= paragraph.size()) {
                size_t space = paragraph.find(' ', i);
                std::string_view word = paragraph.substr(i, space == std::string_view::npos ? std::string_view::npos : space - i);
                SecureString candidate = line.empty() ? SecureString(word) : line + " " + SecureString(word);
                if (!line.empty() && measure(candidate, font) > max_width) {
                    text(x, y + dy, line, font, rgb);
                    dy += line_h;
                    line = SecureString(word);
                } else {
                    line = candidate;
                }
                /*
                 * A single word wider than the line (keys, URLs) is cut by characters.
                 */
                while (measure(line, font) > max_width && line.size() > 1) {
                    size_t keep = line.size();
                    while (keep > 1 && measure(std::string_view(line).substr(0, keep), font) > max_width) {
                        keep--;
                        while (keep > 1 && (static_cast<unsigned char>(line[keep]) & 0xC0) == 0x80) {
                            keep--;
                        }
                    }
                    text(x, y + dy, std::string_view(line).substr(0, keep), font, rgb);
                    dy += line_h;
                    line = line.substr(keep);
                }
                if (space == std::string_view::npos) {
                    break;
                }
                i = space + 1;
            }
            text(x, y + dy, line, font, rgb);
            dy += line_h;
            if (newline == std::string_view::npos) {
                break;
            }
            start = newline + 1;
        }
        return dy;
    }
}
