#include "gfx.h"

namespace clientwarden::wii::ui {
    namespace {
        constexpr size_t c_cache_limit = 400;

        SDL_Color color_(std::uint32_t rgb) {
            return SDL_Color { static_cast<Uint8>(rgb >> 16), static_cast<Uint8>(rgb >> 8),
                static_cast<Uint8>(rgb), 255 };
        }
    }

    bool Gfx::init(std::filesystem::path app_dir) {
        if (SDL_Init(SDL_INIT_VIDEO) != 0 || TTF_Init() != 0) {
            return false;
        }
        m_window_ = SDL_CreateWindow("ClientWarden", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                c_screen_w, c_screen_h, 0);
        if (!m_window_) {
            return false;
        }
        m_renderer_ = SDL_CreateRenderer(m_window_, -1, 0);
        if (!m_renderer_) {
            return false;
        }
        m_texture_ = SDL_CreateTexture(m_renderer_, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING,
                c_screen_w, c_screen_h);
        m_canvas_ = SDL_CreateRGBSurfaceWithFormat(0, c_screen_w, c_screen_h, 32, SDL_PIXELFORMAT_ARGB8888);
        SDL_ShowCursor(SDL_DISABLE);

        std::string regular = (app_dir / "DejaVuSans.ttf").string();
        std::string bold = (app_dir / "DejaVuSans-Bold.ttf").string();
        std::error_code error;
        if (!std::filesystem::exists(bold, error)) {
            bold = regular;
        }
        m_small_ = TTF_OpenFont(regular.c_str(), 13);
        m_body_ = TTF_OpenFont(regular.c_str(), 17);
        m_bold_ = TTF_OpenFont(bold.c_str(), 17);
        m_title_ = TTF_OpenFont(bold.c_str(), 24);
        m_code_ = TTF_OpenFont(bold.c_str(), 30);
        return m_texture_ && m_canvas_ && m_small_ && m_body_ && m_bold_ && m_title_ && m_code_;
    }

    Gfx::~Gfx() {
        forgetText();
        for (TTF_Font* font : { m_small_, m_body_, m_bold_, m_title_, m_code_ }) {
            if (font) {
                TTF_CloseFont(font);
            }
        }
        if (m_canvas_) SDL_FreeSurface(m_canvas_);
        if (m_texture_) SDL_DestroyTexture(m_texture_);
        if (m_renderer_) SDL_DestroyRenderer(m_renderer_);
        if (m_window_) SDL_DestroyWindow(m_window_);
    }

    void Gfx::clear(std::uint32_t rgb) {
        SDL_SetClipRect(m_canvas_, nullptr);
        SDL_FillRect(m_canvas_, nullptr, 0xff000000u | rgb);
    }

    void Gfx::fill(Rect rect, std::uint32_t rgb) {
        SDL_Rect r { rect.x, rect.y, rect.w, rect.h };
        SDL_FillRect(m_canvas_, &r, 0xff000000u | rgb);
    }

    void Gfx::outline(Rect rect, std::uint32_t rgb, int t) {
        fill({ rect.x, rect.y, rect.w, t }, rgb);
        fill({ rect.x, rect.y + rect.h - t, rect.w, t }, rgb);
        fill({ rect.x, rect.y, t, rect.h }, rgb);
        fill({ rect.x + rect.w - t, rect.y, t, rect.h }, rgb);
    }

    TTF_Font* Gfx::font_(Font font) {
        switch (font) {
            case Font::Small: return m_small_;
            case Font::BodyBold: return m_bold_;
            case Font::Title: return m_title_;
            case Font::Code: return m_code_;
            default: return m_body_;
        }
    }

    SDL_Surface* Gfx::rendered_(std::string_view text, Font font, std::uint32_t rgb) {
        if (text.empty()) {
            return nullptr;
        }
        Key key { SecureString(text), static_cast<int>(font), rgb };
        std::map<Key, SDL_Surface*>::iterator it = m_cache_.find(key);
        if (it != m_cache_.end()) {
            return it->second;
        }
        if (m_cache_.size() > c_cache_limit) {
            forgetText();
        }
        SDL_Surface* surface = TTF_RenderUTF8_Blended(font_(font), key.m_text.c_str(), color_(rgb));
        if (surface) {
            m_cache_.emplace(std::move(key), surface);
        }
        return surface;
    }

    int Gfx::text(int x, int y, std::string_view text, Font font, std::uint32_t rgb) {
        SDL_Surface* surface = rendered_(text, font, rgb);
        if (!surface) {
            return 0;
        }
        SDL_Rect dst { x, y, surface->w, surface->h };
        SDL_BlitSurface(surface, nullptr, m_canvas_, &dst);
        return surface->w;
    }

    int Gfx::measure(std::string_view text, Font font) {
        if (text.empty()) {
            return 0;
        }
        int w = 0;
        int h = 0;
        TTF_SizeUTF8(font_(font), SecureString(text).c_str(), &w, &h);
        return w;
    }

    int Gfx::lineHeight(Font font) {
        return TTF_FontLineSkip(font_(font));
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

    void Gfx::setClip(Rect rect) {
        SDL_Rect r { rect.x, rect.y, rect.w, rect.h };
        SDL_SetClipRect(m_canvas_, &r);
    }

    void Gfx::clearClip() {
        SDL_SetClipRect(m_canvas_, nullptr);
    }

    void Gfx::present() {
        SDL_UpdateTexture(m_texture_, nullptr, m_canvas_->pixels, m_canvas_->pitch);
        SDL_RenderClear(m_renderer_);
        SDL_RenderCopy(m_renderer_, m_texture_, nullptr, nullptr);
        SDL_RenderPresent(m_renderer_);
    }

    bool Gfx::saveBmp(std::filesystem::path path) {
        /*
         * 24-bit: viewers handle it better than SDL's 32-bit BMP with alpha masks.
         */
        SDL_Surface* rgb = SDL_ConvertSurfaceFormat(m_canvas_, SDL_PIXELFORMAT_BGR24, 0);
        if (!rgb) {
            return false;
        }
        bool ok = SDL_SaveBMP(rgb, path.string().c_str()) == 0;
        SDL_FreeSurface(rgb);
        return ok;
    }

    void Gfx::forgetText() {
        for (std::pair<const Key, SDL_Surface*>& entry : m_cache_) {
            SDL_FreeSurface(entry.second);
        }
        m_cache_.clear();
    }
}
