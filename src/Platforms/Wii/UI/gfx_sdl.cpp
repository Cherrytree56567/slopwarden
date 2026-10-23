#include "gfx.h"

#include <SDL.h>
#include <SDL_ttf.h>

#include <map>

namespace clientwarden::console::ui {
    namespace {
        constexpr size_t c_cache_limit = 400;

        SDL_Color color_(std::uint32_t rgb) {
            return SDL_Color { static_cast<Uint8>(rgb >> 16), static_cast<Uint8>(rgb >> 8),
                static_cast<Uint8>(rgb), 255 };
        }
    }

    struct Gfx::Impl {
        SDL_Window* m_window = nullptr;
        SDL_Renderer* m_renderer = nullptr;
        SDL_Texture* m_texture = nullptr;
        SDL_Surface* m_canvas = nullptr;
        TTF_Font* m_small = nullptr;
        TTF_Font* m_body = nullptr;
        TTF_Font* m_bold = nullptr;
        TTF_Font* m_title = nullptr;
        TTF_Font* m_code = nullptr;

        struct Key {
            SecureString m_text;
            int m_font;
            std::uint32_t m_rgb;
            bool operator<(const Key& o) const {
                if (m_font != o.m_font) return m_font < o.m_font;
                if (m_rgb != o.m_rgb) return m_rgb < o.m_rgb;
                return m_text < o.m_text;
            }
        };
        std::map<Key, SDL_Surface*> m_cache;

        TTF_Font* font(Font font) {
            switch (font) {
                case Font::Small: return m_small;
                case Font::BodyBold: return m_bold;
                case Font::Title: return m_title;
                case Font::Code: return m_code;
                default: return m_body;
            }
        }

        void forget() {
            for (std::pair<const Key, SDL_Surface*>& entry : m_cache) {
                SDL_FreeSurface(entry.second);
            }
            m_cache.clear();
        }

        SDL_Surface* rendered(std::string_view text, Font font, std::uint32_t rgb) {
            if (text.empty()) {
                return nullptr;
            }
            Key key { SecureString(text), static_cast<int>(font), rgb };
            std::map<Key, SDL_Surface*>::iterator it = m_cache.find(key);
            if (it != m_cache.end()) {
                return it->second;
            }
            if (m_cache.size() > c_cache_limit) {
                forget();
            }
            SDL_Surface* surface = TTF_RenderUTF8_Blended(this->font(font), key.m_text.c_str(), color_(rgb));
            if (surface) {
                m_cache.emplace(std::move(key), surface);
            }
            return surface;
        }
    };

    Gfx::Gfx() : m_impl_(std::make_unique<Impl>()) {}

    bool Gfx::init(std::filesystem::path app_dir) {
        if (SDL_Init(SDL_INIT_VIDEO) != 0 || TTF_Init() != 0) {
            return false;
        }
        m_impl_->m_window = SDL_CreateWindow("ClientWarden", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                c_screen_w, c_screen_h, 0);
        if (!m_impl_->m_window) {
            return false;
        }
        m_impl_->m_renderer = SDL_CreateRenderer(m_impl_->m_window, -1, 0);
        if (!m_impl_->m_renderer) {
            return false;
        }
        m_impl_->m_texture = SDL_CreateTexture(m_impl_->m_renderer, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING,
                c_screen_w, c_screen_h);
        m_impl_->m_canvas = SDL_CreateRGBSurfaceWithFormat(0, c_screen_w, c_screen_h, 32, SDL_PIXELFORMAT_ARGB8888);
        SDL_ShowCursor(SDL_DISABLE);

        std::string regular = (app_dir / "DejaVuSans.ttf").string();
        std::string bold = (app_dir / "DejaVuSans-Bold.ttf").string();
        std::error_code error;
        if (!std::filesystem::exists(bold, error)) {
            bold = regular;
        }
        m_impl_->m_small = TTF_OpenFont(regular.c_str(), 13);
        m_impl_->m_body = TTF_OpenFont(regular.c_str(), 17);
        m_impl_->m_bold = TTF_OpenFont(bold.c_str(), 17);
        m_impl_->m_title = TTF_OpenFont(bold.c_str(), 24);
        m_impl_->m_code = TTF_OpenFont(bold.c_str(), 30);
        return m_impl_->m_texture && m_impl_->m_canvas && m_impl_->m_small && m_impl_->m_body && m_impl_->m_bold && m_impl_->m_title && m_impl_->m_code;
    }

    Gfx::~Gfx() {
        forgetText();
        for (TTF_Font* font : { m_impl_->m_small, m_impl_->m_body, m_impl_->m_bold, m_impl_->m_title, m_impl_->m_code }) {
            if (font) {
                TTF_CloseFont(font);
            }
        }
        if (m_impl_->m_canvas) SDL_FreeSurface(m_impl_->m_canvas);
        if (m_impl_->m_texture) SDL_DestroyTexture(m_impl_->m_texture);
        if (m_impl_->m_renderer) SDL_DestroyRenderer(m_impl_->m_renderer);
        if (m_impl_->m_window) SDL_DestroyWindow(m_impl_->m_window);
    }

    void Gfx::clear(std::uint32_t rgb) {
        SDL_SetClipRect(m_impl_->m_canvas, nullptr);
        SDL_FillRect(m_impl_->m_canvas, nullptr, 0xff000000u | rgb);
    }

    void Gfx::fill(Rect rect, std::uint32_t rgb) {
        SDL_Rect r { rect.x, rect.y, rect.w, rect.h };
        SDL_FillRect(m_impl_->m_canvas, &r, 0xff000000u | rgb);
    }

    int Gfx::text(int x, int y, std::string_view text, Font font, std::uint32_t rgb) {
        SDL_Surface* surface = m_impl_->rendered(text, font, rgb);
        if (!surface) {
            return 0;
        }
        SDL_Rect dst { x, y, surface->w, surface->h };
        SDL_BlitSurface(surface, nullptr, m_impl_->m_canvas, &dst);
        return surface->w;
    }

    int Gfx::measure(std::string_view text, Font font) {
        if (text.empty()) {
            return 0;
        }
        int w = 0;
        int h = 0;
        TTF_SizeUTF8(m_impl_->font(font), SecureString(text).c_str(), &w, &h);
        return w;
    }

    int Gfx::lineHeight(Font font) {
        return TTF_FontLineSkip(m_impl_->font(font));
    }

    void Gfx::setClip(Rect rect) {
        SDL_Rect r { rect.x, rect.y, rect.w, rect.h };
        SDL_SetClipRect(m_impl_->m_canvas, &r);
    }

    void Gfx::clearClip() {
        SDL_SetClipRect(m_impl_->m_canvas, nullptr);
    }

    void Gfx::present() {
        SDL_UpdateTexture(m_impl_->m_texture, nullptr, m_impl_->m_canvas->pixels, m_impl_->m_canvas->pitch);
        SDL_RenderClear(m_impl_->m_renderer);
        SDL_RenderCopy(m_impl_->m_renderer, m_impl_->m_texture, nullptr, nullptr);
        SDL_RenderPresent(m_impl_->m_renderer);
    }

    void Gfx::idle() {
        SDL_Delay(16);
    }

    bool Gfx::saveBmp(std::filesystem::path path) {
        /*
         * 24-bit: viewers handle it better than SDL's 32-bit BMP with alpha masks.
         */
        SDL_Surface* rgb = SDL_ConvertSurfaceFormat(m_impl_->m_canvas, SDL_PIXELFORMAT_BGR24, 0);
        if (!rgb) {
            return false;
        }
        bool ok = SDL_SaveBMP(rgb, path.string().c_str()) == 0;
        SDL_FreeSurface(rgb);
        return ok;
    }

    void Gfx::forgetText() {
        m_impl_->forget();
    }
}
