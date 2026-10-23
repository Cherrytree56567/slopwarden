#pragma once
#include <SDL.h>
#include <SDL_ttf.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <string_view>

#include "utils/secure_string/secure_string.h"

/*
 * Software drawing onto a 640x480 surface that's uploaded to the screen once a frame. Drawing
 * in software keeps the UI simple on the Wii's GX renderer and lets test builds save exact
 * screenshots of what's shown.
 */
namespace clientwarden::wii::ui {
    constexpr int c_screen_w = 640;
    constexpr int c_screen_h = 480;

    struct Rect {
        int x = 0;
        int y = 0;
        int w = 0;
        int h = 0;

        bool contains(int px, int py) const { return px >= x && py >= y && px < x + w && py < y + h; }
        bool intersects(const Rect& o) const {
            return x < o.x + o.w && o.x < x + w && y < o.y + o.h && o.y < y + h;
        }
    };

    /**
     * @brief The Catppuccin Mocha palette the desktop apps use.
     */
    namespace colors {
        constexpr std::uint32_t c_background = 0x11111b;
        constexpr std::uint32_t c_surface = 0x1e1e2e;
        constexpr std::uint32_t c_surface2 = 0x313244;
        constexpr std::uint32_t c_overlay = 0x45475a;
        constexpr std::uint32_t c_text = 0xcdd6f4;
        constexpr std::uint32_t c_subtext = 0xa6adc8;
        constexpr std::uint32_t c_accent = 0x89b4fa;
        constexpr std::uint32_t c_on_accent = 0x11111b;
        constexpr std::uint32_t c_red = 0xf38ba8;
        constexpr std::uint32_t c_green = 0xa6e3a1;
        constexpr std::uint32_t c_yellow = 0xf9e2af;
    }

    enum class Font { Small, Body, BodyBold, Title, Code };

    /**
     * @brief The drawing surface, fonts and a cache of rendered text.
     */
    class Gfx {
    public:
        /**
         * @brief Opens the window and loads the fonts from the app folder.
         *
         * @param app_dir Where DejaVuSans.ttf and DejaVuSans-Bold.ttf are
         * @return False if SDL or the fonts couldn't be set up
         */
        bool init(std::filesystem::path app_dir);
        ~Gfx();

        void clear(std::uint32_t rgb);
        void fill(Rect rect, std::uint32_t rgb);
        void outline(Rect rect, std::uint32_t rgb, int thickness = 2);

        /**
         * @brief Draws text with its top-left at (x, y), clipped to the current clip.
         *
         * @return The width drawn
         */
        int text(int x, int y, std::string_view text, Font font, std::uint32_t rgb);

        /**
         * @brief Draws text cut to fit max_width with "…".
         */
        void textFit(int x, int y, std::string_view text, Font font, std::uint32_t rgb, int max_width);

        /**
         * @brief Draws text wrapped at max_width.
         *
         * @return The height used
         */
        int textWrapped(int x, int y, std::string_view text, Font font, std::uint32_t rgb, int max_width);

        int measure(std::string_view text, Font font);
        int lineHeight(Font font);

        void setClip(Rect rect);
        void clearClip();

        /**
         * @brief Shows the frame.
         */
        void present();

        /**
         * @brief Saves the last frame as a BMP (test builds).
         */
        bool saveBmp(std::filesystem::path path);

        /**
         * @brief Drops cached text renderings (they may show secrets).
         */
        void forgetText();

    private:
        TTF_Font* font_(Font font);
        SDL_Surface* rendered_(std::string_view text, Font font, std::uint32_t rgb);

        SDL_Window* m_window_ = nullptr;
        SDL_Renderer* m_renderer_ = nullptr;
        SDL_Texture* m_texture_ = nullptr;
        SDL_Surface* m_canvas_ = nullptr;
        TTF_Font* m_small_ = nullptr;
        TTF_Font* m_body_ = nullptr;
        TTF_Font* m_bold_ = nullptr;
        TTF_Font* m_title_ = nullptr;
        TTF_Font* m_code_ = nullptr;

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
        std::map<Key, SDL_Surface*> m_cache_;
    };
}
