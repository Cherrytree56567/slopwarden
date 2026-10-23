#include "gfx.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <map>
#include <vector>

#include <3ds.h>
#include <ft2build.h>
#include FT_FREETYPE_H

/*
 * The 3DS backend: everything is drawn in software into a canvas at the touch screen's real
 * resolution (320x240), from logical coordinates on the 512x384 canvas the shared UI lays out
 * (console_metrics.h), then copied into the bottom screen's framebuffer each frame. Text is
 * DejaVu Sans rasterised by FreeType at the physical size, so it stays sharp. The top screen
 * shows the app's name and a hint, drawn once.
 */
namespace clientwarden::console::ui {
    namespace {
        constexpr int c_bottom_w = 320;
        constexpr int c_bottom_h = 240;
        constexpr int c_top_w = 400;
        constexpr int c_top_h = 240;
        constexpr size_t c_glyph_limit = 600;

        /*
         * Logical to physical: x * 5 / 8, rounding so adjacent rectangles still meet.
         */
        int phys_(int logical) {
            return logical >= 0 ? (logical * 5 + 4) / 8 : -((-logical * 5 + 4) / 8);
        }

        int logical_(int physical) {
            return (physical * 8 + 4) / 5;
        }

        /*
         * Pixel sizes on the real screen.
         */
        int pixelSize_(Font font) {
            switch (font) {
                case Font::Small: return 10;
                case Font::BodyBold: return 13;
                case Font::Title: return 16;
                case Font::Code: return 22;
                default: return 13;
            }
        }

        bool bold_(Font font) {
            return font == Font::BodyBold || font == Font::Title || font == Font::Code;
        }

        /*
         * Decodes one UTF-8 character, advancing i; invalid bytes become U+FFFD.
         */
        char32_t next_(std::string_view s, size_t& i) {
            unsigned char lead = static_cast<unsigned char>(s[i++]);
            if (lead < 0x80) {
                return lead;
            }
            int extra = (lead & 0xE0) == 0xC0 ? 1 : (lead & 0xF0) == 0xE0 ? 2 : (lead & 0xF8) == 0xF0 ? 3 : -1;
            if (extra < 0) {
                return 0xFFFD;
            }
            char32_t code = lead & (0x3F >> extra);
            for (int k = 0; k < extra; ++k) {
                if (i >= s.size() || (static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) {
                    return 0xFFFD;
                }
                code = (code << 6) | (static_cast<unsigned char>(s[i++]) & 0x3F);
            }
            return code;
        }

        struct Glyph {
            int m_left = 0;
            int m_top = 0;
            int m_width = 0;
            int m_rows = 0;
            int m_advance = 0;
            std::vector<uint8_t> m_alpha;
        };

        /*
         * One canvas of 0xRRGGBB pixels with a clip rectangle, in physical pixels.
         */
        struct Canvas {
            int m_w = 0;
            int m_h = 0;
            std::vector<uint32_t> m_pixels;
            int m_clip_x0 = 0, m_clip_y0 = 0, m_clip_x1 = 0, m_clip_y1 = 0;

            void resize(int w, int h) {
                m_w = w;
                m_h = h;
                m_pixels.assign(static_cast<size_t>(w) * h, 0);
                unclip();
            }

            void unclip() {
                m_clip_x0 = 0;
                m_clip_y0 = 0;
                m_clip_x1 = m_w;
                m_clip_y1 = m_h;
            }

            void fill(int x0, int y0, int x1, int y1, uint32_t rgb) {
                x0 = std::max(x0, m_clip_x0);
                y0 = std::max(y0, m_clip_y0);
                x1 = std::min(x1, m_clip_x1);
                y1 = std::min(y1, m_clip_y1);
                if (x1 <= x0 || y1 <= y0) {
                    return; // entirely outside the clip
                }
                for (int y = y0; y < y1; ++y) {
                    std::fill(m_pixels.begin() + y * m_w + x0, m_pixels.begin() + y * m_w + x1, rgb);
                }
            }

            void blend(int x, int y, uint32_t rgb, uint8_t alpha) {
                if (x < m_clip_x0 || y < m_clip_y0 || x >= m_clip_x1 || y >= m_clip_y1 || alpha == 0) {
                    return;
                }
                uint32_t& dst = m_pixels[static_cast<size_t>(y) * m_w + x];
                if (alpha == 255) {
                    dst = rgb;
                    return;
                }
                auto mix = [alpha](uint32_t a, uint32_t b, int shift) {
                    uint32_t ca = (a >> shift) & 0xFF;
                    uint32_t cb = (b >> shift) & 0xFF;
                    return ((cb * alpha + ca * (255 - alpha)) / 255) << shift;
                };
                dst = mix(dst, rgb, 16) | mix(dst, rgb, 8) | mix(dst, rgb, 0);
            }

            /*
             * Copies into a 3DS framebuffer, which is stored rotated: columns of 240 BGR pixels
             * running bottom to top.
             */
            void present(u8* framebuffer) const {
                for (int x = 0; x < m_w; ++x) {
                    u8* column = framebuffer + static_cast<size_t>(x) * m_h * 3;
                    for (int y = 0; y < m_h; ++y) {
                        uint32_t rgb = m_pixels[static_cast<size_t>(y) * m_w + x];
                        u8* out = column + static_cast<size_t>(m_h - 1 - y) * 3;
                        out[0] = static_cast<u8>(rgb);
                        out[1] = static_cast<u8>(rgb >> 8);
                        out[2] = static_cast<u8>(rgb >> 16);
                    }
                }
            }
        };
    }

    struct Gfx::Impl {
        FT_Library m_library = nullptr;
        FT_Face m_regular = nullptr;
        FT_Face m_bold = nullptr;
        std::vector<uint8_t> m_regular_data;
        std::vector<uint8_t> m_bold_data;
        std::map<std::pair<int, char32_t>, Glyph> m_glyphs; // (size, bold) key -> glyph
        Canvas m_bottom;
        Canvas m_top;

        FT_Face face(Font font) {
            return bold_(font) && m_bold ? m_bold : m_regular;
        }

        const Glyph& glyph(Font font, char32_t code) {
            int key = pixelSize_(font) * 2 + (bold_(font) ? 1 : 0);
            std::map<std::pair<int, char32_t>, Glyph>::iterator it = m_glyphs.find({ key, code });
            if (it != m_glyphs.end()) {
                return it->second;
            }
            if (m_glyphs.size() > c_glyph_limit) {
                m_glyphs.clear();
            }
            Glyph out;
            FT_Face f = face(font);
            FT_Set_Pixel_Sizes(f, 0, static_cast<FT_UInt>(pixelSize_(font)));
            if (FT_Load_Char(f, code, FT_LOAD_RENDER | FT_LOAD_TARGET_NORMAL) == 0) {
                FT_GlyphSlot slot = f->glyph;
                out.m_left = slot->bitmap_left;
                out.m_top = slot->bitmap_top;
                out.m_width = static_cast<int>(slot->bitmap.width);
                out.m_rows = static_cast<int>(slot->bitmap.rows);
                out.m_advance = static_cast<int>(slot->advance.x >> 6);
                out.m_alpha.resize(static_cast<size_t>(out.m_width) * out.m_rows);
                for (int row = 0; row < out.m_rows; ++row) {
                    std::copy_n(slot->bitmap.buffer + row * slot->bitmap.pitch, out.m_width,
                            out.m_alpha.begin() + row * out.m_width);
                }
            }
            return m_glyphs.emplace(std::make_pair(key, code), std::move(out)).first->second;
        }

        int ascender(Font font) {
            FT_Face f = face(font);
            FT_Set_Pixel_Sizes(f, 0, static_cast<FT_UInt>(pixelSize_(font)));
            return static_cast<int>(f->size->metrics.ascender >> 6);
        }

        int lineHeight(Font font) {
            FT_Face f = face(font);
            FT_Set_Pixel_Sizes(f, 0, static_cast<FT_UInt>(pixelSize_(font)));
            return static_cast<int>(f->size->metrics.height >> 6);
        }

        /*
         * Draws physical-pixel text with its top-left at (x, y); returns the width.
         */
        int draw(Canvas& canvas, int x, int y, std::string_view text, Font font, uint32_t rgb) {
            int baseline = y + ascender(font);
            int pen = x;
            for (size_t i = 0; i < text.size();) {
                const Glyph& g = glyph(font, next_(text, i));
                for (int row = 0; row < g.m_rows; ++row) {
                    for (int col = 0; col < g.m_width; ++col) {
                        canvas.blend(pen + g.m_left + col, baseline - g.m_top + row, rgb,
                                g.m_alpha[static_cast<size_t>(row) * g.m_width + col]);
                    }
                }
                pen += g.m_advance;
            }
            return pen - x;
        }

        int width(std::string_view text, Font font) {
            int w = 0;
            for (size_t i = 0; i < text.size();) {
                w += glyph(font, next_(text, i)).m_advance;
            }
            return w;
        }

        static bool load(FT_Library library, std::filesystem::path path, std::vector<uint8_t>& data, FT_Face& face) {
            std::ifstream in(path, std::ios::binary);
            if (!in) {
                return false;
            }
            data.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            return FT_New_Memory_Face(library, data.data(), static_cast<FT_Long>(data.size()), 0, &face) == 0;
        }

        void drawTop() {
            m_top.fill(0, 0, c_top_w, c_top_h, colors::c_background);
            int y = 84;
            draw(m_top, 24, y, "ClientWarden", Font::Code, colors::c_text);
            draw(m_top, 24, y + 34, "Bitwarden on the Nintendo 3DS", Font::Body, colors::c_subtext);
            draw(m_top, 24, c_top_h - 34, "Touch screen or D-pad + A.  L/R scroll.  START: menu.", Font::Small,
                    colors::c_subtext);
        }
    };

    Gfx::Gfx() : m_impl_(std::make_unique<Impl>()) {}

    bool Gfx::init(std::filesystem::path app_dir) {
        gfxInitDefault();
        gfxSetDoubleBuffering(GFX_BOTTOM, true);
        Impl& impl = *m_impl_;
        impl.m_bottom.resize(c_bottom_w, c_bottom_h);
        impl.m_top.resize(c_top_w, c_top_h);
        if (FT_Init_FreeType(&impl.m_library) != 0 ||
                !Impl::load(impl.m_library, app_dir / "DejaVuSans.ttf", impl.m_regular_data, impl.m_regular)) {
            return false;
        }
        if (!Impl::load(impl.m_library, app_dir / "DejaVuSans-Bold.ttf", impl.m_bold_data, impl.m_bold)) {
            impl.m_bold = nullptr;
        }
        impl.drawTop();
        return true;
    }

    Gfx::~Gfx() {
        Impl& impl = *m_impl_;
        forgetText();
        if (impl.m_bold) FT_Done_Face(impl.m_bold);
        if (impl.m_regular) FT_Done_Face(impl.m_regular);
        if (impl.m_library) FT_Done_FreeType(impl.m_library);
        gfxExit();
    }

    void Gfx::clear(std::uint32_t rgb) {
        m_impl_->m_bottom.unclip();
        m_impl_->m_bottom.fill(0, 0, c_bottom_w, c_bottom_h, rgb);
    }

    void Gfx::fill(Rect r, std::uint32_t rgb) {
        m_impl_->m_bottom.fill(phys_(r.x), phys_(r.y), phys_(r.x + r.w), phys_(r.y + r.h), rgb);
    }

    int Gfx::text(int x, int y, std::string_view text, Font font, std::uint32_t rgb) {
        if (text.empty()) {
            return 0;
        }
        return logical_(m_impl_->draw(m_impl_->m_bottom, phys_(x), phys_(y), text, font, rgb));
    }

    int Gfx::measure(std::string_view text, Font font) {
        return text.empty() ? 0 : logical_(m_impl_->width(text, font));
    }

    int Gfx::lineHeight(Font font) {
        return logical_(m_impl_->lineHeight(font));
    }

    void Gfx::setClip(Rect r) {
        Canvas& c = m_impl_->m_bottom;
        c.m_clip_x0 = std::clamp(phys_(r.x), 0, c.m_w);
        c.m_clip_y0 = std::clamp(phys_(r.y), 0, c.m_h);
        c.m_clip_x1 = std::clamp(phys_(r.x + r.w), 0, c.m_w);
        c.m_clip_y1 = std::clamp(phys_(r.y + r.h), 0, c.m_h);
    }

    void Gfx::clearClip() {
        m_impl_->m_bottom.unclip();
    }

    void Gfx::present() {
        m_impl_->m_bottom.present(gfxGetFramebuffer(GFX_BOTTOM, GFX_LEFT, nullptr, nullptr));
        m_impl_->m_top.present(gfxGetFramebuffer(GFX_TOP, GFX_LEFT, nullptr, nullptr));
        gfxFlushBuffers();
        gfxSwapBuffers();
        gspWaitForVBlank();
    }

    void Gfx::idle() {
        gspWaitForVBlank();
    }

    bool Gfx::saveBmp(std::filesystem::path path) {
        const Canvas& c = m_impl_->m_bottom;
        int row_bytes = (c.m_w * 3 + 3) & ~3;
        uint32_t size = 54 + static_cast<uint32_t>(row_bytes * c.m_h);
        uint8_t header[54] = { 'B', 'M' };
        auto put32 = [&header](int at, uint32_t v) {
            for (int k = 0; k < 4; ++k) header[at + k] = static_cast<uint8_t>(v >> (8 * k));
        };
        put32(2, size);
        put32(10, 54);
        put32(14, 40);
        put32(18, static_cast<uint32_t>(c.m_w));
        put32(22, static_cast<uint32_t>(c.m_h));
        header[26] = 1;
        header[28] = 24;
        put32(34, static_cast<uint32_t>(row_bytes * c.m_h));
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(header), sizeof header);
        std::vector<uint8_t> row(static_cast<size_t>(row_bytes), 0);
        for (int y = c.m_h - 1; y >= 0; --y) {
            for (int x = 0; x < c.m_w; ++x) {
                uint32_t rgb = c.m_pixels[static_cast<size_t>(y) * c.m_w + x];
                row[x * 3] = static_cast<uint8_t>(rgb);
                row[x * 3 + 1] = static_cast<uint8_t>(rgb >> 8);
                row[x * 3 + 2] = static_cast<uint8_t>(rgb >> 16);
            }
            out.write(reinterpret_cast<const char*>(row.data()), row_bytes);
        }
        return static_cast<bool>(out);
    }

    /*
     * Glyphs aren't secrets (they're shared by every string), and the canvas is overwritten each
     * frame, so nothing is cached that could hold a secret.
     */
    void Gfx::forgetText() {}
}
