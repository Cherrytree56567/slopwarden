#pragma once

/*
 * The 3DS draws the shared console UI on a 512x384 logical canvas, scaled by 5/8 onto the
 * 320x240 touch screen (UI/gfx_3ds.cpp), so the layout written for the Wii's 640x480 fits
 * without crowding the text.
 */
namespace clientwarden::console::metrics {
    constexpr int c_screen_w = 512;
    constexpr int c_screen_h = 384;
}
