//! ClientWarden for Linux and Windows: an iced UI over the vault core.

mod app;
mod bridge;
mod clipboard;
#[cfg(debug_assertions)]
mod devscript;
mod model;
mod views;

use std::path::PathBuf;

use iced::theme::Palette;
use iced::{Color, Theme};

use app::App;

/// The passphrase word list the generator needs, shipped inside the binary.
const WORD_LIST: &[u8] = include_bytes!("../../../../ClientWarden/clientgen.txt");

/// The data directory: $CW_DATA_DIR if set (development), else the platform's usual place.
fn data_directory() -> PathBuf {
    if let Some(dir) = std::env::var_os("CW_DATA_DIR") {
        return PathBuf::from(dir);
    }
    directories::ProjectDirs::from("app", "ct5", "ClientWarden")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".clientwarden"))
}

/// Creates the folders, writes the word list if it's missing or stale, and starts the core.
fn start_core() {
    let data = data_directory();
    let resources = data.join("resources");
    let _ = std::fs::create_dir_all(&resources);
    let words = resources.join("clientgen.txt");
    if std::fs::read(&words).map(|existing| existing != WORD_LIST).unwrap_or(true) {
        let _ = std::fs::write(&words, WORD_LIST);
    }
    bridge::init(&data, &resources);
}

fn theme(_: &App) -> Theme {
    Theme::custom(
        "Catppuccin".to_string(),
        Palette {
            background: Color::from_rgb8(17, 17, 27),
            text: Color::from_rgb8(205, 214, 244),
            primary: Color::from_rgb8(137, 180, 250),
            success: Color::from_rgb8(166, 227, 161),
            warning: Color::from_rgb8(249, 226, 175),
            danger: Color::from_rgb8(243, 139, 168),
        },
    )
}

fn main() -> iced::Result {
    start_core();
    iced::application(App::new, App::update, views::view)
        .title(App::title)
        .theme(theme)
        .subscription(App::subscription)
        .window_size((1180.0, 760.0))
        .run()
}
