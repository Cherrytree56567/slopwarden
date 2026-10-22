//! Development only (debug builds): drives the UI from a script so it can be tested without
//! a person at the keyboard. Set CW_UI_SCRIPT to a file of commands, one per line, e.g.
//!
//! ```text
//! server self
//! base http://localhost:8222
//! email test@example.com
//! password hunter2
//! login
//! wait 5
//! shot vault        # writes $CW_SHOT_DIR/vault.png
//! ```

use std::path::PathBuf;
use std::time::Duration;

use iced::futures::channel::mpsc;
use iced::futures::{SinkExt, Stream, StreamExt};
use iced::widget::text_editor;

use crate::app::{Dialog, GeneratorKind, Message, OpenSend, Section, Server};
use crate::model::Filter;

#[derive(Debug, Clone)]
pub enum Step {
    Run(Box<Message>),
    Shot(String),
    Select(usize),
    SelectSend(usize),
    /// Open the selected Send's own link as a recipient would
    OpenSelectedSend,
    /// Paste text into a multi-line editor
    Editor(String, String),
}

pub fn script() -> Option<PathBuf> {
    std::env::var_os("CW_UI_SCRIPT").map(PathBuf::from)
}

/// The script's steps, paced by its "wait" lines.
pub fn steps() -> impl Stream<Item = Step> {
    iced::stream::channel(8, async |mut output| {
        let (sender, mut receiver) = mpsc::unbounded();
        std::thread::spawn(move || {
            let text = script().and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
            std::thread::sleep(Duration::from_secs(2));
            for line in text.lines() {
                let line = line.split(" #").next().unwrap_or("").trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (command, rest) = line.split_once(' ').unwrap_or((line, ""));
                if command == "wait" {
                    std::thread::sleep(Duration::from_secs_f32(rest.parse().unwrap_or(1.0)));
                    continue;
                }
                match parse(command, rest) {
                    Some(step) => {
                        let _ = sender.unbounded_send(step);
                    }
                    None => eprintln!("devscript: unknown command {command}"),
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        while let Some(step) = receiver.next().await {
            let _ = output.send(step).await;
        }
    })
}

fn run(message: Message) -> Option<Step> {
    Some(Step::Run(Box::new(message)))
}

fn parse(command: &str, rest: &str) -> Option<Step> {
    let value = rest.to_string();
    let (first, second) = rest.split_once(' ').unwrap_or((rest, ""));
    match command {
        "shot" => Some(Step::Shot(value)),
        "select" => Some(Step::Select(rest.parse().ok()?)),
        "select-send" => Some(Step::SelectSend(rest.parse().ok()?)),
        "open-selected-send" => Some(Step::OpenSelectedSend),
        "notes" => Some(Step::Editor("notes".into(), value)),
        "send-text" => Some(Step::Editor("send:text".into(), value)),
        "server" => run(Message::ServerPicked(match rest {
            "eu" => Server::BitwardenEu,
            "self" => Server::SelfHosted,
            _ => Server::BitwardenUs,
        })),
        "base" => run(Message::BaseUrl(value)),
        "email" => run(Message::Email(value)),
        "password" => run(Message::Password(value)),
        "login" => run(Message::LogIn),
        "code" => run(Message::Code(value)),
        "submit-code" => run(Message::SubmitCode),
        "unlock-password" => run(Message::UnlockPassword(value)),
        "unlock" => run(Message::Unlock),
        "lock" => run(Message::Lock),
        "logout" => run(Message::LogOut),
        "section" => run(Message::Section(match rest {
            "sends" => Section::Sends,
            "generator" => Section::Generator,
            "settings" => Section::Settings,
            _ => Section::Items,
        })),
        "filter" => run(Message::Filter(match first {
            "favorites" => Filter::Favorites,
            "trash" => Filter::Trash,
            "archived" => Filter::Archived,
            "type" => Filter::Type(second.to_string()),
            _ => Filter::All,
        })),
        "search" => run(Message::Search(value)),
        "new" => run(Message::New(value)),
        "edit" => run(Message::Edit),
        "name" => run(Message::EditName(value)),
        "field" => run(Message::EditField(first.parse().ok()?, second.to_string())),
        "uri" => run(Message::EditUri(first.parse().ok()?, second.to_string())),
        "totp" => run(Message::EditTotp(value)),
        "generate-field" => run(Message::GenerateField(rest.parse().ok()?)),
        "save" => run(Message::Save),
        "reveal" => run(Message::Reveal(value)),
        "history" => run(Message::ToggleHistory),
        "favourite" => run(Message::ToggleFavorite),
        "action" => run(Message::ItemAction(match rest {
            "bin" => "items.bin",
            "restore" => "items.restore",
            "archive" => "items.archive",
            "unarchive" => "items.unarchive",
            "duplicate" => "items.duplicate",
            _ => return None,
        })),
        "new-folder" => run(Message::OpenDialog(Dialog::NewFolder(value))),
        "open-send" => run(Message::OpenDialog(Dialog::OpenSend(OpenSend { link: value, ..OpenSend::default() }))),
        "dialog-secret" => run(Message::DialogSecret(value)),
        "confirm" => run(Message::ConfirmDialog),
        "close" => run(Message::CloseDialog),
        "new-send" => run(Message::NewSend(rest == "file")),
        "send-name" => run(Message::SendName(value)),
        "send-password" => run(Message::SendPassword(value)),
        "send-max" => run(Message::SendMaxViews(value)),
        "save-send" => run(Message::SaveSend),
        "gen-kind" => run(Message::GeneratorKind(match rest {
            "passphrase" => GeneratorKind::Passphrase,
            "pin" => GeneratorKind::Pin,
            _ => GeneratorKind::Password,
        })),
        "generate" => run(Message::Generate),
        "sync" => run(Message::SyncNow),
        "quit" => run(Message::Quit),
        _ => None,
    }
}

/// The paste action for an editor step.
pub fn paste(text: String) -> text_editor::Action {
    text_editor::Action::Edit(text_editor::Edit::Paste(std::sync::Arc::new(text)))
}

/// Saves a screenshot as $CW_SHOT_DIR/<name>.png.
pub fn save_png(name: &str, width: u32, height: u32, rgba: &[u8]) {
    let dir = std::env::var_os("CW_SHOT_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::write(dir.join(format!("{name}.png")), encode_png(width, height, rgba));
}

/// An uncompressed PNG (zlib "stored" blocks): big, but needs no image library.
fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity((width as usize * 4 + 1) * height as usize);
    for row in rgba.chunks(width as usize * 4).take(height as usize) {
        raw.push(0);
        raw.extend_from_slice(row);
    }

    let mut zlib = vec![0x78, 0x01];
    let mut blocks = raw.chunks(65535).peekable();
    while let Some(block) = blocks.next() {
        zlib.push(if blocks.peek().is_none() { 1 } else { 0 });
        let len = block.len() as u16;
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &raw {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());

    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut header = Vec::new();
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut png, b"IHDR", &header);
    chunk(&mut png, b"IDAT", &zlib);
    chunk(&mut png, b"IEND", &[]);
    png
}

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    png.extend_from_slice(&(data.len() as u32).to_be_bytes());
    png.extend_from_slice(kind);
    png.extend_from_slice(data);
    let mut crc = 0xFFFF_FFFFu32;
    for byte in kind.iter().chain(data) {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { 0xEDB8_8320 ^ (crc >> 1) } else { crc >> 1 };
        }
    }
    png.extend_from_slice(&(!crc).to_be_bytes());
}
