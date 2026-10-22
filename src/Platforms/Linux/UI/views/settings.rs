//! The password generator and the settings page.

use iced::widget::{button, checkbox, column, container, pick_list, row, rule, slider, text, toggler};
use iced::{Alignment, Length};

use super::{El, caption, card, gap, heading};
use crate::app::{AUTO_LOCK_CHOICES, App, CLIPBOARD_CHOICES, GeneratorKind, Message};

fn page<'a>(title: &'a str, content: impl Into<El<'a>>) -> El<'a> {
    container(column![text(title).size(24), rule::horizontal(1), content.into()].spacing(14).max_width(560))
        .padding(28)
        .width(Length::Fill)
        .into()
}

pub fn generator(app: &App) -> El<'_> {
    let mut options = column![pick_list(GeneratorKind::ALL, Some(app.generator_kind), Message::GeneratorKind)].spacing(10);
    match app.generator_kind {
        GeneratorKind::Password => {
            options = options
                .push(row![caption(format!("Length: {}", app.length)), slider(5..=128, app.length, Message::GeneratorLength)].spacing(12).align_y(Alignment::Center))
                .push(checkbox(app.uppercase).label("Capital letters (A-Z)").on_toggle(Message::GeneratorUpper))
                .push(checkbox(app.numbers).label("Numbers (0-9)").on_toggle(Message::GeneratorNumbers))
                .push(checkbox(app.symbols).label("Symbols (!@#$%^&*)").on_toggle(Message::GeneratorSymbols));
        }
        GeneratorKind::Passphrase => {
            options = options
                .push(row![caption(format!("Words: {}", app.words)), slider(3..=20, app.words, Message::GeneratorWords)].spacing(12).align_y(Alignment::Center))
                .push(checkbox(app.capitalize).label("Capitalise").on_toggle(Message::GeneratorCapitalize));
        }
        GeneratorKind::Pin => {
            options = options.push(
                row![caption(format!("Digits: {}", app.digits)), slider(4..=12, app.digits, Message::GeneratorDigits)].spacing(12).align_y(Alignment::Center),
            );
        }
    }

    let output = container(
        row![
            text(if app.generated.is_empty() { "Press Generate" } else { app.generated.as_str() }).size(18).width(Length::Fill),
            button(text("Copy")).style(button::secondary).on_press_maybe((!app.generated.is_empty()).then_some(Message::CopyGenerated)),
            button(text("Generate")).style(button::primary).on_press(Message::Generate),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    )
    .padding(14)
    .style(card);

    page("Generator", column![output, options].spacing(16))
}

pub fn settings(app: &App) -> El<'_> {
    let auto_lock = if AUTO_LOCK_CHOICES.contains(&app.auto_lock) { Some(app.auto_lock) } else { None };
    let clipboard = if CLIPBOARD_CHOICES.contains(&app.clipboard_clear) { Some(app.clipboard_clear) } else { None };
    page(
        "Settings",
        column![
            heading("ACCOUNT"),
            text(app.account_email.as_str()),
            row![
                button(text("Sync now")).style(button::secondary).on_press_maybe((!app.busy).then_some(Message::SyncNow)),
                button(text("Lock")).style(button::secondary).on_press(Message::Lock),
                button(text("Log out")).style(button::danger).on_press(Message::LogOut),
            ]
            .spacing(8),
            gap(6.0),
            heading("SECURITY"),
            caption("Lock after this long without use"),
            pick_list(AUTO_LOCK_CHOICES, auto_lock, Message::AutoLock).placeholder(app.auto_lock.to_string()),
            toggler(app.timeout_logout).label("Log out instead of locking").on_toggle(Message::TimeoutLogout),
            caption("Clear copied passwords after"),
            pick_list(CLIPBOARD_CHOICES, clipboard, Message::ClipboardClear).placeholder(app.clipboard_clear.to_string()),
        ]
        .spacing(10),
    )
}
