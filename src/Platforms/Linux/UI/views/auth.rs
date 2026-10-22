//! Logging in and unlocking.

use iced::widget::{button, column, container, pick_list, text, text_input};
use iced::{Alignment, Length};

use super::{El, caption, card, gap};
use crate::app::{App, Message, Server};

/// A centred card.
fn panel<'a>(content: impl Into<El<'a>>) -> El<'a> {
    container(container(content).padding(28).width(400).style(card))
        .center(Length::Fill)
        .into()
}

fn submit<'a>(label: &'a str, busy: bool, message: Message) -> El<'a> {
    button(container(text(if busy { "Please wait…" } else { label })).center_x(Length::Fill))
        .width(Length::Fill)
        .padding(10)
        .style(button::primary)
        .on_press_maybe((!busy).then_some(message))
        .into()
}

pub fn login(app: &App) -> El<'_> {
    let mut form = column![
        text("ClientWarden").size(28),
        caption("Log in to your Bitwarden account"),
        gap(12.0),
        caption("Server"),
        pick_list(Server::ALL, Some(app.server), Message::ServerPicked).width(Length::Fill),
    ]
    .spacing(6);
    if app.server == Server::SelfHosted {
        form = form.push(
            text_input("https://vault.example.com", &app.base_url)
                .on_input(Message::BaseUrl)
                .padding(8),
        );
    }
    form = form
        .push(gap(4.0))
        .push(caption("Email"))
        .push(text_input("you@example.com", &app.email).on_input(Message::Email).padding(8))
        .push(caption("Master password"))
        .push(
            text_input("", app.password.as_str())
                .secure(true)
                .on_input(Message::Password)
                .on_submit(Message::LogIn)
                .padding(8),
        )
        .push(gap(8.0))
        .push(submit("Log in", app.busy, Message::LogIn));
    panel(form)
}

pub fn code(app: &App) -> El<'_> {
    let explanation = if app.code_is_device {
        "This is a new device. Enter the verification code sent to your email."
    } else {
        "Enter the code from your authenticator app or email."
    };
    panel(
        column![
            text("Two-step login").size(24),
            caption(explanation),
            gap(8.0),
            text_input("Code", app.code.as_str())
                .on_input(Message::Code)
                .on_submit(Message::SubmitCode)
                .padding(8),
            gap(4.0),
            submit("Continue", app.busy, Message::SubmitCode),
            button(container(text("Cancel")).center_x(Length::Fill))
                .width(Length::Fill)
                .style(button::text)
                .on_press(Message::CancelLogin),
        ]
        .spacing(8),
    )
}

pub fn passkey() -> El<'static> {
    panel(
        column![
            text("Passkey required").size(24),
            text(
                "This account uses a passkey or security key for two-step login, which this app \
                 can't use yet. Log in with another two-step method, or turn the passkey off for \
                 this account in the web vault."
            ),
            gap(8.0),
            button(container(text("Back")).center_x(Length::Fill))
                .width(Length::Fill)
                .style(button::secondary)
                .on_press(Message::CancelLogin),
        ]
        .spacing(10),
    )
}

pub fn unlock(app: &App) -> El<'_> {
    panel(
        column![
            text("Vault locked").size(26),
            caption(app.account_email.as_str()),
            gap(10.0),
            caption("Master password"),
            text_input("", app.unlock_password.as_str())
                .secure(true)
                .on_input(Message::UnlockPassword)
                .on_submit(Message::Unlock)
                .padding(8),
            gap(6.0),
            submit("Unlock", app.busy, Message::Unlock),
            button(container(text("Log out")).center_x(Length::Fill))
                .width(Length::Fill)
                .style(button::text)
                .on_press(Message::LogOut),
        ]
        .spacing(6)
        .align_x(Alignment::Start),
    )
}
