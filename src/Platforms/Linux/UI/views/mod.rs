//! Drawing the app. Each area has its own module; this one picks the screen and holds the
//! small pieces they share.

mod auth;
mod dialogs;
mod items;
mod sends;
mod settings;
mod sidebar;

use iced::widget::{button, column, container, opaque, row, space, stack, text};
use iced::{Alignment, Background, Border, Color, Element, Length, Theme};

use crate::app::{App, Message, Screen, Section};

pub type El<'a> = Element<'a, Message>;

/// Masked text for a secret.
pub const MASK: &str = "••••••••";

pub fn view(app: &App) -> El<'_> {
    let screen: El<'_> = match app.screen {
        Screen::Starting => container(text("Loading…").size(18)).center(Length::Fill).into(),
        Screen::Login => auth::login(app),
        Screen::Code => auth::code(app),
        Screen::Passkey => auth::passkey(),
        Screen::Unlock => auth::unlock(app),
        Screen::Vault => vault(app),
    };

    let mut layers = stack![screen].width(Length::Fill).height(Length::Fill);
    if let Some(dialog) = &app.dialog {
        layers = layers.push(opaque(
            container(
                container(dialogs::view(app, dialog))
                    .padding(20)
                    .width(440)
                    .style(card),
            )
            .center(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color { a: 0.6, ..Color::BLACK })),
                ..container::Style::default()
            }),
        ));
    }
    if let Some(message) = &app.toast {
        layers = layers.push(
            container(
                container(
                    row![
                        text(message.as_str()),
                        button(text("×")).style(button::text).on_press(Message::DismissToast)
                    ]
                    .spacing(12)
                    .align_y(Alignment::Center),
                )
                .padding([6, 14])
                .style(card),
            )
            .align_bottom(Length::Fill)
            .center_x(Length::Fill)
            .padding(20),
        );
    }
    layers.into()
}

fn vault(app: &App) -> El<'_> {
    let content: El<'_> = match app.section {
        Section::Items => row![
            container(items::list(app)).width(320).height(Length::Fill).style(panel),
            container(items::details(app)).width(Length::Fill).height(Length::Fill),
        ]
        .into(),
        Section::Sends => row![
            container(sends::list(app)).width(320).height(Length::Fill).style(panel),
            container(sends::details(app)).width(Length::Fill).height(Length::Fill),
        ]
        .into(),
        Section::Generator => settings::generator(app),
        Section::Settings => settings::settings(app),
    };
    row![
        container(sidebar::view(app)).width(230).height(Length::Fill).style(sidebar_style),
        content
    ]
    .into()
}

/// A raised box: dialogs, toasts, cards.
pub fn card(theme: &Theme) -> container::Style {
    let palette = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(palette.background.weak.color)),
        border: Border { radius: 10.0.into(), width: 1.0, color: palette.background.strong.color },
        text_color: Some(palette.background.weak.text),
        ..container::Style::default()
    }
}

fn panel(theme: &Theme) -> container::Style {
    let palette = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(palette.background.base.color)),
        border: Border { width: 0.0, ..Border::default() },
        ..container::Style::default()
    }
}

fn sidebar_style(theme: &Theme) -> container::Style {
    let palette = theme.extended_palette();
    container::Style {
        background: Some(Background::Color(palette.background.weakest.color)),
        ..container::Style::default()
    }
}

/// A list row that's highlighted when selected.
pub fn row_button<'a>(content: impl Into<El<'a>>, selected: bool, on_press: Message) -> El<'a> {
    button(content)
        .width(Length::Fill)
        .padding([6, 10])
        .style(move |theme: &Theme, status| {
            if selected {
                button::primary(theme, status)
            } else {
                let mut style = button::text(theme, status);
                if matches!(status, button::Status::Hovered) {
                    style.background = Some(Background::Color(theme.extended_palette().background.weak.color));
                }
                style
            }
        })
        .on_press(on_press)
        .into()
}

/// A small text-only button.
pub fn link<'a>(label: &'a str, on_press: Option<Message>) -> El<'a> {
    button(text(label).size(13))
        .padding([2, 6])
        .style(button::text)
        .on_press_maybe(on_press)
        .into()
}

/// A dimmed caption.
pub fn caption<'a>(label: impl text::IntoFragment<'a>) -> El<'a> {
    text(label)
        .size(12)
        .style(|theme: &Theme| text::Style { color: Some(theme.extended_palette().background.strong.text) })
        .into()
}

/// A section heading.
pub fn heading<'a>(label: &'a str) -> El<'a> {
    text(label)
        .size(12)
        .style(|theme: &Theme| text::Style { color: Some(theme.extended_palette().primary.base.color) })
        .into()
}

/// A labelled value with trailing actions.
pub fn labelled<'a>(label: String, value: El<'a>, actions: Vec<El<'a>>) -> El<'a> {
    column![
        caption(label),
        row![container(value).width(Length::Fill)]
            .extend(actions)
            .spacing(4)
            .align_y(Alignment::Center)
    ]
    .spacing(2)
    .into()
}

pub fn gap(height: f32) -> El<'static> {
    space().height(height).into()
}
