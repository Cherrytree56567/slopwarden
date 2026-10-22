//! Bitwarden Send: the user's Sends, editing one, and opening someone else's link.

use iced::widget::{
    button, checkbox, column, container, pick_list, row, rule, scrollable, space, text, text_editor,
    text_input,
};
use iced::{Alignment, Length};

use super::{El, caption, gap, link, row_button};
use crate::app::{App, DELETION_CHOICES, Dialog, EXPIRY_CHOICES, Message, OpenSend};
use crate::model::{format_date, now};

pub fn list(app: &App) -> El<'_> {
    let header = row![
        button(text("New text")).style(button::primary).on_press(Message::NewSend(false)),
        button(text("New file")).style(button::secondary).on_press(Message::NewSend(true)),
        space().width(Length::Fill),
        link("Open link…", Some(Message::OpenDialog(Dialog::OpenSend(OpenSend::default())))),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .padding(10);

    let mut rows = column![].spacing(2).padding([0, 8]);
    if app.sends.is_empty() {
        rows = rows.push(
            container(caption("No Sends. Share text or a file securely with a link."))
                .center_x(Length::Fill)
                .padding(30),
        );
    }
    for send in &app.sends {
        let selected = app.send.as_ref().is_some_and(|s| s.id == send.id);
        let views = match send.max_views.as_str() {
            "" => format!("{} views", send.access_count),
            max => format!("{}/{} views", send.access_count, max),
        };
        let mut flags = Vec::new();
        if send.file {
            flags.push("file");
        }
        if send.has_password {
            flags.push("password");
        }
        if send.disabled {
            flags.push("disabled");
        }
        let line = format!("{views} · deleted {}{}", format_date(send.deletion_date),
            if flags.is_empty() { String::new() } else { format!(" · {}", flags.join(", ")) });
        let name = if send.name.is_empty() { "Untitled".to_string() } else { send.name.clone() };
        let line: El<'_> = if selected { text(line).size(12).into() } else { caption(line) };
        rows = rows.push(row_button(
            column![text(name).size(14), line].spacing(2),
            selected,
            Message::SelectSend(send.id.clone()),
        ));
    }
    column![header, scrollable(rows).height(Length::Fill)].into()
}

pub fn details(app: &App) -> El<'_> {
    let Some(send) = &app.send else {
        return container(caption("Select a Send, or create one")).center(Length::Fill).into();
    };
    let new = send.id.is_empty();

    let mut body = column![
        row![
            text(if new { "New Send" } else { "Edit Send" }).size(22),
            space().width(Length::Fill),
            link("Delete", (!new).then(|| Message::OpenDialog(Dialog::DeleteSend(send.id.clone())))),
            button(text(if app.busy { "Saving…" } else { "Save" }))
                .style(button::primary)
                .on_press_maybe((!app.busy).then_some(Message::SaveSend)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        rule::horizontal(1),
        caption("Name"),
        text_input("Name", &send.name).on_input(Message::SendName).padding(8),
    ]
    .spacing(8)
    .padding(20);

    if send.file {
        if new {
            body = body.push(
                row![
                    text(if send.file_name.is_empty() { "No file chosen".to_string() } else { send.file_name.clone() })
                        .width(Length::Fill),
                    button(text("Choose file…")).style(button::secondary).on_press(Message::SendChooseFile),
                ]
                .align_y(Alignment::Center),
            );
        } else {
            body = body.push(caption("File")).push(text(format!("{} ({})", send.file_name, send.file_size)));
        }
    } else if let Some(content) = app.editors.get("send:text") {
        body = body
            .push(caption("Text"))
            .push(text_editor(content).on_action(|a| Message::EditorAction("send:text".into(), a)).height(120))
            .push(checkbox(send.text_hidden).label("Hide the text by default").on_toggle(Message::SendTextHidden));
    }

    let deletion = format!("Deleted {}", format_date(send.deletion_date));
    let expiry = if send.expiration_date > 0 {
        format!("Expires {}", format_date(send.expiration_date))
    } else {
        "Never expires".to_string()
    };
    body = body
        .push(gap(4.0))
        .push(caption("Deletion date"))
        .push(pick_list(DELETION_CHOICES, None::<crate::app::Days>, Message::SendDeletion).placeholder(deletion).width(Length::Fill))
        .push(caption("Expiration"))
        .push(pick_list(EXPIRY_CHOICES, None::<crate::app::Days>, Message::SendExpiry).placeholder(expiry).width(Length::Fill))
        .push(caption("Maximum views (empty for unlimited)"))
        .push(text_input("Unlimited", &send.max_views).on_input(Message::SendMaxViews).padding(8))
        .push(caption(if send.has_password { "New password (empty keeps the current one)" } else { "Password (optional)" }))
        .push(
            row![
                text_input("", send.new_password.as_str()).secure(true).on_input(Message::SendPassword).padding(8),
                link("Remove password", (send.has_password && !new).then_some(Message::RemoveSendPassword)),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        )
        .push(checkbox(send.hide_email).label("Hide my email from recipients").on_toggle(Message::SendHideEmail))
        .push(checkbox(send.disabled).label("Disable this Send").on_toggle(Message::SendDisabled));
    if let Some(content) = app.editors.get("send:notes") {
        body = body
            .push(caption("Private notes"))
            .push(text_editor(content).on_action(|a| Message::EditorAction("send:notes".into(), a)).height(80));
    }

    if !send.share_url.is_empty() {
        body = body.push(gap(6.0)).push(caption("Link")).push(
            row![
                text(send.share_url.as_str()).size(13).width(Length::Fill),
                button(text("Copy link")).style(button::primary).on_press(Message::CopySendLink),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );
        if send.access_count > 0 {
            body = body.push(caption(format!("Opened {} times", send.access_count)));
        }
        if send.expiration_date > 0 && send.expiration_date < now() {
            body = body.push(caption("This Send has expired."));
        }
    }
    scrollable(body).height(Length::Fill).into()
}
