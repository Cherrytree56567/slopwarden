//! Modal dialogs: folders, collections, deleting, sharing, re-prompt and opening a Send.

use iced::widget::{button, checkbox, column, pick_list, row, space, text, text_input};
use iced::{Alignment, Length};

use super::{El, MASK, caption};
use crate::app::{App, Dialog, Message};

fn buttons<'a>(confirm: &'a str, danger: bool, enabled: bool) -> El<'a> {
    row![
        space().width(Length::Fill),
        button(text("Cancel")).style(button::secondary).on_press(Message::CloseDialog),
        button(text(confirm))
            .style(if danger { button::danger } else { button::primary })
            .on_press_maybe(enabled.then_some(Message::ConfirmDialog)),
    ]
    .spacing(8)
    .into()
}

fn name_dialog<'a>(title: &'a str, name: &'a str, confirm: &'a str) -> El<'a> {
    column![
        text(title).size(20),
        text_input("Name", name).on_input(Message::DialogText).on_submit(Message::ConfirmDialog).padding(8),
        buttons(confirm, false, !name.trim().is_empty()),
    ]
    .spacing(14)
    .into()
}

fn confirm_dialog<'a>(title: &'a str, message: &'a str, confirm: &'a str) -> El<'a> {
    column![text(title).size(20), text(message), buttons(confirm, true, true)].spacing(14).into()
}

pub fn view<'a>(app: &'a App, dialog: &'a Dialog) -> El<'a> {
    match dialog {
        Dialog::NewFolder(name) => name_dialog("New folder", name, "Create"),
        Dialog::RenameFolder(_, name) => name_dialog("Rename folder", name, "Rename"),
        Dialog::NewCollection(_, name) => name_dialog("New collection", name, "Create"),
        Dialog::RenameCollection(_, name) => name_dialog("Rename collection", name, "Rename"),
        Dialog::DeleteFolder(_) => confirm_dialog("Delete folder", "Items in it stay in your vault, without a folder.", "Delete"),
        Dialog::DeleteCollection(_) => confirm_dialog("Delete collection", "Items only in this collection will be deleted for everyone.", "Delete"),
        Dialog::DeleteItem(_) => confirm_dialog("Delete permanently", "This item will be deleted forever.", "Delete"),
        Dialog::DeleteSend(_) => confirm_dialog("Delete Send", "The link will stop working.", "Delete"),
        Dialog::Share(_, organization, selected) => {
            let current = app.organizations.iter().find(|o| &o.id == organization).cloned();
            let mut content = column![
                text("Move to organisation").size(20),
                caption("The organisation will own the item; you can't move it back."),
                pick_list(app.organizations.clone(), current, Message::DialogOrganization)
                    .placeholder("Choose an organisation")
                    .width(Length::Fill),
            ]
            .spacing(10);
            for collection in app.writable_collections(organization) {
                let id = collection.id.clone();
                content = content.push(
                    checkbox(selected.contains(&collection.id))
                        .label(collection.name)
                        .on_toggle(move |on| Message::DialogCollection(id.clone(), on)),
                );
            }
            content.push(buttons("Move", false, !organization.is_empty() && !selected.is_empty())).into()
        }
        Dialog::Collections(id, selected) => {
            let organization = app.item.as_ref().filter(|i| &i.id == id).map(|i| i.organization_id.clone()).unwrap_or_default();
            let mut content = column![text("Collections").size(20)].spacing(10);
            for collection in app.writable_collections(&organization) {
                let cid = collection.id.clone();
                content = content.push(
                    checkbox(selected.contains(&collection.id))
                        .label(collection.name)
                        .on_toggle(move |on| Message::DialogCollection(cid.clone(), on)),
                );
            }
            content.push(buttons("Save", false, !selected.is_empty())).into()
        }
        Dialog::Reprompt(_, password, error) => {
            let mut content = column![
                text("Master password required").size(20),
                caption("This item is protected. Enter your master password to view it."),
                text_input("Master password", password.as_str())
                    .secure(true)
                    .on_input(Message::DialogSecret)
                    .on_submit(Message::ConfirmDialog)
                    .padding(8),
            ]
            .spacing(10);
            if !error.is_empty() {
                content = content.push(caption(error.as_str()));
            }
            content.push(buttons("Continue", false, !password.is_empty())).into()
        }
        Dialog::OpenSend(open) => {
            let mut content = column![text("Open a Send").size(20)].spacing(10);
            if let Some(received) = &open.received {
                content = content.push(text(received.name.as_str()).size(18));
                if !received.creator.is_empty() {
                    content = content.push(caption(format!("Shared by {}", received.creator)));
                }
                if received.file {
                    content = content
                        .push(text(format!("{} ({})", received.file_name, received.file_size)))
                        .push(button(text("Save file…")).style(button::primary).on_press(Message::SaveReceivedFile));
                } else if received.text_hidden && !open.revealed {
                    content = content
                        .push(text(MASK))
                        .push(button(text("Show text")).style(button::secondary).on_press(Message::RevealReceived));
                } else {
                    content = content
                        .push(text(received.text.as_str()))
                        .push(button(text("Copy")).style(button::secondary).on_press(Message::CopyReceived));
                }
                return content
                    .push(row![space().width(Length::Fill), button(text("Done")).style(button::primary).on_press(Message::CloseDialog)])
                    .into();
            }
            content = content.push(
                text_input("https://…/#/send/…", &open.link)
                    .on_input(Message::DialogText)
                    .on_submit(Message::ConfirmDialog)
                    .padding(8),
            );
            if open.needs_password {
                content = content.push(
                    text_input("Password", open.password.as_str())
                        .secure(true)
                        .on_input(Message::DialogSecret)
                        .on_submit(Message::ConfirmDialog)
                        .padding(8),
                );
            }
            if !open.message.is_empty() {
                content = content.push(caption(open.message.as_str()));
            }
            content
                .push(buttons(if app.busy { "Opening…" } else { "Open" }, false, !open.link.trim().is_empty() && !app.busy))
                .align_x(Alignment::Start)
                .into()
        }
    }
}
