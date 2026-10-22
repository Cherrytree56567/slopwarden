//! The item list and the details pane (viewing and editing).

use std::collections::HashSet;

use iced::widget::{
    button, checkbox, column, container, pick_list, progress_bar, row, rule, scrollable, space, text,
    text_editor, text_input,
};
use iced::{Alignment, Length};

use super::{El, MASK, caption, card, gap, heading, labelled, link, row_button};
use crate::app::{App, Dialog, Message};
use crate::model::*;

/// An item type in the "New" menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Kind(&'static str, &'static str);

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
}

pub fn list(app: &App) -> El<'_> {
    let kinds: Vec<Kind> = ITEM_TYPES
        .iter()
        .filter(|(key, _)| app.extended_types || !EXTENDED_TYPES.contains(key))
        .map(|(key, label)| Kind(key, label))
        .collect();
    let can_add = !matches!(app.filter, Filter::Trash | Filter::Archived);

    let header = row![
        text_input("Search", &app.search).on_input(Message::Search).padding(8).width(Length::Fill),
        pick_list(kinds, None::<Kind>, |k| Message::New(k.0.to_string()))
            .placeholder("New")
            .width(90),
    ]
    .spacing(6)
    .padding(10);
    let header: El<'_> = if can_add { header.into() } else {
        row![text_input("Search", &app.search).on_input(Message::Search).padding(8)].padding(10).into()
    };

    let mut rows = column![].spacing(2).padding([0, 8]);
    if app.items.is_empty() {
        rows = rows.push(container(caption("No items")).center_x(Length::Fill).padding(30));
    }
    for summary in &app.items {
        let selected = app.selected.as_deref() == Some(summary.id.as_str());
        let mut title = row![text(summary.name.as_str()).size(14)].spacing(6);
        if summary.favorite {
            title = title.push(caption("★"));
        }
        let subtitle = if summary.subtitle.is_empty() { type_label(&summary.kind).to_string() } else { summary.subtitle.clone() };
        let subtitle: El<'_> = if selected { text(subtitle).size(12).into() } else { caption(subtitle) };
        rows = rows.push(row_button(
            column![title, subtitle].spacing(2),
            selected,
            Message::Select(summary.id.clone()),
        ));
    }
    column![header, scrollable(rows).height(Length::Fill)].into()
}

pub fn details(app: &App) -> El<'_> {
    if let Some(draft) = &app.draft {
        return editor(app, draft);
    }
    let Some(item) = &app.item else {
        return container(caption("Select an item")).center(Length::Fill).into();
    };
    viewer(app, item)
}

fn copy_button<'a>(message: Message) -> El<'a> {
    link("Copy", Some(message))
}

fn viewer<'a>(app: &'a App, item: &'a Item) -> El<'a> {
    let deleted = item.deleted > 0;
    let archived = item.archived > 0;

    // toolbar
    let mut actions = row![].spacing(4).align_y(Alignment::Center);
    if deleted {
        actions = actions
            .push(link("Restore", item.can_edit.then_some(Message::ItemAction("items.restore"))))
            .push(link("Delete forever", item.can_edit.then(|| Message::OpenDialog(Dialog::DeleteItem(item.id.clone())))));
    } else {
        if item.can_edit {
            actions = actions
                .push(button(text("Edit")).style(button::primary).on_press(Message::Edit))
                .push(link(if item.favorite { "Unfavourite" } else { "Favourite" }, Some(Message::ToggleFavorite)));
        }
        actions = actions.push(link("Duplicate", item.can_edit.then_some(Message::ItemAction("items.duplicate"))));
        if item.organization_id.is_empty() {
            if item.can_edit && !app.organizations.is_empty() {
                actions = actions.push(link(
                    "Move to organisation",
                    Some(Message::OpenDialog(Dialog::Share(item.id.clone(), String::new(), HashSet::new()))),
                ));
            }
        } else if item.can_edit {
            actions = actions.push(link(
                "Collections",
                Some(Message::OpenDialog(Dialog::Collections(
                    item.id.clone(),
                    item.collection_ids.iter().cloned().collect(),
                ))),
            ));
        }
        actions = actions
            .push(link(
                if archived { "Unarchive" } else { "Archive" },
                item.can_edit.then_some(Message::ItemAction(if archived { "items.unarchive" } else { "items.archive" })),
            ))
            .push(link("Move to trash", item.can_edit.then_some(Message::ItemAction("items.bin"))));
    }

    let mut body = column![
        row![
            column![text(item.name.as_str()).size(24), caption(type_label(&item.kind))].spacing(2),
            space().width(Length::Fill),
        ],
        actions,
        rule::horizontal(1),
    ]
    .spacing(10)
    .padding(20);

    if deleted {
        body = body.push(caption("This item is in the trash."));
    }
    if !item.can_edit {
        body = body.push(caption("You can view this item but not change it."));
    }

    // fields
    let mut fields = column![].spacing(12);
    for (index, field) in item.fields.iter().enumerate() {
        if field.secret && !item.can_view_password {
            continue;
        }
        if field.value.is_empty() {
            continue;
        }
        let key = format!("field:{index}");
        let shown = !field.secret || app.revealed.contains(&key);
        let value: El<'_> = if shown {
            text(field.value.as_str()).size(15).into()
        } else {
            text(MASK).size(15).into()
        };
        let mut buttons: Vec<El<'_>> = Vec::new();
        if field.secret {
            buttons.push(link(if shown { "Hide" } else { "Show" }, Some(Message::Reveal(key))));
        }
        buttons.push(copy_button(Message::CopyField(index)));
        fields = fields.push(labelled(field_label(&field.key), value, buttons));
    }

    if item.is_login() {
        if let Some(totp) = &app.totp {
            let left = (totp.valid_until - now()).max(0);
            let code = totp.code.as_str();
            let spaced = if code.len() == 6 { format!("{} {}", &code[..3], &code[3..]) } else { code.to_string() };
            fields = fields.push(labelled(
                "Verification code (TOTP)".into(),
                row![
                    text(spaced).size(18),
                    progress_bar(0.0..=totp.period as f32, left as f32).length(60).girth(4),
                    caption(format!("{left}s"))
                ]
                .spacing(10)
                .align_y(Alignment::Center)
                .into(),
                vec![copy_button(Message::CopyTotp)],
            ));
        }
        for uri in &item.uris {
            fields = fields.push(labelled("Website".into(), text(uri.as_str()).into(), vec![copy_button(Message::Copy(uri.clone()))]));
        }
        if item.passkeys > 0 {
            fields = fields.push(labelled("Passkey".into(), text("Saved").into(), vec![]));
        }
    }
    body = body.push(fields);

    if !item.notes.is_empty() {
        body = body.push(labelled("Notes".into(), text(item.notes.as_str()).into(), vec![]));
    }

    if !item.custom.is_empty() {
        let mut custom = column![heading("CUSTOM FIELDS")].spacing(10);
        for (index, field) in item.custom.iter().enumerate() {
            let key = format!("custom:{index}");
            let (value, buttons): (El<'_>, Vec<El<'_>>) = match field.kind {
                1 if !item.can_view_password => continue,
                1 => {
                    let shown = app.revealed.contains(&key);
                    (
                        text(if shown { field.value.as_str() } else { MASK }).into(),
                        vec![link(if shown { "Hide" } else { "Show" }, Some(Message::Reveal(key))), copy_button(Message::CopyCustom(index))],
                    )
                }
                2 => (text(if field.value.as_str() == "true" { "Yes" } else { "No" }).into(), vec![]),
                3 => (caption(format!("Linked to {}", field_label(field.value.as_str()))), vec![]),
                _ => (text(field.value.as_str()).into(), vec![copy_button(Message::CopyCustom(index))]),
            };
            custom = custom.push(labelled(field.name.clone(), value, buttons));
        }
        body = body.push(custom);
    }

    // attachments
    let mut attachments = column![heading("ATTACHMENTS")].spacing(6);
    for attachment in &item.attachments {
        let mut line = row![
            text(attachment.name.as_str()).width(Length::Fill),
            caption(attachment.size.as_str()),
            link("Download", Some(Message::DownloadAttachment(attachment.id.clone(), attachment.name.clone()))),
        ]
        .spacing(6)
        .align_y(Alignment::Center);
        if item.can_edit && !deleted {
            line = line.push(link("Remove", Some(Message::RemoveAttachment(attachment.id.clone()))));
        }
        attachments = attachments.push(line);
    }
    if item.can_edit && !deleted {
        attachments = attachments.push(link("Add attachment…", (!app.busy).then_some(Message::AddAttachment)));
    }
    if !item.attachments.is_empty() || (item.can_edit && !deleted) {
        body = body.push(attachments);
    }

    // history
    if !item.history.is_empty() {
        body = body.push(link(
            if app.show_history { "Hide password history" } else { "Password history" },
            Some(Message::ToggleHistory),
        ));
        if app.show_history {
            let mut history = column![].spacing(6);
            for entry in &item.history {
                history = history.push(
                    row![
                        text(entry.password.as_str()).width(Length::Fill),
                        caption(format_date(entry.date)),
                        copy_button(Message::Copy(entry.password.as_str().to_string())),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                );
            }
            body = body.push(container(history).padding(10).style(card));
        }
    }

    // footer
    let mut footer = column![].spacing(2);
    if let Some(org) = app.organizations.iter().find(|o| o.id == item.organization_id) {
        let names: Vec<&str> = org
            .collections
            .iter()
            .filter(|c| item.collection_ids.contains(&c.id))
            .map(|c| c.name.as_str())
            .collect();
        footer = footer.push(caption(format!("Owner: {}  ·  {}", org.name, names.join(", "))));
    }
    if let Some(folder) = app.folders.iter().find(|f| f.id == item.folder_id) {
        footer = footer.push(caption(format!("Folder: {}", folder.name)));
    }
    footer = footer
        .push(caption(format!("Created {}", format_date(item.created))))
        .push(caption(format!("Updated {}", format_date(item.revised))));
    body = body.push(gap(6.0)).push(footer);

    scrollable(body).height(Length::Fill).into()
}

fn editor<'a>(app: &'a App, draft: &'a Item) -> El<'a> {
    let new = draft.id.is_empty();
    let mut body = column![
        row![
            text(if new { format!("New {}", type_label(&draft.kind).to_lowercase()) } else { "Edit item".to_string() }).size(22),
            space().width(Length::Fill),
            button(text("Cancel")).style(button::secondary).on_press(Message::CancelEdit),
            button(text(if app.busy { "Saving…" } else { "Save" }))
                .style(button::primary)
                .on_press_maybe((!app.busy).then_some(Message::Save)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        rule::horizontal(1),
        caption("Name"),
        text_input("Name", &draft.name).on_input(Message::EditName).padding(8),
    ]
    .spacing(8)
    .padding(20);

    // owner (new items) and folder
    if new && !app.organizations.is_empty() {
        let mut owners = vec![Organization {
            id: String::new(),
            name: "My vault".into(),
            can_manage_collections: false,
            collections: Vec::new(),
        }];
        owners.extend(app.organizations.iter().cloned());
        let current = owners.iter().find(|o| o.id == draft.organization_id).cloned();
        body = body.push(caption("Owner")).push(
            pick_list(owners, current, |o| Message::PickNewItemOrganization(Some(o))).width(Length::Fill),
        );
        if !draft.organization_id.is_empty() {
            let mut collections = column![caption("Collections")].spacing(4);
            for collection in app.writable_collections(&draft.organization_id) {
                let id = collection.id.clone();
                collections = collections.push(
                    checkbox(draft.collection_ids.contains(&collection.id))
                        .label(collection.name)
                        .on_toggle(move |on| Message::ToggleNewItemCollection(id.clone(), on)),
                );
            }
            body = body.push(collections);
        }
    }
    if draft.organization_id.is_empty() {
        let mut folders = vec![Folder { id: String::new(), name: "No folder".into() }];
        folders.extend(app.folders.iter().cloned());
        let current = folders.iter().find(|f| f.id == draft.folder_id).cloned();
        body = body.push(caption("Folder")).push(pick_list(folders, current, Message::EditFolder).width(Length::Fill));
    }
    body = body.push(
        row![
            checkbox(draft.favorite).label("Favourite").on_toggle(|_| Message::ToggleFavorite),
            checkbox(draft.reprompt).label("Ask for the master password").on_toggle(|_| Message::ToggleReprompt),
        ]
        .spacing(20),
    );

    // type fields
    let mut fields = column![].spacing(8);
    for (index, field) in draft.fields.iter().enumerate() {
        if field.secret && !draft.can_view_password {
            continue;
        }
        let key = format!("field:{index}");
        let input: El<'_> = if let Some(content) = app.editors.get(&key) {
            text_editor(content)
                .on_action(move |action| Message::EditorAction(format!("field:{index}"), action))
                .height(120)
                .into()
        } else {
            text_input(&field_label(&field.key), field.value.as_str())
                .secure(field.secret && !app.revealed.contains(&key))
                .on_input(move |v| Message::EditField(index, v))
                .padding(8)
                .into()
        };
        let mut buttons: Vec<El<'_>> = Vec::new();
        if field.secret && !app.editors.contains_key(&key) {
            buttons.push(link(if app.revealed.contains(&key) { "Hide" } else { "Show" }, Some(Message::Reveal(key))));
        }
        if field.key == "password" {
            buttons.push(link("Generate", Some(Message::GenerateField(index))));
        }
        fields = fields.push(labelled(field_label(&field.key), input, buttons));
    }
    body = body.push(fields);

    if draft.is_login() {
        let mut websites = column![caption("Websites")].spacing(4);
        for (index, uri) in draft.uris.iter().enumerate() {
            websites = websites.push(
                row![
                    text_input("https://", uri).on_input(move |v| Message::EditUri(index, v)).padding(8),
                    link("×", Some(Message::RemoveUri(index))),
                ]
                .spacing(4)
                .align_y(Alignment::Center),
            );
        }
        websites = websites.push(link("Add website", Some(Message::AddUri)));
        body = body.push(websites);
        if draft.can_view_password {
            body = body.push(labelled(
                "Authenticator key (TOTP)".into(),
                text_input("otpauth:// or key", draft.totp.as_str())
                    .secure(!app.revealed.contains("totp"))
                    .on_input(Message::EditTotp)
                    .padding(8)
                    .into(),
                vec![link(if app.revealed.contains("totp") { "Hide" } else { "Show" }, Some(Message::Reveal("totp".into())))],
            ));
        }
    }

    if let Some(content) = app.editors.get("notes") {
        body = body.push(caption("Notes")).push(
            text_editor(content)
                .on_action(|action| Message::EditorAction("notes".into(), action))
                .height(110),
        );
    }

    // custom fields
    let mut custom = column![heading("CUSTOM FIELDS")].spacing(6);
    for (index, field) in draft.custom.iter().enumerate() {
        let value: El<'_> = match field.kind {
            2 => checkbox(field.value.as_str() == "true")
                .label("Checked")
                .on_toggle(move |on| Message::ToggleCustom(index, on))
                .into(),
            3 => caption(format!("Linked to {}", field_label(field.value.as_str()))),
            1 if !draft.can_view_password => caption("Hidden"),
            kind => text_input("Value", field.value.as_str())
                .secure(kind == 1 && !app.revealed.contains(&format!("custom:{index}")))
                .on_input(move |v| Message::EditCustomValue(index, v))
                .padding(8)
                .into(),
        };
        custom = custom.push(
            row![
                text_input("Name", &field.name).on_input(move |v| Message::EditCustomName(index, v)).padding(8).width(180),
                container(value).width(Length::Fill),
                link("×", Some(Message::RemoveCustom(index))),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        );
    }
    custom = custom.push(
        row![
            link("Add text", Some(Message::AddCustom(0))),
            link("Add hidden", Some(Message::AddCustom(1))),
            link("Add checkbox", Some(Message::AddCustom(2))),
        ]
        .spacing(6),
    );
    body = body.push(custom);

    scrollable(body).height(Length::Fill).into()
}
