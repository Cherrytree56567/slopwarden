//! The sidebar: filters, types, folders, organisations, and the other sections.

use iced::widget::{column, row, scrollable, text};
use iced::{Alignment, Length};

use super::{El, caption, gap, heading, link, row_button};
use crate::app::{App, Dialog, Message, Section};
use crate::model::{EXTENDED_TYPES, Filter, ITEM_TYPES};

fn entry<'a>(app: &App, label: impl Into<String>, filter: Filter) -> El<'a> {
    let selected = app.section == Section::Items && app.filter == filter;
    row_button(text(label.into()).size(14), selected, Message::Filter(filter))
}

fn section_entry<'a>(app: &App, label: &'a str, section: Section) -> El<'a> {
    row_button(text(label).size(14), app.section == section, Message::Section(section))
}

/// A heading with a "+" on the right.
fn heading_with_add<'a>(label: &'a str, add: Option<Message>) -> El<'a> {
    row![heading(label), iced::widget::space().width(Length::Fill), link("+", add)]
        .align_y(Alignment::Center)
        .into()
}

pub fn view(app: &App) -> El<'_> {
    let mut items = column![
        caption(app.account_email.as_str()),
        gap(6.0),
        heading("VAULT"),
        entry(app, "All items", Filter::All),
        entry(app, "Favourites", Filter::Favorites),
        entry(app, "Trash", Filter::Trash),
        entry(app, "Archived", Filter::Archived),
        gap(8.0),
        heading("TYPES"),
    ]
    .spacing(2)
    .padding(10);

    for (key, label) in ITEM_TYPES {
        if EXTENDED_TYPES.contains(key) && !app.extended_types {
            continue;
        }
        items = items.push(entry(app, *label, Filter::Type((*key).to_string())));
    }

    items = items
        .push(gap(8.0))
        .push(heading_with_add("FOLDERS", Some(Message::OpenDialog(Dialog::NewFolder(String::new())))));
    for folder in &app.folders {
        let selected = app.filter == Filter::Folder(folder.id.clone());
        let mut line = row![row_button(
            text(folder.name.as_str()).size(14),
            selected && app.section == Section::Items,
            Message::Filter(Filter::Folder(folder.id.clone()))
        )]
        .align_y(Alignment::Center);
        if selected {
            line = line
                .push(link("Rename", Some(Message::OpenDialog(Dialog::RenameFolder(folder.id.clone(), folder.name.clone())))))
                .push(link("×", Some(Message::OpenDialog(Dialog::DeleteFolder(folder.id.clone())))));
        }
        items = items.push(line);
    }

    if !app.organizations.is_empty() {
        items = items
            .push(gap(8.0))
            .push(heading("ORGANISATIONS"))
            .push(entry(app, "My vault", Filter::Personal));
        for organization in &app.organizations {
            let add = organization
                .can_manage_collections
                .then(|| Message::OpenDialog(Dialog::NewCollection(organization.id.clone(), String::new())));
            items = items.push(
                row![
                    entry(app, organization.name.as_str(), Filter::Organization(organization.id.clone())),
                    link("+", add)
                ]
                .align_y(Alignment::Center),
            );
            for collection in &organization.collections {
                let filter = Filter::Collection(collection.id.clone());
                let selected = app.filter == filter && app.section == Section::Items;
                let mut line = row![
                    iced::widget::space().width(14),
                    row_button(text(collection.name.as_str()).size(13), selected, Message::Filter(filter))
                ]
                .align_y(Alignment::Center);
                if selected && (collection.manage || organization.can_manage_collections) {
                    line = line
                        .push(link(
                            "Rename",
                            Some(Message::OpenDialog(Dialog::RenameCollection(
                                collection.id.clone(),
                                collection.name.clone(),
                            ))),
                        ))
                        .push(link("×", Some(Message::OpenDialog(Dialog::DeleteCollection(collection.id.clone())))));
                }
                items = items.push(line);
            }
        }
    }

    let sections = column![
        section_entry(app, "Send", Section::Sends),
        section_entry(app, "Generator", Section::Generator),
        section_entry(app, "Settings", Section::Settings),
        row_button(text("Lock").size(14), false, Message::Lock),
    ]
    .spacing(2)
    .padding(10);

    column![scrollable(items).height(Length::Fill), sections].into()
}
