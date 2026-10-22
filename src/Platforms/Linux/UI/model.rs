//! What the UI holds: summaries and drafts parsed from the bridge's JSON. Secret values
//! live in [`Secret`] so they're wiped when dropped.

use serde_json::{Value, json};
use zeroize::Zeroize;

/// A string that's zeroed when dropped or replaced.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn set(&mut self, text: String) {
        self.0.zeroize();
        self.0 = text;
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Reads a string member, or "".
pub fn str_of(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

pub fn bool_of(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

pub fn int_of(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// The bridge's item type names, with what the UI calls them.
pub const ITEM_TYPES: &[(&str, &str)] = &[
    ("login", "Login"),
    ("card", "Card"),
    ("identity", "Identity"),
    ("note", "Secure note"),
    ("sshKey", "SSH key"),
    ("bankAccount", "Bank account"),
    ("driversLicense", "Driver's licence"),
    ("passport", "Passport"),
];

/// Types only newer servers support.
pub const EXTENDED_TYPES: &[&str] = &["bankAccount", "driversLicense", "passport"];

pub fn type_label(name: &str) -> &'static str {
    ITEM_TYPES
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, label)| *label)
        .unwrap_or("Item")
}

/// A field key as a label, e.g. "cardholderName" -> "Cardholder name".
pub fn field_label(key: &str) -> String {
    let known = match key {
        "ssn" => "Social Security number",
        "pin" => "PIN",
        "iban" => "IBAN",
        "swiftCode" => "SWIFT code",
        "code" => "Security code",
        "expMonth" => "Expiry month",
        "expYear" => "Expiry year",
        "keyFingerprint" => "Fingerprint",
        "address1" => "Address 1",
        "address2" => "Address 2",
        "address3" => "Address 3",
        "postalCode" => "Postcode",
        "dateOfBirth" => "Date of birth",
        "nationalIdentificationNumber" => "National ID number",
        _ => "",
    };
    if !known.is_empty() {
        return known.to_string();
    }
    let mut out = String::new();
    for (i, c) in key.chars().enumerate() {
        if i == 0 {
            out.extend(c.to_uppercase());
        } else if c.is_uppercase() {
            out.push(' ');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether a field is long text (keys, notes).
pub fn is_multiline(key: &str) -> bool {
    matches!(key, "privateKey" | "publicKey")
}

#[derive(Debug, Clone, PartialEq)]
pub struct Folder {
    pub id: String,
    pub name: String,
}

impl std::fmt::Display for Folder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Collection {
    pub id: String,
    pub name: String,
    pub read_only: bool,
    pub manage: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub can_manage_collections: bool,
    pub collections: Vec<Collection>,
}

impl std::fmt::Display for Organization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

impl Organization {
    pub fn parse(value: &Value) -> Self {
        let collections = value
            .get("collections")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|c| Collection {
                        id: str_of(c, "id"),
                        name: str_of(c, "name"),
                        read_only: bool_of(c, "readOnly"),
                        manage: bool_of(c, "manage"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            id: str_of(value, "id"),
            name: str_of(value, "name"),
            can_manage_collections: bool_of(value, "canManageCollections"),
            collections,
        }
    }
}

/// One row of the item list.
#[derive(Debug, Clone)]
pub struct Summary {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub subtitle: String,
    pub favorite: bool,
    pub reprompt: bool,
}

impl Summary {
    pub fn parse(value: &Value) -> Self {
        Self {
            id: str_of(value, "id"),
            kind: str_of(value, "type"),
            name: str_of(value, "name"),
            subtitle: str_of(value, "subtitle"),
            favorite: bool_of(value, "favorite"),
            reprompt: bool_of(value, "reprompt"),
        }
    }
}

/// Which items the list shows.
#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    All,
    Favorites,
    Trash,
    Archived,
    Type(String),
    Folder(String),
    Personal,
    Organization(String),
    Collection(String),
}

impl Filter {
    pub fn args(&self, search: &str) -> Value {
        let (filter, value) = match self {
            Filter::All => ("all", String::new()),
            Filter::Favorites => ("favorites", String::new()),
            Filter::Trash => ("trash", String::new()),
            Filter::Archived => ("archived", String::new()),
            Filter::Type(t) => ("type", t.clone()),
            Filter::Folder(id) => ("folder", id.clone()),
            Filter::Personal => ("personal", String::new()),
            Filter::Organization(id) => ("organization", id.clone()),
            Filter::Collection(id) => ("collection", id.clone()),
        };
        json!({ "filter": filter, "value": value, "search": search.trim(), "icons": false })
    }
}

#[derive(Debug, Clone)]
pub struct Field {
    pub key: String,
    pub secret: bool,
    pub value: Secret,
}

#[derive(Debug, Clone)]
pub struct CustomField {
    /// 0 text, 1 hidden, 2 checkbox, 3 linked
    pub kind: i64,
    pub name: String,
    pub value: Secret,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    pub size: String,
}

#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub date: i64,
    pub password: Secret,
}

/// An item as shown in the details pane, and edited in place when `editing` is set.
#[derive(Debug, Clone, Default)]
pub struct Item {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub notes: Secret,
    pub folder_id: String,
    pub favorite: bool,
    pub reprompt: bool,
    pub organization_id: String,
    pub collection_ids: Vec<String>,
    pub can_edit: bool,
    pub can_view_password: bool,
    pub created: i64,
    pub revised: i64,
    pub deleted: i64,
    pub archived: i64,
    pub fields: Vec<Field>,
    pub custom: Vec<CustomField>,
    pub attachments: Vec<Attachment>,
    pub uris: Vec<String>,
    pub totp: Secret,
    pub history: Vec<HistoryEntry>,
    pub passkeys: usize,
}

impl Item {
    pub fn parse(value: &Value) -> Self {
        let fields = value
            .get("fields")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|f| Field {
                        key: str_of(f, "key"),
                        secret: bool_of(f, "secret"),
                        value: Secret::new(str_of(f, "value")),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let custom = value
            .get("customFields")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|f| CustomField {
                        kind: int_of(f, "type"),
                        name: str_of(f, "name"),
                        value: Secret::new(str_of(f, "value")),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let attachments = value
            .get("attachments")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|a| Attachment {
                        id: str_of(a, "id"),
                        name: str_of(a, "name"),
                        size: str_of(a, "size"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let login = value.get("login").cloned().unwrap_or(Value::Null);
        let uris = login
            .get("uris")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        let history = login
            .get("passwordHistory")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|h| HistoryEntry {
                        date: int_of(h, "date"),
                        password: Secret::new(str_of(h, "password")),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let passkeys = login.get("passkeys").and_then(Value::as_array).map_or(0, Vec::len);
        let collection_ids = value
            .get("collectionIds")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        let mut login_copy = login;
        let totp = Secret::new(str_of(&login_copy, "totp"));
        crate::bridge::wipe(&mut login_copy);

        Self {
            id: str_of(value, "id"),
            kind: str_of(value, "type"),
            name: str_of(value, "name"),
            notes: Secret::new(str_of(value, "notes")),
            folder_id: str_of(value, "folderId"),
            favorite: bool_of(value, "favorite"),
            reprompt: bool_of(value, "reprompt"),
            organization_id: str_of(value, "organizationId"),
            collection_ids,
            can_edit: bool_of(value, "canEdit"),
            can_view_password: bool_of(value, "canViewPassword"),
            created: int_of(value, "created"),
            revised: int_of(value, "revised"),
            deleted: int_of(value, "deleted"),
            archived: int_of(value, "archived"),
            fields,
            custom,
            attachments,
            uris,
            totp,
            history,
            passkeys,
        }
    }

    /// A blank item of a type, with the schema's fields.
    pub fn blank(kind: &str, schema: &[(String, bool)]) -> Self {
        Self {
            kind: kind.to_string(),
            can_edit: true,
            can_view_password: true,
            fields: schema
                .iter()
                .filter(|(key, _)| key != "totp")
                .map(|(key, secret)| Field { key: key.clone(), secret: *secret, value: Secret::default() })
                .collect(),
            ..Self::default()
        }
    }

    pub fn is_login(&self) -> bool {
        self.kind == "login"
    }

    /// The items.save arguments.
    pub fn save_args(&self) -> Value {
        let mut fields = serde_json::Map::new();
        for field in &self.fields {
            if !(field.secret && !self.can_view_password) {
                fields.insert(field.key.clone(), Value::String(field.value.as_str().to_string()));
            }
        }
        let custom: Vec<Value> = self
            .custom
            .iter()
            .map(|f| json!({ "type": f.kind, "name": f.name, "value": f.value.as_str() }))
            .collect();
        let mut args = json!({
            "type": self.kind,
            "name": self.name,
            "notes": self.notes.as_str(),
            "folderId": self.folder_id,
            "favorite": self.favorite,
            "reprompt": self.reprompt,
            "fields": fields,
            "customFields": custom,
        });
        if !self.id.is_empty() {
            args["id"] = json!(self.id);
        } else if !self.organization_id.is_empty() {
            args["organizationId"] = json!(self.organization_id);
            args["collectionIds"] = json!(self.collection_ids);
        }
        if self.is_login() {
            let uris: Vec<&String> = self.uris.iter().filter(|u| !u.trim().is_empty()).collect();
            let mut login = json!({ "uris": uris });
            if self.can_view_password {
                login["totp"] = json!(self.totp.as_str());
            }
            args["login"] = login;
        }
        args
    }
}

/// A Send as listed and edited.
#[derive(Debug, Clone, Default)]
pub struct SendDraft {
    pub id: String,
    pub file: bool,
    pub name: String,
    pub notes: String,
    pub text: Secret,
    pub text_hidden: bool,
    pub file_name: String,
    pub file_size: String,
    pub file_path: String,
    pub max_views: String,
    pub access_count: i64,
    pub expiration_date: i64,
    pub deletion_date: i64,
    pub disabled: bool,
    pub hide_email: bool,
    pub has_password: bool,
    pub new_password: Secret,
    pub share_url: Secret,
}

impl SendDraft {
    pub fn parse(value: &Value) -> Self {
        let max = value.get("maxAccessCount").and_then(Value::as_i64);
        Self {
            id: str_of(value, "id"),
            file: str_of(value, "type") == "file",
            name: str_of(value, "name"),
            notes: str_of(value, "notes"),
            text: Secret::new(str_of(value, "text")),
            text_hidden: bool_of(value, "textHidden"),
            file_name: str_of(value, "fileName"),
            file_size: str_of(value, "fileSize"),
            file_path: String::new(),
            max_views: max.map(|m| m.to_string()).unwrap_or_default(),
            access_count: int_of(value, "accessCount"),
            expiration_date: int_of(value, "expirationDate"),
            deletion_date: int_of(value, "deletionDate"),
            disabled: bool_of(value, "disabled"),
            hide_email: bool_of(value, "hideEmail"),
            has_password: bool_of(value, "hasPassword"),
            new_password: Secret::default(),
            share_url: Secret::new(str_of(value, "shareUrl")),
        }
    }

    pub fn new(file: bool) -> Self {
        Self { file, deletion_date: now() + 7 * 86400, ..Self::default() }
    }

    /// The sends.save arguments.
    pub fn save_args(&self) -> Value {
        let mut args = json!({
            "type": if self.file { "file" } else { "text" },
            "name": self.name,
            "notes": self.notes,
            "maxAccessCount": self.max_views.trim().parse::<i64>().unwrap_or(0),
            "expirationDate": self.expiration_date,
            "deletionDate": self.deletion_date,
            "disabled": self.disabled,
            "hideEmail": self.hide_email,
        });
        if !self.id.is_empty() {
            args["id"] = json!(self.id);
        }
        if self.file {
            if self.id.is_empty() {
                args["path"] = json!(self.file_path);
            }
        } else {
            args["text"] = json!(self.text.as_str());
            args["textHidden"] = json!(self.text_hidden);
        }
        if !self.new_password.is_empty() {
            args["password"] = json!(self.new_password.as_str());
        }
        args
    }
}

/// Seconds since 1970.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A timestamp as local date and time.
pub fn format_date(seconds: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(seconds, 0) {
        chrono::LocalResult::Single(date) => date.format("%-d %b %Y, %H:%M").to_string(),
        _ => String::new(),
    }
}
