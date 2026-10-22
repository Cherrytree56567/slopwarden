//! The application: state, messages and how each message changes the state. The views are
//! in views/.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use iced::widget::text_editor;
use iced::{Subscription, Task, event, time};
use serde_json::{Value, json};

use crate::bridge;
use crate::clipboard;
use crate::model::*;

/// Which screen is showing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Screen {
    Starting,
    Login,
    Code,
    Passkey,
    Unlock,
    Vault,
}

/// The vault window's sections.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Section {
    Items,
    Sends,
    Generator,
    Settings,
}

/// Where the account lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    BitwardenUs,
    BitwardenEu,
    SelfHosted,
}

impl std::fmt::Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Server::BitwardenUs => "bitwarden.com",
            Server::BitwardenEu => "bitwarden.eu",
            Server::SelfHosted => "Self-hosted",
        })
    }
}

impl Server {
    pub const ALL: [Server; 3] = [Server::BitwardenUs, Server::BitwardenEu, Server::SelfHosted];
}

/// Password generator modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorKind {
    Password,
    Passphrase,
    Pin,
}

impl std::fmt::Display for GeneratorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GeneratorKind::Password => "Password",
            GeneratorKind::Passphrase => "Passphrase",
            GeneratorKind::Pin => "PIN",
        })
    }
}

impl GeneratorKind {
    pub const ALL: [GeneratorKind; 3] =
        [GeneratorKind::Password, GeneratorKind::Passphrase, GeneratorKind::Pin];
}

/// A labelled number of seconds, for the settings pickers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seconds(pub i64);

impl std::fmt::Display for Seconds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0;
        if s == 0 {
            f.write_str("Never")
        } else if s % 3600 == 0 {
            write!(f, "{} hour{}", s / 3600, if s == 3600 { "" } else { "s" })
        } else if s % 60 == 0 {
            write!(f, "{} minute{}", s / 60, if s == 60 { "" } else { "s" })
        } else {
            write!(f, "{s} seconds")
        }
    }
}

pub const AUTO_LOCK_CHOICES: [Seconds; 7] = [
    Seconds(60),
    Seconds(300),
    Seconds(900),
    Seconds(1800),
    Seconds(3600),
    Seconds(14400),
    Seconds(28800),
];
pub const CLIPBOARD_CHOICES: [Seconds; 5] =
    [Seconds(10), Seconds(20), Seconds(30), Seconds(60), Seconds(120)];

/// Days from now, for Send deletion and expiry dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Days(pub i64);

impl std::fmt::Display for Days {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Never"),
            1 => f.write_str("1 day"),
            n => write!(f, "{n} days"),
        }
    }
}

pub const DELETION_CHOICES: [Days; 6] = [Days(1), Days(2), Days(3), Days(7), Days(14), Days(30)];
pub const EXPIRY_CHOICES: [Days; 6] = [Days(0), Days(1), Days(2), Days(3), Days(7), Days(30)];

/// Modal dialogs.
#[derive(Debug, Clone)]
pub enum Dialog {
    NewFolder(String),
    RenameFolder(String, String),
    DeleteFolder(String),
    NewCollection(String, String),
    RenameCollection(String, String),
    DeleteCollection(String),
    DeleteItem(String),
    /// item, organisation, collections
    Share(String, String, HashSet<String>),
    Collections(String, HashSet<String>),
    /// item id, password, error
    Reprompt(String, Secret, String),
    OpenSend(OpenSend),
    DeleteSend(String),
}

/// The "open a Send link" dialog.
#[derive(Debug, Clone, Default)]
pub struct OpenSend {
    pub link: String,
    pub password: Secret,
    pub needs_password: bool,
    pub message: String,
    pub received: Option<Received>,
    pub revealed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Received {
    pub file: bool,
    pub name: String,
    pub text: Secret,
    pub text_hidden: bool,
    pub file_name: String,
    pub file_size: String,
    pub creator: String,
}

/// A live TOTP code.
#[derive(Debug, Clone)]
pub struct Totp {
    pub code: Secret,
    pub valid_until: i64,
    pub period: i64,
}

#[derive(Debug, Clone)]
pub enum Message {
    // background results and events
    Event(String),
    State(Result<Value, String>),
    Done(Result<Value, String>),
    Activity,
    Tick,
    DismissToast,

    // login
    ServerPicked(Server),
    BaseUrl(String),
    Email(String),
    Password(String),
    LogIn,
    LoginResult(Result<Value, String>),
    Code(String),
    SubmitCode,
    CancelLogin,

    // unlock
    UnlockPassword(String),
    Unlock,
    UnlockResult(Result<Value, String>),
    Lock,
    LogOut,

    // vault loading
    Loaded(&'static str, Result<Value, String>),
    Section(Section),
    Filter(Filter),
    Search(String),
    Items(u64, Result<Value, String>),
    Select(String),
    ItemLoaded(Result<Value, String>),
    TotpLoaded(String, Result<Value, String>),

    // item details
    Copy(String),
    CopyField(usize),
    CopyCustom(usize),
    CopyTotp,
    Reveal(String),
    ToggleHistory,
    New(String),
    Edit,
    CancelEdit,
    Save,
    Saved(Result<Value, String>),
    EditName(String),
    EditField(usize, String),
    GenerateField(usize),
    Generated(usize, Result<Value, String>),
    EditUri(usize, String),
    AddUri,
    RemoveUri(usize),
    EditTotp(String),
    AddCustom(i64),
    EditCustomName(usize, String),
    EditCustomValue(usize, String),
    ToggleCustom(usize, bool),
    RemoveCustom(usize),
    EditFolder(Folder),
    ToggleFavorite,
    ToggleReprompt,
    PickNewItemOrganization(Option<Organization>),
    ToggleNewItemCollection(String, bool),
    ItemAction(&'static str),
    ItemActionDone(&'static str, Result<Value, String>),
    AddAttachment,
    AttachmentPicked(Option<PathBuf>),
    DownloadAttachment(String, String),
    AttachmentTarget(String, Option<PathBuf>),
    RemoveAttachment(String),

    /// A multi-line editor changed: "notes", "field:<index>", "send:text" or "send:notes"
    EditorAction(String, text_editor::Action),

    // dialogs
    OpenDialog(Dialog),
    CloseDialog,
    DialogText(String),
    DialogSecret(String),
    DialogOrganization(Organization),
    DialogCollection(String, bool),
    ConfirmDialog,
    RepromptResult(String, Result<Value, String>),

    // sends
    Sends(Result<Value, String>),
    SelectSend(String),
    NewSend(bool),
    SendName(String),
    SendTextHidden(bool),
    SendMaxViews(String),
    SendDeletion(Days),
    SendExpiry(Days),
    SendDisabled(bool),
    SendHideEmail(bool),
    SendPassword(String),
    SendChooseFile,
    SendFilePicked(Option<PathBuf>),
    SaveSend,
    SendSaved(Result<Value, String>),
    CopySendLink,
    RemoveSendPassword,
    OpenSendResult(Result<Value, String>),
    SaveReceivedFile,
    ReceivedTarget(Option<PathBuf>),
    RevealReceived,
    CopyReceived,

    // generator
    GeneratorKind(GeneratorKind),
    GeneratorLength(u8),
    GeneratorUpper(bool),
    GeneratorNumbers(bool),
    GeneratorSymbols(bool),
    GeneratorWords(u8),
    GeneratorCapitalize(bool),
    GeneratorDigits(u8),
    Generate,
    GeneratorResult(Result<Value, String>),
    CopyGenerated,

    /// Close the app (scripted test runs)
    #[cfg(debug_assertions)]
    Quit,
    #[cfg(debug_assertions)]
    Script(crate::devscript::Step),
    #[cfg(debug_assertions)]
    ScriptShot(String, iced::window::Screenshot),

    // settings
    AutoLock(Seconds),
    TimeoutLogout(bool),
    ClipboardClear(Seconds),
    SyncNow,
}

pub struct App {
    pub screen: Screen,
    pub section: Section,
    pub toast: Option<String>,
    pub busy: bool,

    pub server: Server,
    pub base_url: String,
    pub email: String,
    pub password: Secret,
    pub code: Secret,
    pub code_is_device: bool,
    pub unlock_password: Secret,
    pub account_email: String,

    pub schema: HashMap<String, Vec<(String, bool)>>,
    pub extended_types: bool,
    pub folders: Vec<Folder>,
    pub organizations: Vec<Organization>,
    pub filter: Filter,
    pub search: String,
    pub items: Vec<Summary>,
    list_generation: u64,
    pub selected: Option<String>,
    pub item: Option<Item>,
    pub draft: Option<Item>,
    pub revealed: HashSet<String>,
    pub show_history: bool,
    pub totp: Option<Totp>,
    /// Items whose master-password re-prompt was passed this session
    reprompted: HashSet<String>,
    pub dialog: Option<Dialog>,
    /// Multi-line editors for the item or Send being edited
    pub editors: HashMap<String, text_editor::Content>,

    pub sends: Vec<SendDraft>,
    pub send: Option<SendDraft>,

    pub generator_kind: GeneratorKind,
    pub length: u8,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub words: u8,
    pub capitalize: bool,
    pub digits: u8,
    pub generated: Secret,

    pub auto_lock: Seconds,
    pub timeout_logout: bool,
    pub clipboard_clear: Seconds,

    last_activity: Instant,
    toast_at: Instant,
}

/// A bridge call as a task.
fn call(
    method: &'static str,
    args: Value,
    done: impl FnOnce(Result<Value, String>) -> Message + Send + 'static,
) -> Task<Message> {
    Task::perform(bridge::request(method, args), done)
}

fn pick_file() -> Task<Option<PathBuf>> {
    Task::perform(rfd::AsyncFileDialog::new().pick_file(), |file| {
        file.map(|f| f.path().to_path_buf())
    })
}

fn save_file(name: String) -> Task<Option<PathBuf>> {
    Task::perform(rfd::AsyncFileDialog::new().set_file_name(name).save_file(), |file| {
        file.map(|f| f.path().to_path_buf())
    })
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let app = Self {
            screen: Screen::Starting,
            section: Section::Items,
            toast: None,
            busy: false,
            server: Server::BitwardenUs,
            base_url: String::new(),
            email: String::new(),
            password: Secret::default(),
            code: Secret::default(),
            code_is_device: false,
            unlock_password: Secret::default(),
            account_email: String::new(),
            schema: HashMap::new(),
            extended_types: false,
            folders: Vec::new(),
            organizations: Vec::new(),
            filter: Filter::All,
            search: String::new(),
            items: Vec::new(),
            list_generation: 0,
            selected: None,
            item: None,
            draft: None,
            revealed: HashSet::new(),
            show_history: false,
            totp: None,
            reprompted: HashSet::new(),
            dialog: None,
            editors: HashMap::new(),
            sends: Vec::new(),
            send: None,
            generator_kind: GeneratorKind::Password,
            length: 20,
            uppercase: true,
            numbers: true,
            symbols: true,
            words: 4,
            capitalize: true,
            digits: 6,
            generated: Secret::default(),
            auto_lock: Seconds(300),
            timeout_logout: false,
            clipboard_clear: Seconds(30),
            last_activity: Instant::now() - Duration::from_secs(60),
            toast_at: Instant::now(),
        };
        (app, call("state.get", json!({}), Message::State))
    }

    pub fn title(&self) -> String {
        "ClientWarden".to_string()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subscriptions = vec![
            Subscription::run(bridge::events).map(Message::Event),
            event::listen_with(|event, _status, _window| match event {
                iced::Event::Keyboard(iced::keyboard::Event::KeyPressed { .. })
                | iced::Event::Mouse(iced::mouse::Event::ButtonPressed(_)) => {
                    Some(Message::Activity)
                }
                _ => None,
            }),
        ];
        #[cfg(debug_assertions)]
        if crate::devscript::script().is_some() {
            subscriptions.push(Subscription::run(crate::devscript::steps).map(Message::Script));
        }
        if self.totp.is_some() || self.toast.is_some() {
            subscriptions.push(time::every(Duration::from_secs(1)).map(|_| Message::Tick));
        }
        Subscription::batch(subscriptions)
    }

    fn fail(&mut self, error: String) {
        self.busy = false;
        self.toast = Some(capitalise(&error));
        self.toast_at = Instant::now();
    }

    fn note(&mut self, message: &str) {
        self.toast = Some(message.to_string());
        self.toast_at = Instant::now();
    }

    /// Forgets everything decrypted: on lock, logout or a vault switch.
    fn clear_vault(&mut self) {
        self.items.clear();
        self.folders.clear();
        self.organizations.clear();
        self.selected = None;
        self.item = None;
        self.draft = None;
        self.revealed.clear();
        self.show_history = false;
        self.totp = None;
        self.reprompted.clear();
        self.dialog = None;
        self.editors.clear();
        self.sends.clear();
        self.send = None;
        self.generated = Secret::default();
        self.search.clear();
        self.filter = Filter::All;
        self.section = Section::Items;
    }

    /// Moves to the screen for a vault state.
    fn route(&mut self, state: &str) -> Task<Message> {
        match state {
            "Unlocked" => {
                if self.screen != Screen::Vault {
                    self.screen = Screen::Vault;
                    return self.load_vault();
                }
                Task::none()
            }
            "Unlockable" => {
                self.clear_vault();
                self.screen = Screen::Unlock;
                call("vault.profile", json!({}), |r| Message::Loaded("profile", r))
            }
            "WaitingForTotp" | "WaitingForDeviceVerification" => {
                self.code_is_device = state == "WaitingForDeviceVerification";
                self.screen = Screen::Code;
                Task::none()
            }
            "WaitingForPasskey" => {
                self.screen = Screen::Passkey;
                Task::none()
            }
            _ => {
                self.clear_vault();
                self.screen = Screen::Login;
                Task::none()
            }
        }
    }

    fn load_vault(&mut self) -> Task<Message> {
        Task::batch([
            call("vault.profile", json!({}), |r| Message::Loaded("profile", r)),
            call("schema.types", json!({}), |r| Message::Loaded("schema", r)),
            call("settings.get", json!({}), |r| Message::Loaded("settings", r)),
            self.reload_nav(),
            self.reload_items(),
            call("sends.list", json!({}), Message::Sends),
        ])
    }

    fn reload_nav(&self) -> Task<Message> {
        Task::batch([
            call("folders.list", json!({}), |r| Message::Loaded("folders", r)),
            call("organizations.list", json!({}), |r| Message::Loaded("organizations", r)),
        ])
    }

    fn reload_items(&mut self) -> Task<Message> {
        self.list_generation += 1;
        let generation = self.list_generation;
        call("items.list", self.filter.args(&self.search), move |r| Message::Items(generation, r))
    }

    fn open_item(&mut self, id: String) -> Task<Message> {
        self.selected = Some(id.clone());
        self.draft = None;
        self.revealed.clear();
        self.show_history = false;
        self.totp = None;
        call("items.get", json!({ "id": id }), Message::ItemLoaded)
    }

    fn refresh_totp(&self) -> Task<Message> {
        match &self.item {
            Some(item) if item.is_login() && !item.totp.is_empty() => {
                let id = item.id.clone();
                call("items.totp", json!({ "id": id.clone() }), move |r| Message::TotpLoaded(id, r))
            }
            _ => Task::none(),
        }
    }

    fn after_item_change(&mut self) -> Task<Message> {
        let reload = self.reload_items();
        match self.selected.clone() {
            Some(id) => Task::batch([reload, self.open_item(id)]),
            None => reload,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Event(text) => {
                /*
                 * Events arrive asynchronously and can be stale (login passes through
                 * intermediate states), so ask for the current state rather than trusting it.
                 */
                let event: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                if str_of(&event, "event") == "state" {
                    return call("state.get", json!({}), Message::State);
                }
                Task::none()
            }
            Message::State(Ok(state)) => {
                let name = str_of(&state, "state");
                if name == "Failed" {
                    self.note(&format!("The vault couldn't load: {}", str_of(&state, "failure")));
                }
                self.route(&name)
            }
            Message::State(Err(error)) => {
                self.screen = Screen::Login;
                self.fail(error);
                Task::none()
            }
            Message::Done(result) => {
                self.busy = false;
                if let Err(error) = result {
                    self.fail(error);
                }
                Task::none()
            }
            Message::Activity => {
                if self.screen == Screen::Vault && self.last_activity.elapsed() > Duration::from_secs(10) {
                    self.last_activity = Instant::now();
                    return call("activity.note", json!({}), |_| Message::Tick);
                }
                Task::none()
            }
            Message::Tick => {
                if self.toast_at.elapsed() > Duration::from_secs(5) {
                    self.toast = None;
                }
                match &self.totp {
                    Some(totp) if now() >= totp.valid_until => self.refresh_totp(),
                    _ => Task::none(),
                }
            }
            Message::DismissToast => {
                self.toast = None;
                Task::none()
            }

            // login
            Message::ServerPicked(server) => {
                self.server = server;
                Task::none()
            }
            Message::BaseUrl(url) => {
                self.base_url = url;
                Task::none()
            }
            Message::Email(email) => {
                self.email = email;
                Task::none()
            }
            Message::Password(password) => {
                self.password.set(password);
                Task::none()
            }
            Message::LogIn => {
                if self.email.trim().is_empty() || self.password.is_empty() {
                    self.note("Enter your email and master password");
                    return Task::none();
                }
                let urls = match self.server {
                    Server::BitwardenUs => json!({
                        "vault": "https://vault.bitwarden.com", "api": "https://api.bitwarden.com",
                        "icons": "https://icons.bitwarden.net",
                        "notifications": "https://notifications.bitwarden.com" }),
                    Server::BitwardenEu => json!({
                        "vault": "https://vault.bitwarden.eu", "api": "https://api.bitwarden.eu",
                        "icons": "https://icons.bitwarden.eu",
                        "notifications": "https://notifications.bitwarden.eu" }),
                    Server::SelfHosted => {
                        let base = self.base_url.trim().trim_end_matches('/').to_string();
                        if !base.starts_with("https://") && !base.starts_with("http://") {
                            self.note("Enter your server's address, starting with https://");
                            return Task::none();
                        }
                        json!({ "vault": base, "api": format!("{base}/api"),
                            "icons": format!("{base}/icons"),
                            "notifications": format!("{base}/notifications") })
                    }
                };
                let args = json!({ "email": self.email.trim(), "password": self.password.as_str() });
                self.password = Secret::default();
                self.busy = true;
                Task::perform(
                    async move {
                        bridge::request("auth.setServer", urls).await?;
                        bridge::request("auth.login", args).await
                    },
                    Message::LoginResult,
                )
            }
            Message::LoginResult(result) => {
                self.busy = false;
                match result {
                    Ok(value) => match str_of(&value, "result").as_str() {
                        "Success" => call("state.get", json!({}), Message::State),
                        "NeedsTotp" | "NeedsDeviceVerification" => {
                            self.code_is_device = str_of(&value, "result") == "NeedsDeviceVerification";
                            self.code = Secret::default();
                            self.screen = Screen::Code;
                            Task::none()
                        }
                        "NeedsPasskey" => {
                            self.screen = Screen::Passkey;
                            Task::none()
                        }
                        "InvalidCredentials" => {
                            self.note("Wrong email, password or code");
                            Task::none()
                        }
                        "Offline" => {
                            self.note("Can't reach the server");
                            Task::none()
                        }
                        _ => {
                            self.note("Login failed");
                            Task::none()
                        }
                    },
                    Err(error) => {
                        self.fail(error);
                        Task::none()
                    }
                }
            }
            Message::Code(code) => {
                self.code.set(code);
                Task::none()
            }
            Message::SubmitCode => {
                let args = json!({ "code": self.code.as_str().trim() });
                self.code = Secret::default();
                self.busy = true;
                call("auth.submitCode", args, Message::LoginResult)
            }
            Message::CancelLogin => {
                self.screen = Screen::Login;
                call("auth.logout", json!({}), Message::Done)
            }

            // unlock
            Message::UnlockPassword(password) => {
                self.unlock_password.set(password);
                Task::none()
            }
            Message::Unlock => {
                let args = json!({ "password": self.unlock_password.as_str() });
                self.unlock_password = Secret::default();
                self.busy = true;
                call("auth.unlock", args, Message::UnlockResult)
            }
            Message::UnlockResult(result) => {
                self.busy = false;
                match result {
                    Ok(value) => match str_of(&value, "result").as_str() {
                        "Success" => call("state.get", json!({}), Message::State),
                        "InvalidPassword" => {
                            self.note("Incorrect master password");
                            Task::none()
                        }
                        _ => {
                            self.note("Couldn't unlock the vault");
                            Task::none()
                        }
                    },
                    Err(error) => {
                        self.fail(error);
                        Task::none()
                    }
                }
            }
            Message::Lock => call("auth.lock", json!({}), Message::Done),
            Message::LogOut => call("auth.logout", json!({}), Message::Done),

            // vault loading
            Message::Loaded(what, Ok(value)) => {
                match what {
                    "profile" => {
                        self.account_email = str_of(&value, "email");
                        self.extended_types = bool_of(&value, "extendedItemTypes");
                    }
                    "schema" => {
                        self.schema.clear();
                        for entry in value.as_array().into_iter().flatten() {
                            let fields = entry
                                .get("fields")
                                .and_then(Value::as_array)
                                .map(|list| {
                                    list.iter().map(|f| (str_of(f, "key"), bool_of(f, "secret"))).collect()
                                })
                                .unwrap_or_default();
                            self.schema.insert(str_of(entry, "type"), fields);
                        }
                    }
                    "settings" => {
                        self.auto_lock = Seconds(int_of(&value, "autoLockSeconds"));
                        self.clipboard_clear = Seconds(int_of(&value, "clipboardClearSeconds"));
                        self.timeout_logout = str_of(&value, "timeoutAction") == "logout";
                    }
                    "folders" => {
                        self.folders = value
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(|f| Folder { id: str_of(f, "id"), name: str_of(f, "name") })
                            .collect();
                    }
                    "organizations" => {
                        self.organizations =
                            value.as_array().into_iter().flatten().map(Organization::parse).collect();
                    }
                    "nav" | "synced" => {
                        self.busy = false;
                        return self.nav_changed();
                    }
                    _ => {}
                }
                Task::none()
            }
            Message::Loaded(_, Err(error)) => {
                self.fail(error);
                Task::none()
            }
            Message::Section(section) => {
                self.section = section;
                if section == Section::Sends {
                    return call("sends.list", json!({}), Message::Sends);
                }
                Task::none()
            }
            Message::Filter(filter) => {
                self.filter = filter;
                self.section = Section::Items;
                self.reload_items()
            }
            Message::Search(search) => {
                self.search = search;
                self.reload_items()
            }
            Message::Items(generation, result) => {
                if generation != self.list_generation {
                    return Task::none();
                }
                match result {
                    Ok(mut value) => {
                        self.items = value.as_array().into_iter().flatten().map(Summary::parse).collect();
                        bridge::wipe(&mut value);
                    }
                    Err(error) => self.fail(error),
                }
                Task::none()
            }
            Message::Select(id) => {
                let reprompt = self.items.iter().any(|s| s.id == id && s.reprompt);
                if reprompt && !self.reprompted.contains(&id) {
                    self.dialog = Some(Dialog::Reprompt(id, Secret::default(), String::new()));
                    return Task::none();
                }
                self.open_item(id)
            }
            Message::ItemLoaded(result) => {
                match result {
                    Ok(mut value) => {
                        let item = Item::parse(&value);
                        bridge::wipe(&mut value);
                        if Some(&item.id) == self.selected.as_ref() {
                            self.item = Some(item);
                            return self.refresh_totp();
                        }
                    }
                    Err(error) => self.fail(error),
                }
                Task::none()
            }
            Message::TotpLoaded(id, result) => {
                if self.item.as_ref().map(|i| &i.id) == Some(&id) {
                    self.totp = result.ok().filter(|v| !v.is_null()).map(|mut v| {
                        let totp = Totp {
                            code: Secret::new(str_of(&v, "code")),
                            valid_until: int_of(&v, "validUntil"),
                            period: int_of(&v, "period").max(1),
                        };
                        bridge::wipe(&mut v);
                        totp
                    });
                }
                Task::none()
            }

            // item details
            Message::Copy(text) => {
                self.copy(&text);
                Task::none()
            }
            Message::CopyField(index) => {
                if let Some(value) = self.item.as_ref().and_then(|i| i.fields.get(index)).map(|f| f.value.clone()) {
                    self.copy(value.as_str());
                }
                Task::none()
            }
            Message::CopyCustom(index) => {
                if let Some(value) = self.item.as_ref().and_then(|i| i.custom.get(index)).map(|f| f.value.clone()) {
                    self.copy(value.as_str());
                }
                Task::none()
            }
            Message::CopyTotp => {
                if let Some(code) = self.totp.as_ref().map(|t| t.code.clone()) {
                    self.copy(code.as_str());
                }
                Task::none()
            }
            Message::Reveal(key) => {
                if !self.revealed.remove(&key) {
                    self.revealed.insert(key);
                }
                Task::none()
            }
            Message::ToggleHistory => {
                self.show_history = !self.show_history;
                Task::none()
            }
            Message::New(kind) => {
                let schema = self.schema.get(&kind).cloned().unwrap_or_default();
                let mut item = Item::blank(&kind, &schema);
                match &self.filter {
                    Filter::Folder(id) => item.folder_id = id.clone(),
                    Filter::Favorites => item.favorite = true,
                    Filter::Organization(id) => {
                        item.organization_id = id.clone();
                        if let Some(c) = self.writable_collections(id).first() {
                            item.collection_ids = vec![c.id.clone()];
                        }
                    }
                    Filter::Collection(id) => {
                        if let Some(org) = self.organizations.iter().find(|o| o.collections.iter().any(|c| &c.id == id)) {
                            item.organization_id = org.id.clone();
                            item.collection_ids = vec![id.clone()];
                        }
                    }
                    _ => {}
                }
                if item.is_login() {
                    item.uris.push(String::new());
                }
                self.section = Section::Items;
                self.selected = None;
                self.item = None;
                self.totp = None;
                self.draft = Some(item);
                self.item_editors();
                Task::none()
            }
            Message::Edit => {
                if let Some(item) = &self.item {
                    if item.can_edit {
                        let mut draft = item.clone();
                        if draft.is_login() && draft.uris.is_empty() {
                            draft.uris.push(String::new());
                        }
                        self.draft = Some(draft);
                        self.item_editors();
                    }
                }
                Task::none()
            }
            Message::CancelEdit => {
                self.draft = None;
                Task::none()
            }
            Message::Save => {
                let Some(draft) = &self.draft else { return Task::none() };
                if draft.name.trim().is_empty() {
                    self.note("Give the item a name");
                    return Task::none();
                }
                if draft.id.is_empty() && !draft.organization_id.is_empty() && draft.collection_ids.is_empty() {
                    self.note("Choose at least one collection");
                    return Task::none();
                }
                self.busy = true;
                call("items.save", draft.save_args(), Message::Saved)
            }
            Message::Saved(result) => {
                self.busy = false;
                match result {
                    Ok(value) => {
                        self.draft = None;
                        if !bool_of(&value, "synced") {
                            self.note("Saved on this device; it'll sync when the server is reachable");
                        }
                        self.selected = Some(str_of(&value, "id"));
                        self.after_item_change()
                    }
                    Err(error) => {
                        self.fail(error);
                        Task::none()
                    }
                }
            }
            Message::EditName(name) => {
                if let Some(d) = &mut self.draft {
                    d.name = name;
                }
                Task::none()
            }
            Message::EditField(index, value) => {
                if let Some(field) = self.draft.as_mut().and_then(|d| d.fields.get_mut(index)) {
                    field.value.set(value);
                }
                Task::none()
            }
            Message::GenerateField(index) => {
                call("generator.password", self.generator_args(), move |r| Message::Generated(index, r))
            }
            Message::Generated(index, result) => {
                match result {
                    Ok(Value::String(mut password)) => {
                        if let Some(field) = self.draft.as_mut().and_then(|d| d.fields.get_mut(index)) {
                            field.value.set(std::mem::take(&mut password));
                        }
                    }
                    Ok(_) => {}
                    Err(error) => self.fail(error),
                }
                Task::none()
            }
            Message::EditUri(index, uri) => {
                if let Some(slot) = self.draft.as_mut().and_then(|d| d.uris.get_mut(index)) {
                    *slot = uri;
                }
                Task::none()
            }
            Message::AddUri => {
                if let Some(d) = &mut self.draft {
                    d.uris.push(String::new());
                }
                Task::none()
            }
            Message::RemoveUri(index) => {
                if let Some(d) = &mut self.draft {
                    if index < d.uris.len() {
                        d.uris.remove(index);
                    }
                }
                Task::none()
            }
            Message::EditTotp(totp) => {
                if let Some(d) = &mut self.draft {
                    d.totp.set(totp);
                }
                Task::none()
            }
            Message::AddCustom(kind) => {
                if let Some(d) = &mut self.draft {
                    d.custom.push(CustomField {
                        kind,
                        name: String::new(),
                        value: Secret::new(if kind == 2 { "false" } else { "" }),
                    });
                }
                Task::none()
            }
            Message::EditCustomName(index, name) => {
                if let Some(field) = self.draft.as_mut().and_then(|d| d.custom.get_mut(index)) {
                    field.name = name;
                }
                Task::none()
            }
            Message::EditCustomValue(index, value) => {
                if let Some(field) = self.draft.as_mut().and_then(|d| d.custom.get_mut(index)) {
                    field.value.set(value);
                }
                Task::none()
            }
            Message::ToggleCustom(index, on) => {
                if let Some(field) = self.draft.as_mut().and_then(|d| d.custom.get_mut(index)) {
                    field.value.set(on.to_string());
                }
                Task::none()
            }
            Message::RemoveCustom(index) => {
                if let Some(d) = &mut self.draft {
                    if index < d.custom.len() {
                        d.custom.remove(index);
                    }
                }
                Task::none()
            }
            Message::EditFolder(folder) => {
                if let Some(d) = &mut self.draft {
                    d.folder_id = folder.id;
                }
                Task::none()
            }
            Message::ToggleFavorite => {
                if let Some(d) = &mut self.draft {
                    d.favorite = !d.favorite;
                    return Task::none();
                }
                let Some(item) = &self.item else { return Task::none() };
                if !item.can_edit {
                    return Task::none();
                }
                let args = json!({ "id": item.id, "favorite": !item.favorite });
                call("items.save", args, Message::Saved)
            }
            Message::ToggleReprompt => {
                if let Some(d) = &mut self.draft {
                    d.reprompt = !d.reprompt;
                }
                Task::none()
            }
            Message::PickNewItemOrganization(organization) => {
                if let Some(d) = &mut self.draft {
                    d.collection_ids.clear();
                    d.organization_id = organization.map(|o| o.id).unwrap_or_default();
                    if !d.organization_id.is_empty() {
                        d.folder_id.clear();
                    }
                }
                Task::none()
            }
            Message::ToggleNewItemCollection(id, on) => {
                if let Some(d) = &mut self.draft {
                    d.collection_ids.retain(|c| c != &id);
                    if on {
                        d.collection_ids.push(id);
                    }
                }
                Task::none()
            }
            Message::ItemAction(action) => {
                let Some(item) = &self.item else { return Task::none() };
                let id = item.id.clone();
                call(action, json!({ "id": id }), move |r| Message::ItemActionDone(action, r))
            }
            Message::ItemActionDone(action, result) => match result {
                Ok(value) => {
                    match action {
                        "items.duplicate" => {
                            if let Some(id) = value.as_str() {
                                self.selected = Some(id.to_string());
                            }
                        }
                        "items.delete" => {
                            self.selected = None;
                            self.item = None;
                        }
                        _ => {
                            if value == Value::Bool(false) {
                                self.note("That didn't reach the server; try again when online");
                            }
                        }
                    }
                    self.after_item_change()
                }
                Err(error) => {
                    self.fail(error);
                    Task::none()
                }
            },
            Message::AddAttachment => pick_file().map(Message::AttachmentPicked),
            Message::AttachmentPicked(Some(path)) => {
                let Some(item) = &self.item else { return Task::none() };
                self.busy = true;
                let args = json!({ "id": item.id, "path": path.to_string_lossy() });
                call("attachments.add", args, |r| Message::ItemActionDone("attachments.add", r))
            }
            Message::AttachmentPicked(None) => Task::none(),
            Message::DownloadAttachment(id, name) => {
                save_file(name).map(move |path| Message::AttachmentTarget(id.clone(), path))
            }
            Message::AttachmentTarget(attachment, Some(path)) => {
                let Some(item) = &self.item else { return Task::none() };
                let args = json!({ "id": item.id, "attachmentId": attachment, "path": path.to_string_lossy() });
                call("attachments.download", args, Message::Done)
            }
            Message::AttachmentTarget(_, None) => Task::none(),
            Message::RemoveAttachment(attachment) => {
                let Some(item) = &self.item else { return Task::none() };
                let args = json!({ "id": item.id, "attachmentId": attachment });
                call("attachments.remove", args, |r| Message::ItemActionDone("attachments.remove", r))
            }

            Message::EditorAction(key, action) => {
                let Some(content) = self.editors.get_mut(&key) else { return Task::none() };
                content.perform(action);
                let text = content.text();
                match key.as_str() {
                    "notes" => {
                        if let Some(d) = &mut self.draft {
                            d.notes.set(text);
                        }
                    }
                    "send:text" => return self.edit_send(|s| s.text.set(text)),
                    "send:notes" => return self.edit_send(|s| s.notes = text),
                    other => {
                        let index = other.strip_prefix("field:").and_then(|i| i.parse::<usize>().ok());
                        if let Some(field) = index.and_then(|i| self.draft.as_mut()?.fields.get_mut(i)) {
                            field.value.set(text);
                        }
                    }
                }
                Task::none()
            }

            // dialogs
            Message::OpenDialog(dialog) => {
                self.dialog = Some(dialog);
                Task::none()
            }
            Message::CloseDialog => {
                self.dialog = None;
                Task::none()
            }
            Message::DialogText(text) => {
                match &mut self.dialog {
                    Some(Dialog::NewFolder(name))
                    | Some(Dialog::RenameFolder(_, name))
                    | Some(Dialog::NewCollection(_, name))
                    | Some(Dialog::RenameCollection(_, name)) => *name = text,
                    Some(Dialog::OpenSend(open)) => open.link = text,
                    _ => {}
                }
                Task::none()
            }
            Message::DialogSecret(text) => {
                match &mut self.dialog {
                    Some(Dialog::Reprompt(_, password, _)) => password.set(text),
                    Some(Dialog::OpenSend(open)) => open.password.set(text),
                    _ => {}
                }
                Task::none()
            }
            Message::DialogOrganization(organization) => {
                if let Some(Dialog::Share(_, org, collections)) = &mut self.dialog {
                    *org = organization.id;
                    collections.clear();
                }
                Task::none()
            }
            Message::DialogCollection(id, on) => {
                if let Some(Dialog::Share(_, _, set)) | Some(Dialog::Collections(_, set)) = &mut self.dialog {
                    if on {
                        set.insert(id);
                    } else {
                        set.remove(&id);
                    }
                }
                Task::none()
            }
            Message::ConfirmDialog => self.confirm_dialog(),
            Message::RepromptResult(id, result) => match result {
                Ok(Value::Bool(true)) => {
                    self.dialog = None;
                    self.reprompted.insert(id.clone());
                    self.open_item(id)
                }
                Ok(_) => {
                    if let Some(Dialog::Reprompt(_, _, error)) = &mut self.dialog {
                        *error = "Incorrect master password".to_string();
                    }
                    Task::none()
                }
                Err(error) => {
                    self.fail(error);
                    Task::none()
                }
            },

            // sends
            Message::Sends(result) => {
                match result {
                    Ok(mut value) => {
                        self.sends = value.as_array().into_iter().flatten().map(SendDraft::parse).collect();
                        bridge::wipe(&mut value);
                        if let Some(current) = &self.send {
                            if let Some(fresh) = self.sends.iter().find(|s| s.id == current.id && !current.id.is_empty()) {
                                self.send = Some(fresh.clone());
                            }
                        }
                    }
                    Err(error) => self.fail(error),
                }
                Task::none()
            }
            Message::SelectSend(id) => {
                self.send = self.sends.iter().find(|s| s.id == id).cloned();
                self.send_editors();
                Task::none()
            }
            Message::NewSend(file) => {
                self.send = Some(SendDraft::new(file));
                self.send_editors();
                Task::none()
            }
            Message::SendName(v) => self.edit_send(|s| s.name = v),
            Message::SendTextHidden(v) => self.edit_send(|s| s.text_hidden = v),
            Message::SendMaxViews(v) => {
                self.edit_send(|s| s.max_views = v.chars().filter(char::is_ascii_digit).collect())
            }
            Message::SendDeletion(days) => self.edit_send(|s| s.deletion_date = now() + days.0 * 86400),
            Message::SendExpiry(days) => {
                self.edit_send(|s| s.expiration_date = if days.0 == 0 { 0 } else { now() + days.0 * 86400 })
            }
            Message::SendDisabled(v) => self.edit_send(|s| s.disabled = v),
            Message::SendHideEmail(v) => self.edit_send(|s| s.hide_email = v),
            Message::SendPassword(v) => self.edit_send(|s| s.new_password.set(v)),
            Message::SendChooseFile => pick_file().map(Message::SendFilePicked),
            Message::SendFilePicked(Some(path)) => {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                self.edit_send(|s| {
                    s.file_path = path.to_string_lossy().into_owned();
                    s.file_name = name.clone();
                    if s.name.is_empty() {
                        s.name = name;
                    }
                })
            }
            Message::SendFilePicked(None) => Task::none(),
            Message::SaveSend => {
                let Some(send) = &self.send else { return Task::none() };
                if send.file && send.id.is_empty() && send.file_path.is_empty() {
                    self.note("Choose a file to send");
                    return Task::none();
                }
                self.busy = true;
                call("sends.save", send.save_args(), Message::SendSaved)
            }
            Message::SendSaved(result) => {
                self.busy = false;
                match result {
                    Ok(mut value) => {
                        self.send = Some(SendDraft::parse(&value));
                        bridge::wipe(&mut value);
                        self.send_editors();
                        call("sends.list", json!({}), Message::Sends)
                    }
                    Err(error) => {
                        self.fail(error);
                        Task::none()
                    }
                }
            }
            Message::CopySendLink => {
                if let Some(link) = self.send.as_ref().map(|s| s.share_url.clone()) {
                    self.copy(link.as_str());
                }
                Task::none()
            }
            Message::RemoveSendPassword => {
                let Some(send) = &self.send else { return Task::none() };
                let id = send.id.clone();
                Task::perform(
                    async move {
                        bridge::request("sends.removePassword", json!({ "id": id })).await?;
                        bridge::request("sends.list", json!({})).await
                    },
                    Message::Sends,
                )
            }
            Message::OpenSendResult(result) => {
                self.busy = false;
                let Some(Dialog::OpenSend(open)) = &mut self.dialog else { return Task::none() };
                match result {
                    Ok(mut value) => {
                        match str_of(&value, "result").as_str() {
                            "Success" => {
                                let send = value.get("send").cloned().unwrap_or(Value::Null);
                                open.received = Some(Received {
                                    file: str_of(&send, "type") == "file",
                                    name: str_of(&send, "name"),
                                    text: Secret::new(str_of(&send, "text")),
                                    text_hidden: bool_of(&send, "textHidden"),
                                    file_name: str_of(&send, "fileName"),
                                    file_size: str_of(&send, "fileSize"),
                                    creator: str_of(&send, "creator"),
                                });
                                open.message.clear();
                                let mut send = send;
                                bridge::wipe(&mut send);
                            }
                            "NeedsPassword" => {
                                open.needs_password = true;
                                open.message = "This Send is password protected.".into();
                            }
                            "WrongPassword" => {
                                open.needs_password = true;
                                open.message = "Wrong password.".into();
                            }
                            "NotAvailable" => {
                                open.message = "This Send has expired, been deleted or reached its view limit.".into()
                            }
                            "InvalidLink" => open.message = "That isn't a Send link.".into(),
                            "Offline" => open.message = "Can't reach the server.".into(),
                            _ => open.message = "Couldn't open this Send.".into(),
                        }
                        bridge::wipe(&mut value);
                    }
                    Err(error) => open.message = capitalise(&error),
                }
                Task::none()
            }
            Message::SaveReceivedFile => {
                let name = match &self.dialog {
                    Some(Dialog::OpenSend(OpenSend { received: Some(r), .. })) => r.file_name.clone(),
                    _ => return Task::none(),
                };
                save_file(name).map(Message::ReceivedTarget)
            }
            Message::ReceivedTarget(Some(path)) => {
                call("sends.downloadReceived", json!({ "path": path.to_string_lossy() }), Message::Done)
            }
            Message::ReceivedTarget(None) => Task::none(),
            Message::RevealReceived => {
                if let Some(Dialog::OpenSend(open)) = &mut self.dialog {
                    open.revealed = true;
                }
                Task::none()
            }
            Message::CopyReceived => {
                let text = match &self.dialog {
                    Some(Dialog::OpenSend(OpenSend { received: Some(r), .. })) => r.text.clone(),
                    _ => return Task::none(),
                };
                self.copy(text.as_str());
                Task::none()
            }

            // generator
            Message::GeneratorKind(kind) => {
                self.generator_kind = kind;
                self.update(Message::Generate)
            }
            Message::GeneratorLength(v) => {
                self.length = v;
                self.update(Message::Generate)
            }
            Message::GeneratorUpper(v) => {
                self.uppercase = v;
                self.update(Message::Generate)
            }
            Message::GeneratorNumbers(v) => {
                self.numbers = v;
                self.update(Message::Generate)
            }
            Message::GeneratorSymbols(v) => {
                self.symbols = v;
                self.update(Message::Generate)
            }
            Message::GeneratorWords(v) => {
                self.words = v;
                self.update(Message::Generate)
            }
            Message::GeneratorCapitalize(v) => {
                self.capitalize = v;
                self.update(Message::Generate)
            }
            Message::GeneratorDigits(v) => {
                self.digits = v;
                self.update(Message::Generate)
            }
            Message::Generate => {
                let (method, args) = match self.generator_kind {
                    GeneratorKind::Password => ("generator.password", self.generator_args()),
                    GeneratorKind::Passphrase => (
                        "generator.passphrase",
                        json!({ "words": self.words, "capitalize": self.capitalize }),
                    ),
                    GeneratorKind::Pin => ("generator.pin", json!({ "digits": self.digits })),
                };
                call(method, args, Message::GeneratorResult)
            }
            Message::GeneratorResult(result) => {
                match result {
                    Ok(Value::String(mut text)) => self.generated.set(std::mem::take(&mut text)),
                    Ok(_) => {}
                    Err(error) => self.fail(error),
                }
                Task::none()
            }
            Message::CopyGenerated => {
                let text = self.generated.clone();
                self.copy(text.as_str());
                Task::none()
            }

            #[cfg(debug_assertions)]
            Message::Quit => iced::exit(),
            #[cfg(debug_assertions)]
            Message::Script(step) => self.script_step(step),
            #[cfg(debug_assertions)]
            Message::ScriptShot(name, shot) => {
                crate::devscript::save_png(&name, shot.size.width, shot.size.height, &shot.rgba);
                Task::none()
            }

            // settings
            Message::AutoLock(seconds) => {
                self.auto_lock = seconds;
                call("settings.set", json!({ "autoLockSeconds": seconds.0 }), Message::Done)
            }
            Message::TimeoutLogout(logout) => {
                self.timeout_logout = logout;
                let action = if logout { "logout" } else { "lock" };
                call("settings.set", json!({ "timeoutAction": action }), Message::Done)
            }
            Message::ClipboardClear(seconds) => {
                self.clipboard_clear = seconds;
                call("settings.set", json!({ "clipboardClearSeconds": seconds.0 }), Message::Done)
            }
            Message::SyncNow => {
                self.busy = true;
                Task::perform(bridge::request("vault.sync", json!({})), |r| match r {
                    Ok(Value::Bool(false)) => Message::Done(Err("couldn't sync with the server".into())),
                    other => Message::Loaded("synced", other),
                })
            }
        }
    }

    /// Sets up the multi-line editors for the item draft.
    fn item_editors(&mut self) {
        self.editors.retain(|key, _| key.starts_with("send:"));
        if let Some(draft) = &self.draft {
            self.editors.insert("notes".into(), text_editor::Content::with_text(draft.notes.as_str()));
            for (index, field) in draft.fields.iter().enumerate() {
                if is_multiline(&field.key) {
                    self.editors.insert(format!("field:{index}"), text_editor::Content::with_text(field.value.as_str()));
                }
            }
        }
    }

    /// Sets up the multi-line editors for the Send being edited.
    fn send_editors(&mut self) {
        self.editors.retain(|key, _| !key.starts_with("send:"));
        if let Some(send) = &self.send {
            self.editors.insert("send:text".into(), text_editor::Content::with_text(send.text.as_str()));
            self.editors.insert("send:notes".into(), text_editor::Content::with_text(&send.notes));
        }
    }

    #[cfg(debug_assertions)]
    fn script_step(&mut self, step: crate::devscript::Step) -> Task<Message> {
        use crate::devscript::Step;
        match step {
            Step::Run(message) => self.update(*message),
            Step::Shot(name) => iced::window::latest()
                .and_then(iced::window::screenshot)
                .map(move |shot| Message::ScriptShot(name.clone(), shot)),
            Step::Select(index) => match self.items.get(index) {
                Some(item) => self.update(Message::Select(item.id.clone())),
                None => Task::none(),
            },
            Step::SelectSend(index) => match self.sends.get(index) {
                Some(send) => self.update(Message::SelectSend(send.id.clone())),
                None => Task::none(),
            },
            Step::OpenSelectedSend => {
                let link = self.send.as_ref().map(|s| s.share_url.as_str().to_string()).unwrap_or_default();
                self.update(Message::OpenDialog(Dialog::OpenSend(OpenSend { link, ..OpenSend::default() })))
            }
            Step::Editor(key, text) => {
                self.update(Message::EditorAction(key, crate::devscript::paste(text)))
            }
        }
    }

    fn edit_send(&mut self, f: impl FnOnce(&mut SendDraft)) -> Task<Message> {
        if let Some(send) = &mut self.send {
            f(send);
        }
        Task::none()
    }

    fn copy(&mut self, text: &str) {
        if clipboard::copy(text, self.clipboard_clear.0.max(0) as u64) {
            self.note("Copied");
        } else {
            self.note("Couldn't use the clipboard");
        }
    }

    fn generator_args(&self) -> Value {
        json!({ "length": self.length, "uppercase": self.uppercase,
            "numbers": self.numbers, "symbols": self.symbols })
    }

    /// Collections in an organisation that items can be added to.
    pub fn writable_collections(&self, organization: &str) -> Vec<Collection> {
        self.organizations
            .iter()
            .find(|o| o.id == organization)
            .map(|o| o.collections.iter().filter(|c| !c.read_only).cloned().collect())
            .unwrap_or_default()
    }

    fn confirm_dialog(&mut self) -> Task<Message> {
        let Some(dialog) = self.dialog.clone() else { return Task::none() };
        let reload_nav = |r: Result<Value, String>| match r {
            Ok(_) => Message::Loaded("nav", Ok(Value::Null)),
            Err(e) => Message::Done(Err(e)),
        };
        let task = match dialog {
            Dialog::NewFolder(name) if !name.trim().is_empty() => {
                call("folders.create", json!({ "name": name.trim() }), reload_nav)
            }
            Dialog::RenameFolder(id, name) if !name.trim().is_empty() => {
                call("folders.rename", json!({ "id": id, "name": name.trim() }), reload_nav)
            }
            Dialog::DeleteFolder(id) => {
                if self.filter == Filter::Folder(id.clone()) {
                    self.filter = Filter::All;
                }
                call("folders.delete", json!({ "id": id }), reload_nav)
            }
            Dialog::NewCollection(org, name) if !name.trim().is_empty() => {
                call("collections.create", json!({ "organizationId": org, "name": name.trim() }), reload_nav)
            }
            Dialog::RenameCollection(id, name) if !name.trim().is_empty() => {
                call("collections.rename", json!({ "id": id, "name": name.trim() }), reload_nav)
            }
            Dialog::DeleteCollection(id) => {
                if self.filter == Filter::Collection(id.clone()) {
                    self.filter = Filter::All;
                }
                call("collections.delete", json!({ "id": id }), reload_nav)
            }
            Dialog::DeleteItem(id) => {
                call("items.delete", json!({ "id": id }), |r| Message::ItemActionDone("items.delete", r))
            }
            Dialog::Share(id, org, collections) => {
                if org.is_empty() || collections.is_empty() {
                    self.note("Choose an organisation and at least one collection");
                    return Task::none();
                }
                let ids: Vec<String> = collections.into_iter().collect();
                call("items.share", json!({ "id": id, "organizationId": org, "collectionIds": ids }), |r| {
                    Message::ItemActionDone("items.share", r)
                })
            }
            Dialog::Collections(id, collections) => {
                let ids: Vec<String> = collections.into_iter().collect();
                call("items.setCollections", json!({ "id": id, "collectionIds": ids }), |r| {
                    Message::ItemActionDone("items.setCollections", r)
                })
            }
            Dialog::Reprompt(id, password, _) => {
                let args = json!({ "password": password.as_str() });
                return call("auth.verifyPassword", args, move |r| Message::RepromptResult(id, r));
            }
            Dialog::OpenSend(open) => {
                if open.link.trim().is_empty() {
                    return Task::none();
                }
                self.busy = true;
                let args = json!({ "link": open.link.trim(), "password": open.password.as_str() });
                return call("sends.open", args, Message::OpenSendResult);
            }
            Dialog::DeleteSend(id) => {
                self.send = None;
                Task::perform(
                    async move {
                        bridge::request("sends.delete", json!({ "id": id })).await?;
                        bridge::request("sends.list", json!({})).await
                    },
                    Message::Sends,
                )
            }
            _ => return Task::none(),
        };
        self.dialog = None;
        task
    }

    /// Called after folders/collections change.
    pub fn nav_changed(&mut self) -> Task<Message> {
        Task::batch([self.reload_nav(), self.reload_items()])
    }
}

/// "something failed" -> "Something failed".
fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}
