#include "JsonBridge.h"

#include <fstream>
#include <iterator>

#include "items/bank_account_item/bank_account_item.h"
#include "items/card_item/card_item.h"
#include "items/drivers_license_item/drivers_license_item.h"
#include "items/identity_item/identity_item.h"
#include "items/login_item/login_item.h"
#include "items/note_item/note_item.h"
#include "items/passport_item/passport_item.h"
#include "items/ssh_key_item/ssh_key_item.h"
#include "utils/encoding/encoding.h"
#include "utils/logger/logger.h"

namespace clientwarden::bridge {
    namespace {
        /**
         * @brief Names the bridge uses for cipher types.
         */
        constexpr std::pair<CipherType, std::string_view> c_type_names[] = {
            { CipherType::Login, "login" }, { CipherType::Note, "note" }, { CipherType::Card, "card" },
            { CipherType::Identity, "identity" }, { CipherType::SshKey, "sshKey" },
            { CipherType::BankAccount, "bankAccount" }, { CipherType::DriversLicense, "driversLicense" },
            { CipherType::Passport, "passport" }
        };

        SecureString typeName_(CipherType type) {
            for (const std::pair<CipherType, std::string_view>& entry : c_type_names) {
                if (entry.first == type) {
                    return SecureString(entry.second);
                }
            }
            return "generic";
        }

        CipherType typeFromName_(std::string_view name) {
            for (const std::pair<CipherType, std::string_view>& entry : c_type_names) {
                if (entry.second == name) {
                    return entry.first;
                }
            }
            throw VaultError("unknown item type");
        }

        SecureString stateName_(VaultState state) {
            switch (state) {
                case VaultState::Unknown: return "Unknown";
                case VaultState::LoggedOut: return "LoggedOut";
                case VaultState::Unlockable: return "Unlockable";
                case VaultState::WaitingForTotp: return "WaitingForTotp";
                case VaultState::WaitingForDeviceVerification: return "WaitingForDeviceVerification";
                case VaultState::WaitingForPasskey: return "WaitingForPasskey";
                case VaultState::Unlocked: return "Unlocked";
                case VaultState::Failed: return "Failed";
            }
            return "Unknown";
        }

        SecureString loginResultName_(LoginResult result) {
            switch (result) {
                case LoginResult::Success: return "Success";
                case LoginResult::NeedsTotp: return "NeedsTotp";
                case LoginResult::NeedsDeviceVerification: return "NeedsDeviceVerification";
                case LoginResult::NeedsPasskey: return "NeedsPasskey";
                case LoginResult::InvalidCredentials: return "InvalidCredentials";
                case LoginResult::Offline: return "Offline";
                case LoginResult::Failed: return "Failed";
            }
            return "Failed";
        }

        SecureString unlockResultName_(UnlockResult result) {
            switch (result) {
                case UnlockResult::Success: return "Success";
                case UnlockResult::InvalidPassword: return "InvalidPassword";
                case UnlockResult::Failed: return "Failed";
            }
            return "Failed";
        }

        SecureString receiveResultName_(ReceiveResult result) {
            switch (result) {
                case ReceiveResult::Success: return "Success";
                case ReceiveResult::NeedsPassword: return "NeedsPassword";
                case ReceiveResult::WrongPassword: return "WrongPassword";
                case ReceiveResult::NotAvailable: return "NotAvailable";
                case ReceiveResult::InvalidLink: return "InvalidLink";
                case ReceiveResult::Offline: return "Offline";
                case ReceiveResult::Failed: return "Failed";
            }
            return "Failed";
        }

        bool boolAt_(const Json& args, std::string_view key, bool fallback) {
            const Json& value = at(args, key);
            return value.is_boolean() ? value.get<bool>() : fallback;
        }

        std::int64_t intAt_(const Json& args, std::string_view key, std::int64_t fallback) {
            const Json& value = at(args, key);
            return value.is_number_integer() ? value.get<std::int64_t>() : fallback;
        }

        /**
         * @brief A required string argument.
         */
        SecureString require_(const Json& args, std::string_view key) {
            const Json& value = at(args, key);
            if (!value.is_string()) {
                throw VaultError(SecureString("missing argument: ") + SecureString(key));
            }
            return value.get<SecureString>();
        }

        std::vector<SecureString> stringsAt_(const Json& args, std::string_view key) {
            std::vector<SecureString> out;
            for (const Json& value : at(args, key)) {
                if (value.is_string()) {
                    out.push_back(value.get<SecureString>());
                }
            }
            return out;
        }

        /**
         * @brief Loads an item as its concrete class, so typed extras (websites, TOTP) work.
         */
        std::shared_ptr<GenericItem> loadItem_(Orchestrator& orchestrator, std::string_view id) {
            std::optional<CipherType> type = orchestrator.getItemType(id);
            if (!type) {
                throw VaultError("item not found");
            }
            switch (*type) {
                case CipherType::Login: return orchestrator.getItem<LoginItem>(id);
                case CipherType::Card: return orchestrator.getItem<CardItem>(id);
                case CipherType::Identity: return orchestrator.getItem<IdentityItem>(id);
                case CipherType::Note: return orchestrator.getItem<NoteItem>(id);
                case CipherType::SshKey: return orchestrator.getItem<SshKeyItem>(id);
                case CipherType::BankAccount: return orchestrator.getItem<BankAccountItem>(id);
                case CipherType::DriversLicense: return orchestrator.getItem<DriversLicenseItem>(id);
                case CipherType::Passport: return orchestrator.getItem<PassportItem>(id);
                default: return orchestrator.getGenericItem(id);
            }
        }

        /**
         * @brief Starts a new item of a type, personal or in an organisation.
         */
        std::shared_ptr<GenericItem> createItem_(Orchestrator& orchestrator, CipherType type,
                std::optional<SecureString> organization, std::vector<SecureString> collections) {
            if (organization) {
                switch (type) {
                    case CipherType::Login: return orchestrator.createItem<LoginItem>(*organization, collections);
                    case CipherType::Card: return orchestrator.createItem<CardItem>(*organization, collections);
                    case CipherType::Identity: return orchestrator.createItem<IdentityItem>(*organization, collections);
                    case CipherType::SshKey: return orchestrator.createItem<SshKeyItem>(*organization, collections);
                    case CipherType::BankAccount: return orchestrator.createItem<BankAccountItem>(*organization, collections);
                    case CipherType::DriversLicense: return orchestrator.createItem<DriversLicenseItem>(*organization, collections);
                    case CipherType::Passport: return orchestrator.createItem<PassportItem>(*organization, collections);
                    default: return orchestrator.createItem<NoteItem>(*organization, collections);
                }
            }
            switch (type) {
                case CipherType::Login: return orchestrator.createItem<LoginItem>();
                case CipherType::Card: return orchestrator.createItem<CardItem>();
                case CipherType::Identity: return orchestrator.createItem<IdentityItem>();
                case CipherType::SshKey: return orchestrator.createItem<SshKeyItem>();
                case CipherType::BankAccount: return orchestrator.createItem<BankAccountItem>();
                case CipherType::DriversLicense: return orchestrator.createItem<DriversLicenseItem>();
                case CipherType::Passport: return orchestrator.createItem<PassportItem>();
                default: return orchestrator.createItem<NoteItem>();
            }
        }

        /**
         * @brief The full JSON view of an item. Items in "hide passwords" collections never
         * include secret values.
         */
        Json itemJson_(GenericItem& item) {
            bool hide = !item.canViewPassword();
            std::optional<SecureString> folder = item.getFolderId();
            std::optional<SecureString> organization = item.getOrganizationId();

            Json fields = Json::array();
            if (std::optional<TypeSchema> schema = Schema::forType(item.getType())) {
                for (FieldId field : schema->m_fields) {
                    bool secret = Schema::isSecret(field);
                    if (field == fields::login::c_totp) {
                        continue;   // reported under "login"
                    }
                    fields.push_back({ { "key", SecureString(field.m_key) }, { "secret", secret },
                        { "value", hide && secret ? Json() : Json(item.getFieldValue(field.m_key)) } });
                }
            }

            Json custom = Json::array();
            for (const GenericItem::CustomField& field : item.getFields()) {
                bool secret = field.m_type == CustomFieldType::Hidden;
                custom.push_back({ { "type", static_cast<int>(field.m_type) }, { "name", field.m_name },
                    { "value", hide && secret ? Json() : Json(field.m_value) } });
            }

            Json attachments = Json::array();
            for (const GenericItem::Attachment& attachment : item.getAttachments()) {
                attachments.push_back({ { "id", attachment.m_id }, { "name", attachment.m_file_name },
                    { "size", attachment.m_size } });
            }

            Json result = {
                { "id", item.getId() }, { "type", typeName_(item.getType()) }, { "name", item.getName() },
                { "notes", item.getNotes() }, { "folderId", folder ? Json(*folder) : Json() },
                { "favorite", item.getFavorite() }, { "reprompt", item.getReprompt() },
                { "organizationId", organization ? Json(*organization) : Json() },
                { "collectionIds", item.getCollectionIds() }, { "canEdit", item.canEdit() },
                { "canViewPassword", !hide }, { "created", item.getCreationDate() },
                { "revised", item.getRevisionDate() }, { "deleted", item.getDeletionDate() },
                { "archived", item.getArchivedDate() }, { "fields", fields }, { "customFields", custom },
                { "attachments", attachments }
            };

            if (item.getType() == CipherType::Login) {
                LoginItem& login = static_cast<LoginItem&>(item);
                Json history = Json::array();
                if (!hide) {
                    for (const PasswordHistoryEntry& entry : login.getPasswordHistory()) {
                        history.push_back({ { "date", entry.m_last_used }, { "password", entry.m_password } });
                    }
                }
                result["login"] = { { "uris", login.getWebsites() },
                    { "totp", hide ? Json() : Json(login.getTotpSecret()) }, { "passwordHistory", history },
                    { "passkeys", login.getPasskeyCreationDates() } };
            }
            return result;
        }

        /**
         * @brief Applies an items.save payload to an item. Only the keys present change.
         */
        void applyItem_(GenericItem& item, const Json& args) {
            if (at(args, "name").is_string()) item.setName(stringAt(args, "name"));
            if (at(args, "notes").is_string()) item.setNotes(stringAt(args, "notes"));
            if (args.contains("folderId")) {
                SecureString folder = stringAt(args, "folderId");
                folder.empty() ? item.removeFolder() : item.setFolder(folder);
            }
            if (at(args, "favorite").is_boolean()) item.setFavorite(boolAt_(args, "favorite", false));
            if (at(args, "reprompt").is_boolean()) item.setReprompt(boolAt_(args, "reprompt", false));

            const Json& fields = at(args, "fields");
            if (fields.is_object()) {
                for (Json::const_iterator it = fields.begin(); it != fields.end(); ++it) {
                    if (it.value().is_string()) {
                        item.setFieldValue(it.key(), it.value().get_ref<const SecureString&>());
                    }
                }
            }

            if (args.contains("customFields")) {
                /*
                 * Hidden values aren't sent to the UI for "hide passwords" items; keep the stored
                 * ones rather than the blanks that come back.
                */
                std::vector<GenericItem::CustomField> previous = item.getFields();
                bool hide = !item.canViewPassword();
                item.clearFields();
                for (const Json& field : at(args, "customFields")) {
                    CustomFieldType type = static_cast<CustomFieldType>(intAt_(field, "type", 0));
                    SecureString name = stringAt(field, "name");
                    SecureString value = stringAt(field, "value");
                    if (hide && type == CustomFieldType::Hidden && value.empty()) {
                        for (const GenericItem::CustomField& old : previous) {
                            if (old.m_type == type && old.m_name == name) {
                                value = old.m_value;
                            }
                        }
                    }
                    item.addField(type, name, value);
                }
            }

            if (item.getType() == CipherType::Login) {
                LoginItem& login = static_cast<LoginItem&>(item);
                const Json& login_args = at(args, "login");
                if (login_args.contains("uris")) {
                    for (const SecureString& uri : login.getWebsites()) {
                        login.removeWebsite(uri);
                    }
                    for (const SecureString& uri : stringsAt_(login_args, "uris")) {
                        login.addWebsite(uri);
                    }
                }
                if (at(login_args, "totp").is_string()) {
                    login.setTotp(stringAt(login_args, "totp"));
                }
            }
        }

        Json sendJson_(Send& send) {
            std::optional<int> max = send.getMaxAccessCount();
            return { { "id", send.getId() }, { "type", send.getType() == SendType::File ? "file" : "text" },
                { "name", send.getName() }, { "notes", send.getNotes() }, { "text", send.getText() },
                { "textHidden", send.getTextHidden() }, { "fileName", send.getFileName() },
                { "fileSize", send.getFileSize() }, { "maxAccessCount", max ? Json(*max) : Json() },
                { "accessCount", send.getAccessCount() }, { "expirationDate", send.getExpirationDate() },
                { "deletionDate", send.getDeletionDate() }, { "disabled", send.getDisabled() },
                { "hideEmail", send.getHideEmail() }, { "hasPassword", send.hasPassword() },
                { "shareUrl", send.getShareUrl() } };
        }

        std::optional<SecureBytes> readFile_(std::string_view path) {
            std::ifstream in(std::filesystem::path(SecureString(path).c_str()), std::ios::binary);
            if (!in) {
                return std::nullopt;
            }
            return SecureBytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        }
    }

    JsonBridge::JsonBridge(std::function<std::shared_ptr<Vault>()> vault) : m_vault_(std::move(vault)) {
        registerHandlers_();
    }

    void JsonBridge::onEvent(std::function<void(SecureString)> listener) {
        std::lock_guard<std::mutex> lock(m_event_mutex_);
        m_listener_ = std::move(listener);
    }

    SecureString JsonBridge::call(std::string_view method, std::string_view args) {
        try {
            std::shared_ptr<Vault> vault = m_vault_();
            if (!vault) {
                throw VaultError("no vault");
            }

            /*
             * Forward this vault's state changes to the UI (re-registered if the active vault
             * changes).
            */
            {
                std::lock_guard<std::mutex> lock(m_event_mutex_);
                if (m_observed_ != vault) {
                    m_observed_ = vault;
                    vault->onStateChange([this](VaultState state) {
                        std::function<void(SecureString)> listener;
                        {
                            std::lock_guard<std::mutex> inner(m_event_mutex_);
                            listener = m_listener_;
                        }
                        if (listener) {
                            listener(Json({ { "event", "state" }, { "state", stateName_(state) } }).dump());
                        }
                    });
                }
            }

            std::map<SecureString, Handler, std::less<>>::iterator handler = m_handlers_.find(method);
            if (handler == m_handlers_.end()) {
                throw VaultError(SecureString("unknown method: ") + SecureString(method));
            }
            Json parsed = args.empty() ? Json::object() : Json::parse(args.begin(), args.end(), nullptr, false);
            if (parsed.is_discarded()) {
                throw VaultError("arguments are not valid JSON");
            }
            Json result = handler->second(*vault, parsed);
            return Json({ { "ok", true }, { "result", result } }).dump();
        } catch (const std::exception& e) {
            return Json({ { "ok", false }, { "error", SecureString(e.what()) } }).dump();
        }
    }

    void JsonBridge::registerHandlers_() {
        std::map<SecureString, Handler, std::less<>>& h = m_handlers_;

        /*
         * State and authentication
        */
        h["state.get"] = [](Vault& v, const Json&) -> Json {
            return { { "state", stateName_(v.getState()) }, { "failure", v.getFailureReason() },
                { "online", v.getNetwork()->isOnline() } };
        };
        h["auth.setServer"] = [](Vault& v, const Json& a) -> Json {
            v.setServer(ServerUrls { require_(a, "vault"), stringAt(a, "api").empty() ? require_(a, "vault") : stringAt(a, "api"),
                stringAt(a, "icons").empty() ? SecureString("https://icons.bitwarden.net") : stringAt(a, "icons"),
                stringAt(a, "notifications") });
            return nullptr;
        };
        h["auth.login"] = [](Vault& v, const Json& a) -> Json {
            return { { "result", loginResultName_(v.login(require_(a, "email"), require_(a, "password"))) } };
        };
        h["auth.submitCode"] = [](Vault& v, const Json& a) -> Json {
            return { { "result", loginResultName_(v.submitCode(require_(a, "code"))) } };
        };
        h["auth.pendingPasskey"] = [](Vault& v, const Json&) -> Json {
            std::optional<PasskeyRequest> request = v.getPendingPasskey();
            if (!request) {
                return nullptr;
            }
            return { { "challenge", request->m_challenge }, { "relyingParty", request->m_relying_party } };
        };
        h["auth.submitPasskey"] = [](Vault& v, const Json& a) -> Json {
            SecureBytes id = encoding::base64Decode(require_(a, "credentialId"));
            SecureBytes data = encoding::base64Decode(require_(a, "authenticatorData"));
            SecureBytes client = encoding::base64Decode(require_(a, "clientDataJson"));
            SecureBytes signature = encoding::base64Decode(require_(a, "signature"));
            return { { "result", loginResultName_(v.submitPasskey(id, data, client, signature)) } };
        };
        h["auth.unlock"] = [](Vault& v, const Json& a) -> Json {
            return { { "result", unlockResultName_(v.unlock(require_(a, "password"))) } };
        };
        h["auth.unlockBiometric"] = [](Vault& v, const Json&) -> Json {
            return { { "result", unlockResultName_(v.unlockWithBiometrics()) } };
        };
        h["auth.lock"] = [](Vault& v, const Json&) -> Json {
            v.lock();
            return nullptr;
        };
        h["auth.logout"] = [](Vault& v, const Json&) -> Json {
            v.logout();
            return nullptr;
        };
        h["auth.verifyPassword"] = [](Vault& v, const Json& a) -> Json {
            return v.verifyMasterPassword(require_(a, "password"));
        };
        h["auth.biometrics"] = [](Vault& v, const Json& a) -> Json {
            if (at(a, "enabled").is_boolean()) {
                bool ok = boolAt_(a, "enabled", false) ? v.enableBiometrics() : v.disableBiometrics();
                if (!ok) {
                    throw VaultError("couldn't change biometric unlock");
                }
            }
            return v.biometricsEnabled();
        };
        h["activity.note"] = [](Vault& v, const Json&) -> Json {
            v.noteActivity(std::time(nullptr));
            return nullptr;
        };

        /*
         * Vault
        */
        h["vault.sync"] = [](Vault& v, const Json&) -> Json { return v.syncNow(); };
        h["vault.profile"] = [](Vault& v, const Json&) -> Json {
            return { { "name", v.getProfile()->getName() }, { "email", v.getProfile()->getEmail() },
                { "premium", v.getProfile()->getPremium() },
                { "extendedItemTypes", v.getFeatures()->supportsExtendedItemTypes() } };
        };
        h["schema.types"] = [](Vault&, const Json&) -> Json {
            Json types = Json::array();
            for (const TypeSchema& schema : Schema::all()) {
                Json fields = Json::array();
                for (FieldId field : schema.m_fields) {
                    fields.push_back({ { "key", SecureString(field.m_key) }, { "secret", Schema::isSecret(field) } });
                }
                types.push_back({ { "type", typeName_(schema.m_type) }, { "fields", fields } });
            }
            return types;
        };

        /*
         * Items
        */
        h["items.list"] = [](Vault& v, const Json& a) -> Json {
            std::shared_ptr<Orchestrator> orchestrator = v.getOrchestrator();
            CipherQuery query = orchestrator->query();
            SecureString filter = stringAt(a, "filter");
            SecureString value = stringAt(a, "value");
            if (filter == "trash") {
                query.inBin();
            } else if (filter == "archived") {
                query.notInBin().archived();
            } else {
                query.notInBin().notArchived();
                if (filter == "favorites") query.favorites();
                else if (filter == "type") query.ofType(typeFromName_(value));
                else if (filter == "folder") query.inFolder(value);
                else if (filter == "organization") query.inOrganization(value);
                else if (filter == "collection") query.inCollection(value);
                else if (filter == "personal") query.personal();
            }
            if (!stringAt(a, "search").empty()) {
                query.nameContains(stringAt(a, "search"));
            }

            bool icons = boolAt_(a, "icons", false);
            Json items = Json::array();
            for (ItemSummary& summary : query.run()) {
                try {
                    std::shared_ptr<GenericItem> item = loadItem_(*orchestrator, summary.m_id);
                    SecureString subtitle;
                    Json icon;
                    if (summary.m_type == CipherType::Login) {
                        LoginItem& login = static_cast<LoginItem&>(*item);
                        subtitle = login.getUsername();
                        std::vector<SecureString> uris = login.getWebsites();
                        if (icons && !uris.empty()) {
                            if (std::optional<std::filesystem::path> path = orchestrator->getIcon(uris[0])) {
                                icon = SecureString(path->string().c_str());
                            }
                        }
                    } else if (summary.m_type == CipherType::Card) {
                        subtitle = item->getFieldValue("brand");
                    }
                    std::optional<SecureString> organization = item->getOrganizationId();
                    items.push_back({ { "id", summary.m_id }, { "type", typeName_(summary.m_type) },
                        { "name", item->getName() }, { "subtitle", subtitle }, { "icon", icon },
                        { "favorite", item->getFavorite() }, { "reprompt", item->getReprompt() },
                        { "organizationId", organization ? Json(*organization) : Json() } });
                } catch (const VaultError&) {
                    // items this client can't open (e.g. an organisation without its key)
                }
            }
            return items;
        };
        h["items.get"] = [](Vault& v, const Json& a) -> Json {
            return itemJson_(*loadItem_(*v.getOrchestrator(), require_(a, "id")));
        };
        h["items.save"] = [](Vault& v, const Json& a) -> Json {
            std::shared_ptr<Orchestrator> orchestrator = v.getOrchestrator();
            std::shared_ptr<GenericItem> item;
            SecureString id = stringAt(a, "id");
            if (id.empty()) {
                std::optional<SecureString> organization;
                if (!stringAt(a, "organizationId").empty()) {
                    organization = stringAt(a, "organizationId");
                }
                item = createItem_(*orchestrator, typeFromName_(require_(a, "type")), organization,
                        stringsAt_(a, "collectionIds"));
            } else {
                item = loadItem_(*orchestrator, id);
            }
            applyItem_(*item, a);
            bool synced = item->commit();
            return { { "id", item->getId() }, { "synced", synced } };
        };
        h["items.totp"] = [](Vault& v, const Json& a) -> Json {
            std::optional<TotpCode> code = v.getOrchestrator()->getItem<LoginItem>(require_(a, "id"))->getTotp(std::time(nullptr));
            if (!code) {
                return nullptr;
            }
            return { { "code", code->m_code }, { "validUntil", code->m_valid_until }, { "period", code->m_period } };
        };
        h["items.delete"] = [](Vault& v, const Json& a) -> Json { return loadItem_(*v.getOrchestrator(), require_(a, "id"))->remove(); };
        h["items.bin"] = [](Vault& v, const Json& a) -> Json { return loadItem_(*v.getOrchestrator(), require_(a, "id"))->bin(); };
        h["items.restore"] = [](Vault& v, const Json& a) -> Json { return loadItem_(*v.getOrchestrator(), require_(a, "id"))->restore(); };
        h["items.archive"] = [](Vault& v, const Json& a) -> Json { return loadItem_(*v.getOrchestrator(), require_(a, "id"))->archive(); };
        h["items.unarchive"] = [](Vault& v, const Json& a) -> Json { return loadItem_(*v.getOrchestrator(), require_(a, "id"))->unarchive(); };
        h["items.duplicate"] = [](Vault& v, const Json& a) -> Json { return loadItem_(*v.getOrchestrator(), require_(a, "id"))->duplicate(); };
        h["items.share"] = [](Vault& v, const Json& a) -> Json {
            return loadItem_(*v.getOrchestrator(), require_(a, "id"))->shareTo(require_(a, "organizationId"), stringsAt_(a, "collectionIds"));
        };
        h["items.setCollections"] = [](Vault& v, const Json& a) -> Json {
            return loadItem_(*v.getOrchestrator(), require_(a, "id"))->setCollections(stringsAt_(a, "collectionIds"));
        };

        /*
         * Attachments (files are read from and written to local paths)
        */
        h["attachments.add"] = [](Vault& v, const Json& a) -> Json {
            SecureString path = require_(a, "path");
            std::optional<SecureBytes> content = readFile_(path);
            if (!content) {
                throw VaultError("couldn't read the file");
            }
            SecureString name = stringAt(a, "name");
            if (name.empty()) {
                name = SecureString(std::filesystem::path(path.c_str()).filename().string().c_str());
            }
            std::optional<SecureString> id = loadItem_(*v.getOrchestrator(), require_(a, "id"))->addAttachment(name, *content, nullptr);
            return id ? Json(*id) : Json();
        };
        h["attachments.remove"] = [](Vault& v, const Json& a) -> Json {
            return loadItem_(*v.getOrchestrator(), require_(a, "id"))->removeAttachment(require_(a, "attachmentId"));
        };
        h["attachments.download"] = [](Vault& v, const Json& a) -> Json {
            return loadItem_(*v.getOrchestrator(), require_(a, "id"))->downloadAttachment(require_(a, "attachmentId"),
                    std::filesystem::path(require_(a, "path").c_str()), nullptr);
        };

        /*
         * Folders
        */
        h["folders.list"] = [](Vault& v, const Json&) -> Json {
            Json folders = Json::array();
            for (std::shared_ptr<Folder>& folder : v.getOrchestrator()->getFolders()) {
                folders.push_back({ { "id", folder->getId() }, { "name", folder->getName() } });
            }
            return folders;
        };
        h["folders.create"] = [](Vault& v, const Json& a) -> Json {
            std::shared_ptr<Folder> folder = v.getOrchestrator()->createFolder();
            folder->setName(require_(a, "name")).commit();
            return folder->getId();
        };
        h["folders.rename"] = [](Vault& v, const Json& a) -> Json {
            return v.getOrchestrator()->getFolder(require_(a, "id"))->setName(require_(a, "name")).commit();
        };
        h["folders.delete"] = [](Vault& v, const Json& a) -> Json {
            return v.getOrchestrator()->getFolder(require_(a, "id"))->remove();
        };

        /*
         * Organisations and collections
        */
        h["organizations.list"] = [](Vault& v, const Json&) -> Json {
            std::shared_ptr<Organizations> organizations = v.getOrganizations();
            std::vector<CollectionInfo> collections = organizations->getCollections("");
            Json out = Json::array();
            for (const OrganizationInfo& info : organizations->getOrganizations()) {
                Json children = Json::array();
                for (const CollectionInfo& collection : collections) {
                    if (collection.m_organization_id == info.m_id) {
                        children.push_back({ { "id", collection.m_id }, { "name", collection.m_name },
                            { "readOnly", collection.m_read_only }, { "hidePasswords", collection.m_hide_passwords },
                            { "manage", collection.m_manage } });
                    }
                }
                out.push_back({ { "id", info.m_id }, { "name", info.m_name }, { "role", static_cast<int>(info.m_role) },
                    { "enabled", info.m_enabled }, { "canManageCollections", info.m_can_manage_collections },
                    { "keyAvailable", info.m_key_available }, { "collections", children } });
            }
            return out;
        };
        h["collections.create"] = [](Vault& v, const Json& a) -> Json {
            std::optional<SecureString> id = v.getOrganizations()->createCollection(require_(a, "organizationId"), require_(a, "name"));
            return id ? Json(*id) : Json();
        };
        h["collections.rename"] = [](Vault& v, const Json& a) -> Json {
            return v.getOrganizations()->renameCollection(require_(a, "id"), require_(a, "name"));
        };
        h["collections.delete"] = [](Vault& v, const Json& a) -> Json {
            return v.getOrganizations()->deleteCollection(require_(a, "id"));
        };

        /*
         * Send
        */
        h["sends.list"] = [](Vault& v, const Json&) -> Json {
            Json sends = Json::array();
            for (std::shared_ptr<Send>& send : v.getSends()->getSends()) {
                sends.push_back(sendJson_(*send));
            }
            return sends;
        };
        h["sends.save"] = [](Vault& v, const Json& a) -> Json {
            std::shared_ptr<Sends> sends = v.getSends();
            SecureString id = stringAt(a, "id");
            std::shared_ptr<Send> send = id.empty()
                    ? sends->createSend(stringAt(a, "type") == "file" ? SendType::File : SendType::Text)
                    : sends->getSend(id);

            if (at(a, "name").is_string()) send->setName(stringAt(a, "name"));
            if (at(a, "notes").is_string()) send->setNotes(stringAt(a, "notes"));
            if (send->getType() == SendType::Text && at(a, "text").is_string()) {
                send->setText(stringAt(a, "text"), boolAt_(a, "textHidden", false));
            }
            if (send->getType() == SendType::File && id.empty()) {
                SecureString path = require_(a, "path");
                std::optional<SecureBytes> content = readFile_(path);
                if (!content) {
                    throw VaultError("couldn't read the file");
                }
                send->setFile(SecureString(std::filesystem::path(path.c_str()).filename().string().c_str()), *content);
            }
            if (a.contains("maxAccessCount")) {
                std::int64_t max = intAt_(a, "maxAccessCount", 0);
                send->setMaxAccessCount(max > 0 ? std::optional<int>(static_cast<int>(max)) : std::nullopt);
            }
            if (a.contains("expirationDate")) send->setExpirationDate(static_cast<std::time_t>(intAt_(a, "expirationDate", 0)));
            if (a.contains("deletionDate")) send->setDeletionDate(static_cast<std::time_t>(intAt_(a, "deletionDate", 0)));
            if (at(a, "disabled").is_boolean()) send->setDisabled(boolAt_(a, "disabled", false));
            if (at(a, "hideEmail").is_boolean()) send->setHideEmail(boolAt_(a, "hideEmail", false));
            if (at(a, "password").is_string()) send->setPassword(stringAt(a, "password"));

            if (!send->commit()) {
                throw VaultError("couldn't save the Send");
            }
            return sendJson_(*send);
        };
        h["sends.delete"] = [](Vault& v, const Json& a) -> Json { return v.getSends()->getSend(require_(a, "id"))->remove(); };
        h["sends.removePassword"] = [](Vault& v, const Json& a) -> Json {
            return v.getSends()->getSend(require_(a, "id"))->removePassword();
        };
        h["sends.open"] = [this](Vault& v, const Json& a) -> Json {
            ReceivedSend received;
            ReceiveResult result = v.getSends()->open(require_(a, "link"), stringAt(a, "password"), received);
            Json out = { { "result", receiveResultName_(result) } };
            if (result == ReceiveResult::Success) {
                out["send"] = { { "type", received.m_type == SendType::File ? "file" : "text" },
                    { "name", received.m_name }, { "text", received.m_text }, { "textHidden", received.m_text_hidden },
                    { "fileName", received.m_file_name }, { "fileSize", received.m_file_size },
                    { "expirationDate", received.m_expiration_date }, { "creator", received.m_creator } };
                m_received_ = std::move(received);
            }
            return out;
        };
        h["sends.downloadReceived"] = [this](Vault& v, const Json& a) -> Json {
            if (!m_received_) {
                throw VaultError("open a file Send first");
            }
            return v.getSends()->downloadReceivedFile(*m_received_, std::filesystem::path(require_(a, "path").c_str()), nullptr);
        };

        /*
         * Generator, settings and autofill
        */
        h["generator.password"] = [](Vault& v, const Json& a) -> Json {
            return v.getGenerator()->password(PasswordOptions { static_cast<int>(intAt_(a, "length", 16)),
                boolAt_(a, "uppercase", true), boolAt_(a, "numbers", true), boolAt_(a, "symbols", false) });
        };
        h["generator.pin"] = [](Vault& v, const Json& a) -> Json {
            return v.getGenerator()->pin(static_cast<int>(intAt_(a, "digits", 6)));
        };
        h["generator.passphrase"] = [](Vault& v, const Json& a) -> Json {
            return v.getGenerator()->passphrase(static_cast<int>(intAt_(a, "words", 4)), boolAt_(a, "capitalize", true), '-');
        };
        h["settings.get"] = [](Vault& v, const Json&) -> Json {
            std::shared_ptr<Settings> s = v.getSettings();
            return { { "autoLockSeconds", s->getAutoLockSeconds() }, { "clipboardClearSeconds", s->getClipboardClearSeconds() },
                { "allowScreenshots", s->getAllowScreenshots() },
                { "timeoutAction", s->getTimeoutAction() == TimeoutAction::Logout ? "logout" : "lock" },
                { "biometrics", v.biometricsEnabled() } };
        };
        h["settings.set"] = [](Vault& v, const Json& a) -> Json {
            std::shared_ptr<Settings> s = v.getSettings();
            if (a.contains("autoLockSeconds")) s->setAutoLockSeconds(static_cast<int>(intAt_(a, "autoLockSeconds", 300)));
            if (a.contains("clipboardClearSeconds")) s->setClipboardClearSeconds(static_cast<int>(intAt_(a, "clipboardClearSeconds", 30)));
            if (at(a, "allowScreenshots").is_boolean()) s->setAllowScreenshots(boolAt_(a, "allowScreenshots", false));
            if (at(a, "timeoutAction").is_string()) {
                s->setTimeoutAction(stringAt(a, "timeoutAction") == "logout" ? TimeoutAction::Logout : TimeoutAction::Lock);
            }
            return nullptr;
        };
        h["autofill.match"] = [](Vault& v, const Json& a) -> Json {
            return v.getAutoFill()->matchingLogins(require_(a, "url"), boolAt_(a, "passkeysOnly", false));
        };
    }
}
