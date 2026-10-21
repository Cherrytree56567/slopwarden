#include "Vault.h"

#include <algorithm>
#include <botan/hash.h>
#include <botan/hex.h>

#include "Net/Notifications.h"
#include "Sync/SyncEngine.h"
#include "Util/Util.h"

namespace ClientWarden {
    namespace {
        constexpr auto Tick = std::chrono::seconds(1);
        constexpr std::time_t ConnectivityInterval = 15;
        constexpr const char* LegacyDataCutoff = "2026.6.0";

        int CompareVersions(const std::string& a, const std::string& b) {
            auto parts = [](const std::string& v) {
                std::vector<int> out;
                std::istringstream ss(v);
                for (std::string p; std::getline(ss, p, '.');) {
                    try { out.push_back(std::stoi(p)); } catch (...) { out.push_back(0); }
                }
                return out;
            };
            auto pa = parts(a);
            auto pb = parts(b);
            for (size_t i = 0; i < std::max(pa.size(), pb.size()); ++i) {
                int x = i < pa.size() ? pa[i] : 0;
                int y = i < pb.size() ? pb[i] : 0;
                if (x != y) return x < y ? -1 : 1;
            }
            return 0;
        }

        std::string IdOf(const nlohmann::json& r) {
            auto it = r.find("id");
            return it != r.end() && it->is_string() ? it->get<std::string>() : std::string();
        }

        /*
         * Bare hostname of a URL (icon lookups, passkey relying party). Anything that isn't a plain DNS
         * name is rejected so a crafted URI can't steer the request path.
        */
        std::optional<std::string> HostName(std::string_view url) {
            if (size_t scheme = url.find("://"); scheme != std::string_view::npos) {
                std::string s = ToLower(url.substr(0, scheme));
                if (s != "http" && s != "https") {
                    return std::nullopt;
                }
                url.remove_prefix(scheme + 3);
            } else if (size_t colon = url.find(':'); colon != std::string_view::npos && colon < url.find('/') &&
                (colon + 1 >= url.size() || !std::isdigit(static_cast<unsigned char>(url[colon + 1])))) {
                return std::nullopt;    // mailto:, javascript:, ...
            }
            url = url.substr(0, url.find_first_of("/?#:"));
            if (url.empty() || url.size() > 253 || url.find('.') == std::string_view::npos) {
                return std::nullopt;
            }
            for (unsigned char c : url) {
                if (!std::isalnum(c) && c != '.' && c != '-') {
                    return std::nullopt;
                }
            }
            return ToLower(url);
        }

        void Replace(std::vector<Record>& records, const Record& old, nlohmann::json replacement) {
            auto it = std::find(records.begin(), records.end(), old);
            if (it != records.end()) {
                *it = std::make_shared<const nlohmann::json>(std::move(replacement));
            }
        }
    }

    Vault::Vault(Dependencies deps)
        : secrets(std::move(deps.secrets)),
          files(std::move(deps.files)),
          transport(std::move(deps.transport)),
          api(*transport, DeviceInfo::ForThisPlatform(Session::DeviceId(*secrets))),
          session(*secrets, api),
          store(*files),
          settings(*files),
          generator(PasswordGenerator::FromBundle()) {
        api.SetTokenSource(&session);
        session.OnRevoked([this] { Post([this] { Logout(); }); });
        settings.Load();

        std::optional<Account> account = session.LoadAccount();
        if (account && session.LoadTokens() && store.Load() && !store.Empty()) {
            api.Configure(account->urls);
            state = AuthState::Unlockable;
        } else {
            state = AuthState::LoggedOut;
        }

        worker = std::jthread([this](std::stop_token stop) { BackgroundLoop(stop); });
    }

    Vault::~Vault() {
        worker.request_stop();
        taskCv.notify_all();
        if (worker.joinable()) {
            worker.join();
        }
        StopNotifications();
        session.ClearKeys();
    }

    void Vault::OnStateChange(std::function<void(AuthState)> callback) {
        std::lock_guard lock(observerMutex);
        observer = std::move(callback);
    }

    void Vault::SetState(AuthState next) {
        if (state.exchange(next) == next) {
            return;
        }
        std::function<void(AuthState)> callback;
        {
            std::lock_guard lock(observerMutex);
            callback = observer;
        }
        if (callback) {
            callback(next);
        }
    }

    Crypto::SymmetricKey Vault::UserKey() const {
        return session.UserKey();
    }

    bool Vault::NeedsLegacyData() const {
        std::string version = store.ServerVersion();
        return version.empty() || CompareVersions(version, LegacyDataCutoff) < 0;
    }

    /*
     * Login
    */
    void Vault::SetServer(const ServerUrls& urls) {
        if (!urls.Valid()) {
            throw VaultError("server URLs must start with http:// or https://");
        }
        std::lock_guard lock(authMutex);
        pendingUrls = urls;
        api.Configure(urls);
    }

    LoginResult Vault::Login(std::string_view rawEmail, std::string_view password) {
        std::string email = ToLower(rawEmail);
        while (!email.empty() && std::isspace(static_cast<unsigned char>(email.back()))) email.pop_back();
        while (!email.empty() && std::isspace(static_cast<unsigned char>(email.front()))) email.erase(email.begin());

        {
            std::lock_guard lock(authMutex);
            if (!pendingUrls) {
                throw VaultError("SetServer must be called before Login");
            }
        }

        std::optional<Crypto::KdfParams> kdf = api.PreLogin(email);
        if (!kdf) {
            return api.Online() ? LoginResult::Failed : LoginResult::Offline;
        }

        PendingLogin login { email, *kdf };
        try {
            login.masterKey = Crypto::DeriveMasterKey(password, email, *kdf);
        } catch (const CryptoError& e) {
            Log()->error("Refusing server KDF settings: {}", e.what());
            return LoginResult::Failed;
        }
        login.passwordHash = Crypto::HashMasterPassword(login.masterKey, password);

        TokenResponse token = api.PasswordGrant(email, login.passwordHash);
        {
            std::lock_guard lock(authMutex);
            pending = std::move(login);
        }
        return HandleToken(token);
    }

    LoginResult Vault::SubmitCode(std::string_view code) {
        std::optional<PendingLogin> login;
        {
            std::lock_guard lock(authMutex);
            login = pending;
        }
        if (!login) {
            return LoginResult::Failed;
        }

        TokenResponse token;
        if (State() == AuthState::WaitingForTOTP) {
            token = api.PasswordGrant(login->email, login->passwordHash, TwoFactorToken { TwoFactorProvider::Authenticator, std::string(code) });
        } else if (State() == AuthState::WaitingForDeviceVerif) {
            token = api.PasswordGrant(login->email, login->passwordHash, std::nullopt, std::string(code));
        } else {
            return LoginResult::Failed;
        }
        return HandleToken(token);
    }

    std::optional<PasskeyRequest> Vault::PendingPasskey() const {
        std::lock_guard lock(authMutex);
        return pending ? pending->passkey : std::nullopt;
    }

    LoginResult Vault::SubmitPasskey(std::span<const uint8_t> credentialId, std::span<const uint8_t> authenticatorData,
        std::span<const uint8_t> clientDataJson, std::span<const uint8_t> signature) {
        std::optional<PendingLogin> login;
        {
            std::lock_guard lock(authMutex);
            login = pending;
        }
        if (!login || State() != AuthState::WaitingForPasskey) {
            return LoginResult::Failed;
        }

        auto b64url = [](std::span<const uint8_t> bytes) {
            std::string s = Crypto::Base64Encode(bytes);
            std::replace(s.begin(), s.end(), '+', '-');
            std::replace(s.begin(), s.end(), '/', '_');
            s.erase(std::find(s.begin(), s.end(), '='), s.end());
            return s;
        };

        nlohmann::json assertion = {
            { "id", b64url(credentialId) },
            { "rawId", b64url(credentialId) },
            { "type", "public-key" },
            { "extensions", { { "appid", false } } },
            { "response", {
                { "authenticatorData", b64url(authenticatorData) },
                { "clientDataJson", b64url(clientDataJson) },
                { "signature", b64url(signature) }
            } }
        };
        return HandleToken(api.PasswordGrant(login->email, login->passwordHash, TwoFactorToken { TwoFactorProvider::WebAuthn, assertion.dump() }));
    }

    LoginResult Vault::HandleToken(const TokenResponse& token) {
        using Kind = TokenResponse::Kind;

        switch (token.kind) {
            case Kind::Success:
                return CompleteLogin(token);

            case Kind::TwoFactorRequired: {
                bool webAuthn = std::find(token.providers.begin(), token.providers.end(), TwoFactorProvider::WebAuthn) != token.providers.end();
                bool totp = std::find(token.providers.begin(), token.providers.end(), TwoFactorProvider::Authenticator) != token.providers.end();
                if (totp) {
                    SetState(AuthState::WaitingForTOTP);
                    return LoginResult::NeedsTotp;
                }
                if (webAuthn && !token.webAuthnChallenge.empty()) {
                    {
                        std::lock_guard lock(authMutex);
                        std::string rp = token.webAuthnRelyingParty;
                        if (rp.empty() && pendingUrls) {
                            rp = HostName(pendingUrls->vault).value_or("");
                        }
                        pending->passkey = PasskeyRequest { token.webAuthnChallenge, rp };
                    }
                    SetState(AuthState::WaitingForPasskey);
                    return LoginResult::NeedsPasskey;
                }
                Log()->warn("No supported two-factor provider offered");
                return LoginResult::Failed;
            }

            case Kind::NewDeviceVerification:
                SetState(AuthState::WaitingForDeviceVerif);
                return LoginResult::NeedsDeviceVerification;

            case Kind::InvalidCredentials:
                return LoginResult::InvalidCredentials;

            case Kind::Failed:
                break;
        }
        return api.Online() ? LoginResult::Failed : LoginResult::Offline;
    }

    LoginResult Vault::CompleteLogin(const TokenResponse& token) {
        PendingLogin login;
        ServerUrls urls;
        {
            std::lock_guard lock(authMutex);
            if (!pending || !pendingUrls) {
                return LoginResult::Failed;
            }
            login = std::move(*pending);
            urls = *pendingUrls;
            pending.reset();
        }

        store.Clear();
        if (!session.SetTokens(token) || !session.SaveAccount(Account { login.email, login.kdf, urls })) {
            session.Forget();
            return LoginResult::Failed;
        }

        if (!Sync()) {
            session.Forget();
            store.Clear();
            SetState(AuthState::LoggedOut);
            return LoginResult::Failed;
        }

        if (UnlockWithMasterKey(std::move(login.masterKey)) != UnlockResult::Success) {
            session.Forget();
            store.Clear();
            SetState(AuthState::LoggedOut);
            return LoginResult::Failed;
        }
        return LoginResult::Success;
    }

    /*
     * Lock / unlock
    */
    UnlockResult Vault::UnlockWithMasterKey(Bytes masterKey) {
        std::optional<std::string> protectedKey = store.ProtectedUserKey();
        if (!protectedKey) {
            return UnlockResult::Failed;
        }

        Crypto::SymmetricKey userKey;
        try {
            userKey = Crypto::UnwrapKey(*protectedKey, Crypto::StretchMasterKey(masterKey));
        } catch (const CryptoError&) {
            return UnlockResult::InvalidPassword;
        }

        session.SetKeys(std::move(masterKey), std::move(userKey));
        OnUnlocked();
        return UnlockResult::Success;
    }

    void Vault::OnUnlocked() {
        lastActivity = std::time(nullptr);
        SetState(AuthState::Unlocked);
        StartNotifications();
        RequestSync();
    }

    UnlockResult Vault::Unlock(std::string_view password) {
        if (State() != AuthState::Unlockable) {
            return UnlockResult::Failed;
        }
        std::optional<Account> account = session.LoadAccount();
        if (!account) {
            return UnlockResult::Failed;
        }

        Bytes masterKey;
        try {
            masterKey = Crypto::DeriveMasterKey(password, account->email, account->kdf);
        } catch (const CryptoError& e) {
            Log()->error("Unlock failed: {}", e.what());
            return UnlockResult::Failed;
        }
        return UnlockWithMasterKey(std::move(masterKey));
    }

    UnlockResult Vault::UnlockWithBiometrics() {
        if (State() != AuthState::Unlockable) {
            return UnlockResult::Failed;
        }
        std::optional<Bytes> masterKey = session.LoadBiometricKey();
        if (!masterKey) {
            return UnlockResult::Failed;
        }
        return UnlockWithMasterKey(std::move(*masterKey));
    }

    void Vault::Lock() {
        if (State() != AuthState::Unlocked) {
            return;
        }
        StopNotifications();
        session.ClearKeys();
        lastActivity = 0;
        SetState(AuthState::Unlockable);
    }

    void Vault::Logout() {
        StopNotifications();
        std::lock_guard lock(lifecycleMutex);
        ++epoch;
        session.Forget();
        store.Clear();
        settings.Reset();
        files->RemoveTree("icons");
        files->Remove("cw.log");
        {
            std::lock_guard auth(authMutex);
            pending.reset();
        }
        lastActivity = 0;
        SetState(AuthState::LoggedOut);
    }

    bool Vault::VerifyMasterPassword(std::string_view password) {
        std::optional<Account> account = session.LoadAccount();
        if (!account || !session.HasKeys()) {
            return false;
        }
        try {
            return session.MasterKeyEquals(Crypto::DeriveMasterKey(password, account->email, account->kdf));
        } catch (const CryptoError&) {
            return false;
        }
    }

    bool Vault::EnableBiometrics() {
        return State() == AuthState::Unlocked && session.SaveBiometricKey();
    }

    bool Vault::DisableBiometrics() {
        return session.RemoveBiometricKey();
    }

    bool Vault::BiometricsEnabled() {
        return session.HasBiometricKey();
    }

    void Vault::NoteActivity(std::time_t when) {
        if (State() == AuthState::Unlocked) {
            lastActivity = when;
        }
    }

    /*
     * Sync
    */
    bool Vault::Sync() {
        std::lock_guard serial(syncMutex);
        uint64_t startEpoch;
        {
            std::lock_guard lock(lifecycleMutex);
            startEpoch = epoch;
        }

        for (const auto& id : store.PendingFolderDeletes()) {
            if (api.DeleteFolder(id)) store.ClearPendingFolderDelete(id);
        }
        for (const auto& id : store.PendingCipherDeletes()) {
            if (api.DeleteCipher(id)) store.ClearPendingCipherDelete(id);
        }

        std::optional<nlohmann::json> remote = api.Sync();
        if (!remote || !remote->is_object()) {
            return false;
        }

        /*
         * A different user key means the password or account changed on
         * another device; everything cached here is now stale.
        */
        std::optional<std::string> localKey = store.ProtectedUserKey();
        auto profile = remote->find("profile");
        if (localKey && profile != remote->end() && profile->is_object() && profile->value("key", "") != *localKey) {
            Log()->warn("Account key changed remotely; logging out");
            Post([this] { Logout(); });
            return false;
        }

        VaultStore::Snapshot before = store.Take();
        auto pendingFolders = store.PendingFolderDeletes();
        auto pendingCiphers = store.PendingCipherDeletes();

        MergeResult folders = Merge(before.folders, (*remote)["folders"], { pendingFolders.begin(), pendingFolders.end() });

        std::unordered_map<std::string, std::string> folderIdRemap;
        for (const auto& f : folders.toCreate) {
            if (auto res = api.CreateFolder(f->value("name", ""))) {
                folderIdRemap[IdOf(*f)] = IdOf(*res);
                Replace(folders.merged, f, *res);
            }
        }
        for (const auto& f : folders.toUpdate) {
            if (auto res = api.UpdateFolder(IdOf(*f), f->value("name", ""))) {
                Replace(folders.merged, f, *res);
            }
        }

        /*
         * Ciphers filed under a folder that was just uploaded need its new
         * server-assigned id.
        */
        std::vector<Record> localCiphers = before.ciphers;
        if (!folderIdRemap.empty()) {
            for (auto& c : localCiphers) {
                auto folder = c->find("folderId");
                if (folder != c->end() && folder->is_string() && folderIdRemap.contains(folder->get<std::string>())) {
                    nlohmann::json copy = *c;
                    copy["folderId"] = folderIdRemap[folder->get<std::string>()];
                    c = std::make_shared<const nlohmann::json>(std::move(copy));
                }
            }
        }

        MergeResult ciphers = Merge(localCiphers, (*remote)["ciphers"], { pendingCiphers.begin(), pendingCiphers.end() });
        bool legacy = NeedsLegacyData();
        for (const auto& c : ciphers.toCreate) {
            if (auto res = api.CreateCipher(Item::WireFormat(*c, legacy))) {
                Replace(ciphers.merged, c, *res);
            }
        }
        for (const auto& c : ciphers.toUpdate) {
            if (auto res = api.UpdateCipher(Item::WireFormat(*c, legacy))) {
                Replace(ciphers.merged, c, *res);
            }
        }

        std::lock_guard lock(lifecycleMutex);
        if (epoch != startEpoch) {
            return false;   // logged out while we were talking to the server
        }
        store.ApplySync(before, std::move(*remote), std::move(ciphers.merged), std::move(folders.merged));
        return true;
    }

    void Vault::RequestSync() {
        if (!syncQueued.exchange(true)) {
            Post([this] {
                syncQueued = false;
                Sync();
            });
        }
    }

    /*
     * Items
    */
    std::optional<Item> Vault::GetItem(const std::string& id) const {
        Record record = store.Cipher(id);
        if (!record) {
            return std::nullopt;
        }
        return Item::FromJson(*record, UserKey());
    }

    Item Vault::NewItem(CipherType type) const {
        return Item::Create(type, UserKey());
    }

    ItemQuery Vault::Query() const {
        return ItemQuery(store.Ciphers(), UserKey());
    }

    bool Vault::Save(Item& item) {
        UserKey();  // must be unlocked
        item.Touch();

        Record existing = store.Cipher(item.Id());
        bool isNew = !existing || existing->value("createdOffline", false);

        std::optional<nlohmann::json> res = isNew ? api.CreateCipher(item.ToWire(NeedsLegacyData())) : api.UpdateCipher(item.ToWire(NeedsLegacyData()));
        if (res && IdOf(*res).size()) {
            if (isNew && existing && IdOf(*res) != item.Id()) {
                store.RemoveCipher(item.Id(), false);
            }
            item.Replace(std::move(*res));
            store.PutCipher(item.Json());
            return true;
        }

        nlohmann::json local = item.Json();
        if (isNew) {
            local["createdOffline"] = true;
        }
        item.Replace(local);
        store.PutCipher(std::move(local));
        return false;
    }

    bool Vault::Delete(const Item& item) {
        Record existing = store.Cipher(item.Id());
        if (!existing) {
            return true;
        }
        if (existing->value("createdOffline", false)) {
            store.RemoveCipher(item.Id(), false);
            return true;
        }
        bool ok = api.DeleteCipher(item.Id());
        store.RemoveCipher(item.Id(), !ok);
        return ok;
    }

    bool Vault::CommitStatusChange(Item& item, bool ok) {
        item.Touch();
        store.PutCipher(item.Json());
        if (ok) {
            RequestSync();  // pick up the server's revision date
        }
        return ok;
    }

    bool Vault::MoveToBin(Item& item) {
        item.MarkDeleted(true);
        return CommitStatusChange(item, api.SoftDeleteCipher(item.Id()));
    }

    bool Vault::Restore(Item& item) {
        item.MarkDeleted(false);
        return CommitStatusChange(item, api.RestoreCipher(item.Id()));
    }

    bool Vault::Archive(Item& item) {
        item.MarkArchived(true);
        return CommitStatusChange(item, api.ArchiveCiphers({ item.Id() }));
    }

    bool Vault::Unarchive(Item& item) {
        item.MarkArchived(false);
        return CommitStatusChange(item, api.UnarchiveCiphers({ item.Id() }));
    }

    Item Vault::Duplicate(const Item& item) {
        Item copy = item.Duplicate(UserKey());
        Save(copy);
        return copy;
    }

    std::optional<std::string> Vault::AddAttachment(Item& item, std::string_view fileName, std::span<const uint8_t> content,
        std::function<void(float)> onProgress) {
        Record existing = store.Cipher(item.Id());
        if (!existing || existing->value("createdOffline", false)) {
            throw VaultError("save the item online before adding attachments");
        }

        Crypto::SymmetricKey attachmentKey = Crypto::SymmetricKey::Generate();
        std::string wrappedKey = Crypto::WrapKey(attachmentKey, item.Key());
        std::string encryptedName = Crypto::Encrypt(fileName, item.Key());
        std::vector<uint8_t> encrypted = Crypto::EncryptBuffer(content, attachmentKey);

        auto res = api.UploadAttachment(item.Id(), encryptedName, wrappedKey, encrypted, std::move(onProgress));
        if (!res) {
            return std::nullopt;
        }

        if ((*res)["cipherResponse"].is_object()) {
            item.Replace((*res)["cipherResponse"]);
            store.PutCipher(item.Json());
        }
        return (*res)["attachmentId"].get<std::string>();
    }

    bool Vault::RemoveAttachment(Item& item, const std::string& attachmentId) {
        if (!api.DeleteAttachment(item.Id(), attachmentId)) {
            return false;
        }

        nlohmann::json updated = item.Json();
        if (updated["attachments"].is_array()) {
            auto& list = updated["attachments"];
            list.erase(std::remove_if(list.begin(), list.end(), [&](const nlohmann::json& a) {
                return a.is_object() && a.value("id", "") == attachmentId;
            }), list.end());
        }
        item.Replace(std::move(updated));
        store.PutCipher(item.Json());
        return true;
    }

    bool Vault::DownloadAttachment(const Item& item, const std::string& attachmentId, const std::filesystem::path& destination,
        std::function<void(float)> onProgress) {
        auto download = api.DownloadAttachment(item.Id(), attachmentId, std::move(onProgress));
        if (!download) {
            return false;
        }

        Crypto::SymmetricKey attachmentKey = Crypto::UnwrapKey(download->meta["key"].get<std::string>(), item.Key());
        Bytes plaintext = Crypto::DecryptBuffer(download->content, attachmentKey);
        files->Write(destination, std::span<const uint8_t>(plaintext.data(), plaintext.size()));
        return true;
    }

    /*
     * Folders
    */
    std::vector<FolderInfo> Vault::Folders() const {
        Crypto::SymmetricKey key = UserKey();
        std::vector<FolderInfo> out;
        for (const auto& f : store.Folders()) {
            try {
                out.push_back({ IdOf(*f), Crypto::DecryptString(f->value("name", ""), key) });
            } catch (const CryptoError&) {
                Log()->warn("Skipping undecryptable folder");
            }
        }
        return out;
    }

    std::optional<SecretString> Vault::FolderName(const std::string& id) const {
        Record f = store.Folder(id);
        if (!f) {
            return std::nullopt;
        }
        return Crypto::DecryptString(f->value("name", ""), UserKey());
    }

    std::string Vault::CreateFolder(std::string_view name) {
        std::string encrypted = Crypto::Encrypt(name, UserKey());
        if (auto res = api.CreateFolder(encrypted)) {
            store.PutFolder(*res);
            return IdOf(*res);
        }

        std::string id = NewGuid();
        store.PutFolder({ { "id", id }, { "name", encrypted }, { "object", "folder" }, { "revisionDate", NowTime() }, { "createdOffline", true } });
        return id;
    }

    bool Vault::RenameFolder(const std::string& id, std::string_view name) {
        Record existing = store.Folder(id);
        if (!existing) {
            return false;
        }

        nlohmann::json folder = *existing;
        folder["name"] = Crypto::Encrypt(name, UserKey());
        folder["revisionDate"] = NowTime();

        if (!folder.value("createdOffline", false)) {
            if (auto res = api.UpdateFolder(id, folder["name"])) {
                store.PutFolder(*res);
                return true;
            }
        }
        store.PutFolder(std::move(folder));
        return false;
    }

    bool Vault::DeleteFolder(const std::string& id) {
        Record existing = store.Folder(id);
        if (!existing) {
            return true;
        }

        bool ok = existing->value("createdOffline", false) || api.DeleteFolder(id);
        store.RemoveFolder(id, !ok);

        /*
         * The server moves a deleted folder's items to "no folder"; mirror
         * that locally so they don't point at a missing folder.
        */
        for (const auto& c : store.Ciphers()) {
            auto folder = c->find("folderId");
            if (folder != c->end() && folder->is_string() && folder->get<std::string>() == id) {
                nlohmann::json copy = *c;
                copy["folderId"] = nullptr;
                store.PutCipher(std::move(copy));
            }
        }
        return ok;
    }

    /*
     * Misc
    */
    std::string Vault::ProfileName() const {
        nlohmann::json profile = store.Profile();
        auto name = profile.find("name");
        return name != profile.end() && name->is_string() ? name->get<std::string>() : std::string("Unknown");
    }

    bool Vault::ServerAtLeast(std::string_view version) const {
        std::string current = store.ServerVersion();
        return !current.empty() && CompareVersions(current, std::string(version)) >= 0;
    }

    std::optional<std::string> Vault::Icon(std::string_view url) {
        std::optional<std::string> domain = HostName(url);
        if (!domain) {
            return std::nullopt;
        }

        /*
         * Hash the domain for the cache filename so the cache never
         * builds paths from (attacker-influenced) URL text.
        */
        Bytes digest = Botan::HashFunction::create_or_throw("SHA-256")->process(*domain);
        std::string name = Botan::hex_encode(digest.data(), 16, false);
        std::filesystem::path icon = std::filesystem::path("icons") / (name + ".png");
        std::filesystem::path failed = std::filesystem::path("icons") / (name + ".failed");

        if (files->Exists(icon)) {
            return (files->Root() / icon).string();
        }
        if (files->Exists(failed) || !api.Online()) {
            return std::nullopt;
        }

        std::optional<std::vector<uint8_t>> png = api.Icon(*domain);
        if (!png) {
            files->Write(failed, std::string_view());
            return std::nullopt;
        }
        files->Write(icon, std::span<const uint8_t>(*png));
        return (files->Root() / icon).string();
    }

    void Vault::CopyToClipboard(std::string_view text) {
        clipboard.Copy(text, std::chrono::seconds(settings.ClipboardClearSeconds()));
    }

    /*
     * Background work
     *
     * One worker thread runs posted tasks (sync, lock, logout requested
     * from other threads) and a 1s housekeeping tick. The notification
     * listener has its own thread because it blocks on the socket.
    */
    void Vault::Post(std::function<void()> task) {
        {
            std::lock_guard lock(taskMutex);
            tasks.push_back(std::move(task));
        }
        taskCv.notify_one();
    }

    void Vault::BackgroundLoop(std::stop_token stop) {
        auto nextTick = std::chrono::steady_clock::now() + Tick;

        while (!stop.stop_requested()) {
            std::function<void()> task;
            {
                std::unique_lock lock(taskMutex);
                taskCv.wait_until(lock, stop, nextTick, [&] { return !tasks.empty(); });
                if (stop.stop_requested()) {
                    return;
                }
                if (!tasks.empty()) {
                    task = std::move(tasks.front());
                    tasks.pop_front();
                }
            }

            try {
                if (task) {
                    task();
                }
                if (std::chrono::steady_clock::now() >= nextTick) {
                    nextTick = std::chrono::steady_clock::now() + Tick;
                    Housekeeping();
                }
            } catch (const std::exception& e) {
                Log()->error("Background task failed: {}", e.what());
            }
        }
    }

    void Vault::Housekeeping() {
        std::time_t now = std::time(nullptr);

        if (State() == AuthState::Unlocked) {
            std::time_t last = lastActivity.load();
            if (last != 0 && now - last >= settings.AutoLockSeconds()) {
                Log()->info("Auto-locking after inactivity");
                Lock();
                return;
            }
        }

        if (State() == AuthState::Unlocked || State() == AuthState::Unlockable) {
            if (!api.Online() && now - lastConnectivityCheck >= ConnectivityInterval) {
                lastConnectivityCheck = now;
                if (api.CheckAlive() && State() == AuthState::Unlocked) {
                    RequestSync();
                }
            }

            if (api.Online() && store.ServerVersion().empty()) {
                if (auto config = api.Config(); config && (*config)["version"].is_string()) {
                    store.SetServerVersion((*config)["version"].get<std::string>());
                }
            }
        }
    }

    void Vault::StartNotifications() {
        std::lock_guard lock(notificationMutex);
        if (!notifications.joinable()) {
            notifications = std::jthread([this](std::stop_token stop) { NotificationLoop(stop); });
        }
    }

    void Vault::StopNotifications() {
        std::jthread t;
        {
            std::lock_guard lock(notificationMutex);
            t = std::move(notifications);
        }
        if (t.joinable()) {
            t.request_stop();
            t.join();
        }
    }

    void Vault::NotificationLoop(std::stop_token stop) {
        std::mutex m;
        std::condition_variable_any cv;
        auto backoff = std::chrono::seconds(1);

        while (!stop.stop_requested()) {
            std::optional<std::string> token = session.AccessToken();
            bool connected = token && api.Transport().Listen(*token, [this](std::string_view frame) {
                for (PushType type : ParseNotificationFrame(frame)) {
                    switch (type) {
                        case PushType::LogOut:
                            Post([this] { Logout(); });
                            break;
                        case PushType::SyncOrgKeys:
                        case PushType::SyncSettings:
                            break;
                        default:
                            RequestSync();
                            break;
                    }
                }
            }, stop);

            /*
             * Reconnect with exponential backoff, capped at a minute.
            */
            backoff = connected ? std::chrono::seconds(1) : std::min(backoff * 2, std::chrono::seconds(60));
            std::unique_lock lock(m);
            cv.wait_for(lock, stop, backoff, [] { return false; });
        }
    }
}
