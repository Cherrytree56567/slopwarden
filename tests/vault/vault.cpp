#include <catch2/catch_test_macros.hpp>
#include <thread>
#include "Vault.h"
#include "support/FakeServer.h"

using namespace ClientWarden;
using namespace ClientWarden::Testing;

namespace {
    /*
     * Owns the "device" (keychain + disk) and the server, so tests can
     * restart the app by building a new Vault over the same state.
    */
    struct Fixture {
        FakeServer server;
        MemorySecretStore secrets;
        MemoryFileStore files;

        std::unique_ptr<Vault> Start() {
            return std::make_unique<Vault>(Vault::Dependencies {
                std::make_unique<SharedSecrets>(secrets),
                std::make_unique<SharedFiles>(files),
                std::make_unique<FakeTransport>(server)
            });
        }

        std::unique_ptr<Vault> LoggedIn() {
            auto vault = Start();
            vault->SetServer(TestUrls());
            REQUIRE(vault->Login(server.email, server.password) == LoginResult::Success);
            return vault;
        }
    };

    template <typename Pred>
    bool Eventually(Pred pred) {
        for (int i = 0; i < 300; ++i) {
            if (pred()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return pred();
    }
}

TEST_CASE("Fresh install starts logged out") {
    Fixture f;
    REQUIRE(f.Start()->State() == AuthState::LoggedOut);
}

TEST_CASE("Login with password") {
    Fixture f;
    auto vault = f.LoggedIn();

    REQUIRE(vault->State() == AuthState::Unlocked);
    REQUIRE(vault->ProfileName() == "Test User");
    REQUIRE(f.secrets.Get("account"));
    REQUIRE(f.secrets.Get("tokens"));
    REQUIRE(f.files.Exists("vault.json"));

    /*
     * The master password hash is only needed during login.
    */
    REQUIRE_FALSE(f.secrets.Get("masterPasswordHash"));
}

TEST_CASE("Login rejects a wrong password") {
    Fixture f;
    auto vault = f.Start();
    vault->SetServer(TestUrls());

    REQUIRE(vault->Login(f.server.email, "wrong") == LoginResult::InvalidCredentials);
    REQUIRE(vault->State() == AuthState::LoggedOut);
}

TEST_CASE("Login normalises the email") {
    Fixture f;
    auto vault = f.Start();
    vault->SetServer(TestUrls());
    REQUIRE(vault->Login("  USER@Example.com ", f.server.password) == LoginResult::Success);
}

TEST_CASE("Login requires a server") {
    Fixture f;
    REQUIRE_THROWS_AS(f.Start()->Login(f.server.email, f.server.password), VaultError);
}

TEST_CASE("Login refuses weak KDF settings from the server") {
    Fixture f;
    f.server.kdf.iterations = 1;
    auto vault = f.Start();
    vault->SetServer(TestUrls());
    REQUIRE(vault->Login(f.server.email, f.server.password) == LoginResult::Failed);
    REQUIRE(f.server.Count(HttpMethod::Post, "/identity/connect/token") == 0);
}

TEST_CASE("Login while offline") {
    Fixture f;
    f.server.online = false;
    auto vault = f.Start();
    vault->SetServer(TestUrls());
    REQUIRE(vault->Login(f.server.email, f.server.password) == LoginResult::Offline);
}

TEST_CASE("Login with TOTP") {
    Fixture f;
    f.server.requireTotp = true;
    auto vault = f.Start();
    vault->SetServer(TestUrls());

    REQUIRE(vault->Login(f.server.email, f.server.password) == LoginResult::NeedsTotp);
    REQUIRE(vault->State() == AuthState::WaitingForTOTP);
    REQUIRE(vault->SubmitCode("000000") == LoginResult::InvalidCredentials);
    REQUIRE(vault->SubmitCode("123456") == LoginResult::Success);
    REQUIRE(vault->State() == AuthState::Unlocked);
}

TEST_CASE("Login with a passkey") {
    Fixture f;
    f.server.requirePasskey = true;
    auto vault = f.Start();
    vault->SetServer(TestUrls());

    REQUIRE(vault->Login(f.server.email, f.server.password) == LoginResult::NeedsPasskey);
    auto request = vault->PendingPasskey();
    REQUIRE(request);
    REQUIRE(request->challenge == "chal-123");
    REQUIRE(request->relyingParty == "vault.example");

    /*
     * Regression: raw authenticator bytes used to go straight into JSON,
     * which throws on anything that isn't valid UTF-8.
    */
    std::vector<uint8_t> binary = { 0xff, 0xfe, 0x00, 0x80 };
    REQUIRE(vault->SubmitPasskey(binary, binary, binary, binary) == LoginResult::Success);

    nlohmann::json assertion = nlohmann::json::parse(f.server.lastPasskeyAssertion);
    REQUIRE(assertion["id"] == "__4AgA");
    REQUIRE(assertion["response"]["signature"] == "__4AgA");
}

TEST_CASE("Login with new device verification") {
    Fixture f;
    f.server.requireDeviceVerification = true;
    auto vault = f.Start();
    vault->SetServer(TestUrls());

    REQUIRE(vault->Login(f.server.email, f.server.password) == LoginResult::NeedsDeviceVerification);
    REQUIRE(vault->SubmitCode("654321") == LoginResult::Success);
}

TEST_CASE("The device id survives logout so the server recognises the device") {
    Fixture f;
    auto vault = f.LoggedIn();
    std::string first = ParseForm(f.server.Last(HttpMethod::Post, "/identity/connect/token")->body)["deviceIdentifier"];
    vault->Logout();

    vault->SetServer(TestUrls());
    REQUIRE(vault->Login(f.server.email, f.server.password) == LoginResult::Success);
    REQUIRE(ParseForm(f.server.Last(HttpMethod::Post, "/identity/connect/token")->body)["deviceIdentifier"] == first);
}

TEST_CASE("Create, save and reload an item") {
    Fixture f;
    auto vault = f.LoggedIn();

    Item login = vault->NewItem(CipherType::Login);
    login.SetName("GitHub");
    login.Set(Fields::Login::Username, "octocat");
    login.Set(Fields::Login::Password, "hunter2");
    login.AddUri("https://github.com");
    REQUIRE(vault->Save(login));

    /*
     * The server only ever sees ciphertext, and the item is readable
     * with the account's user key.
    */
    REQUIRE(login.Id().starts_with("srv-"));
    const nlohmann::json& stored = f.server.ciphers[login.Id()];
    REQUIRE(stored.dump().find("hunter2") == std::string::npos);
    REQUIRE(Item::FromJson(stored, f.server.userKey).Get(Fields::Login::Password) == "hunter2");

    auto reloaded = vault->GetItem(login.Id());
    REQUIRE(reloaded);
    REQUIRE(reloaded->Get(Fields::Login::Username) == "octocat");

    REQUIRE(vault->Query().OfType(CipherType::Login).NameContains("hub").Ids() == std::vector<std::string> { login.Id() });
}

TEST_CASE("Saves include the legacy data blob only for old servers") {
    Fixture f;
    f.server.version = "2026.3.0";
    auto vault = f.LoggedIn();
    REQUIRE(Eventually([&] { return f.server.Count(HttpMethod::Get, "/api/config") > 0; }));

    Item note = vault->NewItem(CipherType::Note);
    vault->Save(note);
    REQUIRE(nlohmann::json::parse(f.server.Last(HttpMethod::Post, "/api/ciphers")->body).contains("data"));
}

TEST_CASE("Lock and unlock") {
    Fixture f;
    auto vault = f.LoggedIn();
    Item note = vault->NewItem(CipherType::Note);
    note.SetName("Diary");
    vault->Save(note);

    vault->Lock();
    REQUIRE(vault->State() == AuthState::Unlockable);
    REQUIRE_THROWS_AS(vault->GetItem(note.Id()), VaultError);
    REQUIRE_THROWS_AS(vault->Query(), VaultError);

    REQUIRE(vault->Unlock("wrong") == UnlockResult::InvalidPassword);
    REQUIRE(vault->State() == AuthState::Unlockable);

    REQUIRE(vault->Unlock(f.server.password) == UnlockResult::Success);
    REQUIRE(vault->GetItem(note.Id())->Name() == "Diary");
}

TEST_CASE("Restarting the app keeps the session but requires unlock") {
    Fixture f;
    std::string id;
    {
        auto vault = f.LoggedIn();
        Item note = vault->NewItem(CipherType::Note);
        vault->Save(note);
        id = note.Id();
    }

    auto vault = f.Start();
    REQUIRE(vault->State() == AuthState::Unlockable);
    REQUIRE(vault->Unlock(f.server.password) == UnlockResult::Success);
    REQUIRE(vault->GetItem(id));
}

TEST_CASE("Unlock works offline") {
    Fixture f;
    { f.LoggedIn(); }
    f.server.online = false;

    auto vault = f.Start();
    REQUIRE(vault->Unlock(f.server.password) == UnlockResult::Success);
}

TEST_CASE("Offline edits are kept and uploaded on the next sync") {
    Fixture f;
    auto vault = f.LoggedIn();

    Item folderless = vault->NewItem(CipherType::Note);
    vault->Save(folderless);

    f.server.online = false;

    Item offline = vault->NewItem(CipherType::Login);
    offline.SetName("Created offline");
    std::string folder = vault->CreateFolder("Offline folder");
    offline.SetFolderId(folder);
    REQUIRE_FALSE(vault->Save(offline));
    REQUIRE(vault->GetItem(offline.Id()));

    REQUIRE_FALSE(vault->Delete(folderless));
    REQUIRE_FALSE(vault->GetItem(folderless.Id()));

    f.server.online = true;
    REQUIRE(vault->Sync());

    /*
     * The offline item was created server-side, the offline folder was
     * created and the item re-pointed at its new id, and the queued
     * delete went through.
    */
    REQUIRE_FALSE(f.server.ciphers.contains(folderless.Id()));
    REQUIRE(f.server.folders.size() == 1);
    std::string serverFolder = f.server.folders.begin()->first;

    auto summaries = vault->Query().OfType(CipherType::Login).Ids();
    REQUIRE(summaries.size() == 1);
    REQUIRE(summaries[0].starts_with("srv-"));
    REQUIRE(vault->GetItem(summaries[0])->FolderId() == serverFolder);
    REQUIRE(f.server.ciphers[summaries[0]]["folderId"] == serverFolder);
}

TEST_CASE("Sync takes newer remote changes and drops remote deletions") {
    Fixture f;
    auto vault = f.LoggedIn();

    Item a = vault->NewItem(CipherType::Note);
    a.SetName("A");
    vault->Save(a);
    Item b = vault->NewItem(CipherType::Note);
    vault->Save(b);

    Item remote = Item::FromJson(f.server.ciphers[a.Id()], f.server.userKey);
    remote.SetName("A (edited elsewhere)");
    nlohmann::json edited = remote.Json();
    edited["revisionDate"] = NowTime(60);
    f.server.ciphers[a.Id()] = edited;
    f.server.ciphers.erase(b.Id());

    REQUIRE(vault->Sync());
    REQUIRE(vault->GetItem(a.Id())->Name() == "A (edited elsewhere)");
    REQUIRE_FALSE(vault->GetItem(b.Id()));
}

TEST_CASE("Expired access tokens are refreshed transparently") {
    Fixture f;
    auto vault = f.LoggedIn();
    f.server.InvalidateAccessToken();

    Item note = vault->NewItem(CipherType::Note);
    REQUIRE(vault->Save(note));
}

TEST_CASE("A revoked refresh token logs out") {
    Fixture f;
    auto vault = f.LoggedIn();
    f.server.InvalidateAccessToken();
    f.server.revokeRefresh = true;

    vault->Sync();
    REQUIRE(Eventually([&] { return vault->State() == AuthState::LoggedOut; }));
}

TEST_CASE("A remote key change logs out") {
    Fixture f;
    auto vault = f.LoggedIn();
    f.server.protectedKey = Crypto::WrapKey(Crypto::SymmetricKey::Generate(), Crypto::StretchMasterKey(f.server.masterKey));

    REQUIRE_FALSE(vault->Sync());
    REQUIRE(Eventually([&] { return vault->State() == AuthState::LoggedOut; }));
}

TEST_CASE("Logout wipes credentials and local data") {
    Fixture f;
    auto vault = f.LoggedIn();
    REQUIRE(vault->EnableBiometrics());
    vault->Icon("https://github.com/login");
    std::string device = std::string(f.secrets.Get("deviceId")->c_str());

    std::vector<AuthState> seen;
    vault->OnStateChange([&](AuthState s) { seen.push_back(s); });
    vault->Logout();

    REQUIRE(vault->State() == AuthState::LoggedOut);
    REQUIRE(seen == std::vector<AuthState> { AuthState::LoggedOut });
    for (const char* key : { "account", "tokens", "internalKey" }) {
        CAPTURE(key);
        REQUIRE_FALSE(f.secrets.Get(key));
    }
    REQUIRE(std::string(f.secrets.Get("deviceId")->c_str()) == device);
    REQUIRE_FALSE(f.files.Exists("vault.json"));
    REQUIRE_FALSE(f.files.Exists("settings.json"));
    REQUIRE(f.Start()->State() == AuthState::LoggedOut);
}

TEST_CASE("Biometric unlock") {
    Fixture f;
    auto vault = f.LoggedIn();
    REQUIRE_FALSE(vault->BiometricsEnabled());
    REQUIRE(vault->EnableBiometrics());
    REQUIRE(vault->BiometricsEnabled());

    vault->Lock();
    REQUIRE(vault->UnlockWithBiometrics() == UnlockResult::Success);

    vault->DisableBiometrics();
    vault->Lock();
    REQUIRE(vault->UnlockWithBiometrics() == UnlockResult::Failed);
}

TEST_CASE("Master password re-prompt") {
    Fixture f;
    auto vault = f.LoggedIn();
    REQUIRE(vault->VerifyMasterPassword(f.server.password));
    REQUIRE_FALSE(vault->VerifyMasterPassword("nope"));
}

TEST_CASE("Auto-lock after inactivity") {
    Fixture f;
    auto vault = f.LoggedIn();
    std::vector<AuthState> seen;
    std::mutex m;
    vault->OnStateChange([&](AuthState s) { std::lock_guard l(m); seen.push_back(s); });

    vault->NoteActivity(std::time(nullptr) - 10000);
    REQUIRE(Eventually([&] { return vault->State() == AuthState::Unlockable; }));
    std::lock_guard l(m);
    REQUIRE(seen == std::vector<AuthState> { AuthState::Unlockable });
}

TEST_CASE("Bin, restore, archive and duplicate") {
    Fixture f;
    auto vault = f.LoggedIn();
    Item item = vault->NewItem(CipherType::Card);
    item.SetName("Visa");
    item.Set(Fields::Card::Number, "4111111111111111");
    vault->Save(item);

    REQUIRE(vault->MoveToBin(item));
    REQUIRE(vault->Query().InBin().Ids() == std::vector<std::string> { item.Id() });
    REQUIRE(f.server.ciphers[item.Id()]["deletedDate"].is_string());

    REQUIRE(vault->Restore(item));
    REQUIRE(vault->Query().InBin().Ids().empty());

    REQUIRE(vault->Archive(item));
    REQUIRE(vault->Query().Archived().Ids() == std::vector<std::string> { item.Id() });
    REQUIRE(vault->Unarchive(item));

    Item copy = vault->Duplicate(item);
    REQUIRE(copy.Id() != item.Id());
    REQUIRE(f.server.ciphers.contains(copy.Id()));
    REQUIRE(vault->GetItem(copy.Id())->Get(Fields::Card::Number) == "4111111111111111");
}

TEST_CASE("Attachments round trip encrypted") {
    Fixture f;
    auto vault = f.LoggedIn();
    Item item = vault->NewItem(CipherType::Note);
    vault->Save(item);

    std::string body = "top secret attachment";
    auto id = vault->AddAttachment(item, "secret.txt", std::span(reinterpret_cast<const uint8_t*>(body.data()), body.size()));
    REQUIRE(id);
    REQUIRE(f.server.blobs[*id].find("top secret") == std::string::npos);
    REQUIRE(item.Attachments().at(0).fileName == "secret.txt");

    REQUIRE(vault->DownloadAttachment(item, *id, "/downloads/secret.txt"));
    REQUIRE(f.files.Read("/downloads/secret.txt") == body);

    REQUIRE(vault->RemoveAttachment(item, *id));
    REQUIRE(item.Attachments().empty());
}

TEST_CASE("Attachments need an item the server knows about") {
    Fixture f;
    auto vault = f.LoggedIn();
    Item unsaved = vault->NewItem(CipherType::Note);
    REQUIRE_THROWS_AS(vault->AddAttachment(unsaved, "x", {}), VaultError);
}

TEST_CASE("Folders") {
    Fixture f;
    auto vault = f.LoggedIn();

    std::string id = vault->CreateFolder("Work");
    REQUIRE(f.server.folders.contains(id));
    REQUIRE(vault->FolderName(id) == "Work");

    REQUIRE(vault->RenameFolder(id, "Office"));
    REQUIRE(vault->Folders().at(0).name == "Office");

    Item item = vault->NewItem(CipherType::Note);
    item.SetFolderId(id);
    vault->Save(item);

    REQUIRE(vault->DeleteFolder(id));
    REQUIRE(vault->Folders().empty());
    REQUIRE_FALSE(vault->GetItem(item.Id())->FolderId());
}

TEST_CASE("Icons are cached by hashed domain") {
    Fixture f;
    auto vault = f.LoggedIn();

    auto path = vault->Icon("https://github.com/login?next=/");
    REQUIRE(path);
    REQUIRE(path->find("github") == std::string::npos);
    REQUIRE(vault->Icon("https://github.com/other") == path);
    REQUIRE(f.server.Count(HttpMethod::Get, "/github.com/icon.png") == 1);

    /*
     * Only the bare hostname ever reaches the icon service.
    */
    vault->Icon("https://evil.com/../../x");
    REQUIRE(f.server.Last(HttpMethod::Get, "/evil.com")->path == "/evil.com/icon.png");
    REQUIRE_FALSE(vault->Icon("javascript:alert(1)"));
    REQUIRE_FALSE(vault->Icon("https://ex ample.com"));
}

TEST_CASE("Keychain entries from the old layout are migrated") {
    Fixture f;
    {
        auto vault = f.LoggedIn();
    }
    nlohmann::json account = nlohmann::json::parse(std::string(f.secrets.Get("account")->c_str()));
    f.secrets.Remove("account");
    f.secrets.Remove("tokens");

    f.secrets.Set("email", f.server.email);
    f.secrets.Set("salt", f.server.email);
    f.secrets.Set("kdfType", "0");
    f.secrets.Set("kdfIterations", std::to_string(f.server.kdf.iterations));
    f.secrets.Set("kdfMemory", "0");
    f.secrets.Set("kdfParallelism", "0");
    f.secrets.Set("vaultURL", "https://vault.example");
    f.secrets.Set("mainURL", "https://vault.example");
    f.secrets.Set("apiURL", "https://api.example");
    f.secrets.Set("iconURL", "https://icons.example");
    f.secrets.Set("wssURL", "wss://notify.example");
    f.secrets.Set("accessString", f.server.accessToken);
    f.secrets.Set("refreshToken", f.server.refreshToken);
    f.secrets.Set("needsRefreshTime", NowTime(3600));

    auto vault = f.Start();
    REQUIRE(vault->State() == AuthState::Unlockable);
    REQUIRE(f.secrets.Get("account"));
    REQUIRE_FALSE(f.secrets.Get("accessString"));
    REQUIRE_FALSE(f.secrets.Get("kdfIterations"));

    REQUIRE(vault->Unlock(f.server.password) == UnlockResult::Success);
    REQUIRE(vault->Sync());
}

TEST_CASE("Settings are clamped and persisted") {
    Fixture f;
    {
        auto vault = f.Start();
        vault->Preferences().SetAutoLockSeconds(1);
        vault->Preferences().SetClipboardClearSeconds(45);
        vault->Preferences().SetAllowScreenshots(true);
    }
    auto vault = f.Start();
    REQUIRE(vault->Preferences().AutoLockSeconds() == 5);
    REQUIRE(vault->Preferences().ClipboardClearSeconds() == 45);
    REQUIRE(vault->Preferences().AllowScreenshots());
}
