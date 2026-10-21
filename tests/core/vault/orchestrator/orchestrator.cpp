#include <catch2/catch_test_macros.hpp>

#include "core/support_vault.h"
#include "items/card_item/card_item.h"
#include "items/login_item/login_item.h"
#include "items/note_item/note_item.h"
#include "utils/timestamp/timestamp.h"

using namespace clientwarden;
using namespace clientwarden::testing;

TEST_CASE("Create, commit and reload an item") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    std::shared_ptr<LoginItem> login = orchestrator->createItem<LoginItem>();
    login->setName("GitHub").setUsername("octocat").setPassword("hunter2").addWebsite("https://github.com");
    REQUIRE(login->commit());

    /*
     * The server only ever sees ciphertext readable with the account's user key.
    */
    REQUIRE(login->getId().starts_with("srv-"));
    Json stored = fixture.m_server->m_ciphers[login->getId()];
    REQUIRE(stored.dump().find("hunter2") == SecureString::npos);

    std::shared_ptr<LoginItem> reloaded = orchestrator->getItem<LoginItem>(login->getId());
    REQUIRE(reloaded->getUsername() == "octocat");
    REQUIRE(reloaded->getPassword() == "hunter2");
    REQUIRE(orchestrator->query().ofType(CipherType::Login).nameContains("hub").ids()
        == std::vector<SecureString> { login->getId() });
}

TEST_CASE("Loading an item as the wrong type is refused") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<NoteItem> note = vault->getOrchestrator()->createItem<NoteItem>();
    note->commit();

    REQUIRE_THROWS_AS(vault->getOrchestrator()->getItem<LoginItem>(note->getId()), VaultError);
    REQUIRE_THROWS_AS(vault->getOrchestrator()->getItem<NoteItem>("missing"), VaultError);
    REQUIRE(vault->getOrchestrator()->getGenericItem(note->getId())->getType() == CipherType::Note);
}

TEST_CASE("Offline edits are kept and uploaded on the next sync") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    std::shared_ptr<NoteItem> doomed = orchestrator->createItem<NoteItem>();
    doomed->commit();

    fixture.m_server->m_online = false;

    std::shared_ptr<Folder> folder = orchestrator->createFolder();
    REQUIRE_FALSE(folder->setName("Offline folder").commit());

    std::shared_ptr<LoginItem> offline = orchestrator->createItem<LoginItem>();
    REQUIRE_FALSE(offline->setName("Created offline").setFolder(folder->getId()).commit());
    REQUIRE(orchestrator->hasItem(offline->getId()));

    REQUIRE_FALSE(doomed->remove());
    REQUIRE_FALSE(orchestrator->hasItem(doomed->getId()));

    fixture.m_server->m_online = true;
    REQUIRE(vault->syncNow());

    /*
     * The offline item and folder were created server-side, the item re-pointed at the
     * folder's new id, and the queued delete went through.
    */
    REQUIRE_FALSE(fixture.m_server->m_ciphers.contains(doomed->getId()));
    REQUIRE(fixture.m_server->m_folders.size() == 1);
    SecureString server_folder = fixture.m_server->m_folders.begin()->first;

    std::vector<SecureString> logins = orchestrator->query().ofType(CipherType::Login).ids();
    REQUIRE(logins.size() == 1);
    REQUIRE(logins[0].starts_with("srv-"));
    REQUIRE(orchestrator->getItem<LoginItem>(logins[0])->getFolderId() == server_folder);
    REQUIRE(fixture.m_server->m_ciphers[logins[0]]["folderId"] == server_folder);
}

TEST_CASE("Sync takes newer remote changes and drops remote deletions") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    std::shared_ptr<NoteItem> a = orchestrator->createItem<NoteItem>();
    a->setName("A").commit();
    std::shared_ptr<NoteItem> b = orchestrator->createItem<NoteItem>();
    b->commit();

    /*
     * Edit A "on another device": decrypt with the server's copy of the user key.
    */
    Json remote = fixture.m_server->m_ciphers[a->getId()];
    SymmetricKey item_key = fixture.m_server->m_crypto.unwrapKey(stringAt(remote, "key"), fixture.m_server->m_user_key);
    remote["name"] = fixture.m_server->m_crypto.encryptText("A (edited elsewhere)", item_key);
    remote["revisionDate"] = timestamp::now(60);
    fixture.m_server->m_ciphers[a->getId()] = remote;
    fixture.m_server->m_ciphers.erase(b->getId());

    REQUIRE(vault->syncNow());
    REQUIRE(orchestrator->getItem<NoteItem>(a->getId())->getName() == "A (edited elsewhere)");
    REQUIRE_FALSE(orchestrator->hasItem(b->getId()));
}

TEST_CASE("Bin, restore, archive and duplicate") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    std::shared_ptr<CardItem> card = orchestrator->createItem<CardItem>();
    card->setName("Visa").setNumber("4111111111111111").commit();

    REQUIRE(card->bin());
    REQUIRE(orchestrator->query().inBin().ids() == std::vector<SecureString> { card->getId() });
    REQUIRE(fixture.m_server->m_ciphers[card->getId()]["deletedDate"].is_string());

    REQUIRE(card->restore());
    REQUIRE(orchestrator->query().inBin().ids().empty());

    REQUIRE(card->archive());
    REQUIRE(orchestrator->query().archived().ids() == std::vector<SecureString> { card->getId() });
    REQUIRE(card->unarchive());

    SecureString copy = card->duplicate();
    REQUIRE(copy != card->getId());
    REQUIRE(fixture.m_server->m_ciphers.contains(copy));
    REQUIRE(orchestrator->getItem<CardItem>(copy)->getNumber() == "4111111111111111");
}

TEST_CASE("Attachments round trip encrypted") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<NoteItem> note = vault->getOrchestrator()->createItem<NoteItem>();
    note->commit();

    std::string_view body = "top secret attachment";
    std::optional<SecureString> id = note->addAttachment("secret.txt", encoding::bytesOf(body), nullptr);
    REQUIRE(id);
    SecureBytes blob = fixture.m_server->m_blobs[*id];
    REQUIRE(encoding::textOf(blob).find("top secret") == std::string_view::npos);
    REQUIRE(note->getAttachments().at(0).m_file_name == "secret.txt");

    REQUIRE(note->downloadAttachment(*id, "/downloads/secret.txt", nullptr));
    std::optional<SecureBytes> written = fixture.m_files->read("/downloads/secret.txt");
    REQUIRE(written);
    REQUIRE(encoding::textOf(*written) == body);

    REQUIRE(note->removeAttachment(*id));
    REQUIRE(note->getAttachments().empty());
}

TEST_CASE("Attachments need an item the server knows about") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<NoteItem> unsaved = vault->getOrchestrator()->createItem<NoteItem>();
    REQUIRE_THROWS_AS(unsaved->addAttachment("x", std::span<const uint8_t>(), nullptr), VaultError);
}

TEST_CASE("Folders") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    std::shared_ptr<Folder> folder = orchestrator->createFolder();
    REQUIRE(folder->setName("Work").commit());
    REQUIRE(fixture.m_server->m_folders.contains(folder->getId()));
    REQUIRE(orchestrator->getFolder(folder->getId())->getName() == "Work");

    REQUIRE(folder->setName("Office").commit());
    REQUIRE(orchestrator->getFolders().at(0)->getName() == "Office");

    std::shared_ptr<NoteItem> note = orchestrator->createItem<NoteItem>();
    note->setFolder(folder->getId()).commit();

    REQUIRE(folder->remove());
    REQUIRE(orchestrator->getFolders().empty());
    REQUIRE_FALSE(orchestrator->getItem<NoteItem>(note->getId())->getFolderId());
}

TEST_CASE("Icons are cached under a hash of the domain") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    std::optional<std::filesystem::path> path = orchestrator->getIcon("https://github.com/login?next=/");
    REQUIRE(path);
    REQUIRE(path->native().find("github") == SecureString::npos);
    REQUIRE(orchestrator->getIcon("https://github.com/other") == path);
    REQUIRE(fixture.m_server->count(HttpMethod::Get, "/github.com/icon.png") == 1);
}

TEST_CASE("hostName only accepts plain DNS names") {
    REQUIRE(Orchestrator::hostName("https://GitHub.com/login") == "github.com");
    REQUIRE(Orchestrator::hostName("github.com:8443/x") == "github.com");
    REQUIRE(Orchestrator::hostName("https://evil.com/../../x") == "evil.com");
    REQUIRE_FALSE(Orchestrator::hostName("javascript:alert(1)"));
    REQUIRE_FALSE(Orchestrator::hostName("ftp://example.com"));
    REQUIRE_FALSE(Orchestrator::hostName("https://ex ample.com"));
    REQUIRE_FALSE(Orchestrator::hostName("localhost"));
}

TEST_CASE("Organisation items are reported, not mistaken for tampering") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    Json org = { { "id", "org-cipher" }, { "type", 2 }, { "organizationId", "org-1" },
        { "key", Crypto().wrapKey(SymmetricKey::generate(), SymmetricKey::generate()) }, { "revisionDate", timestamp::now() } };
    fixture.m_server->m_ciphers["org-cipher"] = org;
    REQUIRE(vault->syncNow());

    REQUIRE_THROWS_AS(vault->getOrchestrator()->getItem<NoteItem>("org-cipher"), VaultError);
    REQUIRE(vault->getState() == VaultState::Unlocked);
}

TEST_CASE("Item types are known without decrypting") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<CardItem> card = vault->getOrchestrator()->createItem<CardItem>();
    card->commit();

    REQUIRE(vault->getOrchestrator()->getItemType(card->getId()) == CipherType::Card);
    REQUIRE_FALSE(vault->getOrchestrator()->getItemType("missing"));
}

TEST_CASE("Creating an item in an organisation") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString collection = fixture.m_server->addCollection(org, "Shared", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    std::shared_ptr<LoginItem> login = orchestrator->createItem<LoginItem>(org, { collection });
    login->setName("Team account").setPassword("shared-secret");
    REQUIRE(login->commit());

    /*
     * The server stores it in the organisation, encrypted under the organisation key.
    */
    Json stored = fixture.m_server->m_ciphers[login->getId()];
    REQUIRE(stored["organizationId"] == org);
    REQUIRE(stored["collectionIds"][0] == collection);
    SymmetricKey item_key = Crypto().unwrapKey(stringAt(stored, "key"), fixture.m_server->organizationKey(org));
    REQUIRE(Crypto().decryptText(stringAt(stored["login"], "password"), item_key) == "shared-secret");

    REQUIRE(orchestrator->getItem<LoginItem>(login->getId())->getPassword() == "shared-secret");
    REQUIRE(orchestrator->query().inOrganization(org).nameContains("team").ids()
            == std::vector<SecureString> { login->getId() });
    REQUIRE(orchestrator->query().personal().ids().empty());
    REQUIRE(orchestrator->query().inCollection(collection).ids().size() == 1);
}

TEST_CASE("Organisation items need a collection and the server") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString collection = fixture.m_server->addCollection(org, "Shared", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    REQUIRE_THROWS_AS(vault->getOrchestrator()->createItem<NoteItem>(org, {}), VaultError);
    REQUIRE_THROWS_AS(vault->getOrchestrator()->createItem<NoteItem>("not-a-member", { collection }), VaultError);

    fixture.m_server->m_online = false;
    std::shared_ptr<NoteItem> note = vault->getOrchestrator()->createItem<NoteItem>(org, { collection });
    REQUIRE_THROWS_AS(note->commit(), VaultError);
    REQUIRE_FALSE(vault->getOrchestrator()->hasItem(note->getId()));
}

TEST_CASE("Moving a personal item into an organisation") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString collection = fixture.m_server->addCollection(org, "Shared", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    std::shared_ptr<NoteItem> note = orchestrator->createItem<NoteItem>();
    note->setName("Wi-Fi").setNotes("password123").commit();
    std::optional<SecureString> attachment = note->addAttachment("router.txt", encoding::bytesOf("admin"), nullptr);
    REQUIRE(attachment);

    REQUIRE_THROWS_AS(note->shareTo(org, {}), VaultError);
    REQUIRE(note->shareTo(org, { collection }));
    REQUIRE(note->getOrganizationId() == org);

    std::shared_ptr<NoteItem> reloaded = orchestrator->getItem<NoteItem>(note->getId());
    REQUIRE(reloaded->getNotes() == "password123");
    REQUIRE(reloaded->getCollectionIds() == std::vector<SecureString> { collection });
    REQUIRE(reloaded->downloadAttachment(*attachment, "/out/router.txt", nullptr));
    REQUIRE(encoding::textOf(*fixture.m_files->read("/out/router.txt")) == "admin");

    /*
     * The item key is now wrapped by the organisation key, not the user key.
    */
    Json stored = fixture.m_server->m_ciphers[note->getId()];
    REQUIRE_NOTHROW(Crypto().unwrapKey(stringAt(stored, "key"), fixture.m_server->organizationKey(org)));
    REQUIRE_THROWS_AS(Crypto().unwrapKey(stringAt(stored, "key"), fixture.m_server->m_user_key), CryptoError);

    REQUIRE_THROWS_AS(reloaded->shareTo(org, { collection }), VaultError);
}

TEST_CASE("Moving a legacy item re-encrypts everything under a new key") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString collection = fixture.m_server->addCollection(org, "Shared", false);

    /*
     * A cipher from before per-item keys: fields encrypted directly with the user key.
    */
    Crypto crypto;
    SymmetricKey user_key = fixture.m_server->m_user_key;
    SymmetricKey attachment_key = SymmetricKey::generate();
    fixture.m_server->m_ciphers["legacy-1"] = {
        { "id", "legacy-1" }, { "type", 2 }, { "key", nullptr }, { "revisionDate", timestamp::now() },
        { "name", crypto.encryptText("Old note", user_key) }, { "notes", crypto.encryptText("old secret", user_key) },
        { "secureNote", { { "type", 0 } } },
        { "passwordHistory", Json::array({ { { "password", crypto.encryptText("pw", user_key) } } }) },
        { "attachments", Json::array({ { { "id", "att-legacy" }, { "fileName", crypto.encryptText("f.txt", user_key) },
            { "key", crypto.wrapKey(attachment_key, user_key) } } }) }
    };
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::shared_ptr<NoteItem> legacy = vault->getOrchestrator()->getItem<NoteItem>("legacy-1");
    REQUIRE(legacy->shareTo(org, { collection }));

    Json stored = fixture.m_server->m_ciphers["legacy-1"];
    SymmetricKey item_key = crypto.unwrapKey(stringAt(stored, "key"), fixture.m_server->organizationKey(org));
    REQUIRE(crypto.decryptText(stringAt(stored, "notes"), item_key) == "old secret");
    REQUIRE(crypto.decryptText(stringAt(stored["passwordHistory"][0], "password"), item_key) == "pw");
    REQUIRE(crypto.decryptText(stringAt(stored["attachments"][0], "fileName"), item_key) == "f.txt");
    REQUIRE(crypto.unwrapKey(stringAt(stored["attachments"][0], "key"), item_key).combined() == attachment_key.combined());
    REQUIRE_THROWS_AS(crypto.decrypt(stringAt(stored, "notes"), user_key), CryptoError);
    REQUIRE_FALSE(stored.contains("attachments2"));
}

TEST_CASE("Changing an organisation item's collections") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString first = fixture.m_server->addCollection(org, "First", false);
    SecureString second = fixture.m_server->addCollection(org, "Second", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::shared_ptr<NoteItem> note = vault->getOrchestrator()->createItem<NoteItem>(org, { first });
    note->commit();
    REQUIRE(note->setCollections({ first, second }));
    REQUIRE(fixture.m_server->m_ciphers[note->getId()]["collectionIds"].size() == 2);

    /*
     * Older servers only have the original route.
    */
    fixture.m_server->m_collections_v2 = false;
    REQUIRE(note->setCollections({ second }));
    REQUIRE(fixture.m_server->m_ciphers[note->getId()]["collectionIds"][0] == second);

    std::shared_ptr<NoteItem> personal = vault->getOrchestrator()->createItem<NoteItem>();
    personal->commit();
    REQUIRE_THROWS_AS(personal->setCollections({ first }), VaultError);
    REQUIRE_THROWS_AS(note->setCollections({}), VaultError);
}

TEST_CASE("Read-only organisation items refuse edits") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString locked = fixture.m_server->addCollection(org, "Locked", true);
    Crypto crypto;
    SymmetricKey item_key = SymmetricKey::generate();
    fixture.m_server->m_ciphers["ro-1"] = { { "id", "ro-1" }, { "type", 2 }, { "organizationId", org },
        { "collectionIds", Json::array({ locked }) }, { "revisionDate", timestamp::now() },
        { "key", crypto.wrapKey(item_key, fixture.m_server->organizationKey(org)) },
        { "name", crypto.encryptText("Policy", item_key) }, { "secureNote", { { "type", 0 } } } };
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::shared_ptr<NoteItem> note = vault->getOrchestrator()->getItem<NoteItem>("ro-1");
    REQUIRE(note->getName() == "Policy");
    REQUIRE_FALSE(note->canEdit());
    REQUIRE_THROWS_AS(note->setName("Changed").commit(), VaultError);
    REQUIRE_THROWS_AS(note->remove(), VaultError);
    REQUIRE_THROWS_AS(note->bin(), VaultError);
}

TEST_CASE("Duplicating an organisation item keeps it in the organisation") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString collection = fixture.m_server->addCollection(org, "Shared", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::shared_ptr<CardItem> card = vault->getOrchestrator()->createItem<CardItem>(org, { collection });
    card->setNumber("4111").commit();
    SecureString copy = card->duplicate();

    REQUIRE(fixture.m_server->m_ciphers[copy]["organizationId"] == org);
    REQUIRE(vault->getOrchestrator()->getItem<CardItem>(copy)->getNumber() == "4111");
}

TEST_CASE("Autofill includes organisation logins") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString collection = fixture.m_server->addCollection(org, "Shared", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::shared_ptr<LoginItem> login = vault->getOrchestrator()->createItem<LoginItem>(org, { collection });
    login->addWebsite("https://intranet.acme.test").commit();
    REQUIRE(vault->getAutoFill()->matchingLogins("https://intranet.acme.test/login", false)
            == std::vector<SecureString> { login->getId() });
}
