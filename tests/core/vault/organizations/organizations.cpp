#include <catch2/catch_test_macros.hpp>

#include "core/support_vault.h"
#include "items/note_item/note_item.h"

using namespace clientwarden;
using namespace clientwarden::testing;

TEST_CASE("Organisation keys are decrypted with the account's RSA key on unlock") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::optional<SymmetricKey> key = vault->getSession()->getOrganizationKey(org);
    REQUIRE(key);
    REQUIRE(key->combined() == fixture.m_server->organizationKey(org).combined());

    vault->lock();
    REQUIRE_FALSE(vault->getSession()->getOrganizationKey(org));
    REQUIRE(vault->unlock(fixture.m_server->m_password) == UnlockResult::Success);
    REQUIRE(vault->getSession()->getOrganizationKey(org));
}

TEST_CASE("Organisations are listed with their roles") {
    Fixture fixture;
    SecureString owned = fixture.m_server->addOrganization("Owned", 0);
    SecureString member = fixture.m_server->addOrganization("Member", 2);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::vector<OrganizationInfo> organizations = vault->getOrganizations()->getOrganizations();
    REQUIRE(organizations.size() == 2);
    REQUIRE(organizations[0].m_id == owned);
    REQUIRE(organizations[0].m_name == "Owned");
    REQUIRE(organizations[0].m_role == OrganizationRole::Owner);
    REQUIRE(organizations[0].m_can_manage_collections);
    REQUIRE(organizations[0].m_key_available);
    REQUIRE(organizations[1].m_id == member);
    REQUIRE_FALSE(organizations[1].m_can_manage_collections);
}

TEST_CASE("Collections are listed with decrypted names, sorted") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString other = fixture.m_server->addOrganization("Other", 2);
    fixture.m_server->addCollection(org, "Zeta", false);
    SecureString alpha = fixture.m_server->addCollection(org, "Alpha", true);
    fixture.m_server->addCollection(other, "Elsewhere", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::vector<CollectionInfo> collections = vault->getOrganizations()->getCollections(org);
    REQUIRE(collections.size() == 2);
    REQUIRE(collections[0].m_name == "Alpha");
    REQUIRE(collections[0].m_id == alpha);
    REQUIRE(collections[0].m_read_only);
    REQUIRE(collections[1].m_name == "Zeta");
    REQUIRE(vault->getOrganizations()->getCollections("").size() == 3);
}

TEST_CASE("A new organisation appears after the next sync") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    REQUIRE(vault->getOrganizations()->getOrganizations().empty());

    SecureString org = fixture.m_server->addOrganization("Late", 2);
    REQUIRE(vault->syncNow());
    REQUIRE(vault->getSession()->getOrganizationKey(org));
    REQUIRE(vault->getOrganizations()->getOrganizations().size() == 1);
}

TEST_CASE("Managing collections requires permission") {
    Fixture fixture;
    SecureString owned = fixture.m_server->addOrganization("Owned", 0);
    SecureString member = fixture.m_server->addOrganization("Member", 2);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Organizations> organizations = vault->getOrganizations();

    std::optional<SecureString> id = organizations->createCollection(owned, "Engineering");
    REQUIRE(id);
    REQUIRE(fixture.m_server->m_collections.contains(*id));
    REQUIRE(fixture.m_server->m_collections[*id]["users"][0]["manage"] == true);
    REQUIRE(organizations->getCollections(owned).at(0).m_name == "Engineering");

    REQUIRE_THROWS_AS(organizations->createCollection(member, "Nope"), VaultError);
    REQUIRE_THROWS_AS(organizations->createCollection("not-a-member", "Nope"), VaultError);
}

TEST_CASE("Renaming a collection keeps its access lists") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 0);
    SecureString collection = fixture.m_server->addCollection(org, "Old", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    REQUIRE(vault->getOrganizations()->renameCollection(collection, "New"));
    REQUIRE(vault->getOrganizations()->getCollections(org).at(0).m_name == "New");
    REQUIRE(fixture.m_server->m_collections[collection]["groups"][0]["id"] == "group-1");
    REQUIRE(fixture.m_server->m_collections[collection]["users"][0]["id"] == "orguser-x");
}

TEST_CASE("Deleting a collection removes it from items") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 0);
    SecureString keep = fixture.m_server->addCollection(org, "Keep", false);
    SecureString doomed = fixture.m_server->addCollection(org, "Doomed", false);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    std::shared_ptr<NoteItem> note = vault->getOrchestrator()->createItem<NoteItem>(org, { keep, doomed });
    note->commit();

    REQUIRE(vault->getOrganizations()->deleteCollection(doomed));
    REQUIRE(vault->getOrganizations()->getCollections(org).size() == 1);
    REQUIRE(vault->getOrchestrator()->getGenericItem(note->getId())->getCollectionIds()
            == std::vector<SecureString> { keep });
    REQUIRE_THROWS_AS(vault->getOrganizations()->deleteCollection("missing"), VaultError);
}

TEST_CASE("canEditIn reflects read-only collections") {
    Fixture fixture;
    SecureString org = fixture.m_server->addOrganization("Acme", 2);
    SecureString open = fixture.m_server->addCollection(org, "Open", false);
    SecureString locked = fixture.m_server->addCollection(org, "Locked", true);
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);

    REQUIRE(vault->getOrganizations()->canEditIn({ open }));
    REQUIRE_FALSE(vault->getOrganizations()->canEditIn({ open, locked }));
    REQUIRE_FALSE(vault->getOrganizations()->canEditIn({ "unknown" }));
}

TEST_CASE("Accounts without a private key have no organisations") {
    Fixture fixture;
    fixture.m_server->m_encrypted_private_key = SecureString();
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    REQUIRE(vault->getOrganizations()->loadKeys() == 0);
}
