#include <catch2/catch_test_macros.hpp>

#include "core/support_vault.h"
#include "utils/encoding/encoding.h"

using namespace clientwarden;
using namespace clientwarden::testing;

TEST_CASE("Create a text Send and open it as the recipient") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Sends> sends = vault->getSends();

    std::shared_ptr<Send> send = sends->createSend(SendType::Text);
    send->setName("Wi-Fi").setText("correct-horse", false);
    REQUIRE(send->commit());
    REQUIRE_FALSE(send->getId().empty());

    /*
     * The server stores ciphertext only; the key lives in the link fragment.
    */
    REQUIRE(fixture.m_server->m_sends[send->getId()].dump().find("correct-horse") == SecureString::npos);
    SecureString link = send->getShareUrl();
    REQUIRE(link.starts_with("https://vault.example/#/send/"));

    ReceivedSend received;
    REQUIRE(sends->open(link, "", received) == ReceiveResult::Success);
    REQUIRE(received.m_type == SendType::Text);
    REQUIRE(received.m_name == "Wi-Fi");
    REQUIRE(received.m_text == "correct-horse");
    REQUIRE(received.m_creator == fixture.m_server->m_email);
    REQUIRE(fixture.m_server->m_sends[send->getId()]["accessCount"] == 1);
}

TEST_CASE("Opening a Send never sends the key or the vault's token") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Send> send = vault->getSends()->createSend(SendType::Text);
    send->setText("secret", false).commit();

    ReceivedSend received;
    REQUIRE(vault->getSends()->open(send->getShareUrl(), "", received) == ReceiveResult::Success);
    std::optional<HttpRequest> access = fixture.m_server->last(HttpMethod::Post, "https://vault.example/api/sends/access/");
    REQUIRE(access);
    REQUIRE(headerOf(*access, "Authorization").empty());

    SecureString fragment = send->getShareUrl().substr(send->getShareUrl().rfind('/') + 1);
    REQUIRE(access->m_path.find(fragment) == SecureString::npos);
    REQUIRE(access->m_body.find(fragment) == SecureString::npos);
}

TEST_CASE("Password protected Sends") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Sends> sends = vault->getSends();

    std::shared_ptr<Send> send = sends->createSend(SendType::Text);
    send->setText("classified", false).setPassword("open sesame").commit();

    ReceivedSend received;
    REQUIRE(sends->open(send->getShareUrl(), "", received) == ReceiveResult::NeedsPassword);
    REQUIRE(sends->open(send->getShareUrl(), "wrong", received) == ReceiveResult::WrongPassword);
    REQUIRE(sends->open(send->getShareUrl(), "open sesame", received) == ReceiveResult::Success);
    REQUIRE(received.m_text == "classified");

    REQUIRE(send->removePassword());
    REQUIRE_FALSE(send->hasPassword());
    REQUIRE(sends->open(send->getShareUrl(), "", received) == ReceiveResult::Success);
}

TEST_CASE("Access limits and disabling") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Sends> sends = vault->getSends();

    std::shared_ptr<Send> send = sends->createSend(SendType::Text);
    send->setText("once", false).setMaxAccessCount(1).commit();

    ReceivedSend received;
    REQUIRE(sends->open(send->getShareUrl(), "", received) == ReceiveResult::Success);
    REQUIRE(sends->open(send->getShareUrl(), "", received) == ReceiveResult::NotAvailable);

    std::shared_ptr<Send> other = sends->createSend(SendType::Text);
    other->setText("off", false).commit();
    REQUIRE(other->setDisabled(true).commit());
    REQUIRE(sends->open(other->getShareUrl(), "", received) == ReceiveResult::NotAvailable);
}

TEST_CASE("File Sends upload encrypted and decrypt for the recipient") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Sends> sends = vault->getSends();

    std::shared_ptr<Send> send = sends->createSend(SendType::File);
    REQUIRE_THROWS_AS(send->commit(), VaultError);  // no file chosen yet
    send->setName("Report").setFile("report.txt", encoding::bytesOf("quarterly numbers"));
    REQUIRE(send->commit());

    SecureBytes uploaded = fixture.m_server->m_send_files[send->getId()];
    REQUIRE(encoding::textOf(uploaded).find("quarterly") == std::string_view::npos);

    ReceivedSend received;
    REQUIRE(sends->open(send->getShareUrl(), "", received) == ReceiveResult::Success);
    REQUIRE(received.m_type == SendType::File);
    REQUIRE(received.m_file_name == "report.txt");
    REQUIRE(sends->downloadReceivedFile(received, "/downloads/report.txt", nullptr));
    REQUIRE(encoding::textOf(*fixture.m_files->read("/downloads/report.txt")) == "quarterly numbers");

    REQUIRE_THROWS_AS(send->setFile("other.txt", encoding::bytesOf("x")), VaultError);
}

TEST_CASE("Servers with only the send_access grant (newer Vaultwarden)") {
    Fixture fixture;
    fixture.m_server->m_send_token_flow = true;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Sends> sends = vault->getSends();

    std::shared_ptr<Send> text = sends->createSend(SendType::Text);
    text->setText("classified", false).setPassword("open sesame").setMaxAccessCount(1).commit();

    ReceivedSend received;
    REQUIRE(sends->open(text->getShareUrl(), "", received) == ReceiveResult::NeedsPassword);
    REQUIRE(sends->open(text->getShareUrl(), "wrong", received) == ReceiveResult::WrongPassword);
    REQUIRE(sends->open(text->getShareUrl(), "open sesame", received) == ReceiveResult::Success);
    REQUIRE(received.m_text == "classified");
    REQUIRE(sends->open(text->getShareUrl(), "open sesame", received) == ReceiveResult::NotAvailable);

    /*
     * The token request carries neither the link's key nor the vault's own token.
    */
    std::optional<HttpRequest> grant = fixture.m_server->last(HttpMethod::Post, "https://vault.example/identity/connect/token");
    REQUIRE(grant);
    REQUIRE(headerOf(*grant, "Authorization").empty());
    SecureString fragment = text->getShareUrl().substr(text->getShareUrl().rfind('/') + 1);
    REQUIRE(grant->m_body.find(fragment) == SecureString::npos);

    std::shared_ptr<Send> file = sends->createSend(SendType::File);
    file->setFile("report.txt", encoding::bytesOf("quarterly numbers")).commit();
    REQUIRE(sends->open(file->getShareUrl(), "", received) == ReceiveResult::Success);
    REQUIRE(sends->downloadReceivedFile(received, "/downloads/report.txt", nullptr));
    REQUIRE(encoding::textOf(*fixture.m_files->read("/downloads/report.txt")) == "quarterly numbers");
}

TEST_CASE("Editing, listing and deleting Sends") {
    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Sends> sends = vault->getSends();

    std::shared_ptr<Send> send = sends->createSend(SendType::Text);
    send->setName("Draft").setText("v1", false).commit();
    REQUIRE(send->setName("Final").setText("v2", true).commit());

    std::shared_ptr<Send> reloaded = sends->getSend(send->getId());
    REQUIRE(reloaded->getName() == "Final");
    REQUIRE(reloaded->getText() == "v2");
    REQUIRE(sends->getSends().size() == 1);

    REQUIRE(send->remove());
    REQUIRE(sends->getSends().empty());
    REQUIRE_FALSE(fixture.m_server->m_sends.contains(send->getId()));
    REQUIRE_THROWS_AS(sends->getSend(send->getId()), VaultError);
}

TEST_CASE("Sends come from sync and stay after restart") {
    Fixture fixture;
    SecureString id;
    {
        std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
        std::shared_ptr<Send> send = vault->getSends()->createSend(SendType::Text);
        send->setName("Kept").commit();
        id = send->getId();
    }
    std::shared_ptr<BitwardenVault> vault = startVault(fixture);
    REQUIRE(vault->unlock(fixture.m_server->m_password) == UnlockResult::Success);
    REQUIRE(vault->getSends()->getSend(id)->getName() == "Kept");

    vault->lock();
    REQUIRE_THROWS_AS(vault->getSends()->getSends(), VaultError);
}

TEST_CASE("Send links are parsed in every Bitwarden format") {
    SecureBytes material(16, 0x07);
    SecureString key = encoding::base64UrlEncode(material);

    std::optional<SendLink> web = Sends::parseLink(SecureString("https://vault.example/#/send/abc123/") + key);
    REQUIRE(web);
    REQUIRE(web->m_origin == "https://vault.example");
    REQUIRE(web->m_access_id == "abc123");
    REQUIRE(web->m_key_material == material);

    std::optional<SendLink> cloud = Sends::parseLink(SecureString("https://send.bitwarden.com/#abc123/") + key);
    REQUIRE(cloud);
    REQUIRE(cloud->m_origin == "https://vault.bitwarden.com");

    REQUIRE_FALSE(Sends::parseLink("ftp://vault.example/#/send/abc/" + key));
    REQUIRE_FALSE(Sends::parseLink("https://vault.example/send/abc123"));
    REQUIRE_FALSE(Sends::parseLink("https://vault.example/#/send/abc123/short"));
    REQUIRE_FALSE(Sends::parseLink(SecureString("https://vault.example/#/send/../x/") + key));

    Fixture fixture;
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    ReceivedSend received;
    REQUIRE(vault->getSends()->open("not a link", "", received) == ReceiveResult::InvalidLink);
    REQUIRE(vault->getSends()->open(SecureString("https://vault.example/#/send/missing/") + key, "", received)
            == ReceiveResult::NotAvailable);
}
