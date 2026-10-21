#include <catch2/catch_test_macros.hpp>

#include "items/send/send.h"
#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"

using namespace clientwarden;

namespace {
    /**
     * @brief A detached Send (no vault) for testing the builder.
     */
    Send detached(SendType type) {
        std::shared_ptr<Crypto> crypto = std::make_shared<Crypto>();
        SecureBytes material(16, 0x42);
        return Send(nullptr, crypto, { { "type", static_cast<int>(type) } }, material);
    }
}

TEST_CASE("Send keys are HKDF of the key material") {
    Crypto crypto;
    SecureBytes material(16, 0x42);
    SymmetricKey key = Send::deriveKey(crypto, material);
    REQUIRE(key.combined() == crypto.hkdf(material, "bitwarden-send", "send", 64));
}

TEST_CASE("Send fields round trip through encryption") {
    Send send = detached(SendType::Text);
    send.setName("Wi-Fi").setNotes("for guests").setText("hunter2", true);

    REQUIRE(send.getName() == "Wi-Fi");
    REQUIRE(send.getNotes() == "for guests");
    REQUIRE(send.getText() == "hunter2");
    REQUIRE(send.getTextHidden());
    REQUIRE(send.getJson().dump().find("hunter2") == SecureString::npos);
}

TEST_CASE("Send options") {
    Send send = detached(SendType::Text);
    std::time_t tomorrow = std::time(nullptr) + 86400;
    send.setMaxAccessCount(3).setExpirationDate(tomorrow).setDeletionDate(tomorrow).setDisabled(true).setHideEmail(true);

    REQUIRE(send.getMaxAccessCount() == 3);
    REQUIRE(send.getExpirationDate() == tomorrow);
    REQUIRE(send.getDeletionDate() == tomorrow);
    REQUIRE(send.getDisabled());
    REQUIRE(send.getHideEmail());

    send.setMaxAccessCount(std::nullopt).setExpirationDate(0);
    REQUIRE_FALSE(send.getMaxAccessCount());
    REQUIRE(send.getExpirationDate() == 0);

    REQUIRE_THROWS_AS(send.setDeletionDate(std::time(nullptr) - 10), VaultError);
    REQUIRE_THROWS_AS(send.setDeletionDate(std::time(nullptr) + 40 * 86400), VaultError);
}

TEST_CASE("Send passwords are stored as a salted hash") {
    Crypto crypto;
    Send send = detached(SendType::Text);
    REQUIRE_FALSE(send.hasPassword());

    send.setPassword("open sesame");
    REQUIRE(send.hasPassword());
    REQUIRE(stringAt(send.getJson(), "password") == Send::hashPassword(crypto, "open sesame", SecureBytes(16, 0x42)));
    REQUIRE(send.getJson().dump().find("open sesame") == SecureString::npos);
}

TEST_CASE("Text and file Sends only accept their own content") {
    Send text = detached(SendType::Text);
    REQUIRE_THROWS_AS(text.setFile("a.txt", encoding::bytesOf("x")), VaultError);

    Send file = detached(SendType::File);
    REQUIRE_THROWS_AS(file.setText("x", false), VaultError);
    file.setFile("report.pdf", encoding::bytesOf("%PDF"));
    REQUIRE(file.getFileName() == "report.pdf");
    REQUIRE(file.getPendingFile());
}

TEST_CASE("Detached Sends can't be committed") {
    Send send = detached(SendType::Text);
    REQUIRE_THROWS_AS(send.commit(), VaultError);
    REQUIRE_THROWS_AS(send.remove(), VaultError);
    REQUIRE(send.getShareUrl().empty());
}
