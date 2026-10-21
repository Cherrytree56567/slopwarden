#include <catch2/catch_test_macros.hpp>

#include "JsonBridge/JsonBridge.h"
#include "core/support_vault.h"

using namespace clientwarden;
using namespace clientwarden::testing;

namespace {
    /**
     * @brief A bridge over one test vault.
     */
    struct BridgeFixture {
        Fixture m_fixture;
        std::shared_ptr<BitwardenVault> m_vault = startVault(m_fixture);
        bridge::JsonBridge m_bridge { [this]() { return std::shared_ptr<Vault>(m_vault); } };

        /**
         * @brief Calls a method and returns its result, failing the test if it errored.
         */
        Json ok(std::string_view method, Json args) {
            Json response = Json::parse(m_bridge.call(method, args.dump()));
            INFO(response.dump());
            REQUIRE(response["ok"] == true);
            return response["result"];
        }

        /**
         * @brief Calls a method that should fail and returns its error.
         */
        SecureString error(std::string_view method, Json args) {
            Json response = Json::parse(m_bridge.call(method, args.dump()));
            REQUIRE(response["ok"] == false);
            return response["error"].get<SecureString>();
        }

        void login() {
            ok("auth.setServer", { { "vault", "https://vault.example" }, { "api", "https://api.example" },
                { "icons", "https://icons.example" } });
            REQUIRE(ok("auth.login", { { "email", m_fixture.m_server->m_email },
                { "password", m_fixture.m_server->m_password } })["result"] == "Success");
        }
    };
}

TEST_CASE("Bridge: login, lock and unlock") {
    BridgeFixture f;
    REQUIRE(f.ok("state.get", Json::object())["state"] == "LoggedOut");
    f.login();
    REQUIRE(f.ok("state.get", Json::object())["state"] == "Unlocked");
    REQUIRE(f.ok("vault.profile", Json::object())["name"] == "Test User");

    f.ok("auth.lock", Json::object());
    REQUIRE(f.ok("auth.unlock", { { "password", "wrong" } })["result"] == "InvalidPassword");
    REQUIRE(f.ok("auth.unlock", { { "password", f.m_fixture.m_server->m_password } })["result"] == "Success");
}

TEST_CASE("Bridge: errors are reported, never thrown") {
    BridgeFixture f;
    REQUIRE(f.error("no.such.method", Json::object()).find("unknown method") != SecureString::npos);
    REQUIRE(Json::parse(f.m_bridge.call("auth.unlock", "{not json"))["ok"] == false);
    REQUIRE(f.error("auth.login", Json::object()).find("missing argument") != SecureString::npos);
    REQUIRE(f.error("items.list", Json::object()).find("locked") != SecureString::npos);
}

TEST_CASE("Bridge: create, read, edit and list items") {
    BridgeFixture f;
    f.login();

    Json saved = f.ok("items.save", { { "type", "login" }, { "name", "GitHub" },
        { "fields", { { "username", "octocat" }, { "password", "hunter2" } } },
        { "login", { { "uris", { "https://github.com" } }, { "totp", "JBSWY3DPEHPK3PXP" } } },
        { "customFields", { { { "type", 1 }, { "name", "pin" }, { "value", "1234" } } } } });
    SecureString id = saved["id"].get<SecureString>();
    REQUIRE(saved["synced"] == true);

    Json item = f.ok("items.get", { { "id", id } });
    REQUIRE(item["type"] == "login");
    REQUIRE(item["name"] == "GitHub");
    REQUIRE(item["fields"][0] == Json({ { "key", "username" }, { "secret", false }, { "value", "octocat" } }));
    REQUIRE(item["fields"][1]["secret"] == true);
    REQUIRE(item["login"]["uris"][0] == "https://github.com");
    REQUIRE(item["customFields"][0]["value"] == "1234");
    REQUIRE(f.ok("items.totp", { { "id", id } })["code"].get<SecureString>().size() == 6);

    f.ok("items.save", { { "id", id }, { "fields", { { "password", "new" } } }, { "favorite", true } });
    item = f.ok("items.get", { { "id", id } });
    REQUIRE(item["fields"][1]["value"] == "new");
    REQUIRE(item["fields"][0]["value"] == "octocat");     // untouched keys stay
    REQUIRE(item["login"]["passwordHistory"].size() == 1);

    REQUIRE(f.ok("items.list", { { "filter", "favorites" } }).size() == 1);
    REQUIRE(f.ok("items.list", { { "filter", "type" }, { "value", "card" } }).empty());
    REQUIRE(f.ok("items.list", { { "search", "git" } })[0]["subtitle"] == "octocat");

    REQUIRE(f.ok("items.bin", { { "id", id } }) == true);
    REQUIRE(f.ok("items.list", { { "filter", "trash" } }).size() == 1);
    REQUIRE(f.ok("items.restore", { { "id", id } }) == true);
    REQUIRE(f.ok("items.delete", { { "id", id } }) == true);
    REQUIRE(f.ok("items.list", Json::object()).empty());
}

TEST_CASE("Bridge: every item type works by field key") {
    BridgeFixture f;
    f.login();
    for (const Json& type : f.ok("schema.types", Json::object())) {
        CAPTURE(type["type"]);
        Json fields = Json::object();
        for (const Json& field : type["fields"]) {
            fields[field["key"].get<SecureString>()] = SecureString("v-") + field["key"].get<SecureString>();
        }
        SecureString id = f.ok("items.save", { { "type", type["type"] }, { "name", "x" }, { "fields", fields } })["id"].get<SecureString>();
        for (const Json& field : f.ok("items.get", { { "id", id } })["fields"]) {
            REQUIRE(field["value"] == SecureString("v-") + field["key"].get<SecureString>());
        }
    }
    REQUIRE(f.error("items.save", { { "type", "spaceship" } }).find("unknown item type") != SecureString::npos);
}

TEST_CASE("Bridge: folders, organisations and Sends") {
    BridgeFixture f;
    SecureString org = f.m_fixture.m_server->addOrganization("Acme", 0);
    SecureString collection = f.m_fixture.m_server->addCollection(org, "Shared", false);
    f.login();

    SecureString folder = f.ok("folders.create", { { "name", "Work" } }).get<SecureString>();
    REQUIRE(f.ok("folders.list", Json::object())[0]["name"] == "Work");

    Json organizations = f.ok("organizations.list", Json::object());
    REQUIRE(organizations[0]["name"] == "Acme");
    REQUIRE(organizations[0]["collections"][0]["id"] == collection);

    SecureString id = f.ok("items.save", { { "type", "note" }, { "name", "Team note" }, { "organizationId", org },
        { "collectionIds", { collection } }, { "folderId", folder } })["id"].get<SecureString>();
    REQUIRE(f.ok("items.list", { { "filter", "collection" }, { "value", collection } }).size() == 1);
    REQUIRE(f.ok("items.list", { { "filter", "folder" }, { "value", folder } }).size() == 1);
    REQUIRE(f.ok("items.get", { { "id", id } })["organizationId"] == org);

    Json send = f.ok("sends.save", { { "type", "text" }, { "name", "Wi-Fi" }, { "text", "pw" }, { "password", "s3" } });
    REQUIRE(send["hasPassword"] == true);
    REQUIRE(f.ok("sends.open", { { "link", send["shareUrl"] } })["result"] == "NeedsPassword");
    Json opened = f.ok("sends.open", { { "link", send["shareUrl"] }, { "password", "s3" } });
    REQUIRE(opened["send"]["text"] == "pw");
    REQUIRE(f.ok("sends.list", Json::object()).size() == 1);
}

TEST_CASE("Bridge: hide-passwords items never return secrets") {
    BridgeFixture f;
    SecureString org = f.m_fixture.m_server->addOrganization("Acme", 2);
    SecureString collection = f.m_fixture.m_server->addCollection(org, "Hidden", false);
    f.m_fixture.m_server->m_collections[collection]["hidePasswords"] = true;
    f.login();

    SecureString id = f.ok("items.save", { { "type", "login" }, { "name", "Bank" }, { "organizationId", org },
        { "collectionIds", { collection } }, { "fields", { { "password", "top-secret" } } } })["id"].get<SecureString>();

    /*
     * The fake marks viewPassword per cipher; simulate the server hiding it.
    */
    f.m_fixture.m_server->m_ciphers[id]["viewPassword"] = false;
    f.ok("vault.sync", Json::object());

    Json item = f.ok("items.get", { { "id", id } });
    REQUIRE(item["canViewPassword"] == false);
    REQUIRE(item["fields"][1]["value"].is_null());
    REQUIRE(item.dump().find("top-secret") == SecureString::npos);
}

TEST_CASE("Bridge: generator and settings") {
    BridgeFixture f;
    f.login();
    REQUIRE(f.ok("generator.password", { { "length", 24 } }).get<SecureString>().size() == 24);
    REQUIRE(f.ok("generator.pin", { { "digits", 8 } }).get<SecureString>().size() == 8);

    f.ok("settings.set", { { "autoLockSeconds", 600 }, { "timeoutAction", "logout" } });
    Json settings = f.ok("settings.get", Json::object());
    REQUIRE(settings["autoLockSeconds"] == 600);
    REQUIRE(settings["timeoutAction"] == "logout");
}

TEST_CASE("Bridge: state changes are pushed as events") {
    BridgeFixture f;
    std::mutex mutex;
    std::vector<SecureString> events;
    f.m_bridge.onEvent([&](SecureString event) {
        std::lock_guard<std::mutex> lock(mutex);
        events.push_back(event);
    });
    f.login();
    f.ok("auth.lock", Json::object());

    std::lock_guard<std::mutex> lock(mutex);
    REQUIRE(Json::parse(events.back())["state"] == "Unlockable");
}
