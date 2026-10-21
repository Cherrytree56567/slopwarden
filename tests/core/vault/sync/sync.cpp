#include <catch2/catch_test_macros.hpp>

#include "vault/sync/sync.h"

using namespace clientwarden;

namespace {
    using IdSet = std::unordered_set<SecureString, SecureStringHash, std::equal_to<>>;

    const std::string_view c_old = "2026-01-01T00:00:00.000Z";
    const std::string_view c_new = "2026-06-01T00:00:00.000Z";

    /**
     * @brief A local record.
     */
    Record local(std::string_view id, std::string_view revision, bool offline = false) {
        Json j = { { "id", SecureString(id) }, { "revisionDate", SecureString(revision) } };
        if (offline) {
            j["createdOffline"] = true;
        }
        return std::make_shared<const Json>(std::move(j));
    }

    /**
     * @brief A remote record.
     */
    Json remote(std::string_view id, std::string_view revision) {
        return { { "id", SecureString(id) }, { "revisionDate", SecureString(revision) } };
    }

    /**
     * @brief Ids of records, in order.
     */
    std::vector<SecureString> ids(const std::vector<Record>& records) {
        std::vector<SecureString> out;
        for (const Record& r : records) {
            out.push_back(stringAt(*r, "id"));
        }
        return out;
    }

    /**
     * @brief A transport that never reaches anything.
     */
    class Offline : public HttpTransport {
    public:
        void configure(ServerUrls) override {}
        HttpResponse send(HttpRequest) override { return HttpResponse(); }
        bool listen(std::string_view, std::function<void(std::span<const uint8_t>)>, std::stop_token) override {
            return false;
        }
    };

    /**
     * @brief A server whose /api/sync response has no folders, and which runs a hook after
     * building it (the moment another request lands while the sync is in flight).
     */
    class SlowSync : public HttpTransport {
    public:
        std::function<void()> m_during_sync;

        void configure(ServerUrls) override {}
        HttpResponse send(HttpRequest request) override {
            HttpResponse response;
            response.m_status = 200;
            if (request.m_path == "/api/sync") {
                Json body = { { "profile", { { "id", "user-1" } } }, { "folders", Json::array() }, { "ciphers", Json::array() } };
                if (m_during_sync) {
                    m_during_sync();
                }
                SecureString text = body.dump();
                response.m_body = SecureBytes(text.begin(), text.end());
            }
            return response;
        }
        bool listen(std::string_view, std::function<void(std::span<const uint8_t>)>, std::stop_token) override {
            return false;
        }
    };

    class FixedToken : public AccessTokenSource {
    public:
        std::optional<SecureString> getAccessToken() override { return SecureString("t"); }
        bool refresh(std::string_view) override { return false; }
    };
}

TEST_CASE("Sync::merge rules") {
    std::vector<Record> locals = {
        local("same", c_old),
        local("localNewer", c_new),
        local("remoteNewer", c_old),
        local("deletedRemotely", c_old),
        local("offline", c_new, true),
    };
    Json remotes = Json::array({
        remote("same", c_old),
        remote("localNewer", c_old),
        remote("remoteNewer", c_new),
        remote("addedRemotely", c_old),
        remote("pendingDelete", c_old),
    });

    Sync::MergeResult m = Sync::merge(locals, remotes, IdSet { "pendingDelete" });

    REQUIRE(ids(m.m_merged) == std::vector<SecureString> { "same", "localNewer", "remoteNewer", "offline", "addedRemotely" });
    REQUIRE(ids(m.m_to_create) == std::vector<SecureString> { "offline" });
    REQUIRE(ids(m.m_to_update) == std::vector<SecureString> { "localNewer" });
    REQUIRE(stringAt(*m.m_merged[2], "revisionDate") == c_new);
    REQUIRE(m.m_merged[1] == locals[1]);
}

TEST_CASE("Sync::merge ignores duplicates and records without ids") {
    std::vector<Record> locals = { local("a", c_old), local("a", c_new),
        std::make_shared<const Json>(Json { { "x", 1 } }) };
    Json remotes = Json::array({ remote("a", c_old), remote("a", c_old), Json { { "no", "id" } } });

    REQUIRE(ids(Sync::merge(locals, remotes, IdSet()).m_merged) == std::vector<SecureString> { "a" });
}

TEST_CASE("Sync::merge tolerates a malformed remote list") {
    REQUIRE(Sync::merge({ local("a", c_old) }, Json("not an array"), IdSet()).m_merged.empty());
}

TEST_CASE("Sync::run fails cleanly without a server and leaves the cache alone") {
    std::shared_ptr<Store> store = std::make_shared<Store>(std::make_shared<MemoryFileStore>());
    store->putCipher(Json { { "id", "c1" } });
    std::shared_ptr<Network> network = std::make_shared<Network>(std::make_shared<Offline>(),
        DeviceInfo::forThisPlatform("dev"));
    Sync sync(network, store, std::make_shared<Features>(store));

    bool called = false;
    sync.onAccountKeyChanged([&called]() { called = true; });
    sync.invalidate();
    REQUIRE_FALSE(sync.run());
    REQUIRE(store->getCipher("c1"));
    REQUIRE_FALSE(called);
}

TEST_CASE("Sync::run keeps records saved while its request was in flight") {
    std::shared_ptr<Store> store = std::make_shared<Store>(std::make_shared<MemoryFileStore>());
    std::shared_ptr<SlowSync> transport = std::make_shared<SlowSync>();
    std::shared_ptr<Network> network = std::make_shared<Network>(transport, DeviceInfo::forThisPlatform("dev"));
    network->setTokenSource(std::make_shared<FixedToken>());
    Sync sync(network, store, std::make_shared<Features>(store));

    /*
     * Saved online after the server built its response, so the response doesn't have it.
    */
    transport->m_during_sync = [&store]() {
        store->putFolder(Json { { "id", "f-new" }, { "revisionDate", SecureString(c_new) } });
    };
    REQUIRE(sync.run());
    REQUIRE(store->getFolder("f-new"));
}
