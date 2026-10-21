#include <catch2/catch_test_macros.hpp>

#include "utils/encoding/encoding.h"
#include "vault/store/store.h"

using namespace clientwarden;

namespace {
    /**
     * @brief A record with an id and a marker value.
     */
    Json rec(std::string_view id, int value = 0) {
        return { { "id", SecureString(id) }, { "v", value } };
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
     * @brief A store over a fresh in-memory file store.
     */
    struct Fixture {
        std::shared_ptr<MemoryFileStore> m_files = std::make_shared<MemoryFileStore>();
        std::shared_ptr<Store> m_store = std::make_shared<Store>(m_files);
    };
}

TEST_CASE("RecordSet keeps order, replaces in place and indexes by id") {
    RecordSet set;
    set.put(std::make_shared<const Json>(rec("a")));
    set.put(std::make_shared<const Json>(rec("b")));
    set.put(std::make_shared<const Json>(rec("a", 2)));
    set.put(std::make_shared<const Json>(Json { { "noid", 1 } }));

    REQUIRE(ids(set.all()) == std::vector<SecureString> { "a", "b" });
    REQUIRE((*set.find("a"))["v"] == 2);
    REQUIRE(set.find("missing") == nullptr);

    REQUIRE(set.remove("a"));
    REQUIRE_FALSE(set.remove("a"));
    REQUIRE(ids(set.all()) == std::vector<SecureString> { "b" });
    REQUIRE(set.find("b"));

    REQUIRE(RecordSet::fromJson(set.toJson()).all().size() == 1);
    REQUIRE(RecordSet::fromJson(Json::array({ 1, rec("x") })).all().size() == 1);

    set.clear();
    REQUIRE(set.all().empty());
}

TEST_CASE("SecureStringHash hashes equal text equally") {
    SecureStringHash hash;
    REQUIRE(hash("abc") == hash(SecureString("abc")));
}

TEST_CASE("Store persists and reloads everything") {
    Fixture f;
    REQUIRE_FALSE(f.m_store->load());
    REQUIRE(f.m_store->empty());

    f.m_store->applySync(Store::Snapshot(), Json { { "profile", { { "name", "Alice" }, { "key", "k" } } },
        { "domains", { { "equivalentDomains", Json::array() } } } }, {}, {});
    f.m_store->putCipher(rec("c1"));
    f.m_store->putFolder(rec("f1"));
    f.m_store->setServerVersion("2026.9.0");
    f.m_store->putCipher(rec("c2"));
    f.m_store->removeCipher("c2", true);

    Store reloaded(f.m_files);
    REQUIRE(reloaded.load());
    REQUIRE_FALSE(reloaded.empty());
    REQUIRE(stringAt(reloaded.getProfile(), "name") == "Alice");
    REQUIRE(reloaded.getSection("domains").is_object());
    REQUIRE(reloaded.getSection("missing").is_null());
    REQUIRE(reloaded.getServerVersion() == "2026.9.0");
    REQUIRE(reloaded.getCipher("c1"));
    REQUIRE(reloaded.getFolder("f1"));
    REQUIRE(reloaded.getPendingCipherDeletes() == std::vector<SecureString> { "c2" });
}

TEST_CASE("Store ignores a corrupt cache") {
    Fixture f;
    f.m_files->write("vault.json", encoding::bytesOf("{not json"));
    REQUIRE_FALSE(f.m_store->load());
    REQUIRE(f.m_store->empty());
}

TEST_CASE("Store cipher and folder CRUD") {
    Fixture f;
    f.m_store->putCipher(rec("c1", 1));
    f.m_store->putCipher(rec("c1", 2));
    REQUIRE((*f.m_store->getCipher("c1"))["v"] == 2);
    REQUIRE(f.m_store->getCiphers().size() == 1);

    f.m_store->putFolder(rec("f1"));
    REQUIRE(f.m_store->getFolders().size() == 1);
    f.m_store->removeFolder("f1", true);
    REQUIRE_FALSE(f.m_store->getFolder("f1"));
    REQUIRE(f.m_store->getPendingFolderDeletes() == std::vector<SecureString> { "f1" });
    f.m_store->clearPendingFolderDelete("f1");
    REQUIRE(f.m_store->getPendingFolderDeletes().empty());
}

TEST_CASE("Store only queues remote deletes for records the server knows") {
    Fixture f;
    Json offline = rec("o1");
    offline["createdOffline"] = true;
    f.m_store->putCipher(offline);
    f.m_store->putCipher(rec("c1"));

    f.m_store->removeCipher("o1", true);
    f.m_store->removeCipher("c1", false);
    REQUIRE(f.m_store->getPendingCipherDeletes().empty());

    f.m_store->putCipher(rec("c2"));
    f.m_store->removeCipher("c2", true);
    REQUIRE(f.m_store->getPendingCipherDeletes() == std::vector<SecureString> { "c2" });
    f.m_store->clearPendingCipherDelete("c2");
    REQUIRE(f.m_store->getPendingCipherDeletes().empty());
}

TEST_CASE("Store::clear forgets everything and deletes the file") {
    Fixture f;
    f.m_store->putCipher(rec("c1"));
    REQUIRE(f.m_files->exists("vault.json"));
    f.m_store->clear();
    REQUIRE(f.m_store->getCiphers().empty());
    REQUIRE(f.m_store->empty());
    REQUIRE_FALSE(f.m_files->exists("vault.json"));
}

TEST_CASE("Store::applySync replaces top level but keeps the version") {
    Fixture f;
    f.m_store->setServerVersion("2026.9.0");
    f.m_store->applySync(f.m_store->takeSnapshot(), Json { { "profile", { { "name", "A" } } },
        { "ciphers", Json::array({ rec("ignored") }) } }, { std::make_shared<const Json>(rec("c1")) }, {});

    REQUIRE(f.m_store->getServerVersion() == "2026.9.0");
    REQUIRE(ids(f.m_store->getCiphers()) == std::vector<SecureString> { "c1" });
    REQUIRE(f.m_store->getSection("ciphers").is_null());
}

TEST_CASE("Store::applySync keeps edits, additions and deletions made during the sync") {
    Fixture f;
    f.m_store->putCipher(rec("edited", 1));
    f.m_store->putCipher(rec("deleted", 1));
    f.m_store->putCipher(rec("untouched", 1));
    Store::Snapshot before = f.m_store->takeSnapshot();
    REQUIRE(before.m_ciphers.size() == 3);

    f.m_store->putCipher(rec("edited", 2));
    f.m_store->removeCipher("deleted", false);
    f.m_store->putCipher(rec("added", 2));

    std::vector<Record> merged = {
        std::make_shared<const Json>(rec("edited", 9)),
        std::make_shared<const Json>(rec("deleted", 9)),
        std::make_shared<const Json>(rec("untouched", 9)),
        std::make_shared<const Json>(rec("remote", 9)),
    };
    f.m_store->applySync(before, Json::object(), merged, {});

    REQUIRE((*f.m_store->getCipher("edited"))["v"] == 2);
    REQUIRE_FALSE(f.m_store->getCipher("deleted"));
    REQUIRE((*f.m_store->getCipher("untouched"))["v"] == 9);
    REQUIRE(f.m_store->getCipher("added"));
    REQUIRE(f.m_store->getCipher("remote"));
}
