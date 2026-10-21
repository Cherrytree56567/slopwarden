#include <catch2/catch_test_macros.hpp>
#include <filesystem>

#include "platform/file_store/file_store.h"
#include "utils/encoding/encoding.h"
#include "utils/uuid/uuid.h"

using namespace clientwarden;

namespace {
    /**
     * @brief Reads a file as text, or "<missing>".
     */
    SecureString readText(FileStore& store, std::filesystem::path file) {
        std::optional<SecureBytes> data = store.read(std::move(file));
        return data ? SecureString(data->begin(), data->end()) : SecureString("<missing>");
    }

    /**
     * @brief Exercises the FileStore contract on any implementation.
     */
    void checkContract(FileStore& store) {
        REQUIRE_FALSE(store.read("nope.json"));
        REQUIRE_FALSE(store.exists("nope.json"));

        store.write("a.json", encoding::bytesOf("one"));
        REQUIRE(store.exists("a.json"));
        REQUIRE(readText(store, "a.json") == "one");

        store.write("a.json", encoding::bytesOf("two"));
        REQUIRE(readText(store, "a.json") == "two");

        store.write("dir/b.png", encoding::bytesOf("png"));
        store.write("dir/sub/c.png", encoding::bytesOf("png"));
        store.write("dirx/keep.png", encoding::bytesOf("keep"));
        store.removeTree("dir");
        REQUIRE_FALSE(store.exists("dir/b.png"));
        REQUIRE_FALSE(store.exists("dir/sub/c.png"));
        REQUIRE(store.exists("dirx/keep.png"));

        store.remove("a.json");
        REQUIRE_FALSE(store.exists("a.json"));
        store.remove("a.json");
    }
}

TEST_CASE("MemoryFileStore follows the FileStore contract") {
    MemoryFileStore store;
    checkContract(store);
    REQUIRE(store.root() == "/memory");

    store.write("/abs/file", encoding::bytesOf("x"));
    REQUIRE(readText(store, "/abs/file") == "x");
}

TEST_CASE("DiskFileStore follows the FileStore contract and writes atomically") {
    std::filesystem::path root = std::filesystem::temp_directory_path()
        / std::filesystem::path(("cw-fs-" + uuid::generate()).c_str());
    {
        DiskFileStore store(root);
        REQUIRE(std::filesystem::exists(root));
        REQUIRE(store.root() == root);
        checkContract(store);

        store.write("vault.json", encoding::bytesOf("data"));
        REQUIRE_FALSE(std::filesystem::exists(root / "vault.json.tmp"));
        REQUIRE(std::filesystem::exists(root / "vault.json"));
    }
    std::filesystem::remove_all(root);
}

TEST_CASE("ScopedFileStore confines paths to its subdirectory") {
    std::shared_ptr<MemoryFileStore> inner = std::make_shared<MemoryFileStore>();
    ScopedFileStore scoped(inner, "vaults/v1");
    checkContract(scoped);

    scoped.write("vault.json", encoding::bytesOf("x"));
    REQUIRE(inner->exists("vaults/v1/vault.json"));
    REQUIRE_FALSE(inner->exists("vault.json"));
    REQUIRE(scoped.root() == std::filesystem::path("/memory") / "vaults/v1");

    scoped.write("/downloads/file.txt", encoding::bytesOf("abs"));
    REQUIRE(inner->exists("/downloads/file.txt"));

    ScopedFileStore legacy(inner, "");
    legacy.write("vault.json", encoding::bytesOf("root"));
    REQUIRE(readText(*inner, "vault.json") == "root");
}
