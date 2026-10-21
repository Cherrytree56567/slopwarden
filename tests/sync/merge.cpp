#include <catch2/catch_test_macros.hpp>
#include "Sync/SyncEngine.h"

using namespace ClientWarden;

namespace {
    Record R(std::string id, std::string revision, bool offline = false) {
        nlohmann::json j = { { "id", id }, { "revisionDate", revision } };
        if (offline) {
            j["createdOffline"] = true;
        }
        return std::make_shared<const nlohmann::json>(std::move(j));
    }

    nlohmann::json J(std::string id, std::string revision) {
        return { { "id", id }, { "revisionDate", revision } };
    }

    std::vector<std::string> Ids(const std::vector<Record>& records) {
        std::vector<std::string> out;
        for (const auto& r : records) {
            out.push_back((*r)["id"]);
        }
        return out;
    }

    const char* Old = "2026-01-01T00:00:00.000Z";
    const char* New = "2026-06-01T00:00:00.000Z";
}

TEST_CASE("Merge rules") {
    std::vector<Record> local = {
        R("same", Old),
        R("localNewer", New),
        R("remoteNewer", Old),
        R("deletedRemotely", Old),
        R("offline", New, true),
    };
    nlohmann::json remote = nlohmann::json::array({
        J("same", Old),
        J("localNewer", Old),
        J("remoteNewer", New),
        J("addedRemotely", Old),
        J("pendingDelete", Old),
    });

    MergeResult m = Merge(local, remote, { "pendingDelete" });

    REQUIRE(Ids(m.merged) == std::vector<std::string> { "same", "localNewer", "remoteNewer", "offline", "addedRemotely" });
    REQUIRE(Ids(m.toCreate) == std::vector<std::string> { "offline" });
    REQUIRE(Ids(m.toUpdate) == std::vector<std::string> { "localNewer" });

    REQUIRE((*m.merged[2])["revisionDate"] == New);  // took the remote copy
    REQUIRE(m.merged[1] == local[1]);                 // kept the local pointer
}

TEST_CASE("Merge ignores duplicates and records without ids") {
    std::vector<Record> local = { R("a", Old), R("a", New), std::make_shared<const nlohmann::json>(nlohmann::json { { "x", 1 } }) };
    nlohmann::json remote = nlohmann::json::array({ J("a", Old), J("a", Old), { { "no", "id" } } });

    MergeResult m = Merge(local, remote, {});
    REQUIRE(Ids(m.merged) == std::vector<std::string> { "a" });
}

TEST_CASE("Merge tolerates a malformed remote list") {
    MergeResult m = Merge({ R("a", Old) }, nlohmann::json("not an array"), {});
    REQUIRE(m.merged.empty());
}
