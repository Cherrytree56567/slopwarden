#pragma once
#include <string>
#include <unordered_set>
#include <vector>
#include <nlohmann/json.hpp>

#include "Store/VaultStore.h"

namespace ClientWarden {
    /*
     * Pure two-way merge of local and remote records (ciphers or
     * folders), keyed by id and resolved by revisionDate:
     *
     *  - local createdOffline         -> keep, upload as new
     *  - both, local newer            -> keep local, upload as update
     *  - both, remote newer or equal  -> take remote
     *  - local only                   -> deleted remotely, drop
     *  - remote only, not pending del -> add
     *
     * No I/O happens here so the rules can be tested in isolation.
    */
    struct MergeResult {
        std::vector<Record> merged;
        std::vector<Record> toCreate;
        std::vector<Record> toUpdate;
    };

    MergeResult Merge(const std::vector<Record>& local, const nlohmann::json& remote,
        const std::unordered_set<std::string>& pendingDeletes);
}
