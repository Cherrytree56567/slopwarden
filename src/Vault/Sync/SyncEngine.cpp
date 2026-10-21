#include "SyncEngine.h"

#include <unordered_map>

#include "Util/Util.h"

namespace ClientWarden {
    namespace {
        std::string IdOf(const nlohmann::json& r) {
            auto it = r.find("id");
            return it != r.end() && it->is_string() ? it->get<std::string>() : std::string();
        }

        std::time_t RevisionOf(const nlohmann::json& r) {
            auto it = r.find("revisionDate");
            return it != r.end() && it->is_string() ? ParseTime(it->get<std::string>()) : 0;
        }
    }

    MergeResult Merge(const std::vector<Record>& local, const nlohmann::json& remote,
        const std::unordered_set<std::string>& pendingDeletes) {
        std::unordered_map<std::string, const nlohmann::json*> remoteById;
        std::vector<std::string> remoteOrder;
        if (remote.is_array()) {
            for (const auto& r : remote) {
                std::string id = IdOf(r);
                if (!id.empty() && remoteById.emplace(id, &r).second) {
                    remoteOrder.push_back(std::move(id));
                }
            }
        }

        MergeResult out;
        std::unordered_set<std::string> seen;

        for (const auto& record : local) {
            std::string id = IdOf(*record);
            if (id.empty() || !seen.insert(id).second) {
                continue;
            }

            if (record->value("createdOffline", false)) {
                out.merged.push_back(record);
                out.toCreate.push_back(record);
                continue;
            }

            auto r = remoteById.find(id);
            if (r == remoteById.end()) {
                continue;
            }

            if (RevisionOf(*record) > RevisionOf(*r->second)) {
                out.merged.push_back(record);
                out.toUpdate.push_back(record);
            } else {
                out.merged.push_back(std::make_shared<const nlohmann::json>(*r->second));
            }
        }

        for (const auto& id : remoteOrder) {
            if (!seen.contains(id) && !pendingDeletes.contains(id)) {
                out.merged.push_back(std::make_shared<const nlohmann::json>(*remoteById[id]));
            }
        }
        return out;
    }
}
