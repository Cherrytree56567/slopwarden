#include "VaultStore.h"

#include <mutex>

namespace ClientWarden {
    namespace {
        constexpr const char* VaultFile = "vault.json";

        std::string IdOf(const nlohmann::json& record) {
            auto it = record.find("id");
            return it != record.end() && it->is_string() ? it->get<std::string>() : std::string();
        }

        std::unordered_set<std::string> IdSet(const nlohmann::json& doc, const char* key) {
            std::unordered_set<std::string> out;
            auto it = doc.find(key);
            if (it != doc.end() && it->is_array()) {
                for (const auto& id : *it) {
                    if (id.is_string()) out.insert(id.get<std::string>());
                }
            }
            return out;
        }
    }

    Record RecordSet::Find(const std::string& id) const {
        auto it = index.find(id);
        return it == index.end() ? nullptr : records[it->second];
    }

    void RecordSet::Put(Record record) {
        std::string id = IdOf(*record);
        if (id.empty()) {
            return;
        }
        if (auto it = index.find(id); it != index.end()) {
            records[it->second] = std::move(record);
        } else {
            index.emplace(std::move(id), records.size());
            records.push_back(std::move(record));
        }
    }

    bool RecordSet::Remove(const std::string& id) {
        auto it = index.find(id);
        if (it == index.end()) {
            return false;
        }
        records.erase(records.begin() + it->second);
        index.clear();
        for (size_t i = 0; i < records.size(); ++i) {
            index.emplace(IdOf(*records[i]), i);
        }
        return true;
    }

    void RecordSet::Clear() {
        records.clear();
        index.clear();
    }

    nlohmann::json RecordSet::ToJson() const {
        nlohmann::json out = nlohmann::json::array();
        for (const auto& r : records) {
            out.push_back(*r);
        }
        return out;
    }

    RecordSet RecordSet::FromJson(const nlohmann::json& array) {
        RecordSet set;
        if (array.is_array()) {
            for (const auto& r : array) {
                if (r.is_object()) {
                    set.Put(std::make_shared<const nlohmann::json>(r));
                }
            }
        }
        return set;
    }

    VaultStore::VaultStore(FileStore& files) : files(files) {}

    bool VaultStore::Load() {
        std::optional<std::string> text = files.Read(VaultFile);
        if (!text) {
            return false;
        }

        nlohmann::json doc = nlohmann::json::parse(*text, nullptr, false);
        if (!doc.is_object()) {
            Log()->error("vault.json is corrupt; ignoring local cache");
            return false;
        }

        std::unique_lock lock(mutex);
        ciphers = RecordSet::FromJson(doc["ciphers"]);
        folders = RecordSet::FromJson(doc["folders"]);
        deletedCiphers = IdSet(doc, "deletedCiphers");
        deletedFolders = IdSet(doc, "deletedFolders");
        for (const char* key : { "ciphers", "folders", "deletedCiphers", "deletedFolders" }) {
            doc.erase(key);
        }
        topLevel = std::move(doc);
        return true;
    }

    void VaultStore::Clear() {
        std::unique_lock lock(mutex);
        topLevel = nlohmann::json::object();
        ciphers.Clear();
        folders.Clear();
        deletedCiphers.clear();
        deletedFolders.clear();
        files.Remove(VaultFile);
    }

    bool VaultStore::Empty() const {
        std::shared_lock lock(mutex);
        return !topLevel.contains("profile");
    }

    void VaultStore::Persist() {
        nlohmann::json doc = topLevel;
        doc["ciphers"] = ciphers.ToJson();
        doc["folders"] = folders.ToJson();
        doc["deletedCiphers"] = deletedCiphers;
        doc["deletedFolders"] = deletedFolders;
        files.Write(VaultFile, doc.dump());
    }

    nlohmann::json VaultStore::Profile() const {
        std::shared_lock lock(mutex);
        auto it = topLevel.find("profile");
        return it == topLevel.end() ? nlohmann::json::object() : *it;
    }

    std::optional<std::string> VaultStore::ProtectedUserKey() const {
        nlohmann::json profile = Profile();
        auto key = profile.find("key");
        if (key == profile.end() || !key->is_string()) {
            return std::nullopt;
        }
        return key->get<std::string>();
    }

    std::string VaultStore::ServerVersion() const {
        std::shared_lock lock(mutex);
        auto it = topLevel.find("version");
        return it != topLevel.end() && it->is_string() ? it->get<std::string>() : std::string();
    }

    void VaultStore::SetServerVersion(const std::string& version) {
        std::unique_lock lock(mutex);
        topLevel["version"] = version;
        Persist();
    }

    Record VaultStore::Cipher(const std::string& id) const {
        std::shared_lock lock(mutex);
        return ciphers.Find(id);
    }

    std::vector<Record> VaultStore::Ciphers() const {
        std::shared_lock lock(mutex);
        return ciphers.All();
    }

    void VaultStore::PutCipher(nlohmann::json cipher) {
        std::unique_lock lock(mutex);
        ciphers.Put(std::make_shared<const nlohmann::json>(std::move(cipher)));
        Persist();
    }

    void VaultStore::RemoveCipher(const std::string& id, bool queueRemoteDelete) {
        std::unique_lock lock(mutex);
        Record existing = ciphers.Find(id);
        ciphers.Remove(id);
        if (queueRemoteDelete && existing && !existing->value("createdOffline", false)) {
            deletedCiphers.insert(id);
        }
        Persist();
    }

    Record VaultStore::Folder(const std::string& id) const {
        std::shared_lock lock(mutex);
        return folders.Find(id);
    }

    std::vector<Record> VaultStore::Folders() const {
        std::shared_lock lock(mutex);
        return folders.All();
    }

    void VaultStore::PutFolder(nlohmann::json folder) {
        std::unique_lock lock(mutex);
        folders.Put(std::make_shared<const nlohmann::json>(std::move(folder)));
        Persist();
    }

    void VaultStore::RemoveFolder(const std::string& id, bool queueRemoteDelete) {
        std::unique_lock lock(mutex);
        Record existing = folders.Find(id);
        folders.Remove(id);
        if (queueRemoteDelete && existing && !existing->value("createdOffline", false)) {
            deletedFolders.insert(id);
        }
        Persist();
    }

    std::vector<std::string> VaultStore::PendingCipherDeletes() const {
        std::shared_lock lock(mutex);
        return { deletedCiphers.begin(), deletedCiphers.end() };
    }

    std::vector<std::string> VaultStore::PendingFolderDeletes() const {
        std::shared_lock lock(mutex);
        return { deletedFolders.begin(), deletedFolders.end() };
    }

    void VaultStore::ClearPendingCipherDelete(const std::string& id) {
        std::unique_lock lock(mutex);
        deletedCiphers.erase(id);
        Persist();
    }

    void VaultStore::ClearPendingFolderDelete(const std::string& id) {
        std::unique_lock lock(mutex);
        deletedFolders.erase(id);
        Persist();
    }

    VaultStore::Snapshot VaultStore::Take() const {
        std::shared_lock lock(mutex);
        return { ciphers.All(), folders.All() };
    }

    void VaultStore::Commit(RecordSet& target, const std::vector<Record>& before, std::vector<Record> merged) {
        std::unordered_map<std::string, Record> was;
        for (const auto& r : before) {
            was.emplace(IdOf(*r), r);
        }

        /*
         * Anything added or edited locally while the sync ran is newer
         * than the merge result, so it wins.
        */
        RecordSet next;
        for (auto& r : merged) {
            next.Put(std::move(r));
        }
        for (const auto& current : target.All()) {
            std::string id = IdOf(*current);
            auto prior = was.find(id);
            if (prior == was.end() || prior->second != current) {
                next.Put(current);
            }
        }
        for (const auto& [id, prior] : was) {
            if (!target.Find(id)) {
                next.Remove(id);    // deleted locally mid-sync
            }
        }
        target = std::move(next);
    }

    void VaultStore::ApplySync(const Snapshot& before, nlohmann::json remoteTopLevel, std::vector<Record> mergedCiphers,
        std::vector<Record> mergedFolders) {
        std::unique_lock lock(mutex);

        std::string version = topLevel.value("version", "");
        for (const char* key : { "ciphers", "folders" }) {
            remoteTopLevel.erase(key);
        }
        topLevel = std::move(remoteTopLevel);
        if (!version.empty()) {
            topLevel["version"] = version;
        }

        Commit(ciphers, before.ciphers, std::move(mergedCiphers));
        Commit(folders, before.folders, std::move(mergedFolders));
        Persist();
    }
}
