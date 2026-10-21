#include "store.h"

#include <functional>
#include <mutex>

#include "utils/encoding/encoding.h"
#include "utils/logger/logger.h"

namespace clientwarden {
    namespace {
        constexpr std::string_view c_vault_file = "vault.json";

        using IdSet = std::unordered_set<SecureString, SecureStringHash, std::equal_to<>>;

        /**
         * @brief The string id of a record.
         *
         * @param record A cipher or folder
         * @return The id, or empty if missing
         */
        SecureString idOf_(const Json& record) {
            return stringAt(record, "id");
        }

        /**
         * @brief Reads a JSON array of ids into a set.
         *
         * @param doc The vault document
         * @param key The member holding the array
         * @return The ids
         */
        IdSet idSet_(const Json& doc, std::string_view key) {
            IdSet out;
            const Json& array = at(doc, key);
            if (array.is_array()) {
                for (const Json& id : array) {
                    if (id.is_string()) {
                        out.insert(id.get<SecureString>());
                    }
                }
            }
            return out;
        }

        /**
         * @brief Whether a record is marked as created offline.
         *
         * @param record A cipher or folder
         * @return True if it hasn't reached the server yet
         */
        bool createdOffline_(const Json& record) {
            const Json& flag = at(record, "createdOffline");
            return flag.is_boolean() && flag.get<bool>();
        }

        /**
         * @brief Serialises an id set as a JSON array.
         *
         * @param ids The ids
         * @return The array
         */
        Json idArray_(const IdSet& ids) {
            Json out = Json::array();
            for (const SecureString& id : ids) {
                out.push_back(id);
            }
            return out;
        }
    }

    size_t SecureStringHash::operator()(std::string_view text) const {
        return std::hash<std::string_view>()(text);
    }

    Record RecordSet::find(std::string_view id) const {
        std::unordered_map<SecureString, size_t, SecureStringHash, std::equal_to<>>::const_iterator
                it = m_index_.find(id);
        return it == m_index_.end() ? nullptr : m_records_[it->second];
    }

    void RecordSet::put(Record record) {
        SecureString id = idOf_(*record);
        if (id.empty()) {
            return;
        }
        std::unordered_map<SecureString, size_t, SecureStringHash, std::equal_to<>>::iterator it =
                m_index_.find(id);
        if (it != m_index_.end()) {
            m_records_[it->second] = std::move(record);
        } else {
            m_index_.emplace(std::move(id), m_records_.size());
            m_records_.push_back(std::move(record));
        }
    }

    bool RecordSet::remove(std::string_view id) {
        std::unordered_map<SecureString, size_t, SecureStringHash, std::equal_to<>>::iterator it =
                m_index_.find(id);
        if (it == m_index_.end()) {
            return false;
        }
        m_records_.erase(m_records_.begin() + static_cast<std::ptrdiff_t>(it->second));
        m_index_.clear();
        for (size_t i = 0; i < m_records_.size(); ++i) {
            m_index_.emplace(idOf_(*m_records_[i]), i);
        }
        return true;
    }

    void RecordSet::clear() {
        m_records_.clear();
        m_index_.clear();
    }

    std::vector<Record> RecordSet::all() const {
        return m_records_;
    }

    Json RecordSet::toJson() const {
        Json out = Json::array();
        for (const Record& record : m_records_) {
            out.push_back(*record);
        }
        return out;
    }

    RecordSet RecordSet::fromJson(const Json& array) {
        RecordSet set;
        if (array.is_array()) {
            for (const Json& record : array) {
                if (record.is_object()) {
                    set.put(std::make_shared<const Json>(record));
                }
            }
        }
        return set;
    }

    Store::Store(std::shared_ptr<FileStore> files) : m_files_(std::move(files)) {}

    bool Store::load() {
        std::optional<SecureBytes> bytes = m_files_->read(std::filesystem::path(c_vault_file));
        if (!bytes) {
            return false;
        }

        Json doc = Json::parse(bytes->begin(), bytes->end(), nullptr, false);
        if (!doc.is_object()) {
            Logger::get()->error("vault.json is corrupt; ignoring local cache");
            return false;
        }

        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        m_ciphers_ = RecordSet::fromJson(at(doc, "ciphers"));
        m_folders_ = RecordSet::fromJson(at(doc, "folders"));
        m_deleted_ciphers_ = idSet_(doc, "deletedCiphers");
        m_deleted_folders_ = idSet_(doc, "deletedFolders");
        for (std::string_view key : { "ciphers", "folders", "deletedCiphers", "deletedFolders" }) {
            doc.erase(SecureString(key));
        }
        m_top_level_ = std::move(doc);
        return true;
    }

    void Store::clear() {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        m_top_level_ = Json::object();
        m_ciphers_.clear();
        m_folders_.clear();
        m_deleted_ciphers_.clear();
        m_deleted_folders_.clear();
        m_files_->remove(std::filesystem::path(c_vault_file));
    }

    bool Store::empty() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return !m_top_level_.contains("profile");
    }

    void Store::persist_() {
        Json doc = m_top_level_;
        doc["ciphers"] = m_ciphers_.toJson();
        doc["folders"] = m_folders_.toJson();
        doc["deletedCiphers"] = idArray_(m_deleted_ciphers_);
        doc["deletedFolders"] = idArray_(m_deleted_folders_);
        SecureString text = doc.dump();
        m_files_->write(std::filesystem::path(c_vault_file), encoding::bytesOf(text));
    }

    Json Store::getProfile() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        const Json& profile = at(m_top_level_, "profile");
        return profile.is_object() ? profile : Json::object();
    }

    Json Store::getSection(std::string_view key) const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return at(m_top_level_, key);
    }

    SecureString Store::getServerVersion() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return stringAt(m_top_level_, "version");
    }

    void Store::setServerVersion(std::string_view version) {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        m_top_level_["version"] = SecureString(version);
        persist_();
    }

    Record Store::getCipher(std::string_view id) const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return m_ciphers_.find(id);
    }

    std::vector<Record> Store::getCiphers() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return m_ciphers_.all();
    }

    void Store::putCipher(Json cipher) {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        m_ciphers_.put(std::make_shared<const Json>(std::move(cipher)));
        persist_();
    }

    void Store::removeCipher(std::string_view id, bool queue_remote_delete) {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        Record existing = m_ciphers_.find(id);
        m_ciphers_.remove(id);
        if (queue_remote_delete && existing && !createdOffline_(*existing)) {
            m_deleted_ciphers_.insert(SecureString(id));
        }
        persist_();
    }

    Record Store::getFolder(std::string_view id) const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return m_folders_.find(id);
    }

    std::vector<Record> Store::getFolders() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return m_folders_.all();
    }

    void Store::putFolder(Json folder) {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        m_folders_.put(std::make_shared<const Json>(std::move(folder)));
        persist_();
    }

    void Store::removeFolder(std::string_view id, bool queue_remote_delete) {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        Record existing = m_folders_.find(id);
        m_folders_.remove(id);
        if (queue_remote_delete && existing && !createdOffline_(*existing)) {
            m_deleted_folders_.insert(SecureString(id));
        }
        persist_();
    }

    std::vector<SecureString> Store::getPendingCipherDeletes() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return std::vector<SecureString>(m_deleted_ciphers_.begin(), m_deleted_ciphers_.end());
    }

    std::vector<SecureString> Store::getPendingFolderDeletes() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return std::vector<SecureString>(m_deleted_folders_.begin(), m_deleted_folders_.end());
    }

    void Store::clearPendingCipherDelete(std::string_view id) {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        IdSet::iterator it = m_deleted_ciphers_.find(id);
        if (it != m_deleted_ciphers_.end()) {
            m_deleted_ciphers_.erase(it);
        }
        persist_();
    }

    void Store::clearPendingFolderDelete(std::string_view id) {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);
        IdSet::iterator it = m_deleted_folders_.find(id);
        if (it != m_deleted_folders_.end()) {
            m_deleted_folders_.erase(it);
        }
        persist_();
    }

    Store::Snapshot Store::takeSnapshot() const {
        std::shared_lock<std::shared_mutex> lock(m_mutex_);
        return Snapshot { m_ciphers_.all(), m_folders_.all() };
    }

    void Store::commit_(
            RecordSet& target, const std::vector<Record>& before, std::vector<Record> merged) {
        std::unordered_map<SecureString, Record, SecureStringHash, std::equal_to<>> was;
        for (const Record& record : before) {
            was.emplace(idOf_(*record), record);
        }

        /*
         * Anything added or edited locally while the sync ran is newer than the merge result,
         * so it wins; anything deleted locally mid-sync stays deleted.
         */
        RecordSet next;
        for (Record& record : merged) {
            next.put(std::move(record));
        }
        for (const Record& current : target.all()) {
            SecureString id = idOf_(*current);
            std::unordered_map<SecureString, Record, SecureStringHash, std::equal_to<>>::iterator
                    prior = was.find(id);
            if (prior == was.end() || prior->second != current) {
                next.put(current);
            }
        }
        for (const std::pair<const SecureString, Record>& prior : was) {
            if (!target.find(prior.first)) {
                next.remove(prior.first);
            }
        }
        target = std::move(next);
    }

    void Store::applySync(const Snapshot& before, Json remote, std::vector<Record> ciphers,
            std::vector<Record> folders) {
        std::unique_lock<std::shared_mutex> lock(m_mutex_);

        SecureString version = stringAt(m_top_level_, "version");
        if (!remote.is_object()) {
            remote = Json::object();
        }
        remote.erase("ciphers");
        remote.erase("folders");
        m_top_level_ = std::move(remote);
        if (!version.empty()) {
            m_top_level_["version"] = version;
        }

        commit_(m_ciphers_, before.m_ciphers, std::move(ciphers));
        commit_(m_folders_, before.m_folders, std::move(folders));
        persist_();
    }
}
