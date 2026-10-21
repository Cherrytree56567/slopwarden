#include "send.h"

#include "utils/encoding/encoding.h"
#include "utils/errors/errors.h"
#include "utils/timestamp/timestamp.h"
#include "vault/sends/sends.h"

namespace clientwarden {
    namespace {
        constexpr std::time_t c_max_deletion_days = 31;

        /**
         * @brief Reads an optional timestamp member.
         *
         * @param object The JSON object
         * @param key The member name
         * @return Seconds since the epoch, or 0 if absent
         */
        std::time_t timeAt_(const Json& object, std::string_view key) {
            return timestamp::parse(stringAt(object, key));
        }

        /**
         * @brief Reads a boolean member, defaulting to false.
         *
         * @param object The JSON object
         * @param key The member name
         * @return The value
         */
        bool flag_(const Json& object, std::string_view key) {
            const Json& value = at(object, key);
            return value.is_boolean() && value.get<bool>();
        }
    }

    Send::Send(std::shared_ptr<Sends> sends, std::shared_ptr<Crypto> crypto, Json send,
            SecureBytes key_material)
        : m_sends_(std::move(sends)), m_crypto_(std::move(crypto)), m_data_(std::move(send)),
          m_key_material_(std::move(key_material)), m_key_(deriveKey(*m_crypto_, m_key_material_)) {
    }

    SymmetricKey Send::deriveKey(Crypto& crypto, std::span<const uint8_t> key_material) {
        return SymmetricKey::fromCombined(crypto.hkdf(key_material, "bitwarden-send", "send", 64));
    }

    SecureString Send::hashPassword(
            Crypto& crypto, std::string_view password, std::span<const uint8_t> key_material) {
        return encoding::base64Encode(
                crypto.pbkdf2(password, key_material, c_password_iterations, 32));
    }

    SecureString Send::decrypt_(const Json& value) const {
        if (!value.is_string()) {
            return SecureString();
        }
        return m_crypto_->decryptText(value.get_ref<const SecureString&>(), m_key_);
    }

    SecureString Send::getId() const {
        return stringAt(m_data_, "id");
    }
    SecureString Send::getAccessId() const {
        return stringAt(m_data_, "accessId");
    }

    SendType Send::getType() const {
        const Json& type = at(m_data_, "type");
        return type.is_number_integer() && type.get<int>() == 1 ? SendType::File : SendType::Text;
    }

    SecureString Send::getName() const {
        return decrypt_(at(m_data_, "name"));
    }
    SecureString Send::getNotes() const {
        return decrypt_(at(m_data_, "notes"));
    }
    SecureString Send::getText() const {
        return decrypt_(at(at(m_data_, "text"), "text"));
    }
    bool Send::getTextHidden() const {
        return flag_(at(m_data_, "text"), "hidden");
    }
    SecureString Send::getFileName() const {
        return decrypt_(at(at(m_data_, "file"), "fileName"));
    }

    SecureString Send::getFileSize() const {
        SecureString name = stringAt(at(m_data_, "file"), "sizeName");
        return name.empty() ? stringAt(at(m_data_, "file"), "size") : name;
    }

    std::optional<int> Send::getMaxAccessCount() const {
        const Json& count = at(m_data_, "maxAccessCount");
        if (!count.is_number_integer()) {
            return std::nullopt;
        }
        return count.get<int>();
    }

    int Send::getAccessCount() const {
        const Json& count = at(m_data_, "accessCount");
        return count.is_number_integer() ? count.get<int>() : 0;
    }

    std::time_t Send::getExpirationDate() const {
        return timeAt_(m_data_, "expirationDate");
    }
    std::time_t Send::getDeletionDate() const {
        return timeAt_(m_data_, "deletionDate");
    }
    bool Send::getDisabled() const {
        return flag_(m_data_, "disabled");
    }
    bool Send::getHideEmail() const {
        return flag_(m_data_, "hideEmail");
    }

    bool Send::hasPassword() const {
        return at(m_data_, "password").is_string() || flag_(m_data_, "authType");
    }

    SecureString Send::getShareUrl() const {
        if (getAccessId().empty() || !m_sends_) {
            return SecureString();
        }
        return m_sends_->shareUrl(getAccessId(), m_key_material_);
    }

    Send& Send::setName(std::string_view name) {
        m_data_["name"] = m_crypto_->encryptText(name, m_key_);
        return *this;
    }

    Send& Send::setNotes(std::string_view notes) {
        m_data_["notes"] = notes.empty() ? Json() : Json(m_crypto_->encryptText(notes, m_key_));
        return *this;
    }

    Send& Send::setText(std::string_view text, bool hidden) {
        if (getType() != SendType::Text) {
            throw VaultError("only text Sends have text");
        }
        m_data_["text"] = { { "text", m_crypto_->encryptText(text, m_key_) },
            { "hidden", hidden } };
        return *this;
    }

    Send& Send::setFile(std::string_view file_name, std::span<const uint8_t> content) {
        if (getType() != SendType::File) {
            throw VaultError("only file Sends have a file");
        }
        if (!getId().empty()) {
            throw VaultError("a file Send's file can't be replaced; create a new Send");
        }
        m_data_["file"] = { { "fileName", m_crypto_->encryptText(file_name, m_key_) } };
        m_pending_file_ = SecureBytes(content.begin(), content.end());
        return *this;
    }

    Send& Send::setMaxAccessCount(std::optional<int> count) {
        m_data_["maxAccessCount"] = count ? Json(*count) : Json();
        return *this;
    }

    Send& Send::setExpirationDate(std::time_t when) {
        m_data_["expirationDate"] = when ? Json(timestamp::format(when)) : Json();
        return *this;
    }

    Send& Send::setDeletionDate(std::time_t when) {
        std::time_t now = std::time(nullptr);
        if (when <= now || when > now + c_max_deletion_days * 86400) {
            throw VaultError("the deletion date must be within the next 31 days");
        }
        m_data_["deletionDate"] = timestamp::format(when);
        return *this;
    }

    Send& Send::setDisabled(bool disabled) {
        m_data_["disabled"] = disabled;
        return *this;
    }

    Send& Send::setHideEmail(bool hide) {
        m_data_["hideEmail"] = hide;
        return *this;
    }

    Send& Send::setPassword(std::string_view password) {
        if (!password.empty()) {
            m_data_["password"] = hashPassword(*m_crypto_, password, m_key_material_);
        }
        return *this;
    }

    bool Send::commit() {
        if (!m_sends_) {
            throw VaultError("Send is not attached to a vault");
        }
        return m_sends_->saveSend(*this);
    }

    bool Send::remove() {
        if (!m_sends_) {
            throw VaultError("Send is not attached to a vault");
        }
        return m_sends_->deleteSend(*this);
    }

    bool Send::removePassword() {
        if (!m_sends_) {
            throw VaultError("Send is not attached to a vault");
        }
        return m_sends_->removePassword(*this);
    }

    Json Send::getJson() const {
        return m_data_;
    }
    SymmetricKey Send::getKey() const {
        return m_key_;
    }
    std::optional<SecureBytes> Send::getPendingFile() const {
        return m_pending_file_;
    }

    void Send::replaceJson(Json send) {
        m_data_ = std::move(send);
        m_pending_file_.reset();
    }
}
