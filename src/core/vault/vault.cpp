#include "vault.h"

#include "utils/logger/logger.h"

namespace clientwarden {
    Vault::Vault(SecureString id, VaultType type) : m_id_(std::move(id)), m_type_(type) {}

    SecureString Vault::getId() const {
        return m_id_;
    }

    VaultType Vault::getType() const {
        return m_type_;
    }

    VaultState Vault::getState() const {
        return m_state_.load();
    }

    SecureString Vault::getFailureReason() const {
        std::lock_guard<std::mutex> lock(m_observer_mutex_);
        return m_failure_reason_;
    }

    void Vault::onStateChange(std::function<void(VaultState)> callback) {
        std::lock_guard<std::mutex> lock(m_observer_mutex_);
        m_observer_ = std::move(callback);
    }

    std::shared_ptr<Crypto> Vault::getCrypto() const {
        return m_crypto_;
    }
    std::shared_ptr<Network> Vault::getNetwork() const {
        return m_network_;
    }
    std::shared_ptr<Session> Vault::getSession() const {
        return m_session_;
    }
    std::shared_ptr<Profile> Vault::getProfile() const {
        return m_profile_;
    }
    std::shared_ptr<Features> Vault::getFeatures() const {
        return m_features_;
    }
    std::shared_ptr<Sync> Vault::getSync() const {
        return m_sync_;
    }
    std::shared_ptr<Settings> Vault::getSettings() const {
        return m_settings_;
    }
    std::shared_ptr<AutoFill> Vault::getAutoFill() const {
        return m_autofill_;
    }
    std::shared_ptr<Orchestrator> Vault::getOrchestrator() const {
        return m_orchestrator_;
    }
    std::shared_ptr<Organizations> Vault::getOrganizations() const {
        return m_organizations_;
    }

    std::shared_ptr<Generator> Vault::getGenerator() const {
        return m_generator_;
    }

    void Vault::setState_(VaultState next) {
        VaultState previous = m_state_.load();
        do {
            /*
             * Failed is terminal until logout: nothing else may overwrite it.
             */
            if (previous == next ||
                    (previous == VaultState::Failed && next != VaultState::LoggedOut)) {
                return;
            }
        } while (!m_state_.compare_exchange_weak(previous, next));

        std::function<void(VaultState)> callback;
        {
            std::lock_guard<std::mutex> lock(m_observer_mutex_);
            callback = m_observer_;
        }
        if (callback) {
            callback(next);
        }
    }

    void Vault::setFailed_(std::string_view reason) {
        {
            std::lock_guard<std::mutex> lock(m_observer_mutex_);
            m_failure_reason_ = SecureString(reason);
        }
        Logger::get()->error("Vault entered the Failed state: {}", reason);
        setState_(VaultState::Failed);
    }
}
