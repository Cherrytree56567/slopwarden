#pragma once
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string_view>

#include "vault/vault.h"

namespace clientwarden::bridge {
    /**
     * @brief One entry point from a UI to the vault: call(method, args) -> result, all JSON.
     *
     * Shared by every UI that isn't Swift (Android over JNI, Linux and Windows from Rust over
     * cxx, the Wii natively), so each platform only needs a thin binding. Every call returns
     * {"ok": true, "result": ...} or {"ok": false, "error": "..."} and never throws.
     *
     * Methods are named "<area>.<action>", e.g. "auth.unlock", "items.list", "sends.open".
     * See JsonBridge.cpp for each method's arguments and result.
     */
    class JsonBridge {
    public:
        /**
         * @brief Creates a bridge.
         *
         * @param vault Returns the vault to act on (normally the active one)
         */
        explicit JsonBridge(std::function<std::shared_ptr<Vault>()> vault);

        /**
         * @brief The process-wide bridge over VaultManager::instance().getActiveVault().
         *
         * @return The bridge
         */
        static JsonBridge& shared();

        /**
         * @brief Runs a method.
         *
         * @param method e.g. "items.get"
         * @param args A JSON object (or empty for none)
         * @return The JSON response
         */
        SecureString call(std::string_view method, std::string_view args);

        /**
         * @brief Receives events the vault raises on its own, as JSON, e.g.
         * {"event": "state", "state": "Unlockable"} after auto-lock. Called on a background thread.
         *
         * @param listener The listener
         */
        void onEvent(std::function<void(SecureString)> listener);

        /**
         * @brief Handles one method: args in, result out; throws VaultError on failure.
         */
        using Handler = std::function<Json(Vault&, const Json&)>;

    private:
        void registerHandlers_();

        std::function<std::shared_ptr<Vault>()> m_vault_;
        std::map<SecureString, Handler, std::less<>> m_handlers_;
        std::mutex m_event_mutex_;
        std::function<void(SecureString)> m_listener_;
        std::shared_ptr<Vault> m_observed_;
        std::optional<ReceivedSend> m_received_;
    };
}
