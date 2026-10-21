#pragma once
#include <memory>
#include <string_view>

#include "vault/crypto/crypto.h"

namespace clientwarden {
    /*
     * Forward declared to break the cycle Orchestrator -> Folder -> Orchestrator.
     */
    class Orchestrator;

    /**
     * @brief A folder, with a builder-style setter like items.
     */
    class Folder {
    public:
        /**
         * @brief Wraps a stored (or new) folder.
         *
         * @param orchestrator Performs commits and deletes
         * @param crypto For the name
         * @param folder The encrypted folder JSON
         * @param user_key Folders are encrypted with the user key
         */
        Folder(std::shared_ptr<Orchestrator> orchestrator, std::shared_ptr<Crypto> crypto,
                Json folder, SymmetricKey user_key);

        /**
         * @brief The folder id.
         *
         * @return The id
         */
        SecureString getId() const;

        /**
         * @brief The decrypted name.
         *
         * @return The name
         */
        SecureString getName() const;

        /**
         * @brief Renames the folder (call commit() to save).
         *
         * @param name The new name
         * @return This folder, for chaining
         */
        Folder& setName(std::string_view name);

        /**
         * @brief Saves the folder (creating it if new).
         *
         * @return True once the server has it; false if queued for sync
         */
        bool commit();

        /**
         * @brief Deletes the folder; its items move to "no folder".
         *
         * @return True once the server has deleted it; false if queued
         */
        bool remove();

        /**
         * @brief The encrypted folder JSON (for the orchestrator).
         *
         * @return A copy of the JSON
         */
        Json getJson() const;

        /**
         * @brief Replaces the JSON with the server's canonical copy.
         *
         * @param folder The new JSON
         */
        void replaceJson(Json folder);

    private:
        std::shared_ptr<Orchestrator> m_orchestrator_;
        std::shared_ptr<Crypto> m_crypto_;
        Json m_data_;
        SymmetricKey m_key_;
    };
}
