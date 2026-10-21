#pragma once
#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "Clientwarden.h"
#include "Auth/Session.h"
#include "Clipboard/Clipboard.h"
#include "Crypto/Crypto.h"
#include "Crypto/PasswordGenerator.h"
#include "Model/CipherSchema.h"
#include "Model/Item.h"
#include "Model/ItemQuery.h"
#include "Net/BitwardenApi.h"
#include "Net/Http.h"
#include "Platform/FileStore.h"
#include "Platform/SecretStore.h"
#include "Settings/Settings.h"
#include "Store/VaultStore.h"

namespace ClientWarden {
    enum class LoginResult {
        Success,
        NeedsTotp,
        NeedsDeviceVerification,
        NeedsPasskey,
        InvalidCredentials,
        Offline,
        Failed
    };

    enum class UnlockResult {
        Success,
        InvalidPassword,
        Failed
    };

    struct PasskeyRequest {
        std::string challenge;
        std::string relyingParty;
    };

    struct FolderInfo {
        std::string id;
        SecretString name;
    };

    /*
     * The vault facade the UI bridges talk to.
     *
     * Layering (each depends only on the ones below it):
     *
     *   Vault              orchestration, auth state machine, background work
     *   Item / ItemQuery   decrypted view of ciphers (pure, no I/O)
     *   VaultStore / Sync  local encrypted cache and merge rules
     *   Session            tokens + keys
     *   BitwardenApi       typed REST calls
     *   HttpTransport, SecretStore, FileStore   platform seams (swappable in tests)
     *   Crypto             Bitwarden crypto primitives
     *
     * All public methods are thread-safe. Methods that need keys throw
     * VaultError while locked; network failures are reported through
     * return values, not exceptions.
    */
    class Vault {
    public:
        struct Dependencies {
            std::unique_ptr<SecretStore> secrets;
            std::unique_ptr<FileStore> files;
            std::unique_ptr<HttpTransport> transport;
        };

        explicit Vault(Dependencies deps);
        ~Vault();

        Vault(const Vault&) = delete;
        Vault& operator=(const Vault&) = delete;

        /*
         * Process-wide instance for the UI bridges, built with the real
         * keychain, filesystem and network.
        */
        static Vault& Instance();
        static void DestroyInstance();

        /*
         * State
        */
        AuthState State() const { return state.load(); }
        bool Online() const { return api.Online(); }

        /*
         * Called on a background thread whenever the state changes, e.g.
         * auto-lock (Unlockable) or a remote logout (LoggedOut).
        */
        void OnStateChange(std::function<void(AuthState)> callback);

        /*
         * Login
        */
        void SetServer(const ServerUrls& urls);
        LoginResult Login(std::string_view email, std::string_view password);
        LoginResult SubmitCode(std::string_view code);

        /*
         * WebAuthn two-factor. Pass the authenticator's raw bytes; they're
         * base64url-encoded for the server here.
        */
        std::optional<PasskeyRequest> PendingPasskey() const;
        LoginResult SubmitPasskey(std::span<const uint8_t> credentialId, std::span<const uint8_t> authenticatorData,
            std::span<const uint8_t> clientDataJson, std::span<const uint8_t> signature);

        /*
         * Lock / unlock
        */
        UnlockResult Unlock(std::string_view password);
        UnlockResult UnlockWithBiometrics();
        void Lock();
        void Logout();

        bool VerifyMasterPassword(std::string_view password);
        bool EnableBiometrics();
        bool DisableBiometrics();
        bool BiometricsEnabled();

        /*
         * Reports user activity for auto-lock.
        */
        void NoteActivity(std::time_t when = std::time(nullptr));

        /*
         * Items. Save/Delete/... return true once the server has the
         * change; on false it's queued locally and retried on next sync.
        */
        bool Sync();
        std::optional<Item> GetItem(const std::string& id) const;
        Item NewItem(CipherType type) const;
        ItemQuery Query() const;

        bool Save(Item& item);
        bool Delete(const Item& item);
        bool MoveToBin(Item& item);
        bool Restore(Item& item);
        bool Archive(Item& item);
        bool Unarchive(Item& item);
        Item Duplicate(const Item& item);

        std::optional<std::string> AddAttachment(Item& item, std::string_view fileName, std::span<const uint8_t> content,
            std::function<void(float)> onProgress = nullptr);
        bool RemoveAttachment(Item& item, const std::string& attachmentId);
        bool DownloadAttachment(const Item& item, const std::string& attachmentId, const std::filesystem::path& destination,
            std::function<void(float)> onProgress = nullptr);

        /*
         * Folders
        */
        std::vector<FolderInfo> Folders() const;
        std::optional<SecretString> FolderName(const std::string& id) const;
        std::string CreateFolder(std::string_view name);
        bool RenameFolder(const std::string& id, std::string_view name);
        bool DeleteFolder(const std::string& id);

        /*
         * Misc
        */
        std::string ProfileName() const;

        /*
         * True once the server is known to run at least this version
         * (e.g. "2026.8.1" added bank account, passport and licence items).
        */
        bool ServerAtLeast(std::string_view version) const;
        std::optional<std::string> Icon(std::string_view url);
        void CopyToClipboard(std::string_view text);

        Settings& Preferences() { return settings; }
        Clipboard& SystemClipboard() { return clipboard; }
        const PasswordGenerator& Generator() const { return generator; }

    private:
        struct PendingLogin {
            std::string email;
            Crypto::KdfParams kdf;
            Bytes masterKey;
            std::string passwordHash;
            std::optional<PasskeyRequest> passkey;
        };

        void SetState(AuthState next);
        Crypto::SymmetricKey UserKey() const;
        bool NeedsLegacyData() const;

        LoginResult HandleToken(const TokenResponse& token);
        LoginResult CompleteLogin(const TokenResponse& token);
        UnlockResult UnlockWithMasterKey(Bytes masterKey);
        void OnUnlocked();

        void Post(std::function<void()> task);
        void RequestSync();
        void BackgroundLoop(std::stop_token stop);
        void NotificationLoop(std::stop_token stop);
        void StartNotifications();
        void StopNotifications();
        void Housekeeping();

        bool CommitStatusChange(Item& item, bool ok);

        std::unique_ptr<SecretStore> secrets;
        std::unique_ptr<FileStore> files;
        std::unique_ptr<HttpTransport> transport;

        BitwardenApi api;
        Session session;
        VaultStore store;
        Settings settings;
        Clipboard clipboard;
        PasswordGenerator generator;

        std::atomic<AuthState> state { AuthState::Unknown };
        std::mutex observerMutex;
        std::function<void(AuthState)> observer;

        mutable std::mutex authMutex;
        std::optional<PendingLogin> pending;
        std::optional<ServerUrls> pendingUrls;

        std::mutex syncMutex;
        std::mutex lifecycleMutex;      // orders a sync's final commit against Logout
        uint64_t epoch = 0;             // bumped by Logout; guarded by lifecycleMutex
        std::atomic<bool> syncQueued { false };
        std::atomic<std::time_t> lastActivity { 0 };
        std::time_t lastConnectivityCheck = 0;

        std::mutex taskMutex;
        std::condition_variable_any taskCv;
        std::deque<std::function<void()>> tasks;

        std::mutex notificationMutex;
        std::jthread notifications;
        std::jthread worker;
    };
}
