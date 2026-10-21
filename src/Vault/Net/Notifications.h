#pragma once
#include <string_view>
#include <vector>

namespace ClientWarden {
    /*
     * Push notification types from the Bitwarden hub.
     * https://github.com/bitwarden/server/blob/main/src/Core/Enums/PushType.cs
    */
    enum class PushType {
        SyncCipherUpdate = 0,
        SyncCipherCreate = 1,
        SyncLoginDelete = 2,
        SyncFolderDelete = 3,
        SyncCiphers = 4,
        SyncVault = 5,
        SyncOrgKeys = 6,
        SyncFolderCreate = 7,
        SyncFolderUpdate = 8,
        SyncCipherDelete = 9,
        SyncSettings = 10,
        LogOut = 11
    };

    /*
     * Decodes one websocket frame of SignalR MessagePack invocations
     * into the push types it carries. Frames are server-controlled, so
     * anything malformed is skipped rather than trusted.
    */
    std::vector<PushType> ParseNotificationFrame(std::string_view frame);
}
