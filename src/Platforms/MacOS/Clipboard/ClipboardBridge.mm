#include "ClipboardBridge.h"
#include "Clipboard.h"
#include "vault_manager/vault_manager.h"

/*
 * The clipboard is platform code; the vault only supplies the clear delay from its settings.
 */
static ClientWarden::Clipboard g_clipboard;

@implementation CWClipboard

- (void)copy:(NSString *)str {
    int delay = 30;
    try {
        delay = clientwarden::VaultManager::instance().getActiveVault()->getSettings()->getClipboardClearSeconds();
    } catch (...) {
    }
    g_clipboard.Copy(std::string_view(str.UTF8String), std::chrono::seconds(delay));
}

- (NSString *)paste {
    std::string s_str = g_clipboard.Paste();
    return [NSString stringWithUTF8String:s_str.c_str()];
}

- (void)setDelay:(NSInteger)delay {
    clientwarden::VaultManager::instance().getActiveVault()->getSettings()->setClipboardClearSeconds(static_cast<int>(delay));
}

- (NSInteger)getDelay {
    return clientwarden::VaultManager::instance().getActiveVault()->getSettings()->getClipboardClearSeconds();
}

@end
