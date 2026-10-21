#include "ClipboardBridge.h"
#include "Vault.h"

@implementation CWClipboard

- (void)copy:(NSString *)str {
    ClientWarden::Vault::Instance().CopyToClipboard(std::string_view(str.UTF8String));
}

- (NSString *)paste {
    std::string s_str = ClientWarden::Vault::Instance().SystemClipboard().Paste();
    return [NSString stringWithUTF8String:s_str.c_str()];
}

- (void)setDelay:(NSInteger)delay {
    ClientWarden::Vault::Instance().Preferences().SetClipboardClearSeconds(static_cast<int>(delay));
}

- (NSInteger)getDelay {
    return ClientWarden::Vault::Instance().Preferences().ClipboardClearSeconds();
}

@end
