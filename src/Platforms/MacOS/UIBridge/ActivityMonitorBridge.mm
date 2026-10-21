#import "ActivityMonitorBridge.h"
#import <Cocoa/Cocoa.h>
#include <thread>
#import "clientwarden-Swift.h"
#include "vault_manager/vault_manager.h"

@implementation ActivityMonitorBridge

+ (void)setupCallbacks {
    [self cb_setLastInactivity];
}

+ (void)cb_setLastInactivity {
    ActivityMonitor.instance.cb_setLastInactivity = ^BOOL(NSDate * _Nonnull date) {
        try {
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();

            v_inst->noteActivity((time_t)[date timeIntervalSince1970]);

            return YES;
        } catch (...) {
            return NO;
        }
    };
}

@end