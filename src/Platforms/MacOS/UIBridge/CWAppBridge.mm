#import "CWAppBridge.h"
#import <Cocoa/Cocoa.h>
#include <thread>
#import "clientwarden-Swift.h"
#include "vault_manager/vault_manager.h"

@implementation CWAppBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self observeVault];
    [self cb_getState];
    [self cb_lock];
    [self cb_shutdown];
}

/*
 * The vault reports state changes it makes on its own (auto-lock,
 * remote logout, revoked session) so the window can follow.
 */
+ (void)observeVault {
    clientwarden::VaultManager::instance().getActiveVault()->onStateChange([](clientwarden::VaultState state) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (state == clientwarden::VaultState::Failed) {
                /*
                 * Tampered or corrupt data: the vault has dropped its keys and must be
                 * restarted before it can be trusted again.
                 */
                ClientwardenWindow.instance.state = WindowStateLogin;
                Toast* toast = [[Toast alloc] initWithMessage:@"Vault data failed an integrity check. Please restart ClientWarden."];
                [[ToastStore instance] addToast:toast];
            } else if (state == clientwarden::VaultState::LoggedOut) {
                ClientwardenWindow.instance.state = WindowStateLogin;
            } else if (state == clientwarden::VaultState::Unlockable) {
                ClientwardenWindow.instance.state = WindowStateUnlock;
            }
        });
    });
}

/*
 * GetState decides whether to present the login view (if the user
 * hasn't logged in yet) or the unlock screen (if the user has
 * logged in).
 */
+ (void)cb_getState {
    ClientwardenWindow.instance.cb_getState = ^WindowState {
        try {
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();

            if (v_inst->getState() == clientwarden::VaultState::Unlockable) {
                return WindowStateUnlock;
            } else if (v_inst->getState() == clientwarden::VaultState::Unlocked) {
                return WindowStateVault;
            } else {
                return WindowStateLogin;
            }
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Get State"];
                [[ToastStore instance] addToast:toast];
            });
            return WindowStateEmpty; //TODO: Add Error View
        }
    };
}

/*
 * lock, just asks the vault to clear passwordHashes and stuff.
 */
+ (void)cb_lock {
    ClientwardenWindow.instance.cb_lock = ^BOOL {
        try {
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();
            v_inst->lock();
            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Lock Vault"];
                [[ToastStore instance] addToast:toast];
            });
            return NO;
        }
    };
}

+ (void)cb_shutdown {
    ClientwardenWindow.instance.cb_shutdown = ^BOOL {
        try {
            clientwarden::VaultManager::destroyInstance();

            return (BOOL)true;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Shutdown Vault"];
                [[ToastStore instance] addToast:toast];
            });
            return NO;
        }
    };
}

@end