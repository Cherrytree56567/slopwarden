#import "UIFeaturesBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "vault_manager/vault_manager.h"

@implementation UIFeaturesBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_checkAbove26_8_1];
}

/*
 * Whether the server supports the item types added in 2026.8.1
 * (bank accounts, driver's licences and passports).
 */
+ (void)cb_checkAbove26_8_1 {
    UIFeatures.instance.cb_checkAbove26_8_1 = ^BOOL() {
        try {
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();

            return (BOOL)v_inst->getFeatures()->supportsExtendedItemTypes();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to check above 26.8.1"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

@end