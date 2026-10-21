#import "SettingsBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

@implementation SettingsBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_logout];
    [self cb_getScrshot];
    [self cb_setScrshot];
    [self cb_getBioUnlock];
    [self cb_setBioUnlock];
    [self cb_getLockDelay];
    [self cb_setLockDelay];
}

/*
 * Logout removes the vault.json, data.json, settings.json and the cw.log files,
 * and sets the state to LogOut
 */
+ (void)cb_logout {
    SettingsPanel.instance.cb_logout = ^BOOL() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            v_inst.Logout();
            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to log out"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}

+ (void)cb_getScrshot {
    SettingsPanel.instance.cb_getScrshot = ^BOOL() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            return (BOOL)v_inst.Preferences().AllowScreenshots();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to get screenshot option"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}
+ (void)cb_setScrshot {
    SettingsPanel.instance.cb_setScrshot = ^BOOL(BOOL value) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            v_inst.Preferences().SetAllowScreenshots((bool)value);

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to set screenshot option"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}

+ (void)cb_getBioUnlock {
    SettingsPanel.instance.cb_getBioUnlock = ^BOOL() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            return (BOOL)v_inst.BiometricsEnabled();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to get biometric unlock value"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}
+ (void)cb_setBioUnlock {
    SettingsPanel.instance.cb_setBioUnlock = ^BOOL(BOOL value) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            return (BOOL)(value ? v_inst.EnableBiometrics() : v_inst.DisableBiometrics());
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to set biometric unlock"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}

+ (void)cb_getLockDelay {
    SettingsPanel.instance.cb_getLockDelay = ^NSInteger() {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            return (NSInteger)v_inst.Preferences().AutoLockSeconds();
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to get Auto Lock Delay"];
                [[ToastStore instance] addToast:toast];
            });
            
            return 300;
        }
    };
}
+ (void)cb_setLockDelay {
    SettingsPanel.instance.cb_setLockDelay = ^BOOL(NSInteger value) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            
            v_inst.Preferences().SetAutoLockSeconds((int)value);

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to set Auto Lock Delay"];
                [[ToastStore instance] addToast:toast];
            });
            
            return NO;
        }
    };
}

@end